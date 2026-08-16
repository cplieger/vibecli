package main

import (
	"bytes"
	"context"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/slogx"
	"github.com/cplieger/slogx/capture"
	"github.com/cplieger/web-terminal-engine/v4/terminal"
)

// trustedContains reports whether ip is inside any of the parsed trusted nets.
func trustedContains(nets []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(ip)
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// mustCIDR parses a CIDR for test setup, failing the test on a bad literal.
func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("net.ParseCIDR(%q): %v", s, err)
	}
	return n
}

// TestParseTrustedProxies pins the WT_TRUSTED_PROXIES parsing that feeds
// webhttp.WithClientIP via the shared webhttp.ParseCIDRs helper. Four
// contracts: an unset/blank var yields nil (so ClientIP ignores X-Forwarded-For
// and logs the spoof-proof socket peer — the directly-exposed default), a valid
// CIDR + bare-IP mix parses into containment-correct nets, a malformed entry
// is warned count-only and skipped while the valid subset is kept, and a
// SEMANTICALLY impossible entry (a default route, which parses cleanly and then
// makes client_ip either the proxy itself or a value the caller forged) is
// warned about by prefix class while still being kept — startup is
// never aborted and never falls open. The warning cases mutate the
// process-global default logger, so the subtests run serially (no t.Parallel).
func TestParseTrustedProxies(t *testing.T) {
	t.Run("unset/empty yields nil (socket-peer default)", func(t *testing.T) {
		t.Setenv("WT_TRUSTED_PROXIES", "")
		if got := parseTrustedProxies(); got != nil {
			t.Errorf("parseTrustedProxies = %v, want nil when WT_TRUSTED_PROXIES is empty", got)
		}
	})

	t.Run("whitespace-only yields nil", func(t *testing.T) {
		t.Setenv("WT_TRUSTED_PROXIES", "  ,  , ")
		if got := parseTrustedProxies(); got != nil {
			t.Errorf("parseTrustedProxies = %v, want nil for a blank list", got)
		}
	})

	t.Run("valid CIDR and bare-IP mix parsed", func(t *testing.T) {
		t.Setenv("WT_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.5 , ::1")
		nets := parseTrustedProxies()
		if len(nets) != 3 {
			t.Fatalf("parseTrustedProxies len = %d, want 3 (%v)", len(nets), nets)
		}
		// The CIDR contains its range; the bare IP became a single-host net.
		for _, c := range []struct {
			ip   string
			want bool
		}{
			{"10.255.0.1", true},   // inside 10.0.0.0/8
			{"192.168.1.5", true},  // the bare host itself
			{"192.168.1.6", false}, // a neighbor of the bare host is NOT trusted
			{"172.16.0.1", false},  // outside every entry
			{"::1", true},          // the bare IPv6 host itself
		} {
			if got := trustedContains(nets, c.ip); got != c.want {
				t.Errorf("trusted contains %s = %v, want %v", c.ip, got, c.want)
			}
		}
	})

	t.Run("malformed entries are warned count-only and skipped, valid subset kept", func(t *testing.T) {
		records := capture.Default(t)

		// The secret-looking malformed entry models the credential-disclosure
		// risk: a compose interpolation mistake can place a token in the var,
		// and the warning must never copy the rejected raw value into the
		// aggregated log stream (CWE-532).
		const secretEntry = "hunter2-sekret-token"
		t.Setenv("WT_TRUSTED_PROXIES", "10.0.0.0/8, not-an-ip, "+secretEntry)
		nets := parseTrustedProxies()

		// Startup is not aborted; only the one valid CIDR is kept.
		if len(nets) != 1 {
			t.Fatalf("parseTrustedProxies len = %d, want 1 (only the valid CIDR kept)", len(nets))
		}
		if !trustedContains(nets, "10.1.2.3") {
			t.Error("kept net does not contain 10.1.2.3; want the 10.0.0.0/8 entry retained")
		}
		// The Warn was emitted at LevelWarn carrying only the malformed-entry
		// COUNT (a structured level+attr assertion, not a rendered-logfmt
		// substring match); the raw values stay out of the log entirely.
		sawWarn := false
		invalidCount := int64(-1)
		for _, r := range records.Records() {
			if r.Level != slog.LevelWarn || !strings.Contains(r.Message, "ignoring malformed") {
				continue
			}
			sawWarn = true
			r.Attrs(func(a slog.Attr) bool {
				if a.Key == "invalid_count" {
					invalidCount = a.Value.Int64()
				}
				return true
			})
		}
		if !sawWarn {
			t.Fatalf("log = %q; want the Warn about malformed entries", records.Messages())
		}
		if invalidCount != 2 {
			t.Errorf("warn attr invalid_count = %d, want 2 (both malformed entries counted)", invalidCount)
		}
		for _, raw := range []string{secretEntry, "not-an-ip"} {
			if logContains(records, raw) {
				t.Errorf("log carries rejected raw entry %q; malformed values may hold credentials and must never be logged", raw)
			}
		}
		// The needles above only catch the two values this test knows. The schema
		// catches a rejected entry that reaches the log truncated, transformed, or
		// under a new key -- and, because it pins the VALUES too, one appended to
		// the fixed hint or substituted for the count, which is the shape a library
		// bump or a well-meant "log a sample" edit would take.
		assertAttrSchema(t, records, slog.LevelWarn, "ignoring malformed", map[string]attrCheck{
			"invalid_count": wantInt(2),
			"hint":          wantString(malformedProxyHint),
		})
	})

	// A default route is syntactically perfect and semantically impossible: it
	// makes every X-Forwarded-For hop of its own family "our own hop" (so ClientIP
	// exhausts the walk and falls back to logging the PROXY), while an entry of the
	// OTHER family is never skipped and is returned as the client — so an
	// unauthenticated caller picks the client_ip recorded for its own request. The
	// warning is the only signal an operator gets; today's parser is silent.
	// Lenient by design: the set is NOT rejected, so this asserts the warning and
	// the unchanged behavior together.
	t.Run("a default route is warned about by prefix length, entries kept", func(t *testing.T) {
		records := capture.Default(t)
		// The sibling is a plausible real proxy address: the warning names the
		// default-route CLASS in fixed wording, so what must be checked is that it
		// never ENUMERATES the operator's own entries (any of which can be a
		// compose-interpolated credential, CWE-532).
		const sibling = "198.51.100.7"
		// TWO default routes, one per family: the parser warns ONCE per boot
		// (main.go breaks out of the loop), so this fixture is what makes that
		// `break` load-bearing -- with one entry the count assertion below
		// cannot tell one-per-boot from one-per-entry.
		t.Setenv("WT_TRUSTED_PROXIES", "0.0.0.0/0,::/0,"+sibling)
		nets := parseTrustedProxies()

		if len(nets) != 3 {
			t.Fatalf("parseTrustedProxies len = %d, want 3 (the warning must not reject the set)", len(nets))
		}
		warns := 0
		for _, r := range records.Records() {
			if r.Level == slog.LevelWarn && strings.Contains(r.Message, "default route") {
				warns++
			}
		}
		if warns != 1 {
			t.Errorf("log = %q, want exactly 1 default-route Warn (got %d; one per boot, not one per entry)", records.Messages(), warns)
		}
		if logContains(records, sibling) {
			t.Error("log enumerates the configured WT_TRUSTED_PROXIES entries; this var can hold a compose-interpolated credential, so the warning must name the var and the prefix class only")
		}
		// The needle above only catches the one value this test knows; the schema
		// catches an entry echoed under ANY key, of ANY length, and (because the
		// hint is pinned to its exact fixed wording) appended to the one attr this
		// record is allowed to carry -- the same reach gap the malformed-entry
		// subtest closes above.
		assertAttrSchema(t, records, slog.LevelWarn, "default route", map[string]attrCheck{
			"hint": wantString(defaultRouteHint),
		})
	})

	t.Run("narrower entries emit no default-route warning", func(t *testing.T) {
		records := capture.Default(t)
		t.Setenv("WT_TRUSTED_PROXIES", "10.0.0.0/8,192.0.2.10,::/128")
		if got := len(parseTrustedProxies()); got != 3 {
			t.Fatalf("parseTrustedProxies len = %d, want 3", got)
		}
		for _, r := range records.Records() {
			if r.Level == slog.LevelWarn && strings.Contains(r.Message, "default route") {
				t.Errorf("log = %q, want no default-route Warn for a correctly narrow proxy set", records.Messages())
			}
		}
	})
}

// logContains reports whether s appears in any captured record's message or
// attribute keys/values (groups resolved recursively). Used to prove rejected
// raw config values and command lines never reach the log stream.
func logContains(records *capture.Recorder, s string) bool {
	var inValue func(v slog.Value) bool
	inValue = func(v slog.Value) bool {
		if v.Kind() == slog.KindGroup {
			for _, a := range v.Group() {
				if strings.Contains(a.Key, s) || inValue(a.Value.Resolve()) {
					return true
				}
			}
			return false
		}
		return strings.Contains(v.String(), s)
	}
	for _, r := range records.Records() {
		if strings.Contains(r.Message, s) {
			return true
		}
		found := false
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Key, s) || inValue(a.Value.Resolve()) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// The two WT_TRUSTED_PROXIES warning hints, duplicated verbatim from
// parseTrustedProxies (main.go). Duplicating the prose is the point: these
// records are the ONLY thing an operator sees about a rejected entry, and the
// entries themselves can be compose-interpolated credentials (CWE-532), so the
// hint must stay a FIXED string that cannot grow an input-derived tail. A
// deliberate rewording updates both sides; anything else is the regression these
// pins exist to fail.
const (
	malformedProxyHint = "each entry must be a CIDR (e.g. 10.0.0.0/8) or a bare IP (e.g. 192.168.1.5)"
	defaultRouteHint   = "list only the reverse proxy's own address(es), e.g. 10.0.0.0/8 or 192.0.2.10; leave WT_TRUSTED_PROXIES unset to log the unspoofable socket peer"
)

// attrCheck validates one attribute's value. A schema pairs every attr key that
// may describe a record with the check its value must pass, so the assertion
// covers the value as well as the name.
type attrCheck func(slog.Value) bool

// wantString requires an attr's rendered value to equal want exactly. Exactness
// is the point for a FIXED operator hint: an allowlist keyed on the name alone
// stays green when a regression appends rejected content ("...unset to log the
// unspoofable socket peer (rejected: <credential>)") to a key it already permits.
func wantString(want string) attrCheck {
	return func(v slog.Value) bool { return v.String() == want }
}

// wantInt requires an attr to be an integer equal to want. Kind is checked too:
// a count replaced by a STRING of the same digits is a different attribute, and
// it is the shape a "log a sample of what we rejected" edit produces.
func wantInt(want int) attrCheck {
	return func(v slog.Value) bool { return v.Kind() == slog.KindInt64 && v.Int64() == int64(want) }
}

// isNotifyFingerprint requires exactly notifyFingerprintHexDigits lowercase hex
// digits — the shape TestNotifyFingerprint pins for the keyed HMAC, checked here
// because the production key is unreachable so the exact value is not computable
// from a live session.
func isNotifyFingerprint(v slog.Value) bool {
	s := v.String()
	return len(s) == notifyFingerprintHexDigits && strings.Trim(s, "0123456789abcdef") == ""
}

// assertAttrSchema pins the EXACT attribute set of the records at level whose
// message contains msgSub: every attr must be in the schema (an unexpected key
// fails), every attr's value must pass its check (a truncated or transformed
// value under an ALLOWED key fails — the leak a key-only allowlist cannot see),
// and every schema key must actually appear in EACH matching record (a required
// attr disappearing is a regression too; the accounting is per record, so two
// matching records cannot split the schema between them and pass on their union,
// and a message that matched nothing at all fails on its own).
// A needle sweep only catches content the test already knows; this catches
// content under any name, of any length, in any shape. Shared by the package's
// two credential boundaries (a rejected WT_TRUSTED_PROXIES entry and a classifier
// notification), so one implementation covers both.
func assertAttrSchema(t *testing.T, records *capture.Recorder, level slog.Level, msgSub string, schema map[string]attrCheck) {
	t.Helper()
	expected := slices.Sorted(maps.Keys(schema))
	matched := false
	for _, r := range records.Records() {
		if r.Level != level || !strings.Contains(r.Message, msgSub) {
			continue
		}
		matched = true
		// A FRESH map per matching record: accounting shared across records would let
		// two of them split the schema between them and pass on their union, so a
		// record carrying only invalid_count and another carrying only hint would
		// satisfy a guarantee neither one meets.
		seen := make(map[string]bool, len(schema))
		r.Attrs(func(a slog.Attr) bool {
			check, ok := schema[a.Key]
			if !ok {
				t.Errorf("%s record %q carries unexpected attr %q = %q; only %v may describe it, "+
					"or untrusted content reaches the log under a new key", level, r.Message, a.Key, a.Value, expected)
				return true
			}
			seen[a.Key] = true
			if !check(a.Value.Resolve()) {
				t.Errorf("%s record %q attr %q = %q is not the expected value; a value that keeps an allowed key "+
					"but carries rejected content (truncated, transformed, or appended) is exactly the leak a key-only allowlist misses",
					level, r.Message, a.Key, a.Value)
			}
			return true
		})
		for _, key := range expected {
			if !seen[key] {
				t.Errorf("%s record %q is missing the required attr %q (want %v); a withheld-credential guarantee "+
					"is worthless if the attrs that carry the diagnosis can silently disappear", level, r.Message, key, expected)
			}
		}
	}
	if !matched {
		t.Errorf("no %s record matching %q was captured; the attrs that carry the withheld-credential diagnosis "+
			"(%v) cannot be checked if the record itself is gone", level, msgSub, expected)
	}
}

// firstAttrValue returns the value of the first occurrence of key across the
// captured records, and whether any record carried it. Attribute equality is
// what an access-log field assertion needs; the rendered-line substring form
// also accepts a value that merely STARTS with the expectation.
func firstAttrValue(records *capture.Recorder, key string) (string, bool) {
	for _, r := range records.Records() {
		var value string
		found := false
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				value, found = a.Value.String(), true
				return false
			}
			return true
		})
		if found {
			return value, true
		}
	}
	return "", false
}

// captureTextLog swaps the process-global default logger for a text handler
// writing into the returned buffer and restores the previous logger on
// cleanup. buildHandler binds WithLogger(slog.Default()) at CONSTRUCTION, so
// the capture must be installed before the handler is built; and because the
// default logger is process-global, callers must not use t.Parallel.
//
// A TEXT handler at the DEFAULT level — slogx's, the same constructor main.go
// installs through slogx.Setup — not the slogx/capture recorder this file uses
// elsewhere, and that is load-bearing: two assertions here turn on level
// FILTERING rather than on capture. TestBuildHandlerSkipsAccessLogForStreams
// proves a HEALTHY /api/health probe never reaches the shipped stream, which is
// only true because the handler drops the Debug record ProbeLogLevel demotes it
// to; and TestBuildHandlerFailingProbeSurfaces reads the rendered level=ERROR.
// A capture.Recorder keeps records at every level, so converting these tests to
// it would make the healthy-probe line present and reduce that assertion to
// "recorded at Debug" - a weaker claim that no longer pins the demotion.
func captureTextLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	// The fleet-standard handler constructor main.go installs through
	// slogx.Setup: text/logfmt, Info by default, UTC-normalized timestamps.
	// The returned LevelVar is unused -- these tests assert against the
	// DEFAULT level, which is what makes the probe-demotion drop observable.
	handler, _ := slogx.NewHandler(slogx.Options{Output: &buf})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestBuildHandlerClientIPThreading proves the trusted-proxy set is threaded
// into webhttp.WithClientIP and drives the access log's client_ip field
// end-to-end through the production middleware chain (buildHandler). Two
// contracts: with NO trusted proxies (unset default) the logged client_ip is the
// unspoofable socket peer and a client-supplied X-Forwarded-For is ignored
// (spoof-safe); with the socket peer inside the trusted set, client_ip resolves
// to the real client from the trusted XFF. httptest.NewRequest gives a fixed
// RemoteAddr of 192.0.2.1:1234, so the peer host is 192.0.2.1. This mutates the
// process-global default logger, so it runs serially (no t.Parallel).
func TestBuildHandlerClientIPThreading(t *testing.T) {
	const (
		peerIP = "192.0.2.1"   // httptest.NewRequest default RemoteAddr host
		xffIP  = "203.0.113.7" // the "real" client behind a proxy
	)
	cases := []struct {
		name       string
		trusted    []*net.IPNet
		wantIP     string
		mustNotLog string // a value no record may carry, in any attr
	}{
		{
			name:       "unset trusts nothing: client_ip is the socket peer, XFF ignored",
			trusted:    nil,
			wantIP:     peerIP,
			mustNotLog: xffIP,
		},
		{
			name:    "trusted peer resolves the real client from X-Forwarded-For",
			trusted: []*net.IPNet{mustCIDR(t, "192.0.2.0/24")},
			wantIP:  xffIP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			records := capture.Default(t)

			mux := http.NewServeMux()
			mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, "/probe", http.NoBody)
			req.Header.Set("X-Forwarded-For", xffIP)
			// Synchronous ServeHTTP: the deferred access-log line fires before it
			// returns, so the record is captured with no goroutine race. The CSP
			// value is irrelevant to client-IP resolution; a fixed policy keeps the
			// stack shape production-true.
			buildHandler(mux, tc.trusted, "default-src 'self'", nil).ServeHTTP(httptest.NewRecorder(), req)

			got, ok := firstAttrValue(records, "client_ip")
			if !ok {
				t.Fatalf("no access-log record carries a client_ip attr; log = %q", records.Messages())
			}
			// EQUALITY, not containment: the field is the resolved HOST, so the old
			// host:port "remote" form (or a value with the forwarded chain appended)
			// has the expected IP as a PREFIX -- a substring check on the rendered
			// line accepts both, and client_ip is the last attr on the line.
			if got != tc.wantIP {
				t.Errorf("access log client_ip = %q, want exactly %q", got, tc.wantIP)
			}
			// The spoof-safe half, which the positive check cannot make: with
			// nothing trusted, the client-supplied header value is
			// attacker-controlled and must not appear in the record at all -- not as
			// client_ip, and not as some extra forwarded-for attr a library bump
			// starts recording (CWE-117).
			if tc.mustNotLog != "" && logContains(records, tc.mustNotLog) {
				t.Errorf("access log = %q carries the untrusted X-Forwarded-For value %q; an attacker-supplied string must not enter the aggregated log stream", records.Messages(), tc.mustNotLog)
			}
		})
	}
}

// TestBuildHandlerSkipsAccessLogForStreams pins the access-log wiring in
// buildHandler: the /api/sessions/events SSE stream must emit NO access-log line
// (it is the one stream path still skipped by PATH, because SSE never switches
// protocols and the response-based WithSkipUpgrades cannot cover it), while a
// request to /ws that never becomes a stream — no upgrade headers (the classic
// reverse-proxy misconfiguration, which the engine refuses with a 426 it logs
// nowhere), or a non-GET carrying them — MUST be logged; a healthy /api/health
// probe is suppressed at the default Info level while a failing probe still
// emits at Warn/Error. The admitted-upgrade half of the contract cannot be shown
// with a fake mux and lives in TestAccessLogSkipsOnlyCompletedUpgrades.
// The token-bearing /api/sessions/ subtree must emit lines whose recorded path
// is the token-free route template (a raw session id must never appear) for the
// route shapes the server actually serves, and the "(unmatched)" marker for a
// path under the subtree that routes nowhere, while normal requests still log
// their real path. A regression dropping the SSE skip would flood the access
// log with one misleading line per reconnect; a regression widening it to the
// whole /ws path would re-hide the unlogged 426; a regression dropping
// WithTemplatePathsUnder would leak live session tokens to log-read consumers;
// all pass every other test. Serial: swaps the process-global default logger
// (buildHandler binds WithLogger(slog.Default()) at construction).
//
// It mounts the ENGINE's real session routes rather than hand-written stand-ins,
// and that is the point: the recorded template now comes from the pattern the mux
// actually matched, so this asserts the app agrees with the ENGINE's route table
// instead of agreeing with its own copy of it. The app used to carry that table
// as a local string-parsing transform, and this test used to register its own
// literal paths — so an engine route added or renamed by a version bump would
// have silently logged as the fail-closed placeholder with nothing failing here.
// Mounting the real surface means the engine's table is the only copy, and a
// change to it shows up in this test's output.
func TestBuildHandlerSkipsAccessLogForStreams(t *testing.T) {
	buf := captureTextLog(t)

	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	// The engine's OWN route table, mounted the way routes.go mounts it. The
	// factory is never invoked (nothing here creates a session), so no PTY is
	// spawned; MountAPI only registers patterns.
	mgr := terminal.NewSessionManager(
		func(string) *terminal.Handler { return terminal.NewHandler([]string{"/bin/true"}) },
		terminal.WithManagerLogger(slog.New(slog.DiscardHandler)),
	)
	t.Cleanup(mgr.Shutdown)
	mgr.MountAPI(mux)
	mux.HandleFunc("/api/health", ok)
	mux.HandleFunc("/probe", ok)

	h := buildHandler(mux, nil, "default-src 'self'", nil)
	// Every session route the engine actually serves, with the METHOD each is
	// registered under (the templates are method-scoped, so a GET at a PUT-only
	// route would route nowhere and prove nothing). pinned-title carries both of
	// its verbs: it is the vendored UI's tab-rename surface, and it had no
	// coverage here at all while this test registered its own stand-in paths.
	// The last entry is a subtree path matching NO engine route: it must not be
	// reported as the legitimate {id}/title route, and its token must not leak.
	// stream marks a route that only returns when the CLIENT disconnects. Now
	// that the engine's real handlers are mounted, /api/sessions/events is the
	// live SSE stream: driven with a background context it never returns, and the
	// test hangs to its deadline (it did). An already-cancelled context is the
	// disconnect, so the handler unwinds immediately and the assertion below --
	// that a stream emits NO access line -- still exercises the real route.
	for _, req := range []struct {
		method, path string
		stream       bool
	}{
		{method: http.MethodGet, path: "/api/sessions/events", stream: true},
		{method: http.MethodPut, path: "/api/sessions/live-token-1234/title"},
		{method: http.MethodDelete, path: "/api/sessions/live-token-5678"},
		{method: http.MethodPut, path: "/api/sessions/live-token-2345/pinned-title"},
		{method: http.MethodDelete, path: "/api/sessions/live-token-3456/pinned-title"},
		{method: http.MethodGet, path: "/api/health"},
		{method: http.MethodGet, path: "/api/sessions"},
		{method: http.MethodGet, path: "/probe"},
		{method: http.MethodGet, path: "/api/sessions/live-token-9012/extra/title"},
	} {
		ctx := t.Context()
		if req.stream {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		h.ServeHTTP(httptest.NewRecorder(),
			httptest.NewRequestWithContext(ctx, req.method, req.path, http.NoBody))
	}
	// A COMPLETE upgrade attempt cannot be exercised here any more, and that is
	// the adoption showing through: the skip is webhttp.WithSkipUpgrades, decided
	// from the RESPONSE, and this mux has no /ws route to upgrade with — a 404 is
	// not a stream, so it is correctly logged. The admitted-upgrade case moved to
	// TestAccessLogSkipsOnlyCompletedUpgrades, which drives a real handshake
	// against the engine. What stays here is the REFUSAL half, which this fake
	// mux can still show.
	//
	// 16 zero bytes, base64: a structurally valid Sec-WebSocket-Key, so the
	// refused request below is refused for its METHOD and nothing else.
	const wsKey = "AAAAAAAAAAAAAAAAAAAAAA=="

	// A request carrying the upgrade HEADERS that never becomes a stream keeps
	// its access line. Here it is refused for its method; over a real engine
	// Accept answers 405, and either way the recorded response is not a protocol
	// switch — the same silence the no-upgrade-headers case exists to remove.
	badUpgrade := httptest.NewRequest(http.MethodPost, "/ws", http.NoBody)
	badUpgrade.Header.Set("Upgrade", "websocket")
	badUpgrade.Header.Set("Connection", "Upgrade")
	badUpgrade.Header.Set("Sec-WebSocket-Version", "13")
	badUpgrade.Header.Set("Sec-WebSocket-Key", wsKey)
	h.ServeHTTP(httptest.NewRecorder(), badUpgrade)

	log := buf.String()
	if !strings.Contains(log, "method=POST path=/ws") {
		t.Errorf("access log = %q, want a line for a non-GET /ws request carrying upgrade headers (it never switches protocols; only a completed upgrade may be skipped)", log)
	}
	// SSE is the one stream path still skipped by a PATH test: it never switches
	// protocols, so the response-based skip cannot cover it (see buildHandler).
	for _, skipped := range []string{"path=/api/sessions/events"} {
		if strings.Contains(log, skipped) {
			t.Errorf("access log = %q, want no access line for skipped path %q (the skip wiring must keep stream lines out)", log, skipped)
		}
	}
	// A HEALTHY probe logs at Debug (ProbeLogLevel), which the Info-level
	// handler above drops — so no /api/health line lands in the stream.
	if strings.Contains(log, "path=/api/health") {
		t.Errorf("access log = %q, want no healthy-probe line at the default level (ProbeLogLevel maps 2xx to Debug)", log)
	}
	for _, token := range []string{"live-token-1234", "live-token-5678", "live-token-2345", "live-token-3456", "live-token-9012"} {
		if strings.Contains(log, token) {
			t.Errorf("access log = %q, must never carry the raw session token %q (WithTemplatePathsUnder must rewrite the subtree's recorded path)", log, token)
		}
	}
	// A subtree path matching no engine route records the prefix plus the
	// unmatched marker: distinguishable from a real route (suffix-only matching
	// would have reported it as a title call, hiding route probing and pointing
	// an operator at the wrong handler) AND distinguishable from
	// "(path-redaction-failed)", which means the path policy itself broke rather
	// than the request routing nowhere.
	if !strings.Contains(log, "path=/api/sessions/(unmatched)") {
		t.Errorf("access log = %q, want the unmatched marker for a subtree path that routes nowhere (only served route shapes may map to a template)", log)
	}
	if strings.Contains(log, "path=(path-redaction-failed)") {
		t.Errorf("access log = %q, must not report a routine unmatched route as a FAILED path policy", log)
	}
	if n := strings.Count(log, "path=/api/sessions/{id}/title"); n != 1 {
		t.Errorf("access log = %q, got %d title-template lines, want exactly 1 (the malformed /extra/title path must not be classified as the title route)", log, n)
	}
	if !strings.Contains(log, "path=/api/sessions/{id} ") {
		t.Errorf("access log = %q, want a template-path access line for the id route (the subtree's telemetry is kept, redacted)", log)
	}
	// Both rename verbs record the SAME template, since the method is its own
	// attribute on the line. Two lines, one template.
	if n := strings.Count(log, "path=/api/sessions/{id}/pinned-title"); n != 2 {
		t.Errorf("access log = %q, got %d pinned-title template lines, want 2 (PUT and DELETE both serve that route)", log, n)
	}
	if !strings.Contains(log, "path=/probe") {
		t.Errorf("access log = %q, want an access line for the normal request path=/probe (the skip list must not swallow everything)", log)
	}
	if !strings.Contains(log, "path=/api/sessions ") {
		t.Errorf("access log = %q, want a kept access line with the REAL path for the exact /api/sessions create/list routes (they miss the subtree prefix and must not be rewritten)", log)
	}

	// A non-upgrade GET /ws never becomes a stream: it is the proxy-stripped-the-
	// upgrade-headers case, whose refusal is otherwise recorded by nobody.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ws", http.NoBody))
	if !strings.Contains(buf.String(), "path=/ws") {
		t.Errorf("access log = %q, want an access line for a NON-upgrade GET /ws (a proxy that strips Upgrade/Connection must not vanish from the log)", buf.String())
	}
}

// TestBuildHandlerFailingProbeSurfaces pins the other half of the
// ProbeLogLevel contract: a FAILING /api/health probe (the readiness 503 when
// kiro-cli is broken or missing) must land in the shipped log stream at
// Error — the silent-skip idiom this replaced hid exactly that signal.
// Serial: swaps the process-global default logger.
func TestBuildHandlerFailingProbeSurfaces(t *testing.T) {
	buf := captureTextLog(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	h := buildHandler(mux, nil, "default-src 'self'", nil)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))

	log := buf.String()
	if !strings.Contains(log, "path=/api/health") {
		t.Errorf("access log = %q, want the failing probe's access line (a 503 health check must not be silent)", log)
	}
	if !strings.Contains(log, "level=ERROR") {
		t.Errorf("access log = %q, want the failing probe at Error (ProbeLogLevel maps 5xx to Error)", log)
	}
}
