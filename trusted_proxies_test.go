package main

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cplieger/slogx/capture"
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

// TestParseTrustedProxies pins the TRUSTED_PROXIES parsing that feeds
// webhttp.WithClientIP via the shared webhttp.ParseCIDRs helper. Three
// contracts: an unset/blank var yields nil (so ClientIP ignores X-Forwarded-For
// and logs the spoof-proof socket peer — the directly-exposed default), a valid
// CIDR + bare-IP mix parses into containment-correct nets, and a malformed entry
// is warned count-only and skipped while the valid subset is kept — startup is
// never aborted and never falls open. The malformed case mutates the
// process-global default logger, so the subtests run serially (no t.Parallel).
func TestParseTrustedProxies(t *testing.T) {
	t.Run("unset/empty yields nil (socket-peer default)", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "")
		if got := parseTrustedProxies(); got != nil {
			t.Errorf("parseTrustedProxies = %v, want nil when TRUSTED_PROXIES is empty", got)
		}
	})

	t.Run("whitespace-only yields nil", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "  ,  , ")
		if got := parseTrustedProxies(); got != nil {
			t.Errorf("parseTrustedProxies = %v, want nil for a blank list", got)
		}
	})

	t.Run("valid CIDR and bare-IP mix parsed", func(t *testing.T) {
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.5 , ::1")
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
		t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, not-an-ip, "+secretEntry)
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

// captureTextLog swaps the process-global default logger for a text handler
// writing into the returned buffer and restores the previous logger on
// cleanup. buildHandler binds WithLogger(slog.Default()) at CONSTRUCTION, so
// the capture must be installed before the handler is built; and because the
// default logger is process-global, callers must not use t.Parallel.
func captureTextLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
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
		name    string
		trusted []*net.IPNet
		wantIP  string
	}{
		{
			name:    "unset trusts nothing: client_ip is the socket peer, XFF ignored",
			trusted: nil,
			wantIP:  peerIP,
		},
		{
			name:    "trusted peer resolves the real client from X-Forwarded-For",
			trusted: []*net.IPNet{mustCIDR(t, "192.0.2.0/24")},
			wantIP:  xffIP,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureTextLog(t)

			mux := http.NewServeMux()
			mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, "/probe", http.NoBody)
			req.Header.Set("X-Forwarded-For", xffIP)
			// Synchronous ServeHTTP: the deferred access-log line fires before it
			// returns, so buf is populated with no goroutine race. The CSP value
			// is irrelevant to client-IP resolution; a fixed policy keeps the
			// stack shape production-true.
			buildHandler(mux, tc.trusted, "default-src 'self'", nil).ServeHTTP(httptest.NewRecorder(), req)

			want := "client_ip=" + tc.wantIP
			if !strings.Contains(buf.String(), want) {
				t.Errorf("access log = %q, want it to contain %q", buf.String(), want)
			}
		})
	}
}

// TestBuildHandlerSkipsAccessLogForStreams pins the access-log wiring in
// buildHandler: the long-lived streams (a real /ws upgrade and the
// /api/sessions/events SSE) must emit NO access-log line, while a request that
// reaches /ws WITHOUT the RFC 6455 upgrade headers — the classic reverse-proxy
// misconfiguration, which the engine refuses with a 426 it logs nowhere — is
// short-lived and MUST be logged; a healthy /api/health probe is suppressed at
// the default Info level while a failing probe still emits at Warn/Error.
// The token-bearing /api/sessions/ subtree must emit lines whose recorded
// path is the token-free route template (WithPathFunc — a raw session id
// must never appear), and normal requests still log their real path. A regression
// dropping the stream skips would flood the access log with one misleading line
// per reconnect; a regression widening them back to the whole /ws path would
// re-hide the unlogged 426; a regression dropping WithPathFunc would leak live
// session tokens to log-read consumers; all pass every other test. Serial: swaps
// the process-global default logger (buildHandler binds
// WithLogger(slog.Default()) at construction).
func TestBuildHandlerSkipsAccessLogForStreams(t *testing.T) {
	buf := captureTextLog(t)

	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	mux.HandleFunc("/ws", ok)
	mux.HandleFunc("/api/sessions/events", ok)
	mux.HandleFunc("/api/sessions/", ok) // subtree: catches the id-bearing REST paths (PUT {id}/title, DELETE {id})
	mux.HandleFunc("/api/health", ok)
	mux.HandleFunc("/api/sessions", ok) // exact path: create/list access lines are documented as KEPT
	mux.HandleFunc("/probe", ok)

	h := buildHandler(mux, nil, "default-src 'self'", nil)
	for _, path := range []string{"/api/sessions/events", "/api/sessions/live-token-1234/title", "/api/sessions/live-token-5678", "/api/health", "/api/sessions", "/probe"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, http.NoBody))
	}
	// A REAL upgrade attempt is the stream shape, so it stays skipped.
	upgrade := httptest.NewRequest(http.MethodGet, "/ws", http.NoBody)
	upgrade.Header.Set("Upgrade", "websocket")
	upgrade.Header.Set("Connection", "keep-alive, Upgrade")
	h.ServeHTTP(httptest.NewRecorder(), upgrade)

	log := buf.String()
	for _, skipped := range []string{"path=/ws", "path=/api/sessions/events"} {
		if strings.Contains(log, skipped) {
			t.Errorf("access log = %q, want no access line for skipped path %q (the skip wiring must keep stream lines out)", log, skipped)
		}
	}
	// A HEALTHY probe logs at Debug (ProbeLogLevel), which the Info-level
	// handler above drops — so no /api/health line lands in the stream.
	if strings.Contains(log, "path=/api/health") {
		t.Errorf("access log = %q, want no healthy-probe line at the default level (ProbeLogLevel maps 2xx to Debug)", log)
	}
	for _, token := range []string{"live-token-1234", "live-token-5678"} {
		if strings.Contains(log, token) {
			t.Errorf("access log = %q, must never carry the raw session token %q (WithPathFunc must rewrite the subtree's recorded path)", log, token)
		}
	}
	if !strings.Contains(log, "path=/api/sessions/{id}/title") {
		t.Errorf("access log = %q, want a template-path access line for the title route (the subtree's telemetry is kept, redacted)", log)
	}
	if !strings.Contains(log, "path=/api/sessions/{id}") {
		t.Errorf("access log = %q, want a template-path access line for the id route (the subtree's telemetry is kept, redacted)", log)
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
