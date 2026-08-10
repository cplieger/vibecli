package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/pinstall"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// This file covers the SEAM between the install manager and the server: the
// per-session argv, the per-session PATH, the session-create gate and the
// loopback repair hook. The pinstall library's own suite covers the manager;
// nothing there can see whether main.go and routes.go actually consume it, and
// every property below was silently breakable before these tests existed.

// TestSessionPathEnv_versionDirectoryLeads pins the precedence rule the whole
// sidecar-resolution story rests on: the active version's directory comes FIRST,
// ahead of everything the image put on PATH.
//
// It matters because $TOOLS/bin is co-owned by the toolbelt engine and
// $TOOLS/go/bin is GOPATH/bin, so either can hold a stale kiro-cli-chat (a
// restored backup volume, a stray `go install`). With the version directory
// leading, `kiro-cli chat` finds its sidecar inside the same digest-verified
// install whether it resolves a sibling of its own executable or a bare name on
// PATH. Reverse the order and that becomes a silent mixed-dispatcher-set bug: the
// main binary is the pinned one, the sidecar is not, and nothing reports it.
func TestSessionPathEnv_versionDirectoryLeads(t *testing.T) {
	t.Setenv("PATH", "/config/tools/bin:/config/tools/go/bin:/usr/bin")

	if got := sessionPathEnv(""); got != nil {
		t.Errorf("sessionPathEnv(\"\") = %v, want nil: with no active version there is nothing to prepend and the child must keep the server's own PATH", got)
	}

	got := sessionPathEnv("/config/tools/kiro-cli-versions/2.14.2")
	want := "PATH=/config/tools/kiro-cli-versions/2.14.2:/config/tools/bin:/config/tools/go/bin:/usr/bin"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("sessionPathEnv = %q, want [%q]", got, want)
	}
}

// TestSessionPathEnv_emptyInheritedPATHDoesNotWidenTheSearchPath pins the
// degenerate branch: with no inherited PATH the overlay is the version directory
// ALONE. Appending an empty inherited value instead emits "PATH=<dir>:", and a
// trailing separator is an EMPTY PATH element, which resolves to the child's
// working directory -- KWEB_WORK_DIR, the user's own repo checkouts. A
// kiro-cli-chat dropped in /workspace would then win bare-name resolution inside
// the session, the opposite of what leading with the version directory is for.
// TestSessionPathEnv_versionDirectoryLeads sets a non-empty PATH, so nothing else
// in the suite reaches this branch.
func TestSessionPathEnv_emptyInheritedPATHDoesNotWidenTheSearchPath(t *testing.T) {
	t.Setenv("PATH", "")

	versionDir := "/config/tools/kiro-cli-versions/2.14.2"
	got := sessionPathEnv(versionDir)
	want := "PATH=" + versionDir
	if len(got) != 1 || got[0] != want {
		t.Fatalf("sessionPathEnv(%q) with no inherited PATH = %q, want [%q]: an empty PATH element resolves to the child's cwd, which is the user's workspace", versionDir, got, want)
	}
}

// TestSessionEnv_reachesSpawnedPTY proves the PATH overlay survives the whole
// path from routeDeps to a live child process. The engine composes each child's
// environment itself (os.Environ plus its TERM identity, with the consumer's
// WithEnv appended LAST so it wins), so a dropped terminal.WithEnv option, or an
// overlay the engine happened to apply before its own entries, would leave every
// session resolving kiro-cli through whatever else is on PATH -- with no failing
// test and no log line. The child reports the PATH it actually received.
func TestSessionEnv_reachesSpawnedPTY(t *testing.T) {
	versionDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "path")
	deps := newTestDeps(true)
	deps.sessionEnv = func() []string { return sessionPathEnv(versionDir) }
	deps.cmd = staticCmd("/bin/sh", "-c", `printf '%s' "$PATH" > '`+marker+`'; exec cat`)
	mustStartSession(t, deps)

	got := strings.TrimSpace(string(readMarkerWithin(t, marker, 1,
		"report its PATH; the session command must write $PATH into the marker")))
	first, _, _ := strings.Cut(got, string(os.PathListSeparator))
	if first != versionDir {
		t.Errorf("child PATH = %q, first entry %q, want the active kiro-cli version directory %q first -- terminal.WithEnv(deps.sessionEnv()) is missing from the session factory, or the engine no longer appends it last",
			got, first, versionDir)
	}
}

// TestSessionCommand_pathReachesArgvOnlyAsDollarZero pins that the cli path enters
// the argv ONLY as $0: the guard script text is invariant across version switches,
// so a version change cannot rewrite the sign-in guard and no path is spliced into
// shell text. That the argv is REBUILT per session (rather than snapshotted at
// boot) is production wiring, and it is pinned through the real runtime by
// TestStartKiroCLI_managedWiringActivatesAnInstalledVersion; a factory this test
// builds itself cannot fail that way.
func TestSessionCommand_pathReachesArgvOnlyAsDollarZero(t *testing.T) {
	const activePath = "/config/tools/kiro-cli-versions/2.14.2/kiro-cli"
	// $0 is the argument after -c's script, so index 3 is the cli path.
	const cliArg = 3
	// ...and index 3 is the LAST element: exclusivity is a claim about the whole
	// argv, so the length is asserted before anything is indexed. Without it an
	// implementation that appends a second copy of the path after $0 passes every
	// check below (and would hand kiro-cli a stray positional argument).
	const wantArgc = cliArg + 1
	empty := sessionCommand("")
	active := sessionCommand(activePath)

	if len(empty) != wantArgc || len(active) != wantArgc {
		t.Fatalf("argv length = %d (empty) / %d (active), want %d for both -- the cli path may appear ONLY as $0, so any further positional argument is either a second copy of it or an unreviewed argument to the guard script; argv = %q / %q",
			len(empty), len(active), wantArgc, empty, active)
	}
	if got := empty[cliArg]; got != "" {
		t.Fatalf("argv carries cli path %q for the empty path the manager reports with no active version, want %q", got, "")
	}
	if got := active[cliArg]; got != activePath {
		t.Errorf("argv cli path = %q, want %q as $0", got, activePath)
	}
	if empty[1] != active[1] || empty[2] != active[2] {
		t.Errorf("the guard script or its -c flag changed with the cli path (%q vs %q); the path may reach the argv only as $0, or a version switch would rewrite the script", empty[:3], active[:3])
	}
	if strings.Contains(active[2], activePath) {
		t.Errorf("the cli path was spliced into the guard script: %q", active[2])
	}
}

// TestKiroReasonTextIsTheClientContract pins the four 503 reason literals and the
// mapping that produces them. The install manager reports a TYPED reason
// (pinstall.Reason) because the wording a consumer shows its own users is the
// consumer's; these strings are THIS app's wording, and they are a published
// contract in three directions: /api/health's reason field, the 503 body of
// POST /api/sessions, and the repair hook's verdict — all read by an operator and
// by a monitoring probe.
//
// The strings are spelled out here rather than compared against the constants,
// which is the whole point: a test that reads `reasonInstalling` on both sides
// passes after a rename and tells nobody that every operator-facing string changed.
// It also pins that ReasonReady renders EMPTY, which every surface relies on to
// omit the field, and that an unknown reason a future library version adds falls
// back to the terminal wording rather than to "".
func TestKiroReasonTextIsTheClientContract(t *testing.T) {
	cases := []struct {
		why  pinstall.Reason
		want string
	}{
		// Only ready renders empty; every withheld verdict below must carry text,
		// because /api/health and the create gate both key on a non-empty reason to
		// report the fault.
		{pinstall.ReasonReady, ""},
		{pinstall.ReasonInstalling, "kiro-cli installing"},
		{pinstall.ReasonRetrying, "kiro-cli install retrying"},
		{pinstall.ReasonUnavailable, "kiro-cli unavailable"},
		{pinstall.ReasonAssertion, "kiro-cli required settings not enforced"},
		// Not a reason the library defines today. A state we cannot name still
		// blocks sessions, so it must read as terminal rather than as ready.
		{pinstall.Reason(200), "kiro-cli unavailable"},
	}
	for _, tc := range cases {
		if got := kiroReasonText(tc.why); got != tc.want {
			t.Errorf("kiroReasonText(%v) = %q, want %q -- these literals are what an operator and the monitoring probe read",
				tc.why, got, tc.want)
		}
	}
}

// TestSessionCreateGate_kiroReasonPerState pins the create gate's kiro-cli layer
// and the reason it reports, per install state. Three separate regressions hide
// here: the layer not being composed at all (creation proceeds and every tab dies
// instantly with a false broken-install alert per tab), the layer replacing the
// tools layer instead of composing with it, and the layer collapsing every state
// to one reason (an operator cannot tell a first-boot download from an exhausted
// retry budget, which call for opposite responses).
func TestSessionCreateGate_kiroReasonPerState(t *testing.T) {
	for _, reason := range []string{
		reasonInstalling,
		reasonRetrying,
		reasonUnavailable,
		reasonSettings,
	} {
		t.Run(reason, func(t *testing.T) {
			deps := newTestDeps(true)
			deps.kiroReady = func() (bool, string) { return false, reason }
			mux, _, _ := mustRegisterRoutes(t, deps)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, terminal.SessionsPath, http.NoBody))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("create while %s: status = %d, want 503 (body %s)", reason, rec.Code, rec.Body.String())
			}
			var env struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("create while %s: body %q is not the standard envelope: %v", reason, rec.Body.String(), err)
			}
			if env.Error != reason {
				t.Errorf("create while %s: envelope error = %q, want the manager's own reason", reason, env.Error)
			}
			if got := rec.Header().Get("Retry-After"); got != "5" {
				t.Errorf("create while %s: Retry-After = %q, want %q", reason, got, "5")
			}
		})
	}
}

// TestSessionCreateGate_kiroComposesWithTools pins that the two blocking layers
// registerRoutes composes are BOTH there and are checked kiro-first. It drives the
// real mux, because the composition order is registerRoutes' own: with the gate
// rebuilt locally, swapping the two `if` blocks in registerRoutes left this test
// green while every "both blocked" 503 started naming the tools layer instead.
//
// Each layer must be able to refuse alone, a ready kiro-cli plus converged tools
// must reach the inner chain (so adding the kiro layer did not replace the tools
// one, nor permanently close the gate), and when both are blocked the reported
// reason must be kiro-cli's -- the dependency a session cannot start without at
// all, and the more specific answer for an operator.
func TestSessionCreateGate_kiroComposesWithTools(t *testing.T) {
	var toolsSyncing, kiroUnready atomic.Bool
	// Unready deps plus a trivial command: the one pass-through case creates a
	// real session, and the factory's fast-death Warn keys on readiness, so an
	// unready handler keeps a stray broken-install line out of a later test's
	// log capture (the same shape TestCreateRateLimit uses).
	deps := newTestDeps(false)
	deps.cmd = staticCmd("/bin/true")
	deps.toolsSyncing = toolsSyncing.Load
	deps.kiroReady = func() (bool, string) { return !kiroUnready.Load(), reasonInstalling }
	mux, _, _ := mustRegisterRoutes(t, deps)

	cases := []struct {
		name       string
		tools      bool
		kiro       bool
		wantCode   int
		wantReason string
	}{
		{name: "both blocked", tools: true, kiro: true, wantCode: http.StatusServiceUnavailable, wantReason: reasonInstalling},
		{name: "kiro only", tools: false, kiro: true, wantCode: http.StatusServiceUnavailable, wantReason: reasonInstalling},
		{name: "tools only", tools: true, kiro: false, wantCode: http.StatusServiceUnavailable, wantReason: "tools installing"},
		{name: "neither", tools: false, kiro: false, wantCode: http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolsSyncing.Store(tc.tools)
			kiroUnready.Store(tc.kiro)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, terminal.SessionsPath, http.NoBody))
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantReason != "" && !strings.Contains(rec.Body.String(), tc.wantReason) {
				t.Errorf("body %q does not name %q", rec.Body.String(), tc.wantReason)
			}
		})
	}
}

// TestKiroRescan_loopbackOnlyAndPostOnly pins the repair hook's admission, which
// is the only thing standing between an unauthenticated port and a route that
// spawns subprocesses. It is admitted exactly like the tools API: the SOCKET PEER
// and the Host header must both be loopback, a proxy/browser provenance header
// refuses even when both loopback legs pass, forwarded headers can never ADMIT,
// and the POST method pattern keeps a GET from driving an install.
//
// A GET answers 405 (Allow: POST) rather than reaching the handler: the app also
// registers the catch-all "/" static pattern, which matches the path for any
// method and would otherwise silence ServeMux's own 405 synthesis, so the
// method-agnostic mount beside the POST one is what makes the mismatch legible.
// What the contract needs is that a GET never REACHES the handler.
func TestKiroRescan_loopbackOnlyAndPostOnly(t *testing.T) {
	newMux := func(t *testing.T, rescan func(context.Context) (bool, error)) *http.ServeMux {
		t.Helper()
		deps := newTestDeps(true)
		deps.kiroRescan = rescan
		deps.kiroReady = func() (bool, string) { return true, "" }
		mux, _, _ := mustRegisterRoutes(t, deps)
		return mux
	}
	// The documented consumer -- kiro-cli's ! escape running curl inside the
	// container -- sends no proxy or browser provenance header at all.
	call := func(mux *http.ServeMux, method, remote, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, kiroRescanPath, http.NoBody)
		req.RemoteAddr = remote
		req.Host = host
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	// The same call carrying a forwarded header. It can only ever REFUSE: a
	// remote caller cannot use it to gain admission, and a request that already
	// satisfies both loopback legs loses admission because the header is
	// positive evidence it did not originate inside the container (the
	// same-loopback reverse-proxy shape, whose Host nginx and Apache rewrite to
	// the upstream address by default).
	callProxied := func(mux *http.ServeMux, method, remote, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, kiroRescanPath, http.NoBody)
		req.RemoteAddr = remote
		req.Host = host
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	calls := 0
	mux := newMux(t, func(context.Context) (bool, error) { calls++; return true, nil })

	if rec := call(mux, http.MethodPost, "127.0.0.1:5555", "localhost:9848"); rec.Code != http.StatusOK {
		t.Errorf("loopback POST: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	// No provenance header: the 403 can only come from the SOCKET-PEER leg, which
	// is otherwise unpinned now that a forwarded header refuses on its own. Verified
	// against a mutant with the peer conjunct dropped from loopbackOnly: without this
	// row the whole package stays green.
	if rec := call(mux, http.MethodPost, "192.168.1.9:5555", "localhost:9848"); rec.Code != http.StatusForbidden {
		t.Errorf("remote peer POST: status = %d, want 403 -- the socket-peer leg alone must refuse a remote caller driving an install", rec.Code)
	}
	if rec := callProxied(mux, http.MethodPost, "192.168.1.9:5555", "localhost:9848"); rec.Code != http.StatusForbidden {
		t.Errorf("remote peer POST: status = %d, want 403 -- a forwarded header claiming loopback must not admit it either", rec.Code)
	}
	if rec := callProxied(mux, http.MethodPost, "127.0.0.1:5555", "localhost:9848"); rec.Code != http.StatusForbidden {
		t.Errorf("both-ends-loopback POST with a forwarded header: status = %d, want 403 (the same-loopback reverse-proxy shape)", rec.Code)
	}
	if rec := call(mux, http.MethodPost, "127.0.0.1:5555", "webterm.example.com"); rec.Code != http.StatusForbidden {
		t.Errorf("loopback peer with a non-loopback Host: status = %d, want 403 (the DNS-rebound-page shape)", rec.Code)
	}
	// The exact response contract, not merely "not 200": the method-agnostic mount
	// exists so a GET answers 405 with Allow: POST instead of the catch-all static
	// handler's bare 404, and a not-200 assertion is green after that mount is
	// reverted.
	if rec := call(mux, http.MethodGet, "127.0.0.1:5555", "localhost:9848"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("loopback GET: status = %d, want 405 -- a rescan changes state, so a GET must not drive one, and the mount must say so rather than 404ing as static", rec.Code)
	} else if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Errorf("loopback GET: Allow = %q, want %q -- the 405 must name the method that works", got, http.MethodPost)
	}
	if calls != 1 {
		t.Errorf("rescan ran %d times, want exactly 1 (only the admitted loopback POST)", calls)
	}
}

// TestKiroRescan_reportsVerdictNotErrorText pins the repair hook's two outcomes:
// 200 when a version is active afterwards, and 503 carrying the manager's own
// readiness reason when none is -- the same verdict /api/health will serve, so a
// caller gets its answer without polling. The error text deliberately stays out
// of the body: it can name a filesystem path, and this response is not the place
// to widen what an unauthenticated-port caller learns about the volume.
func TestKiroRescan_reportsVerdictNotErrorText(t *testing.T) {
	deps := newTestDeps(true)
	deps.kiroRescan = func(context.Context) (bool, error) {
		return false, errors.New("/config/tools/kiro-cli-versions/2.14.2: permission denied")
	}
	deps.kiroReady = func() (bool, string) { return false, reasonUnavailable }
	mux, _, _ := mustRegisterRoutes(t, deps)

	req := httptest.NewRequest(http.MethodPost, kiroRescanPath, http.NoBody)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Host = "localhost:9848"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed rescan: status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, reasonUnavailable) {
		t.Errorf("failed rescan body %q does not carry the manager's reason %q", body, reasonUnavailable)
	}
	if strings.Contains(body, "permission denied") || strings.Contains(body, "/config/tools") {
		t.Errorf("failed rescan body %q leaks the underlying error text and a filesystem path", body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("rescan Cache-Control = %q, want no-store", got)
	}
}

// TestKiroRescan_absentWithoutManager pins that the repair route only exists
// where there is an install to repair. With no manager (a bare `go run` with no
// pins) the route must not be registered at all, rather than answering with a
// nil-dereference panic.
func TestKiroRescan_absentWithoutManager(t *testing.T) {
	mux, _, _ := mustRegisterRoutes(t, newTestDeps(true))
	req := httptest.NewRequest(http.MethodPost, kiroRescanPath, http.NoBody)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Host = "localhost:9848"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("rescan without a manager: status = %d, want 404", rec.Code)
	}
}

// TestStartKiroCLI_shapes pins the two UNMANAGED startup shapes and, most
// importantly, which of them GATES readiness (the managed shape is
// TestStartKiroCLI_managedWiringActivatesAnInstalledVersion's). Getting this
// wrong is silent in both directions: a container that installs kiro-cli but
// reports ready before the install finishes hands every tab a dead terminal
// behind a green health check, and a bare `go run` that reports unready can never
// serve a session at all.
func TestStartKiroCLI_shapes(t *testing.T) {
	t.Run("no pins falls back to the bare name", func(t *testing.T) {
		rt := startKiroCLI(&baseKiro{chatArgs: []string{"--v3"}})
		t.Cleanup(rt.stop)
		if rt.ready == nil {
			t.Fatal("a pin-less run left the readiness policy nil; the route layer's contract is total, so a nil policy panics on first call")
		}
		if ok, reason := rt.ready(); !ok || reason != "" {
			t.Errorf("pin-less readiness = (%v, %q), want (true, \"\"); a bare `go run` would otherwise never be ready", ok, reason)
		}
		if rt.rescan != nil {
			t.Error("a pin-less run wired a rescan hook; there is no managed install to rescan")
		}
		if got := rt.cmd()[3]; got != "kiro-cli" {
			t.Errorf("pin-less argv cli path = %q, want the bare name for PATH resolution", got)
		}
		if got := strings.Join(rt.cmd()[4:], " "); got != "--v3" {
			t.Errorf("pin-less argv chat args = %q, want --v3", got)
		}
		if rt.env == nil {
			t.Fatal("a pin-less run left the session-env policy nil; the route layer's contract is total, so a nil policy panics on first call")
		}
		if got := rt.env(); got != nil {
			t.Errorf("pin-less session env = %q, want nil; there is no version directory to lead with", got)
		}
	})

	t.Run("unusable pins report unready rather than pretending", func(t *testing.T) {
		rt := startKiroCLI(&baseKiro{version: "2.14.2", toolsDir: t.TempDir(), sha256: "not-a-digest"})
		t.Cleanup(rt.stop)
		if rt.ready == nil {
			t.Fatal("an unusable pin left readiness ungated; no version can ever be installed, so sessions must stay gated")
		}
		ok, reason := rt.ready()
		if ok || reason != reasonUnavailable {
			t.Errorf("unusable pin readiness = (%v, %q), want (false, %q)", ok, reason, reasonUnavailable)
		}
	})
}

// TestStartKiroCLI_managedWiringActivatesAnInstalledVersion drives the managed
// path through startKiroCLI end to end, with a version directory already complete
// on the volume so no download happens (the manager skips the install when the pin
// is already activatable, which is also the ordinary restart path in production).
//
// Two properties only this test can see. First, bind-first: startKiroCLI RETURNS
// while the install work is still in flight, so the caller reaches Listen instead
// of blocking behind a download; the poll below is what proves the work continued
// in the background. Second, every runtime function is wired to the manager rather
// than to a boot snapshot: the argv points INTO the activated version directory,
// and the PATH overlay leads with that same directory.
func TestStartKiroCLI_managedWiringActivatesAnInstalledVersion(t *testing.T) {
	// The fixture is the namespace suite's plantOwnVersion: one definition of what a
	// version a previous boot finished looks like (both required dispatchers, the
	// sentinel written last), so the two suites cannot drift on this app's required
	// set.
	fixture := newNSEnv(t)
	versionDir := fixture.plantOwnVersion()

	rt := startKiroCLI(&baseKiro{
		version:     nsVersion,
		sha256:      strings.Repeat("a", 64),
		sha256ARM64: strings.Repeat("b", 64),
		toolsDir:    fixture.tools,
	})
	t.Cleanup(rt.stop)

	if rt.ready == nil || rt.rescan == nil || rt.env == nil {
		t.Fatalf("managed runtime is missing wiring: ready=%v rescan=%v env=%v",
			rt.ready != nil, rt.rescan != nil, rt.env != nil)
	}
	// The activation happens in the background, so poll rather than sleep.
	deadline := time.Now().Add(20 * time.Second)
	var reason string
	for {
		ok, r := rt.ready()
		if ok {
			break
		}
		reason = r
		if time.Now().After(deadline) {
			t.Fatalf("the background install never activated the already-complete version (last readiness reason %q)", reason)
		}
		time.Sleep(10 * time.Millisecond)
	}

	wantBin := filepath.Join(versionDir, nsTool)
	if got := rt.cmd()[3]; got != wantBin {
		t.Errorf("session argv cli path = %q, want the activated version's own binary %q", got, wantBin)
	}
	env := rt.env()
	wantEnv := "PATH=" + versionDir + string(os.PathListSeparator) + os.Getenv("PATH")
	if len(env) != 1 || env[0] != wantEnv {
		t.Errorf("session env = %q, want [%q]", env, wantEnv)
	}

	// The repair hook re-derives the same answer from disk without downloading.
	ok, err := rt.rescan(context.Background())
	if !ok || err != nil {
		t.Errorf("rescan on a healthy install = (%v, %v), want (true, nil)", ok, err)
	}
}

// TestStartKiroCLI_readinessReasonIsThisAppsWording pins the last unguarded step
// of the reason contract: that the MANAGED runtime renders the library's typed
// reason through kiroReasonText rather than serving pinstall's own wording.
// TestKiroReasonTextIsTheClientContract pins the function in isolation and the
// unusable-pin shape reports a hardcoded literal, so replacing the managed
// closure's kiroReasonText(why) with why.String() changes what /api/health, the
// 503 body of POST /api/sessions and the repair hook all serve -- "required
// assertion not enforced" instead of "kiro-cli required settings not enforced" --
// with the whole suite green.
//
// It reaches a non-ready managed verdict with no download: the pinned version is
// already complete on the volume, its dispatchers answer --version with the pin
// (so selection accepts them) and fail every settings call, which is exactly the
// required-assertion state.
func TestStartKiroCLI_readinessReasonIsThisAppsWording(t *testing.T) {
	// One definition of the complete-version layout and this app's required set
	// (kirocli_namespace_test.go's plantOwnVersion), then the ONE deviation this
	// test is about: dispatchers that answer --version with the pin and FAIL every
	// settings call. Hand-building the fixture again is what l-f4 removed from this
	// file, and it would reintroduce the divergence that made a required-set change
	// fail a readiness poll without naming the missing dispatcher.
	fixture := newNSEnv(t)
	dir := fixture.plantOwnVersion()
	for _, name := range []string{nsTool, nsTool + "-chat"} {
		fixture.writeScript(filepath.Join(dir, name),
			"case \"$1\" in --version) printf 'kiro-cli "+nsVersion+"\\n' ; exit 0 ;; esac\nexit 1\n")
	}

	rt := startKiroCLI(&baseKiro{
		version:     nsVersion,
		sha256:      strings.Repeat("a", 64),
		sha256ARM64: strings.Repeat("b", 64),
		toolsDir:    fixture.tools,
	})
	// stop() CANCELS the bind-first install goroutine; it does not JOIN it, and the
	// tail of an in-flight Ensure -- the state record and the convenience symlink --
	// is not context-guarded. A cancel alone therefore leaves that goroutine still
	// writing into the tools tree while t.TempDir's RemoveAll walks it, and the
	// removal fails with "directory not empty" AFTER every assertion below has
	// already passed. That is what made this test flaky under load, and it is the
	// only way it has been observed to fail (measured: 4 failures in 240 runs with
	// the machine loaded, all four the cleanup, none the readiness poll below).
	//
	// Rescan takes the manager's own operation semaphore, so it cannot return until
	// the in-flight Ensure has released it, and after a cancel no further attempt is
	// ever started (EnsureWithRetry breaks on ctx.Err() and an Ensure that has not
	// yet acquired the slot returns at once). Joining on it is what orders the
	// cleanup instead of leaving it to the scheduler. Cleanups run LIFO, so this one
	// runs before the TempDir removal newNSEnv registered.
	t.Cleanup(func() {
		rt.stop()
		if rt.rescan != nil {
			_, _ = rt.rescan(context.Background())
		}
	})
	if rt.ready == nil {
		t.Fatal("the managed runtime wired no readiness gate, so no reason reaches any surface")
	}

	// The verdict settles in the background, so poll rather than sleep.
	deadline := time.Now().Add(5 * time.Second)
	var reason string
	for {
		ok, r := rt.ready()
		if ok {
			t.Fatal("readiness was granted while the required settings assertion fails")
		}
		reason = r
		if reason == reasonSettings {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the managed runtime reported %q, want this app's own wording %q -- the reason an operator and the monitoring probe read is no longer produced by kiroReasonText",
				reason, reasonSettings)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
