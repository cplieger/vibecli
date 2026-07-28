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

	"github.com/cplieger/web-terminal-engine/v3/terminal"
	"github.com/cplieger/web-terminal-kiro/internal/kirocli"
)

// This file covers the SEAM between the install manager and the server: the
// per-session argv, the per-session PATH, the session-create gate and the
// loopback repair hook. internal/kirocli's own tests cover the manager; nothing
// there can see whether main.go and routes.go actually consume it, and every
// property below was silently breakable before these tests existed.

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

	got := sessionPathEnv("/config/tools/opt/kiro-cli/2.14.2")
	want := "PATH=/config/tools/opt/kiro-cli/2.14.2:/config/tools/bin:/config/tools/go/bin:/usr/bin"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("sessionPathEnv = %q, want [%q]", got, want)
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
		t.Errorf("child PATH = %q, first entry %q, want the active kiro-cli version directory %q first -- terminal.WithEnv(sessionEnvFor(deps)) is missing from the session factory, or the engine no longer appends it last",
			got, first, versionDir)
	}
}

// TestSessionCommand_perSessionPicksUpVersionSwitch pins that the argv is built
// per SESSION rather than once at boot. It is the difference between the manager
// being wired in and merely being present: the install finishes AFTER the
// listener binds, so an argv captured at startup holds the empty path the manager
// reports before any version is active, and every tab for the container's
// lifetime then runs the sign-in guard's "not installed" branch. The same
// property is what lets a rescan-recovered install serve the next tab.
func TestSessionCommand_perSessionPicksUpVersionSwitch(t *testing.T) {
	var active atomic.Value
	active.Store("")
	cliPath := func() string { s, _ := active.Load().(string); return s }
	cmd := func() []string { return sessionCommand(cliPath()) }

	// $0 is the argument after -c's script, so index 3 is the cli path.
	const cliArg = 3
	before := cmd()
	if got := before[cliArg]; got != "" {
		t.Fatalf("argv before activation carries cli path %q, want the empty path the manager reports with no active version", got)
	}
	active.Store("/config/tools/opt/kiro-cli/2.14.2/kiro-cli")
	after := cmd()
	if got := after[cliArg]; got != "/config/tools/opt/kiro-cli/2.14.2/kiro-cli" {
		t.Errorf("argv after activation carries cli path %q, want the newly active version's binary -- the factory is closing over a boot constant instead of asking per session", got)
	}
	if before[1] != after[1] || before[2] != after[2] {
		t.Errorf("the guard script or its -c flag changed between sessions (%q vs %q); only $0 may differ", before[:3], after[:3])
	}
}

// TestSessionCommand_chatArgsSurviveVersionSwitch pins the KIRO_CLI_CHAT_ARGS
// contract across the per-session rebuild: the flags stay positional params
// reaching `chat` only, never spliced into the guard script, and they are
// unaffected by which version is active. Rebuilding the argv per session is
// exactly the change that could have dropped or duplicated them.
func TestSessionCommand_chatArgsSurviveVersionSwitch(t *testing.T) {
	argv := sessionCommand("/opt/v/kiro-cli", "--v3", "--effort", "high")
	if got := argv[3]; got != "/opt/v/kiro-cli" {
		t.Errorf("argv[3] = %q, want the cli path as $0", got)
	}
	if got := strings.Join(argv[4:], " "); got != "--v3 --effort high" {
		t.Errorf("chat args = %q, want %q as positional params after $0", got, "--v3 --effort high")
	}
	if strings.Contains(argv[2], "--v3") || strings.Contains(argv[2], "high") {
		t.Errorf("chat args were spliced into the guard script: %q", argv[2])
	}
	// login and whoami must not see them: the script names both without "$@".
	for _, sub := range []string{`"$0" whoami`, `"$0" login --use-device-flow`} {
		if !strings.Contains(argv[2], sub) {
			t.Errorf("guard script lost %q, so the chat-only argument contract can no longer be read from it: %q", sub, argv[2])
		}
	}
	if !strings.Contains(argv[2], `exec "$0" chat "$@"`) {
		t.Errorf("guard script no longer forwards the positional params to chat only: %q", argv[2])
	}
}

// TestSessionCreateGate_kiroReasonPerPhase pins the create gate's kiro-cli layer
// and the reason it reports, per phase. Three separate regressions hide here:
// the layer not being composed at all (creation proceeds and every tab dies
// instantly with a false broken-install alert per tab), the layer replacing the
// tools layer instead of composing with it, and the layer collapsing every phase
// to one reason (an operator cannot tell a first-boot download from an exhausted
// retry budget, which call for opposite responses).
func TestSessionCreateGate_kiroReasonPerPhase(t *testing.T) {
	for _, reason := range []string{
		kirocli.ReasonInstalling,
		kirocli.ReasonRetrying,
		kirocli.ReasonUnavailable,
		kirocli.ReasonSettings,
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
// COMPOSE. Each must be able to refuse on its own, and a ready kiro-cli plus
// converged tools must let the request reach the inner chain -- otherwise adding
// the kiro layer would have silently replaced the tools layer (or permanently
// closed the gate).
func TestSessionCreateGate_kiroComposesWithTools(t *testing.T) {
	var toolsSyncing, kiroUnready atomic.Bool
	inner := 0
	gate := composeGate(func(next http.Handler) http.Handler { return next },
		func() (bool, string) { return toolsSyncing.Load(), "tools installing" })
	gate = composeGate(gate, func() (bool, string) {
		return kiroUnready.Load(), kirocli.ReasonInstalling
	})
	gated := gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inner++
		w.WriteHeader(http.StatusCreated)
	}))
	post := func() (int, string) {
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, terminal.SessionsPath, http.NoBody))
		return rec.Code, rec.Body.String()
	}

	cases := []struct {
		name       string
		tools      bool
		kiro       bool
		wantCode   int
		wantReason string
	}{
		// kiro-cli is checked first: it is the dependency a session cannot start
		// without at all, and its reason is the more specific one.
		{name: "both blocked", tools: true, kiro: true, wantCode: http.StatusServiceUnavailable, wantReason: kirocli.ReasonInstalling},
		{name: "kiro only", tools: false, kiro: true, wantCode: http.StatusServiceUnavailable, wantReason: kirocli.ReasonInstalling},
		{name: "tools only", tools: true, kiro: false, wantCode: http.StatusServiceUnavailable, wantReason: "tools installing"},
		{name: "neither", tools: false, kiro: false, wantCode: http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolsSyncing.Store(tc.tools)
			kiroUnready.Store(tc.kiro)
			code, body := post()
			if code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", code, tc.wantCode, body)
			}
			if tc.wantReason != "" && !strings.Contains(body, tc.wantReason) {
				t.Errorf("body %q does not name %q", body, tc.wantReason)
			}
		})
	}
	if inner != 1 {
		t.Errorf("inner handler ran %d times, want exactly 1 (only the fully-unblocked case may reach it)", inner)
	}
}

// TestKiroRescan_loopbackOnlyAndPostOnly pins the repair hook's admission, which
// is the only thing standing between an unauthenticated port and a route that
// spawns subprocesses. It is admitted exactly like the tools API: the SOCKET PEER
// and the Host header must both be loopback, forwarded headers play no part, and
// the POST method pattern keeps a GET from driving an install.
//
// A GET does not answer 405 here, and that is the mux's doing rather than a gap:
// the app also registers the catch-all "/" static pattern, which matches the path
// for any method, so Go's ServeMux serves the static 404 instead of a
// method-not-allowed. What the contract needs is that a GET never REACHES the
// handler, which is what this asserts.
func TestKiroRescan_loopbackOnlyAndPostOnly(t *testing.T) {
	newMux := func(t *testing.T, rescan func(context.Context) (bool, error)) *http.ServeMux {
		t.Helper()
		deps := newTestDeps(true)
		deps.kiroRescan = rescan
		deps.kiroReady = func() (bool, string) { return true, "" }
		mux, _, _ := mustRegisterRoutes(t, deps)
		return mux
	}
	call := func(mux *http.ServeMux, method, remote, host string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, kiroRescanPath, http.NoBody)
		req.RemoteAddr = remote
		req.Host = host
		// Forwarded headers are client-controlled, so the gate must ignore
		// them even when they claim loopback.
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
	if rec := call(mux, http.MethodPost, "192.168.1.9:5555", "localhost:9848"); rec.Code != http.StatusForbidden {
		t.Errorf("remote peer POST: status = %d, want 403 -- a remote caller must not be able to drive an install", rec.Code)
	}
	if rec := call(mux, http.MethodPost, "127.0.0.1:5555", "webterm.example.com"); rec.Code != http.StatusForbidden {
		t.Errorf("loopback peer with a non-loopback Host: status = %d, want 403 (the DNS-rebound-page shape)", rec.Code)
	}
	if rec := call(mux, http.MethodGet, "127.0.0.1:5555", "localhost:9848"); rec.Code == http.StatusOK {
		t.Errorf("loopback GET: status = %d, want anything but 200 -- a rescan changes state, so a GET must not drive one", rec.Code)
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
		return false, errors.New("/config/tools/opt/kiro-cli/2.14.2: permission denied")
	}
	deps.kiroReady = func() (bool, string) { return false, kirocli.ReasonUnavailable }
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
	if !strings.Contains(body, kirocli.ReasonUnavailable) {
		t.Errorf("failed rescan body %q does not carry the manager's reason %q", body, kirocli.ReasonUnavailable)
	}
	if strings.Contains(body, "permission denied") || strings.Contains(body, "/config/tools") {
		t.Errorf("failed rescan body %q leaks the underlying error text and a filesystem path", body)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("rescan Cache-Control = %q, want no-store", got)
	}
}

// TestKiroRescan_absentWithoutManager pins that the repair route only exists
// where there is an install to repair. With no manager (the KIRO_CLI_PATH
// override, or a bare `go run`) the route must not be registered at all, rather
// than answering with a nil-dereference panic.
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

// TestStartKiroCLI_shapes pins the three startup shapes and, most importantly,
// which of them GATES readiness. Getting this wrong is silent in both
// directions: a container that installs kiro-cli but reports ready before the
// install finishes hands every tab a dead terminal behind a green health check,
// and a bare `go run` that reports unready can never serve a session at all.
func TestStartKiroCLI_shapes(t *testing.T) {
	t.Run("KIRO_CLI_PATH override stands the manager down", func(t *testing.T) {
		rt := startKiroCLI(&baseKiro{override: "/usr/local/bin/kiro-cli", chatArgs: []string{"--v3"}})
		t.Cleanup(rt.stop)
		if rt.ready != nil {
			t.Error("override wired a readiness gate; this server does not own the install, so readiness must stay pure-listener")
		}
		if rt.rescan != nil {
			t.Error("override wired a rescan hook; there is no managed install to rescan")
		}
		if got := rt.cmd()[3]; got != "/usr/local/bin/kiro-cli" {
			t.Errorf("override argv cli path = %q, want the override verbatim", got)
		}
		if got := strings.Join(rt.cmd()[4:], " "); got != "--v3" {
			t.Errorf("override argv chat args = %q, want --v3", got)
		}
		if rt.env != nil {
			t.Error("override wired a PATH overlay; there is no version directory to lead with")
		}
	})

	t.Run("no pins falls back to the bare name", func(t *testing.T) {
		rt := startKiroCLI(&baseKiro{})
		t.Cleanup(rt.stop)
		if rt.ready != nil {
			t.Error("a pin-less run wired a readiness gate; a bare `go run` would then never be ready")
		}
		if got := rt.cmd()[3]; got != "kiro-cli" {
			t.Errorf("pin-less argv cli path = %q, want the bare name for PATH resolution", got)
		}
	})

	t.Run("unusable pins report unready rather than pretending", func(t *testing.T) {
		rt := startKiroCLI(&baseKiro{version: "2.14.2", toolsDir: t.TempDir(), sha256: "not-a-digest"})
		t.Cleanup(rt.stop)
		if rt.ready == nil {
			t.Fatal("an unusable pin left readiness ungated; no version can ever be installed, so sessions must stay gated")
		}
		ok, reason := rt.ready()
		if ok || reason != kirocli.ReasonUnavailable {
			t.Errorf("unusable pin readiness = (%v, %q), want (false, %q)", ok, reason, kirocli.ReasonUnavailable)
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
	const version = "9.9.9"
	toolsDir := t.TempDir()
	versionDir := filepath.Join(toolsDir, "opt", "kiro-cli", version)
	if err := os.MkdirAll(versionDir, 0o750); err != nil {
		t.Fatalf("create version dir: %v", err)
	}
	// A fake dispatcher set: a regular executable answering --version with the
	// pin (what selection probes) and exiting 0 for the settings calls.
	for _, name := range []string{"kiro-cli", "kiro-cli-chat"} {
		script := "#!/bin/sh\ncase \"$1\" in --version) printf 'kiro-cli " + version + "\\n' ;; esac\nexit 0\n"
		if err := os.WriteFile(filepath.Join(versionDir, name), []byte(script), 0o700); err != nil { // #nosec G306 -- a dispatcher fake must be executable
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(versionDir, ".complete"), []byte(version+"\n"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	rt := startKiroCLI(&baseKiro{
		version:     version,
		sha256:      strings.Repeat("a", 64),
		sha256ARM64: strings.Repeat("b", 64),
		toolsDir:    toolsDir,
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

	wantBin := filepath.Join(versionDir, "kiro-cli")
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
