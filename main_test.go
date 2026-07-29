package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/slogx/capture"
	"github.com/cplieger/toolbelt/v2"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
	"github.com/cplieger/webhttp"
)

// fakeCLI writes an executable shell stub standing in for kiro-cli. Its whoami
// exits with whoamiRC (mirroring the real binary: 0 logged in, 1 not); login
// records its argv to a marker file and succeeds; chat records its argv
// (newline-separated, so a space inside one arg is distinguishable from two
// args) and prints a sentinel. The stub lets the sessionCommand wrapper be
// executed for real, so the guard's actual runtime behavior is pinned, not
// just the script text.
func fakeCLI(t *testing.T, dir string, whoamiRC int) (cliPath, loginMarker, chatMarker string) {
	t.Helper()
	cliPath = filepath.Join(dir, "fake kiro-cli") // space: pins the $0 quoting
	loginMarker = filepath.Join(dir, "login-args")
	chatMarker = filepath.Join(dir, "chat-args")
	stub := `#!/bin/sh
case "$1" in
whoami) exit ` + strconv.Itoa(whoamiRC) + ` ;;
login) shift; printf '%s' "$*" > ` + "'" + loginMarker + "'" + `; exit 0 ;;
chat) shift; printf '%s\n' "$@" > ` + "'" + chatMarker + "'" + `; echo CHAT_STARTED ;;
esac
`
	if err := os.WriteFile(cliPath, []byte(stub), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatalf("write fake cli: %v", err)
	}
	return cliPath, loginMarker, chatMarker
}

// TestSessionCommand_loginGuard executes the wrapper against a fake kiro-cli
// and pins the guard's contract: a logged-out CLI (whoami exits 1) gets the
// DEVICE-flow login before chat — the only sign-in flow that works from a
// browser terminal on a headless container (the default flow tries to open a
// local browser, fails, and used to leave a dead session wedging the page) —
// and a logged-in CLI goes straight to chat with no login call.
func TestSessionCommand_loginGuard(t *testing.T) {
	cases := []struct {
		name      string
		whoamiRC  int
		wantLogin bool
	}{
		{name: "logged out: device-flow login runs, then chat", whoamiRC: 1, wantLogin: true},
		{name: "logged in: straight to chat, no login", whoamiRC: 0, wantLogin: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cliPath, loginMarker, _ := fakeCLI(t, dir, tc.whoamiRC)

			argv := sessionCommand(cliPath)
			out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- test executes its own wrapper
			if err != nil {
				t.Fatalf("wrapper run: %v\noutput: %s", err, out)
			}
			if !strings.Contains(string(out), "CHAT_STARTED") {
				t.Errorf("chat did not start; output: %s", out)
			}

			args, readErr := os.ReadFile(loginMarker) // #nosec G304 -- test-owned temp path
			if tc.wantLogin {
				if readErr != nil {
					t.Fatalf("login was not invoked (marker missing): %v", readErr)
				}
				if got := string(args); got != "--use-device-flow" {
					t.Errorf("login args = %q, want %q (the browser-opening default flow cannot work headless)", got, "--use-device-flow")
				}
				if !strings.Contains(string(out), "device-flow sign-in") {
					t.Errorf("missing the sign-in explainer line; output: %s", out)
				}
			} else {
				if readErr == nil {
					t.Errorf("login was invoked for a logged-in CLI; args: %s", args)
				}
				if strings.Contains(string(out), "device-flow sign-in") {
					t.Errorf("sign-in explainer printed for a logged-in CLI; output: %s", out)
				}
			}
		})
	}
}

// TestSessionCommand_extraChatArgs pins the KIRO_CLI_CHAT_ARGS contract: extra
// launch flags (e.g. --v3) are appended to the chat invocation as separate,
// LITERAL argv entries — an arg carrying shell metacharacters or spaces must
// arrive verbatim (positional-param passing, not string splicing into the
// script) — and they never leak into the login call. Without extra args, chat
// runs with an empty argv tail (no stray empty-string argument).
func TestSessionCommand_extraChatArgs(t *testing.T) {
	t.Run("args reach chat verbatim, login unaffected", func(t *testing.T) {
		dir := t.TempDir()
		cliPath, loginMarker, chatMarker := fakeCLI(t, dir, 1) // logged out: login runs too

		injection := `$(touch ` + filepath.Join(dir, "pwned") + `); two words`
		argv := sessionCommand(cliPath, "--v3", "--effort", "high", injection)
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- test executes its own wrapper
		if err != nil {
			t.Fatalf("wrapper run: %v\noutput: %s", err, out)
		}

		got, readErr := os.ReadFile(chatMarker) // #nosec G304 -- test-owned temp path
		if readErr != nil {
			t.Fatalf("chat was not invoked (marker missing): %v", readErr)
		}
		want := "--v3\n--effort\nhigh\n" + injection + "\n"
		if string(got) != want {
			t.Errorf("chat argv = %q, want %q (args must pass as literal positional params)", got, want)
		}

		login, readErr := os.ReadFile(loginMarker) // #nosec G304 -- test-owned temp path
		if readErr != nil {
			t.Fatalf("login was not invoked (marker missing): %v", readErr)
		}
		if string(login) != "--use-device-flow" {
			t.Errorf("login args = %q, want %q (chat args must not leak into login)", login, "--use-device-flow")
		}
		if _, statErr := os.Stat(filepath.Join(dir, "pwned")); statErr == nil {
			t.Error("injection canary fired: a chat arg was shell-evaluated instead of passed literally")
		}
	})

	t.Run("no args: chat argv tail is empty", func(t *testing.T) {
		dir := t.TempDir()
		cliPath, _, chatMarker := fakeCLI(t, dir, 0)

		argv := sessionCommand(cliPath)
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- test executes its own wrapper
		if err != nil {
			t.Fatalf("wrapper run: %v\noutput: %s", err, out)
		}
		got, readErr := os.ReadFile(chatMarker) // #nosec G304 -- test-owned temp path
		if readErr != nil {
			t.Fatalf("chat was not invoked (marker missing): %v", readErr)
		}
		// `printf '%s\n' "$@"` with zero params still prints one empty line;
		// anything beyond that means a stray argument reached chat.
		if string(got) != "\n" {
			t.Errorf("chat argv tail = %q, want none (a stray empty arg would become kiro-cli's [INPUT])", got)
		}
	})
}

// TestSessionCommand_loginFailureAborts pins the guard's failure mode: when the
// device-flow login itself fails (user hit Esc, network down), the wrapper
// exits non-zero WITHOUT starting chat — the session ends cleanly (the engine
// closes it as process-exited) instead of dropping into a chat that would just
// re-prompt for sign-in and dead-end on the browser open.
func TestSessionCommand_loginFailureAborts(t *testing.T) {
	dir := t.TempDir()
	cliPath := filepath.Join(dir, "kiro-cli")
	stub := `#!/bin/sh
case "$1" in
whoami) exit 1 ;;
login) exit 1 ;;
chat) echo CHAT_STARTED ;;
esac
`
	if err := os.WriteFile(cliPath, []byte(stub), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatalf("write fake cli: %v", err)
	}

	argv := sessionCommand(cliPath)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- test executes its own wrapper
	if err == nil {
		t.Fatalf("wrapper succeeded despite login failure; output: %s", out)
	}
	if strings.Contains(string(out), "CHAT_STARTED") {
		t.Errorf("chat started despite login failure; output: %s", out)
	}
}

// TestStartTools_configDirMissing pins the out-of-container shape: a missing
// config dir disables the tools engine (bare `go run` / tests), returning the
// zero toolsRuntime whose nil funcs make registerRoutes skip /api/tools and
// the health tools field, with a Warn naming the fix. close() on the zero
// value must be a safe no-op. This test mutates the process-global default
// logger, so it runs serially (no t.Parallel).
func TestStartTools_configDirMissing(t *testing.T) {
	records := capture.Default(t)

	rt := startTools(baseTools{
		configDir:   filepath.Join(t.TempDir(), "absent"),
		catalogPath: filepath.Join(t.TempDir(), "absent-catalog.json"),
	})

	if rt.engine != nil {
		t.Fatal("engine is non-nil for a missing config dir; want the zero runtime (no tools surface outside the container)")
	}
	if rt.syncing != nil || rt.state != nil {
		t.Error("syncing/state funcs are non-nil; registerRoutes keys the /api/tools mount and the health tools field on nil")
	}
	rt.close() // zero-runtime close must not panic
	if got := records.CountLevel(slog.LevelWarn, "tools engine disabled"); got != 1 {
		t.Errorf("log = %q, want exactly one config-dir-missing Warn (got %d)", records.Messages(), got)
	}
}

// TestStartTools_configDirUnusable pins the third and fourth stat outcomes,
// which used to collapse into the missing-dir path: a config path that is a
// regular FILE, and one whose stat FAILS for a reason other than absence (a
// self-referential symlink is a deterministic ELOOP). Both are a broken mount
// of a production subsystem, not the deliberate out-of-container disable, so
// they follow degraded-not-dead: engine and syncing stay nil (sessions
// ungated) but state() reports "degraded" so /api/health carries the
// informational tools field instead of omitting it and presenting a failed
// subsystem as intentionally off. Serial: mutates the global default logger.
func TestStartTools_configDirUnusable(t *testing.T) {
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	file := filepath.Join(t.TempDir(), "config-as-file")
	if err := os.WriteFile(file, []byte("not a dir\n"), 0o600); err != nil {
		t.Fatalf("write file config path: %v", err)
	}

	for name, tc := range map[string]struct {
		configDir string
		wantMsg   string
	}{
		"regular file": {configDir: file, wantMsg: "tools engine config path is not a directory"},
		"stat failure": {configDir: loop, wantMsg: "tools engine failed to inspect config dir"},
	} {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)

			rt := startTools(baseTools{
				configDir:   tc.configDir,
				catalogPath: filepath.Join(t.TempDir(), "absent-catalog.json"),
			})

			if rt.engine != nil {
				t.Error("engine is non-nil for an unusable config path; want no engine")
			}
			if rt.syncing != nil {
				t.Error("syncing is non-nil for an unusable config path; sessions must remain ungated")
			}
			if rt.state == nil {
				t.Fatal("state is nil for an unusable config path; the health tools field would be omitted, hiding a broken mount")
			}
			if got := rt.state(); got != "degraded" {
				t.Errorf("state = %q, want %q", got, "degraded")
			}
			rt.close()
			if got := records.CountLevel(slog.LevelError, tc.wantMsg); got != 1 {
				t.Errorf("log = %q, want exactly one %q Error (got %d)", records.Messages(), tc.wantMsg, got)
			}
		})
	}
}

// TestStartTools_engineStartFailure pins degraded-not-dead: a config dir whose
// tools.json is the retired v1 format fails toolbelt.New (strict v2 schema),
// and startTools logs the Error and continues without an engine instead of
// taking the server down. Unlike the missing-config-dir path (an intentionally
// disabled subsystem: zero runtime, health omits the tools field entirely), a
// FAILED production subsystem must stay visible: the returned runtime carries
// state "degraded" so /api/health reports {"status":"ok","tools":"degraded"}
// per the documented tools=syncing|ok|degraded contract, while engine and
// syncing stay nil so sessions remain ungated. Serial: mutates the global
// default logger.
func TestStartTools_engineStartFailure(t *testing.T) {
	records := capture.Default(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tools.json"),
		[]byte(`{"runtimes":{"node":{"enabled":false}}}`), 0o644); err != nil {
		t.Fatalf("write retired manifest: %v", err)
	}

	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})

	if rt.engine != nil {
		t.Fatal("engine is non-nil despite a failed toolbelt.New; want no engine (degraded-not-dead)")
	}
	if rt.syncing != nil {
		t.Error("syncing is non-nil despite a failed toolbelt.New; sessions must remain ungated")
	}
	if rt.state == nil {
		t.Fatal("state is nil despite a failed toolbelt.New; the health tools field would be omitted, hiding the failure from health consumers")
	}
	if got := rt.state(); got != "degraded" {
		t.Errorf("state after failed engine start = %q, want %q", got, "degraded")
	}
	rt.close()
	if got := records.CountLevel(slog.LevelError, "tools engine failed to start"); got != 1 {
		t.Errorf("log = %q, want exactly one failed-to-start Error (got %d)", records.Messages(), got)
	}

	// Focused health assertion: an engine-initialization failure surfaces as
	// {"status":"ok","tools":"degraded"} — readiness is unaffected (kiro-cli
	// is the only core dependency) but the dependency failure is visible.
	deps := newTestDeps(true)
	deps.tools = rt.engine
	deps.toolsState = rt.state
	mux, _, _ := mustRegisterRoutes(t, deps)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"tools":"degraded"`) {
		t.Errorf("health after failed engine start = %d %s, want 200 with tools:degraded", rec.Code, rec.Body.String())
	}
}

// TestStartTools_bootConvergenceLiftsGate pins the bind-first boot contract on
// the happy path: with a real (empty) config dir the engine seeds the default
// all-disabled manifest, the boot reconcile has nothing to install, and the
// syncing gate LIFTS with verdict "ok" -- the property that keeps session
// creation from answering 503 "tools installing" forever. All seeded entries
// are disabled, so the pass is offline and fast; the poll is a bounded
// eventually-check on the atomic-backed funcs (race-free).
func TestStartTools_bootConvergenceLiftsGate(t *testing.T) {
	dir := t.TempDir()
	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})
	if rt.engine == nil {
		t.Fatal("engine is nil for an existing config dir; want a running tools engine")
	}
	t.Cleanup(rt.close)

	deadline := time.Now().Add(10 * time.Second)
	for rt.syncing() {
		if time.Now().After(deadline) {
			t.Fatal("boot convergence gate never lifted; session creation would 503 forever")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rt.state(); got != "ok" {
		t.Errorf("state after convergence = %q, want %q (all seeded templates are disabled: nothing to install)", got, "ok")
	}
}

// TestHostAllowlist pins the KWEB_ALLOWED_HOSTS anti-DNS-rebinding gate
// through the real middleware stack (buildHandler): a rebinding attack makes
// an attacker-controlled hostname resolve to this server, so Origin and Host
// AGREE and CrossOriginProtection alone admits both session creation and the
// /ws upgrade — the exact-host allowlist must reject those requests BEFORE
// the terminal routes, while an explicitly allowed Host still reaches them.
// Also pins canonicalization (port/case/trailing dot/IPv6 spelling), that
// X-Forwarded-Host cannot bypass the check, that the cross-origin guard still
// runs AFTER an allowed host, and that an unset allowlist stays permissive
// (backward compatible).
func TestHostAllowlist(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/sessions", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated) // stands in for REST session creation
	})
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // stands in for the WebSocket upgrade route
	})
	do := func(h http.Handler, method, url, origin, xfh string) int {
		req := httptest.NewRequest(method, url, http.NoBody)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if xfh != "" {
			req.Header.Set("X-Forwarded-Host", xfh)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Setenv("KWEB_ALLOWED_HOSTS", "localhost, 192.168.1.5, ::1, Webterm.Example.COM.")
	h := buildHandler(mux, nil, "default-src 'self'", parseAllowedHosts())

	cases := []struct {
		name        string
		method, url string
		origin, xfh string
		want        int
	}{
		{
			name:   "rebound host + matching Origin: session creation rejected",
			method: "POST", url: "http://attacker.evil:9848/api/sessions",
			origin: "http://attacker.evil:9848", want: http.StatusForbidden,
		},
		{
			name:   "rebound host: ws upgrade rejected",
			method: "GET", url: "http://attacker.evil:9848/ws", want: http.StatusForbidden,
		},
		{
			name:   "X-Forwarded-Host cannot smuggle an allowed name",
			method: "GET", url: "http://attacker.evil:9848/ws",
			xfh: "localhost", want: http.StatusForbidden,
		},
		{
			name:   "allowed host: session creation passes",
			method: "POST", url: "http://localhost:9848/api/sessions",
			origin: "http://localhost:9848", want: http.StatusCreated,
		},
		{
			name:   "allowed host: ws upgrade passes",
			method: "GET", url: "http://localhost:9848/ws", want: http.StatusOK,
		},
		{
			name:   "allowed IP passes",
			method: "GET", url: "http://192.168.1.5:9848/ws", want: http.StatusOK,
		},
		{
			name:   "case + trailing dot + port canonicalize",
			method: "GET", url: "http://WEBTERM.example.com:1234/ws", want: http.StatusOK,
		},
		{
			name:   "IPv6 spelling canonicalizes",
			method: "GET", url: "http://[0:0:0:0:0:0:0:1]:9848/ws", want: http.StatusOK,
		},
		{
			name:   "allowed host but cross-origin POST still rejected",
			method: "POST", url: "http://localhost:9848/api/sessions",
			origin: "http://attacker.evil", want: http.StatusForbidden,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(h, tc.method, tc.url, tc.origin, tc.xfh); got != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.url, got, tc.want)
			}
		})
	}

	t.Run("unset allowlist stays permissive", func(t *testing.T) {
		open := buildHandler(mux, nil, "default-src 'self'", nil)
		if got := do(open, "GET", "http://anything.example:9848/ws", "", ""); got != http.StatusOK {
			t.Errorf("GET /ws with nil allowlist = %d, want %d (unset KWEB_ALLOWED_HOSTS must stay backward compatible)", got, http.StatusOK)
		}
	})
}

// TestHostAllowlist_loopbackCarveOut pins the container-internal carve-out
// through the real middleware stack: with a browser-facing allowlist that
// names NO loopback entry, the image's own consumers — the Docker healthcheck
// (Host 127.0.0.1) and in-container tools clients (Host localhost) — must
// still be admitted because BOTH their socket peer and Host are loopback,
// while each attack shape the gate exists for stays rejected: a same-host
// browser hit by DNS rebinding presents a loopback PEER but the attacker's
// HOST (Host leg fails), and a remote client forging Host: 127.0.0.1 is not
// a loopback PEER (peer leg fails). A malformed RemoteAddr fails closed.
func TestHostAllowlist_loopbackCarveOut(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Setenv("KWEB_ALLOWED_HOSTS", "webterm.example.com") // deliberately no loopback entry
	h := buildHandler(mux, nil, "default-src 'self'", parseAllowedHosts())

	do := func(url, remoteAddr string) int {
		req := httptest.NewRequest(http.MethodGet, url, http.NoBody)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	cases := []struct {
		name       string
		url        string
		remoteAddr string
		want       int
	}{
		{
			name: "healthcheck shape: loopback peer + 127.0.0.1 Host admitted",
			url:  "http://127.0.0.1:9848/ws", remoteAddr: "127.0.0.1:54321",
			want: http.StatusOK,
		},
		{
			name: "tools shape: loopback peer + localhost Host admitted",
			url:  "http://localhost:9848/ws", remoteAddr: "127.0.0.1:54321",
			want: http.StatusOK,
		},
		{
			name: "IPv6 loopback peer + ::1 Host admitted",
			url:  "http://[::1]:9848/ws", remoteAddr: "[::1]:54321",
			want: http.StatusOK,
		},
		{
			name: "rebinding via same-host browser: loopback peer + attacker Host rejected",
			url:  "http://attacker.evil:9848/ws", remoteAddr: "127.0.0.1:54321",
			want: http.StatusForbidden,
		},
		{
			name: "forged loopback Host from remote peer rejected",
			url:  "http://127.0.0.1:9848/ws", remoteAddr: "192.168.1.50:44444",
			want: http.StatusForbidden,
		},
		{
			name: "malformed RemoteAddr fails closed",
			url:  "http://127.0.0.1:9848/ws", remoteAddr: "not-an-addr",
			want: http.StatusForbidden,
		},
		{
			name: "allowlisted host from remote peer still passes (unchanged)",
			url:  "http://webterm.example.com:9848/ws", remoteAddr: "192.168.1.50:44444",
			want: http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(tc.url, tc.remoteAddr); got != tc.want {
				t.Errorf("GET %s (peer %s) = %d, want %d", tc.url, tc.remoteAddr, got, tc.want)
			}
		})
	}
}

// TestHostAllowlist_blankConfigurationStaysPermissive drives a configured but
// blank KWEB_ALLOWED_HOSTS (only commas and whitespace) through the real
// parseAllowedHosts into the middleware: blank entries never engage the gate
// (webhttp.ParseHostList leaves the policy INACTIVE), so the documented
// permissive state must hold. Accidentally treating a blank entry as
// non-blank would turn a blank configuration into a deny-all outage.
func TestHostAllowlist_blankConfigurationStaysPermissive(t *testing.T) {
	t.Setenv("KWEB_ALLOWED_HOSTS", "  ,  , ")
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	buildHandler(mux, nil, "default-src 'self'", parseAllowedHosts()).ServeHTTP(
		rec,
		httptest.NewRequest(http.MethodGet, "http://anything.example:9848/probe", http.NoBody),
	)

	if rec.Code != http.StatusNoContent {
		t.Errorf("blank KWEB_ALLOWED_HOSTS: GET /probe status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// TestStartTools_reconcileFailureLiftsGateDegraded pins the degraded-not-dead
// contract on the FAILURE path, which the happy-path convergence test cannot
// reach: a manifest with an enabled tool the (absent) catalog cannot resolve
// makes the boot reconcile job finish failed, and the syncing gate must STILL
// lift — with verdict "degraded" — so session creation never answers 503
// "tools installing" forever after a broken install. The install failure is
// local (no catalog knowledge), so the test is offline and fast.
func TestStartTools_reconcileFailureLiftsGateDegraded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tools.json"),
		[]byte(`{"version":2,"tools":{"no-such-tool-xyz":{}}}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})
	if rt.engine == nil {
		t.Fatal("engine is nil for an existing config dir; want a running tools engine")
	}
	t.Cleanup(rt.close)

	deadline := time.Now().Add(10 * time.Second)
	for rt.syncing() {
		if time.Now().After(deadline) {
			t.Fatal("boot convergence gate never lifted after a failed reconcile; session creation would 503 forever")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rt.state(); got != "degraded" {
		t.Errorf("state after failed reconcile = %q, want %q (a failed install must degrade, not stay syncing or report ok)", got, "degraded")
	}
}

// TestStartTools_emptyManifestSkipsGate pins the job==nil short-circuit: a
// pre-existing EMPTY manifest gives the boot reconcile nothing to converge
// (Reconcile returns a nil job), so the gate must never engage and the verdict
// is immediately "ok" — session creation is never blocked on a no-op pass.
func TestStartTools_emptyManifestSkipsGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tools.json"),
		[]byte(`{"version":2,"tools":{}}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})
	if rt.engine == nil {
		t.Fatal("engine is nil for an existing config dir; want a running tools engine")
	}
	t.Cleanup(rt.close)

	if rt.syncing() {
		t.Error("syncing gate engaged for an empty manifest; want an immediate no-op (nothing to converge)")
	}
	if got := rt.state(); got != "ok" {
		t.Errorf("state for an empty manifest = %q, want %q", got, "ok")
	}
}

// TestWarnIfNoLSPEnabled pins both silent branches of the code-intelligence
// nudge, which the boot-convergence path only exercises on the warning side:
// an ENABLED catalog-marked language server must silence the Warn (the whole
// point of the Lsp inventory marker), while an inventory read failure must report
// its own manifest-unreadable Warn without emitting the no-LSP nudge. Serial:
// mutates the process-global default logger.
func TestWarnIfNoLSPEnabled(t *testing.T) {
	const warnMsg = "no language servers enabled"

	newEngine := func(t *testing.T, manifest, catalog string) (*toolbelt.Engine, string) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(manifest), 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		catalogPath := filepath.Join(dir, "catalog.json")
		if catalog == "" {
			catalogPath = filepath.Join(dir, "absent-catalog.json")
		} else if err := os.WriteFile(catalogPath, []byte(catalog), 0o644); err != nil {
			t.Fatalf("write catalog: %v", err)
		}
		eng, err := toolbelt.New(&toolbelt.Config{
			ConfigDir:   dir,
			ToolsDir:    filepath.Join(dir, "tools"),
			CatalogPath: catalogPath,
		})
		if err != nil {
			t.Fatalf("toolbelt.New: %v", err)
		}
		t.Cleanup(eng.Close)
		return eng, dir
	}
	t.Run("enabled catalog-marked LSP silences the warn", func(t *testing.T) {
		eng, _ := newEngine(t,
			`{"version":2,"tools":{"gopls":{}}}`,
			`{"entries":{"gopls":{"name":"gopls","source":"go:golang.org/x/tools/gopls","lsp":true}}}`)
		records := capture.Default(t)
		warnIfNoLSPEnabled(eng)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q; an enabled Lsp-marked tool must silence the nudge (got %d Warns)", records.Messages(), got)
		}
	})

	t.Run("no enabled LSP warns", func(t *testing.T) {
		// gopls present but disabled (a template), so the nudge must fire.
		eng, _ := newEngine(t,
			`{"version":2,"tools":{"gopls":{"disabled":true}}}`,
			`{"entries":{"gopls":{"name":"gopls","source":"go:golang.org/x/tools/gopls","lsp":true}}}`)
		records := capture.Default(t)
		warnIfNoLSPEnabled(eng)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 1 {
			t.Errorf("log = %q, want exactly one %q Warn (no enabled language server; got %d)", records.Messages(), warnMsg, got)
		}
	})

	t.Run("inventory failure reports itself, not the nudge", func(t *testing.T) {
		eng, dir := newEngine(t, `{"version":2,"tools":{}}`, "")
		// Corrupt the manifest AFTER engine start: Inventory re-reads it from
		// disk, so the read now fails. The property pinned here is that the
		// failure must NOT surface as the LSP nudge Warn (the nudge's absence
		// would otherwise be read as "a language server is enabled"); it
		// reports itself under its own message instead.
		if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte("{not json"), 0o644); err != nil {
			t.Fatalf("corrupt manifest: %v", err)
		}
		records := capture.Default(t)
		warnIfNoLSPEnabled(eng)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q; an inventory failure must not produce the LSP Warn (got %d)", records.Messages(), got)
		}
		const readFailMsg = "tools: manifest unreadable; cannot tell whether a language server is enabled"
		if got := records.CountLevel(slog.LevelWarn, readFailMsg); got != 1 {
			t.Errorf("log = %q, want exactly one %q Warn (the read failure must not regress to Debug; got %d)", records.Messages(), readFailMsg, got)
		}
	})
}

// TestParseAllowedHosts unit-tests the KWEB_ALLOWED_HOSTS parser directly,
// covering the branches TestHostAllowlist's middleware-level driving cannot
// reach: an unset/empty var must yield an INACTIVE policy (the permissive
// backward-compatible default main keys its rebinding warning on), and a
// URL-shaped entry (scheme/path/CIDR pasted where a bare hostname belongs)
// must emit exactly one named Warn while being DROPPED per ParseHostList's
// drop-and-report contract — the entry canonicalizes to a value no
// browser-sent Host ever matches, so retaining it (the pre-webhttp behavior)
// only created an unmatchable key an attacker-chosen Host like "http:9848"
// could in principle collide with. The valid subset must keep working.
// Serial: capture.Default mutates the process-global default logger.
func TestParseAllowedHosts(t *testing.T) {
	allows := func(t *testing.T, policy *webhttp.HostPolicy, host, remoteAddr string) bool {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/probe", http.NoBody)
		if remoteAddr != "" {
			req.RemoteAddr = remoteAddr
		}
		return policy.Allows(req)
	}

	t.Run("unset env yields an inactive policy (any Host accepted)", func(t *testing.T) {
		t.Setenv("KWEB_ALLOWED_HOSTS", "")
		policy := parseAllowedHosts()
		if policy.Active() {
			t.Error("parseAllowedHosts() is active for an unset/empty KWEB_ALLOWED_HOSTS; want the permissive backward-compatible default")
		}
		if !allows(t, policy, "anything.example:9848", "") {
			t.Error("inactive policy rejected a request; unset KWEB_ALLOWED_HOSTS must accept every Host")
		}
	})

	t.Run("URL-shaped entry warns and is dropped", func(t *testing.T) {
		records := capture.Default(t)
		t.Setenv("KWEB_ALLOWED_HOSTS", "http://webterm.example.com, localhost")
		policy := parseAllowedHosts()

		if got := records.CountLevel(slog.LevelWarn, "dropping malformed"); got != 1 {
			t.Errorf("log = %q, want exactly one dropping-malformed Warn (got %d); a pasted URL silently 403-ing every request with no hint is the misconfiguration this Warn exists for", records.Messages(), got)
		}
		if !policy.Active() {
			t.Fatal("policy is inactive despite a non-blank configuration; the gate must engage")
		}
		if got := policy.Size(); got != 1 {
			t.Fatalf("policy size = %d, want 1 (the malformed entry is dropped, the valid one kept)", got)
		}
		if !allows(t, policy, "localhost:9848", "192.168.1.50:44444") {
			t.Error("valid entry localhost missing from the allowlist")
		}
		// The pre-webhttp parser RETAINED the malformed entry as the
		// unmatchable key "http"; the drop-and-report contract removes it, so
		// a request whose Host canonicalizes to "http" must now be rejected.
		if allows(t, policy, "http:9848", "192.168.1.50:44444") {
			t.Error(`Host "http:9848" admitted; the dropped URL-shaped entry must leave no residual key behind`)
		}
	})
}

// TestParseAllowedHosts_allInvalidFailsClosed pins the all-invalid branch
// TestParseAllowedHosts's other cases never reach: a var whose entries are a
// lone ":9848" (a pasted KWEB_ADDR value) and a URL-shaped credential paste
// canonicalizes to an empty host set no browser-sent Host can ever match, so
// the parser must Warn twice — the dropped-entry count, then the resulting
// deny-all state — and yield an ACTIVE EMPTY policy: every non-loopback
// request is rejected (fail closed, never silently unprotected) while the
// loopback carve-out keeps the container's own healthcheck working. The
// warnings carry only the count: a rejected raw entry could hold a credential
// (the secret-looking case below) and must never reach the log (CWE-532).
// Serial: capture.Default mutates the process-global default logger.
func TestParseAllowedHosts_allInvalidFailsClosed(t *testing.T) {
	records := capture.Default(t)
	const secretEntry = "hunter2-sekret-token"
	t.Setenv("KWEB_ALLOWED_HOSTS", ":9848,https://user:"+secretEntry+"@proxy.internal")

	policy := parseAllowedHosts()

	if got := records.CountLevel(slog.LevelWarn, "dropping malformed"); got != 1 {
		t.Errorf("log = %q, want exactly one dropping-malformed Warn (got %d)", records.Messages(), got)
	}
	if got := records.CountLevel(slog.LevelWarn, "no usable entries"); got != 1 {
		t.Errorf("log = %q, want exactly one no-usable-entries deny-all Warn (got %d)", records.Messages(), got)
	}
	invalidCount := int64(-1)
	for _, r := range records.Records() {
		if r.Level != slog.LevelWarn || !strings.Contains(r.Message, "dropping malformed") {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "invalid_count" {
				invalidCount = a.Value.Int64()
			}
			return true
		})
	}
	if invalidCount != 2 {
		t.Errorf("warn attr invalid_count = %d, want 2 (both malformed entries counted)", invalidCount)
	}
	if logContains(records, secretEntry) {
		t.Errorf("log carries rejected raw entry containing %q; malformed KWEB_ALLOWED_HOSTS values may hold credentials and must never be logged", secretEntry)
	}
	if !policy.Active() {
		t.Fatal("policy is inactive despite a non-blank configuration; an all-invalid list must fail closed, not fall open")
	}
	if got := policy.Size(); got != 0 {
		t.Fatalf("policy size = %d, want 0 (every entry dropped)", got)
	}

	deny := httptest.NewRequest(http.MethodGet, "http://webterm.example.com:9848/probe", http.NoBody)
	deny.RemoteAddr = "192.168.1.50:44444"
	if policy.Allows(deny) {
		t.Error("non-loopback request admitted by an active empty policy; all-invalid configuration must deny-all")
	}
	health := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9848/probe", http.NoBody)
	health.RemoteAddr = "127.0.0.1:54321"
	if !policy.Allows(health) {
		t.Error("loopback healthcheck shape rejected; the carve-out must survive an all-invalid configuration")
	}
}

// TestSessionCommand_missingBinaryAborts pins the guard script's first
// branch, which the fakeCLI-based tests never reach (their stub always
// exists): when the configured kiro-cli path does not resolve (a failed
// first-boot install on the persistent volume), the wrapper exits non-zero
// with the operator-facing install hint -- naming /api/health -- and never
// falls through to the device-flow login or chat. Without this branch the
// user would instead see the misleading "not signed in" explainer followed
// by a shell command-not-found error (verified by running the script with
// the guard removed).
func TestSessionCommand_missingBinaryAborts(t *testing.T) {
	cliPath := filepath.Join(t.TempDir(), "no-such-kiro-cli")

	argv := sessionCommand(cliPath)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- test executes its own wrapper
	if err == nil {
		t.Fatalf("wrapper succeeded despite a missing kiro-cli binary; output: %s", out)
	}
	if !strings.Contains(string(out), "kiro-cli is not installed or not on PATH") {
		t.Errorf("missing the operator-facing install hint; output: %s", out)
	}
	if !strings.Contains(string(out), "/api/health") {
		t.Errorf("hint does not point at /api/health; output: %s", out)
	}
	if strings.Contains(string(out), "CHAT_STARTED") || strings.Contains(string(out), "device-flow sign-in") {
		t.Errorf("guard fell through to login/chat despite a missing binary; output: %s", out)
	}
}

func TestEmbeddedRequiredToolsNonEmpty(t *testing.T) {
	names := toolbelt.ParseRequireList(requiredToolsList)
	if len(names) == 0 {
		t.Fatal("embedded required-tools.txt parses to zero names")
	}
	// The seed templates must stay covered: the runtime refresh gate
	// protects exactly what the image-build verify gate protects.
	for _, seed := range []string{"gopls", "typescript-language-server", "pyright", "rust-analyzer", "gh"} {
		if !slices.Contains(names, seed) {
			t.Errorf("required-tools.txt missing seed name %q", seed)
		}
	}
}

// TestAwaitBootConvergence_waitFailureLiftsGateDegraded pins the Wait-error
// branch of awaitBootConvergence, which the startTools-driven tests cannot
// reach (they always hand it a real job ID): when the engine cannot report
// the boot reconcile job's outcome (Wait errors, e.g. an unknown job id),
// the verdict must be recorded as "degraded" exactly once -- the gate-lift
// invariant that keeps session creation from answering 503 "tools
// installing" forever -- and the failure must be operator-visible as the
// boot-reconcile-wait Warn. Serial: capture.Default mutates the
// process-global default logger.
func TestAwaitBootConvergence_waitFailureLiftsGateDegraded(t *testing.T) {
	records := capture.Default(t)
	dir := t.TempDir()
	eng, err := toolbelt.New(&toolbelt.Config{
		ConfigDir: dir,
		ToolsDir:  filepath.Join(dir, "tools"),
	})
	if err != nil {
		t.Fatalf("toolbelt.New: %v", err)
	}
	t.Cleanup(eng.Close)

	var verdicts []string
	awaitBootConvergence(eng, "no-such-job-id", func(v string) { verdicts = append(verdicts, v) })

	if len(verdicts) != 1 || verdicts[0] != "degraded" {
		t.Fatalf("verdicts = %v, want exactly one \"degraded\" (the syncing gate must lift even when the job outcome is unknowable)", verdicts)
	}
	if got := records.CountLevel(slog.LevelWarn, "boot reconcile wait failed"); got != 1 {
		t.Errorf("log = %q, want exactly one wait-failed Warn (got %d)", records.Messages(), got)
	}
}

// jobEvent builds one OnJobChanged callback argument for the reducer table
// below, in the shape toolbelt's jobQueue hands out (a *Job view).
func jobEvent(kind, state string) *toolbelt.Job {
	return &toolbelt.Job{Kind: kind, State: state}
}

// TestToolsStatus_reducerTransitions pins the whole documented state machine of
// the /api/health tools field, one row per transition the reducer must or must
// NOT make. Two properties carry the finding this reducer exists for:
//
//   - degraded -> ok is REACHABLE. The field used to latch the boot verdict, so
//     an operator who repaired the tools through the loopback API kept reading
//     "degraded" until the container was recreated; a signal that only ever
//     gets worse trains its reader to ignore it.
//   - catalog-refresh (and update, uninstall, disable) are EXCLUDED from the
//     policy in both directions. Refresh failure is routine — keep-last-good
//     keeps serving the cached catalog and startTools fires one at boot before
//     the publisher is necessarily reachable — so counting it would degrade a
//     fully converged container on a network hiccup.
//
// The pre-verdict rows pin the phase order: the boot reconcile is itself a
// counted kind and its terminal callback fires up to one Wait poll BEFORE
// startTools' finish closure records the verdict, so without the booted flag a
// converged boot would publish "ok" while the session gate was still closed —
// contradicting what "syncing" promises a health consumer.
func TestToolsStatus_reducerTransitions(t *testing.T) {
	t.Parallel()

	// noBoot means the boot verdict has not been recorded yet: the reducer's
	// live half must still be disarmed.
	const noBoot = ""

	for name, tc := range map[string]struct {
		boot string          // boot verdict, or noBoot
		jobs []*toolbelt.Job // OnJobChanged transitions, in order
		want string
	}{
		"initial state is syncing": {boot: noBoot, want: toolsStateSyncing},
		"pre-verdict success is ignored": {
			boot: noBoot,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindReconcile, toolbelt.JobDone)},
			want: toolsStateSyncing,
		},
		"pre-verdict failure is ignored": {
			boot: noBoot,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindInstall, toolbelt.JobFailed)},
			want: toolsStateSyncing,
		},
		"nil job is ignored": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{nil},
			want: toolsStateOK,
		},
		"boot failure then a successful install heals": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindInstall, toolbelt.JobDone)},
			want: toolsStateOK,
		},
		"boot failure then a successful reconcile heals": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindReconcile, toolbelt.JobDone)},
			want: toolsStateOK,
		},
		"failed install degrades": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindInstall, toolbelt.JobFailed)},
			want: toolsStateDegraded,
		},
		"failed reconcile degrades": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindReconcile, toolbelt.JobFailed)},
			want: toolsStateDegraded,
		},
		"failed catalog refresh does not degrade": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindCatalogRefresh, toolbelt.JobFailed)},
			want: toolsStateOK,
		},
		"successful catalog refresh does not heal": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindCatalogRefresh, toolbelt.JobDone)},
			want: toolsStateDegraded,
		},
		"failed update does not degrade": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindUpdate, toolbelt.JobFailed)},
			want: toolsStateOK,
		},
		"successful update does not heal": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindUpdate, toolbelt.JobDone)},
			want: toolsStateDegraded,
		},
		"failed uninstall does not degrade": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindUninstall, toolbelt.JobFailed)},
			want: toolsStateOK,
		},
		"successful uninstall does not whitewash": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindUninstall, toolbelt.JobDone)},
			want: toolsStateDegraded,
		},
		"failed disable does not degrade": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindDisable, toolbelt.JobFailed)},
			want: toolsStateOK,
		},
		"successful disable does not whitewash": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindDisable, toolbelt.JobDone)},
			want: toolsStateDegraded,
		},
		"an unrecognized future job kind is ignored": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent("some-kind-toolbelt-adds-later", toolbelt.JobFailed)},
			want: toolsStateOK,
		},
		"queued and running are in flight, not verdicts": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{
				jobEvent(toolbelt.JobKindInstall, toolbelt.JobQueued),
				jobEvent(toolbelt.JobKindInstall, toolbelt.JobRunning),
			},
			want: toolsStateOK,
		},
		"cancellation is not a fault": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindInstall, toolbelt.JobCancelled)},
			want: toolsStateOK,
		},
		"cancellation does not heal either": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{jobEvent(toolbelt.JobKindInstall, toolbelt.JobCancelled)},
			want: toolsStateDegraded,
		},
		"the last counted job wins": {
			boot: toolsStateOK,
			jobs: []*toolbelt.Job{
				jobEvent(toolbelt.JobKindInstall, toolbelt.JobFailed),
				jobEvent(toolbelt.JobKindCatalogRefresh, toolbelt.JobFailed),
				jobEvent(toolbelt.JobKindInstall, toolbelt.JobDone),
			},
			want: toolsStateOK,
		},
		"a repair followed by a regression degrades again": {
			boot: toolsStateDegraded,
			jobs: []*toolbelt.Job{
				jobEvent(toolbelt.JobKindInstall, toolbelt.JobDone),
				jobEvent(toolbelt.JobKindReconcile, toolbelt.JobFailed),
			},
			want: toolsStateDegraded,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newToolsStatus()
			if got := s.get(); got != toolsStateSyncing {
				t.Fatalf("initial state = %q, want %q", got, toolsStateSyncing)
			}
			if tc.boot != noBoot {
				s.recordBoot(tc.boot)
			}
			for _, j := range tc.jobs {
				s.observeJob(j)
			}
			if got := s.get(); got != tc.want {
				t.Errorf("state = %q, want %q", got, tc.want)
			}
			// syncing is entered once and never re-entered: a health consumer
			// reads it as the gated boot window, so a post-verdict job must
			// never put the field back there.
			if tc.boot != noBoot && s.get() == toolsStateSyncing {
				t.Errorf("state fell back to %q after the boot verdict; that value means the session-create gate is closed", toolsStateSyncing)
			}
		})
	}
}

// TestStartTools_toolsFieldRecoversLiveWithoutTouchingGates is the end-to-end
// half: the SAME transitions driven through the real toolbelt engine and the
// real Config.OnJobChanged wiring startTools installs, so the callback path
// itself is pinned rather than the reducer in isolation.
//
// The boot manifest fails on purpose (an unresolvable entry with no catalog),
// which is the state the finding describes: repaired tools, working sessions,
// and a health field stuck on "degraded" until the container is recreated. Then
// a real install job heals it, a real catalog-refresh failure does not touch
// it, and a real failed install degrades it again.
//
// After EVERY transition this asserts the two things that must not move:
//
//   - the session-create gate stays LIFTED. A boot failure lifts it
//     deliberately (degraded-not-dead) and the reducer holds no reference to
//     it, so no job outcome may re-close it. Asserted through composeGate with
//     rt.syncing — the exact predicate registerRoutes installs — because that
//     is the property most likely to regress if the two cells are ever merged
//     back into one.
//   - kiro-cli readiness is untouched. It is a separate verdict with its own
//     rescan hook, so health keeps answering 200 {"status":"ok"} while only the
//     informational tools field moves.
func TestStartTools_toolsFieldRecoversLiveWithoutTouchingGates(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash unavailable; the manual install below is the offline success path: %v", err)
	}
	dir := t.TempDir()
	// faketool installs offline via a manual command (no catalog, no network);
	// no-such-tool-xyz has no source and no catalog to hydrate from, so its
	// install always fails. Both enabled, so the boot reconcile fails overall.
	manifest := `{"version":2,"tools":{` +
		`"no-such-tool-xyz":{},` +
		`"faketool":{"source":"manual","version":"1.0.0","probe":"faketool",` +
		`"install":"printf '#!/bin/sh\nexit 0\n' > \"$BIN/faketool\"; chmod 0755 \"$BIN/faketool\""}` +
		`}}`
	if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})
	if rt.engine == nil {
		t.Fatal("engine is nil for an existing config dir; want a running tools engine")
	}
	t.Cleanup(rt.close)

	// The create gate, driven by the production predicate. A real POST would
	// spawn a PTY whose logging goroutines leak into later capture tests, so
	// the inner handler is a stub — the shape TestSessionCreateGate_ToolsSyncing
	// established for the same reason.
	inner := 0
	gated := composeGate(
		func(next http.Handler) http.Handler { return next },
		func() (bool, string) { return rt.syncing(), "tools installing" },
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inner++
		w.WriteHeader(http.StatusCreated)
	}))

	// kiro-cli readiness: a stub this test never flips, so any change in the
	// health status field would have to come from the tools reducer.
	var kiroReadyCalls atomic.Int64
	deps := newTestDeps(true)
	deps.toolsState = rt.state
	deps.kiroReady = func() (bool, string) {
		kiroReadyCalls.Add(1)
		return true, ""
	}
	health := handleHealth(deps)

	assertStage := func(stage, wantTools string) {
		t.Helper()
		if got := rt.state(); got != wantTools {
			t.Fatalf("%s: tools state = %q, want %q", stage, got, wantTools)
		}
		if rt.syncing() {
			t.Fatalf("%s: the session-create gate re-closed; the reducer must not be able to reach it", stage)
		}
		before := inner
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, terminal.SessionsPath, http.NoBody))
		if rec.Code != http.StatusCreated || inner != before+1 {
			t.Fatalf("%s: session create = %d (body %s), want 201 pass-through; the tools field must never gate creation",
				stage, rec.Code, rec.Body.String())
		}
		hrec := httptest.NewRecorder()
		health(hrec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
		if hrec.Code != http.StatusOK {
			t.Fatalf("%s: health = %d (body %s), want 200; tool convergence never gates readiness",
				stage, hrec.Code, hrec.Body.String())
		}
		body := hrec.Body.String()
		if !strings.Contains(body, `"status":"ok"`) {
			t.Fatalf("%s: health body = %s, want status ok (kiro-cli readiness is a separate verdict)", stage, body)
		}
		if !strings.Contains(body, `"tools":"`+wantTools+`"`) {
			t.Fatalf("%s: health body = %s, want tools %q", stage, body, wantTools)
		}
	}

	// Boot: the reconcile fails, the gate lifts anyway, the field degrades.
	deadline := time.Now().Add(30 * time.Second)
	for rt.syncing() {
		if time.Now().After(deadline) {
			t.Fatal("boot convergence gate never lifted after a failed reconcile; session creation would 503 forever")
		}
		time.Sleep(10 * time.Millisecond)
	}
	assertStage("after a failed boot reconcile", toolsStateDegraded)

	runJob := func(stage string, enqueue func() (*toolbelt.Job, error), wantState string) *toolbelt.Job {
		t.Helper()
		j, err := enqueue()
		if err != nil {
			t.Fatalf("%s: enqueue: %v", stage, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		final, err := rt.engine.Wait(ctx, j.ID)
		if err != nil {
			t.Fatalf("%s: wait: %v", stage, err)
		}
		if final.State != wantState {
			t.Fatalf("%s: job state = %q (error %q), want %q", stage, final.State, final.Error, wantState)
		}
		return final
	}

	// THE FINDING: a repair performed through the loopback tools API — which
	// enqueues exactly this install job — heals the field with no restart.
	runJob("repair install", func() (*toolbelt.Job, error) { return rt.engine.Install("faketool") }, toolbelt.JobDone)
	assertStage("after a successful repair install", toolsStateOK)

	// A failed catalog refresh must NOT degrade: keep-last-good makes it
	// routine, and the boot refresh runs before the publisher is reachable.
	// The URL is empty here (no KWEB_TOOL_CATALOG_URL), so the fetch fails.
	runJob("catalog refresh", rt.engine.RefreshCatalog, toolbelt.JobFailed)
	assertStage("after a failed catalog refresh", toolsStateOK)

	// A failed install DOES degrade: a tool the manifest says should be on
	// PATH is not there, which is the only thing this field claims.
	runJob("failing install", func() (*toolbelt.Job, error) { return rt.engine.Install("no-such-tool-xyz") }, toolbelt.JobFailed)
	assertStage("after a failed install", toolsStateDegraded)

	if kiroReadyCalls.Load() == 0 {
		t.Error("kiroReady was never consulted; the health assertions above never proved readiness stayed separate")
	}
}

// TestToolsStatus_callbackAndHealthReadAreRaceClean pins the concurrency
// contract the reducer was written for: OnJobChanged fires from toolbelt's job
// worker (under its queue lock) while /api/health reads the field on request
// goroutines. Meaningful under -race, which CI runs; without it the assertions
// still catch a torn or unexpected value.
func TestToolsStatus_callbackAndHealthReadAreRaceClean(t *testing.T) {
	t.Parallel()

	s := newToolsStatus()
	s.recordBoot(toolsStateDegraded)

	deps := newTestDeps(true)
	deps.toolsState = s.get
	health := handleHealth(deps)

	const rounds = 200
	var wg sync.WaitGroup
	// Writers: the callback path, alternating a failing and a succeeding
	// counted job plus an excluded one.
	for _, kind := range []string{toolbelt.JobKindInstall, toolbelt.JobKindReconcile, toolbelt.JobKindCatalogRefresh} {
		wg.Go(func() {
			for i := range rounds {
				state := toolbelt.JobDone
				if i%2 == 1 {
					state = toolbelt.JobFailed
				}
				s.observeJob(jobEvent(kind, state))
			}
		})
	}
	// Readers: the health handler, plus the raw getter registerRoutes wires.
	for range 3 {
		wg.Go(func() {
			for range rounds {
				rec := httptest.NewRecorder()
				health(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
				if rec.Code != http.StatusOK {
					t.Errorf("health during concurrent job transitions = %d, want 200", rec.Code)
					return
				}
				switch got := s.get(); got {
				case toolsStateOK, toolsStateDegraded:
				default:
					t.Errorf("state read = %q, want ok or degraded (syncing is never re-entered after the boot verdict)", got)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestParseBoolEnv_neverLogsRawValue pins the parser's VOCABULARY (so the local
// parse stays compatible with envx.Bool's) and its fail-closed direction on a bad
// value: a token-shaped value must yield the fallback with ok=false.
//
// It does NOT pin the confidentiality property, and must not be read as doing so:
// parseBoolEnv emits no records at all, so the no-raw-value assertion below is
// satisfied vacuously here. That property lives in the PRODUCTION knob read and is
// pinned by TestParseLogOSCText_warnsByNameOnly. The assertion stays as a
// regression guard for the one thing it can still catch — parseBoolEnv itself
// gaining a log site that echoes the raw value, which is exactly what envx.Bool's
// malformed path does (CWE-532: a durable, queryable copy in the log store) and why
// this parser is local.
// Serial: capture.Default mutates the process-global default logger.
func TestParseBoolEnv_neverLogsRawValue(t *testing.T) {
	const key = "KWEB_TEST_BOOL"
	cases := map[string]struct {
		raw       string
		fallback  bool
		wantValue bool
		wantOK    bool
	}{
		"unset is not a parse failure": {raw: "", fallback: false, wantValue: false, wantOK: true},
		"unset yields the fallback":    {raw: "", fallback: true, wantValue: true, wantOK: true},
		"true":                         {raw: "true", wantValue: true, wantOK: true},
		"1":                            {raw: "1", wantValue: true, wantOK: true},
		"yes uppercase and padded":     {raw: "  YES  ", wantValue: true, wantOK: true},
		"on":                           {raw: "on", wantValue: true, wantOK: true},
		"false":                        {raw: "false", wantValue: false, wantOK: true},
		"0":                            {raw: "0", wantValue: false, wantOK: true},
		"no":                           {raw: "no", wantValue: false, wantOK: true},
		"off":                          {raw: "off", wantValue: false, wantOK: true},
		// The shape that motivates the local parser, on the half this table
		// can actually pin: a token-shaped value must fail closed to the
		// fallback. Whether the raw value stays out of the log is a property
		// of the CALLER's warning, pinned by
		// TestParseLogOSCText_warnsByNameOnly.
		"secret-shaped value fails closed": {
			raw: "s3cr3t-token-abc123", fallback: false, wantValue: false, wantOK: false,
		},
		"secret-shaped value keeps a true fallback": {
			raw: "s3cr3t-token-abc123", fallback: true, wantValue: true, wantOK: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)
			t.Setenv(key, tc.raw)

			value, ok := parseBoolEnv(key, tc.fallback)

			if value != tc.wantValue || ok != tc.wantOK {
				t.Errorf("parseBoolEnv(%q, %v) = (%v, %v), want (%v, %v)",
					tc.raw, tc.fallback, value, ok, tc.wantValue, tc.wantOK)
			}
			if tc.raw != "" && logContains(records, tc.raw) {
				t.Errorf("log = %q carries the raw %s value; parseBoolEnv must stay log-free — echoing the raw value is exactly what envx.Bool's malformed path does (CWE-532) and why this parser is local; the operator-facing warning belongs to the caller, pinned by TestParseLogOSCText_warnsByNameOnly",
					records.Messages(), key)
			}
		})
	}
}

// TestParseLogOSCText_warnsByNameOnly pins the PRODUCTION knob read, which is
// where the confidentiality property actually lives: parseBoolEnv emits no
// records at all, so a test that captures slog around it alone satisfies the
// "no raw value in the log" claim vacuously and would stay green if main went
// back to envx.Bool. This drives parseLogOSCText — the function main calls —
// and asserts the malformed path emits exactly ONE Warn carrying neither the
// raw value in its message nor in any attribute, that the opt-in path warns
// about widened content, and that the default path is silent.
// Serial: capture.Default mutates the process-global default logger.
func TestParseLogOSCText_warnsByNameOnly(t *testing.T) {
	const token = "s3cr3t-token-abc123"
	cases := map[string]struct {
		raw       string
		wantValue bool
		wantWarns int
		wantMsg   string
	}{
		"token-shaped value fails closed and warns by name": {
			raw: token, wantValue: false, wantWarns: 1,
			wantMsg: "unparseable KWEB_LOG_OSC_TEXT",
		},
		"opt-in warns that notification text is logged": {
			raw: "true", wantValue: true, wantWarns: 1,
			wantMsg: "KWEB_LOG_OSC_TEXT is on",
		},
		"unset is the silent default": {raw: "", wantValue: false, wantWarns: 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)
			t.Setenv("KWEB_LOG_OSC_TEXT", tc.raw)

			if got := parseLogOSCText(); got != tc.wantValue {
				t.Errorf("parseLogOSCText() with %q = %v, want %v", tc.raw, got, tc.wantValue)
			}
			if got := records.CountLevel(slog.LevelWarn, ""); got != tc.wantWarns {
				t.Errorf("log = %q, want exactly %d Warn (got %d)", records.Messages(), tc.wantWarns, got)
			}
			if tc.wantMsg != "" && records.CountLevel(slog.LevelWarn, tc.wantMsg) != 1 {
				t.Errorf("log = %q, want a Warn containing %q", records.Messages(), tc.wantMsg)
			}
			if tc.raw == token && logContains(records, token) {
				t.Errorf("log = %q carries the raw KWEB_LOG_OSC_TEXT value; a compose expansion mistake can put a credential on this key, so the malformed path must warn by NAME only (this is why envx.Bool is not used here)",
					records.Messages())
			}
		})
	}
}

// TestParseCatalogRefresh_warnsByNameOnly pins that no supplied
// TOOL_CATALOG_REFRESH value reaches a log record, and that every value toolbelt
// ACCEPTS still gets toolbelt's answer. The wrapper exists only because
// toolbelt's parser calls scheduler.ParseInterval WITHOUT
// scheduler.WithRedactedValue, so its own fallback warning echoes the raw string
// — the CWE-532 shape the KWEB_LOG_OSC_TEXT remedy closed on a knob of exactly
// this kind. Dropping the wrapper (calling toolbelt.ParseCatalogRefresh
// directly) leaves every other test green.
// Serial: capture.Default mutates the process-global default logger.
func TestParseCatalogRefresh_warnsByNameOnly(t *testing.T) {
	const token = "s3cr3t-token-abc123"
	cases := map[string]struct {
		raw       string
		want      time.Duration
		wantWarns int
	}{
		"token-shaped value falls back and warns by name": {token, toolbelt.DefaultCatalogRefresh, 1},
		"negative duration falls back and warns by name":  {"-5m", toolbelt.DefaultCatalogRefresh, 1},
		// A case-varied unit parses only after ToLower, so gating on the lowercased
		// copy would forward it and let the library echo it: Go duration units are
		// case-sensitive and scheduler.ParseInterval lowercases only its sentinels.
		"a case-varied unit is rejected here, not by the library": {"24H", toolbelt.DefaultCatalogRefresh, 1},
		"unset is the silent default":                             {"", toolbelt.DefaultCatalogRefresh, 0},
		"off disables the schedule silently":                      {"off", 0, 0},
		"zero disables the schedule silently":                     {"0", 0, 0},
		// Passed through untouched, so the clamp and the default stay toolbelt's
		// policy alone: "6h" is inside [MinCatalogRefresh, MaxCatalogRefresh] and
		// comes back unchanged.
		"a valid duration is passed through": {"6h", 6 * time.Hour, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)

			if got := parseCatalogRefresh(tc.raw); got != tc.want {
				t.Errorf("parseCatalogRefresh(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			if got := records.CountLevel(slog.LevelWarn, ""); got != tc.wantWarns {
				t.Errorf("log = %q, want exactly %d Warn (got %d)", records.Messages(), tc.wantWarns, got)
			}
			if tc.raw != "" && logContains(records, tc.raw) {
				t.Errorf("log = %q carries the raw TOOL_CATALOG_REFRESH value; a compose expansion mistake can put a credential on this key, so a rejected value must be warned about by NAME only (this is why toolbelt's parser is not called directly)",
					records.Messages())
			}
		})
	}
}

// TestIsWebSocketUpgrade_requiresBothListTokens pins wsAttachLog's
// "an attach was attempted" predicate: both header tokens are required, each
// may arrive in a repeated field line or a comma list, matching is case- and
// whitespace-insensitive, and a token SUBSTRING must not match. The access
// log's skip test is the stricter willUpgrade below; a divergence here is
// silent, dropping the attach record for a request that presented a session
// capability token.
func TestIsWebSocketUpgrade_requiresBothListTokens(t *testing.T) {
	cases := []struct {
		name       string
		upgrade    []string
		connection []string
		want       bool
	}{
		{name: "tokens in repeated fields are accepted case-insensitively", upgrade: []string{"h2c", " WebSocket "}, connection: []string{"keep-alive", "UPGRADE"}, want: true},
		{name: "tokens in comma lists are accepted", upgrade: []string{"h2c, websocket"}, connection: []string{"keep-alive, upgrade"}, want: true},
		{name: "Upgrade token alone is not a websocket handshake", upgrade: []string{"websocket"}, want: false},
		{name: "Connection token alone is not a websocket handshake", connection: []string{"upgrade"}, want: false},
		{name: "token substrings are rejected", upgrade: []string{"websocket-v2"}, connection: []string{"upgrader"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, terminal.WSPath, http.NoBody)
			for _, value := range tc.upgrade {
				req.Header.Add("Upgrade", value)
			}
			for _, value := range tc.connection {
				req.Header.Add("Connection", value)
			}
			if got := isWebSocketUpgrade(req); got != tc.want {
				t.Errorf("isWebSocketUpgrade(Upgrade=%q, Connection=%q) = %v, want %v", tc.upgrade, tc.connection, got, tc.want)
			}
		})
	}
}

// TestWillUpgrade_mirrorsAcceptPreconditions pins the access-log skip predicate
// against every condition the engine's websocket.Accept checks BEFORE it hijacks
// the connection. Each case drops exactly one of them from an otherwise complete
// handshake, so the request is one Accept answers short (405/400/426) rather than
// one that becomes a stream — and a short refusal must keep its access line, or a
// proxy that mangles the handshake presents as a terminal that never connects
// with no status recorded anywhere. Widening this back to isWebSocketUpgrade
// passes every other test.
func TestWillUpgrade_mirrorsAcceptPreconditions(t *testing.T) {
	// 16 zero bytes, base64: a structurally valid Sec-WebSocket-Key whose value
	// willUpgrade never inspects (it counts the field, see its doc comment).
	const key = "AAAAAAAAAAAAAAAAAAAAAA=="
	complete := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, terminal.WSPath, http.NoBody)
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "keep-alive, Upgrade")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", key)
		return r
	}
	cases := map[string]struct {
		mangle func(*http.Request)
		want   bool
	}{
		"a complete handshake is the only skippable shape": {mangle: func(*http.Request) {}, want: true},
		"a non-GET is answered 405, so it keeps its line": {
			mangle: func(r *http.Request) { r.Method = http.MethodPost },
		},
		"HTTP/1.0 is answered 426, so it keeps its line": {
			mangle: func(r *http.Request) { r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.0", 1, 0 },
		},
		"a missing Sec-WebSocket-Key is answered 400": {
			mangle: func(r *http.Request) { r.Header.Del("Sec-WebSocket-Key") },
		},
		"a DUPLICATED Sec-WebSocket-Key is answered 400": {
			mangle: func(r *http.Request) { r.Header.Add("Sec-WebSocket-Key", key) },
		},
		"a wrong Sec-WebSocket-Version is answered 400": {
			mangle: func(r *http.Request) { r.Header.Set("Sec-WebSocket-Version", "8") },
		},
		"missing upgrade headers are answered 426": {
			mangle: func(r *http.Request) { r.Header.Del("Upgrade") },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := complete()
			tc.mangle(req)
			if got := willUpgrade(req); got != tc.want {
				t.Errorf("willUpgrade() = %v, want %v (only a request that really becomes a hijacked stream may be skipped)", got, tc.want)
			}
		})
	}
}

// TestWSAttachLog pins the audit record for the ONE request that presents the
// session capability token. The access logger deliberately skips an admitted /ws
// upgrade (a hijacked stream would log a bogus 200 with an hours-long duration),
// and neither the engine's WebSocketHandler nor its per-session Handler logs an
// attach — the engine's "process started" line comes from the eager start at
// CREATE time, not from an attach. Without this middleware the /ws upgrade is the
// only request to this server with no record anywhere, so a session id leaked
// through a fronting proxy's access log could be replayed with nothing to show an
// operator afterwards (CWE-778, OWASP A09).
//
// Three properties, each a distinct regression:
//   - the record exists for an upgrade-shaped request, at Info, with client_ip
//     and the request id the access log and the response header carry;
//   - the session id is LogID-truncated, never the full token — the log store
//     outlives and out-queries the PTY, so a full id here would just relocate
//     the credential;
//   - a NON-upgrade request to /ws produces no such record: that shape is the
//     access logger's (it gets a real line with the engine's 426), and doubling
//     it here would make the two records disagree about what a stream is.
//
// capture.Default swaps the global default logger, so this test must never call
// t.Parallel.
func TestWSAttachLog(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+terminal.WSPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // stands in for the engine's upgrade handler
	})
	// A session id long enough that LogID must truncate it: an id that fits
	// under the truncation threshold would pass this test with no redaction at
	// all.
	const sessionID = "0123456789abcdef0123456789abcdef"

	do := func(t *testing.T, upgrade bool) *capture.Recorder {
		t.Helper()
		records := capture.Default(t)
		req := httptest.NewRequest(http.MethodGet, terminal.WSPath+"?session="+sessionID, http.NoBody)
		if upgrade {
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Connection", "upgrade")
		}
		buildHandler(mux, nil, "default-src 'self'", nil).ServeHTTP(httptest.NewRecorder(), req)
		return records
	}

	t.Run("upgrade attempt is recorded", func(t *testing.T) {
		records := do(t, true)
		if got := records.CountLevel(slog.LevelInfo, wsAttachMsg); got != 1 {
			t.Fatalf("%q Info count = %d, want 1; the request that presents the session token must leave a record; log = %q",
				wsAttachMsg, got, records.Messages())
		}
		wantID := terminal.LogID(sessionID)
		if wantID == sessionID {
			t.Fatalf("terminal.LogID(%q) returned the id unchanged; pick a longer fixture or the redaction assertion below proves nothing", sessionID)
		}
		for _, tc := range []struct{ key, want string }{
			{"session", wantID},
			{"client_ip", "192.0.2.1"}, // httptest.NewRequest's RemoteAddr, host only
		} {
			if got, ok := records.AttrValue(wsAttachMsg, tc.key); !ok || got != tc.want {
				t.Errorf("attach record %s = %q (present=%v), want %q", tc.key, got, ok, tc.want)
			}
		}
		if got, ok := records.AttrValue(wsAttachMsg, "request_id"); !ok || got == "" {
			t.Errorf("attach record request_id = %q (present=%v), want the id the access log and the response header carry; without it the attach cannot be correlated", got, ok)
		}
		// The full token must not reach the log under ANY key or in the message:
		// truncation is the whole point of routing the id through LogID.
		for _, r := range records.Records() {
			if strings.Contains(r.Message, sessionID) {
				t.Errorf("record message %q carries the full session id", r.Message)
			}
			r.Attrs(func(a slog.Attr) bool {
				if strings.Contains(a.Value.String(), sessionID) {
					t.Errorf("record attr %q = %q carries the full session id; a leaked log line would be a working credential", a.Key, a.Value)
				}
				return true
			})
		}
	})

	t.Run("non-upgrade request is left to the access log", func(t *testing.T) {
		records := do(t, false)
		if got := records.CountLevel(slog.LevelInfo, wsAttachMsg); got != 0 {
			t.Errorf("%q Info count = %d for a request without the upgrade headers, want 0; that shape is the access logger's, which logs it with the engine's 426; log = %q",
				wsAttachMsg, got, records.Messages())
		}
	})
}

// TestIsWebSocketUpgrade_agreesWithTheEngineHandshake cross-checks the app's
// header-matching predicate — the half willUpgrade and wsAttachLog both build on
// — against the ONLY implementation that decides whether a /ws request really
// becomes a stream: the engine's coder/websocket handshake, driven over a real
// server. TestIsWebSocketUpgrade_requiresBothListTokens
// states what THIS app believes an upgrade is; nothing asserts the engine agrees,
// and every disagreement is silent -- a request the engine refuses with 426 that
// the predicate calls a stream leaves no access line anywhere (the CWE-778 silence
// wsAttachLog and this skip exist to remove), and one the engine upgrades that the
// predicate calls a plain request emits a bogus 200 with an hours-long duration.
// The expectations here are DERIVED from the handshake rather than restated, so a
// coder/websocket or engine bump that changes header matching fails this test
// instead of quietly re-opening that silence.
//
// Only the two upgrade headers vary; method, Sec-WebSocket-Version,
// Sec-WebSocket-Key and Origin are held at the values a real handshake carries,
// because those are the engine's OTHER refusal reasons and this predicate
// deliberately does not model them — willUpgrade does, and
// TestWillUpgrade_mirrorsAcceptPreconditions covers them.
func TestIsWebSocketUpgrade_agreesWithTheEngineHandshake(t *testing.T) {
	mux, _, csp, id := mustStartSession(t, newTestDeps(true))

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	cases := []struct {
		name       string
		upgrade    []string
		connection []string
	}{
		{name: "canonical handshake", upgrade: []string{"websocket"}, connection: []string{"Upgrade"}},
		{name: "comma lists", upgrade: []string{"h2c, websocket"}, connection: []string{"keep-alive, upgrade"}},
		{name: "repeated field lines, mixed case, padded", upgrade: []string{"h2c", " WebSocket "}, connection: []string{"keep-alive", "UPGRADE"}},
		{name: "token substrings only", upgrade: []string{"websocket-v2"}, connection: []string{"upgrader"}},
		{name: "upgrade header alone", upgrade: []string{"websocket"}},
		{name: "connection header alone", connection: []string{"upgrade"}},
		{name: "no upgrade headers at all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newWSUpgradeRequest(t, srv.URL, id, srv.URL)
			req.Header.Del("Upgrade")
			req.Header.Del("Connection")
			for _, v := range tc.upgrade {
				req.Header.Add("Upgrade", v)
			}
			for _, v := range tc.connection {
				req.Header.Add("Connection", v)
			}

			// The same header set the server will see, so the predicate is
			// judged on exactly the request the handshake judges.
			probe := httptest.NewRequest(http.MethodGet, terminal.WSPath+"?session="+id, http.NoBody)
			probe.Header = req.Header.Clone()
			predicate := isWebSocketUpgrade(probe)

			resp, doErr := srv.Client().Do(req)
			if doErr != nil {
				t.Fatalf("/ws handshake: %v", doErr)
			}
			defer resp.Body.Close()
			upgraded := resp.StatusCode == http.StatusSwitchingProtocols

			if predicate != upgraded {
				t.Errorf("isWebSocketUpgrade = %v but the engine handshake returned %d (upgraded=%v); the access-log skip and the real upgrade must never disagree",
					predicate, resp.StatusCode, upgraded)
			}
		})
	}
}
