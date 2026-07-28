package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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
// point of the Lsp inventory marker), and an inventory read failure must skip
// the nudge quietly (Debug only) instead of warning spuriously. Serial:
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

// TestParseBoolEnv_neverLogsRawValue pins the confidentiality property the
// local parser exists for: KWEB_LOG_OSC_TEXT is a small enum an operator
// fat-fingers, a compose expansion mistake can land a credential on it
// (`KWEB_LOG_OSC_TEXT: "${DEBUG_FLAG}"`), and envx.Bool's malformed path logs
// the RAW value — a durable, queryable copy in the log store (CWE-532). The
// assertion is the property, not the wording: no captured record may CONTAIN
// the raw string. It also pins the vocabulary (so the local parse stays
// compatible with envx.Bool's) and the fail-closed direction on a bad value.
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
		// The reason the parser is local: a token-shaped value must fail
		// closed to the fallback AND leave no copy of itself anywhere.
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
			if tc.raw != "" && records.Contains(tc.raw) {
				t.Errorf("log = %q carries the raw %s value; a compose expansion mistake can put a credential on this key, so the malformed path must warn by NAME only (this is why envx.Bool is not used here)",
					records.Messages(), key)
			}
		})
	}
}

// TestIsWebSocketUpgrade_requiresBothListTokens pins the access-log stream
// predicate against the engine's own websocket.Accept parsing: both header
// tokens are required, each may arrive in a repeated field line or a comma
// list, matching is case- and whitespace-insensitive, and a token SUBSTRING
// must not match. A divergence here is silent both ways — a one-sided
// malformed handshake vanishes from the access log, or a repeated-field real
// upgrade produces a bogus hours-long 200 access record.
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

// TestHealthEndpoint_unreadableMarkerWarnsOnce pins handleHealth's
// non-ErrNotExist marker branch and its warn-once bound: an unreadable
// readiness marker (an unmounted or read-only /config, an I/O error) is
// otherwise indistinguishable from the expected first-boot absent marker,
// and an unbounded diagnostic would repeat every 30s for the life of the
// fault. A self-referential symlink yields ELOOP deterministically, even as
// root. Serial: capture.Default mutates the process-global default logger.
func TestHealthEndpoint_unreadableMarkerWarnsOnce(t *testing.T) {
	records := capture.Default(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "loop")
	if err := os.Symlink("loop", marker); err != nil {
		t.Fatalf("create self-referential marker symlink: %v", err)
	}
	deps := newTestDeps(true)
	deps.kiroReadyMarker = marker
	handler := handleHealth(deps)
	for range 2 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, http.NoBody))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("unreadable marker status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
		}
	}
	if got := records.CountLevel(slog.LevelWarn, "readiness marker unreadable"); got != 1 {
		t.Errorf("unreadable-marker Warn count = %d, want 1 for repeated probes", got)
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
