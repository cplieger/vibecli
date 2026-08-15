package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// writeToolsManifest plants a tools.json where startTools' engine reads it: the
// tools ROOT (<configDir>/tools), which is the engine's ConfigDir and its
// ToolsDir both, since the manifest, the machine state and the catalog cache now
// live beside the artifacts they describe. Tests that construct toolbelt.New
// directly still choose their own two directories; this is only for the ones
// driving the real composition root.
func writeToolsManifest(t *testing.T, configDir, manifest string) {
	t.Helper()
	root := filepath.Join(configDir, "tools")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("create tools root: %v", err)
	}
	// MkdirAll's mode is a REQUEST, not a setting: it is masked by the umask
	// and, on a filesystem carrying an inheritable group-write ACL, the
	// directory is born group-writable whatever was asked for (measured on a
	// ZFS nfs4acl dataset: 0770 from a 0o700 MkdirAll -- the same condition
	// this app's own docs record for pinstall's install root, where
	// "os.MkdirAll with dirMode = 0o755 cannot beat a ZFS inheritable ACL").
	// toolbelt's VerifyRootIntegrity then refuses to construct the engine over
	// a group-writable managed root, so every test below reaches the
	// root-integrity refusal instead of the shape it means to exercise. Chmod
	// is the only call that SETS the mode.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("make the tools root private: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "tools.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// TestStartTools_configDirMissing pins the out-of-container shape: a missing
// config dir disables the tools engine (bare `go run` / tests), returning the
// engine-less runtime whose nil engine makes registerRoutes skip /api/tools
// while its policies stay callable and report the off-shape defaults (not
// syncing, empty state, which health's omitempty drops), with a Warn naming the
// fix. close() on that runtime must be a safe no-op. This test mutates the
// process-global default logger, so it runs serially (no t.Parallel).
func TestStartTools_configDirMissing(t *testing.T) {
	records := capture.Default(t)

	rt := startTools(baseTools{
		configDir:   filepath.Join(t.TempDir(), "absent"),
		catalogPath: filepath.Join(t.TempDir(), "absent-catalog.json"),
	})

	if rt.engine != nil {
		t.Fatal("engine is non-nil for a missing config dir; want no engine (no tools surface outside the container)")
	}
	if rt.syncing == nil || rt.state == nil {
		t.Fatal("syncing/state funcs are nil; the route layer's policy contract is total, so a nil policy panics on first call")
	}
	if rt.syncing() {
		t.Error("syncing reports true for a missing config dir; sessions must remain ungated")
	}
	if got := rt.state(); got != "" {
		t.Errorf("state = %q, want %q (health's omitempty then drops the tools field)", got, "")
	}
	rt.close() // engine-less close must not panic
	if got := records.CountLevel(slog.LevelWarn, "tools engine disabled"); got != 1 {
		t.Errorf("log = %q, want exactly one config-dir-missing Warn (got %d)", records.Messages(), got)
	}
}

// TestStartTools_configDirUnusable pins the third and fourth stat outcomes,
// which used to collapse into the missing-dir path: a config path that is a
// regular FILE, and one whose stat FAILS for a reason other than absence (a
// self-referential symlink is a deterministic ELOOP). Both are a broken mount
// of a production subsystem, not the deliberate out-of-container disable, so
// they follow degraded-not-dead: the engine stays nil (no /api/tools mount) and
// syncing reports false (sessions ungated) but state() reports "degraded" so
// /api/health carries the informational tools field instead of omitting it and
// presenting a failed subsystem as intentionally off. Serial: mutates the global
// default logger.
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
			if rt.syncing == nil {
				t.Fatal("syncing is nil for an unusable config path; the route layer's policy contract is total, so a nil policy panics on first call")
			}
			if rt.syncing() {
				t.Error("syncing reports true for an unusable config path; sessions must remain ungated")
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

// TestStartTools_engineStartFailure pins degraded-not-dead for a NON-integrity
// engine failure: a manifest in the retired v1 format fails toolbelt.New (strict
// v2 schema), and startTools logs the Error and continues without an engine
// instead of taking the server down. Unlike the missing-config-dir path (an
// intentionally disabled subsystem: no engine, empty state, health omits the
// tools field entirely), a FAILED production subsystem must stay visible: the
// returned runtime carries state "degraded" so /api/health reports
// {"status":"ok","tools":"degraded"} per the documented
// tools=syncing|ok|degraded contract, while the engine stays nil and syncing
// reports false so sessions remain ungated.
//
// It also pins the other half of the root-integrity wiring: this error is not a
// *toolbelt.RootIntegrityError, so the errors.As recovery adds nothing and the
// single failed-to-start line is all an operator gets — the integrity path's
// per-root lines must not appear for every unrelated failure. Serial: mutates
// the global default logger.
func TestStartTools_engineStartFailure(t *testing.T) {
	records := capture.Default(t)

	dir := t.TempDir()
	// The manifest lives in the tools root now (ConfigDir == ToolsDir), so that
	// is where a retired-format one has to be planted to be read at all.
	writeToolsManifest(t, dir, `{"runtimes":{"node":{"enabled":false}}}`)

	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})

	if rt.engine != nil {
		t.Fatal("engine is non-nil despite a failed toolbelt.New; want no engine (degraded-not-dead)")
	}
	if rt.syncing == nil {
		t.Fatal("syncing is nil despite a failed toolbelt.New; the route layer's policy contract is total, so a nil policy panics on first call")
	}
	if rt.syncing() {
		t.Error("syncing reports true despite a failed toolbelt.New; sessions must remain ungated")
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
	if got := records.CountLevel(slog.LevelError, "tools engine refused a managed root"); got != 0 {
		t.Errorf("log = %q, want no per-root integrity line for a schema failure (got %d); errors.As must find nothing outside the ErrRootIntegrity class", records.Messages(), got)
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

// TestStartTools_toolsRootResolution pins the tool subsystem's ONE root: the
// engine's ConfigDir (tools.json, tools-state.json, tool-catalog.cached.json)
// and its ToolsDir (bin/opt/npm/python) are the same directory, and both resolve
// to the path the entrypoint exported and hardened (baseTools.toolsDir, from
// KIRO_CLI_TOOLS_DIR) when it is set, falling back to <configDir>/tools only
// outside the container where no pin is exported.
//
// Before this, the metadata followed a config knob while the artifacts followed
// the entrypoint's export, so the two halves of one subsystem could sit on
// different volumes: state describing a tree that was not there, and a
// hand-authored manifest the engine no longer read. Observable because
// toolbelt.New creates <ToolsDir>/bin (its single PATH dir) and seeds
// <ConfigDir>/tools.json as it starts.
func TestStartTools_toolsRootResolution(t *testing.T) {
	for name, exportRoot := range map[string]bool{
		"the exported root wins over the derivation":     true,
		"derives from the config mount when none is set": false,
	} {
		t.Run(name, func(t *testing.T) {
			configDir := t.TempDir()
			var exported string
			wantRoot := filepath.Join(configDir, "tools")
			if exportRoot {
				exported = filepath.Join(t.TempDir(), "exported-tools")
				wantRoot = exported
			}

			rt := startTools(baseTools{
				configDir:   configDir,
				toolsDir:    exported,
				catalogPath: filepath.Join(configDir, "absent-catalog.json"),
			})
			if rt.engine == nil {
				t.Fatal("engine is nil for an existing config dir; want a running tools engine")
			}
			t.Cleanup(rt.close)

			// bin/ proves ToolsDir, tools.json proves ConfigDir. Both under the
			// same root is the whole point: one subsystem, one home.
			for _, entry := range []string{"bin", "tools.json"} {
				if _, err := os.Stat(filepath.Join(wantRoot, entry)); err != nil {
					t.Errorf("stat %s = %v; want the engine's %s under the resolved tools root (the tree entrypoint.sh hardened and every session has on PATH)", filepath.Join(wantRoot, entry), err, entry)
				}
			}
			// The metadata must not stay at the mount root, which is where the
			// deleted config knob used to put it.
			if _, err := os.Stat(filepath.Join(configDir, "tools.json")); err == nil {
				t.Errorf("the manifest was seeded at %s, beside the mount instead of inside the tools tree it describes", filepath.Join(configDir, "tools.json"))
			}
			if exportRoot {
				if _, err := os.Stat(filepath.Join(configDir, "tools")); err == nil {
					t.Errorf("the engine provisioned into the derived %s/tools instead of the exported root; every tool would land off the session PATH", configDir)
				}
			}
		})
	}
}

// TestStartTools_rootIntegrityRefusalDegrades pins the app's half of toolbelt's
// opt-in root-integrity check (Config.VerifyRootIntegrity): the tools tree is an
// operator-controlled persistent volume and this process runs as root, so a
// managed root that is a symlink or that a foreign host user can write is a
// root-code-execution surface (the engine's install probe EXECUTES what it finds
// in <ToolsDir>/bin, first on PATH).
//
// Two contracts here, and the second is the one the app owns. (1) The refusal
// DEGRADES rather than aborting boot, exactly like any other failed
// toolbelt.New: engine nil, sessions ungated, state "degraded" so /api/health
// carries the informational tools field (its projection is pinned by
// TestStartTools_engineStartFailure). Per web-terminal-kiro.md "Failure posture"
// a dev box must stay reachable so the volume can be repaired from inside.
// (2) The findings are recovered with errors.As and logged ONE LINE PER ROOT,
// with the path and the reason as fields — without that, "degraded" is backed
// only by toolbelt's single joined message and an operator cannot see which root
// or why. Serial: mutates the global default logger.
func TestStartTools_rootIntegrityRefusalDegrades(t *testing.T) {
	const perPathMsg = "tools engine refused a managed root"

	for name, tc := range map[string]struct {
		// unfit makes the tools root at path unfit for the engine.
		unfit      func(t *testing.T, path string)
		wantReason string
	}{
		"symlinked root": {
			unfit: func(t *testing.T, path string) {
				t.Helper()
				target := t.TempDir()
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unsupported here: %v", err)
				}
			},
			wantReason: "is a symlink",
		},
		"group- or other-writable root": {
			unfit: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatalf("create tools root: %v", err)
				}
				// chmod, not the Mkdir perm: umask filters the latter, so a
				// 0o777 request can silently land clean.
				if err := os.Chmod(path, 0o777); err != nil {
					t.Fatalf("loosen tools root: %v", err)
				}
			},
			wantReason: "is group- or other-writable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)
			configDir := t.TempDir()
			root := filepath.Join(configDir, "tools")
			tc.unfit(t, root)

			rt := startTools(baseTools{
				configDir:   configDir,
				catalogPath: filepath.Join(configDir, "absent-catalog.json"),
			})
			t.Cleanup(rt.close)

			if rt.engine != nil {
				t.Fatal("engine is non-nil over an unfit managed root; want no engine (toolbelt refuses, the app degrades)")
			}
			if rt.syncing == nil || rt.state == nil {
				t.Fatal("syncing/state funcs are nil; the route layer's policy contract is total, so a nil policy panics on first call")
			}
			if rt.syncing() {
				t.Error("syncing reports true after a refusal; sessions must remain ungated (degraded-not-dead)")
			}
			if got := rt.state(); got != toolsStateDegraded {
				t.Errorf("state = %q, want %q so /api/health reports the failed subsystem instead of omitting the field", got, toolsStateDegraded)
			}
			// The check runs before anything is written: no seeded manifest, no
			// bin/ inside the tree it refused.
			for _, entry := range []string{"tools.json", "bin"} {
				if _, err := os.Stat(filepath.Join(root, entry)); err == nil {
					t.Errorf("%s exists; the refusal must precede every write to the root it judged unfit", filepath.Join(root, entry))
				}
			}

			if got := records.CountLevel(slog.LevelError, "tools engine failed to start"); got != 1 {
				t.Errorf("log = %q, want exactly one failed-to-start Error (got %d)", records.Messages(), got)
			}
			// ConfigDir and ToolsDir are the same path, and toolbelt judges each
			// of its arguments in turn, so the root is reported twice: the app
			// collapses that into ONE line per path+reason.
			if got := records.CountLevel(slog.LevelError, perPathMsg); got != 1 {
				t.Errorf("log = %q, want exactly one per-root Error naming the offending root (got %d); ConfigDir == ToolsDir makes toolbelt report it twice", records.Messages(), got)
			}
			if !records.HasAttr(perPathMsg, "root", root) {
				t.Errorf("log = %q, want a root=%s field so an operator can see WHICH root was refused", records.Messages(), root)
			}
			if !records.AttrContains(perPathMsg, "reason", tc.wantReason) {
				t.Errorf("log = %q, want a reason field containing %q so an operator can see WHY", records.Messages(), tc.wantReason)
			}
		})
	}
}

// TestHostAllowlist pins the WT_ALLOWED_HOSTS anti-DNS-rebinding gate
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

	t.Setenv("WT_ALLOWED_HOSTS", "localhost, 192.168.1.5, ::1, Webterm.Example.COM.")
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
			t.Errorf("GET /ws with nil allowlist = %d, want %d (unset WT_ALLOWED_HOSTS must stay backward compatible)", got, http.StatusOK)
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

	t.Setenv("WT_ALLOWED_HOSTS", "webterm.example.com") // deliberately no loopback entry
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
// blank WT_ALLOWED_HOSTS (only commas and whitespace) through the real
// parseAllowedHosts into the middleware: blank entries never engage the gate
// (webhttp.ParseHostList leaves the policy INACTIVE), so the documented
// permissive state must hold. Accidentally treating a blank entry as
// non-blank would turn a blank configuration into a deny-all outage.
func TestHostAllowlist_blankConfigurationStaysPermissive(t *testing.T) {
	t.Setenv("WT_ALLOWED_HOSTS", "  ,  , ")
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
		t.Errorf("blank WT_ALLOWED_HOSTS: GET /probe status = %d, want %d", rec.Code, http.StatusNoContent)
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
	writeToolsManifest(t, dir, `{"version":2,"tools":{"no-such-tool-xyz":{}}}`)

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
	writeToolsManifest(t, dir, `{"version":2,"tools":{}}`)

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

	// Returns the engine and the RESOLVED manifest path, which is both what
	// warnIfNoLSPEnabled must echo in its `manifest` field and the file the
	// inventory-failure subtest corrupts.
	newEngine := func(t *testing.T, manifest, catalog string) (*toolbelt.Engine, string) {
		t.Helper()
		dir := t.TempDir()
		manifestPath := filepath.Join(dir, "tools.json")
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
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
		return eng, manifestPath
	}
	t.Run("enabled catalog-marked LSP silences the warn", func(t *testing.T) {
		eng, manifestPath := newEngine(t,
			`{"version":2,"tools":{"gopls":{}}}`,
			`{"entries":{"gopls":{"name":"gopls","source":"go:golang.org/x/tools/gopls","lsp":true}}}`)
		records := capture.Default(t)
		warnIfNoLSPEnabled(eng, manifestPath)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q; an enabled Lsp-marked tool must silence the nudge (got %d Warns)", records.Messages(), got)
		}
	})

	t.Run("no enabled LSP warns", func(t *testing.T) {
		// gopls present but disabled (a template), so the nudge must fire.
		eng, manifestPath := newEngine(t,
			`{"version":2,"tools":{"gopls":{"disabled":true}}}`,
			`{"entries":{"gopls":{"name":"gopls","source":"go:golang.org/x/tools/gopls","lsp":true}}}`)
		records := capture.Default(t)
		warnIfNoLSPEnabled(eng, manifestPath)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 1 {
			t.Errorf("log = %q, want exactly one %q Warn (no enabled language server; got %d)", records.Messages(), warnMsg, got)
		}
		// The nudge tells an operator to edit a file, so it must name the file the
		// engine actually reads. Both hints used to spell "/config/tools.json"
		// literally and went stale when the manifest moved under /config/tools/,
		// sending the operator to a path that no longer exists. Pinning the field
		// to the resolved path is what makes that regression fail here.
		// AttrValue (substring), not AttrValueExact: warnMsg is the stable prefix
		// the count assertions key on, while the emitted message carries a
		// "; kiro code intelligence will be limited" tail.
		if got, ok := records.AttrValue(warnMsg, "manifest"); !ok || got != manifestPath {
			t.Errorf("manifest attr = %q (present=%t), want %q; the nudge must name the manifest the engine reads, not a hardcoded path", got, ok, manifestPath)
		}
	})

	t.Run("inventory failure reports itself, not the nudge", func(t *testing.T) {
		eng, manifestPath := newEngine(t, `{"version":2,"tools":{}}`, "")
		// Corrupt the manifest AFTER engine start: Inventory re-reads it from
		// disk, so the read now fails. The property pinned here is that the
		// failure must NOT surface as the LSP nudge Warn (the nudge's absence
		// would otherwise be read as "a language server is enabled"); it
		// reports itself under its own message instead.
		if err := os.WriteFile(manifestPath, []byte("{not json"), 0o644); err != nil {
			t.Fatalf("corrupt manifest: %v", err)
		}
		records := capture.Default(t)
		warnIfNoLSPEnabled(eng, manifestPath)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q; an inventory failure must not produce the LSP Warn (got %d)", records.Messages(), got)
		}
		const readFailMsg = "tools: manifest unreadable; cannot tell whether a language server is enabled"
		if got := records.CountLevel(slog.LevelWarn, readFailMsg); got != 1 {
			t.Errorf("log = %q, want exactly one %q Warn (the read failure must not regress to Debug; got %d)", records.Messages(), readFailMsg, got)
		}
		// Same regression pin as the nudge above: this record is the one telling
		// an operator which file to repair, so it must name the resolved manifest
		// rather than a path spelled into the hint.
		if got, ok := records.AttrValueExact(readFailMsg, "manifest"); !ok || got != manifestPath {
			t.Errorf("manifest attr = %q (present=%t), want %q; the unreadable-manifest Warn must name the file to repair", got, ok, manifestPath)
		}
	})
}

// TestParseAllowedHosts unit-tests the WT_ALLOWED_HOSTS parser directly,
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
		t.Setenv("WT_ALLOWED_HOSTS", "")
		policy := parseAllowedHosts()
		if policy.Active() {
			t.Error("parseAllowedHosts() is active for an unset/empty WT_ALLOWED_HOSTS; want the permissive backward-compatible default")
		}
		if !allows(t, policy, "anything.example:9848", "") {
			t.Error("inactive policy rejected a request; unset WT_ALLOWED_HOSTS must accept every Host")
		}
	})

	t.Run("URL-shaped entry warns and is dropped", func(t *testing.T) {
		records := capture.Default(t)
		t.Setenv("WT_ALLOWED_HOSTS", "http://webterm.example.com, localhost")
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
// lone ":9848" (a pasted WT_ADDR value) and a URL-shaped credential paste
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
	t.Setenv("WT_ALLOWED_HOSTS", ":9848,https://user:"+secretEntry+"@proxy.internal")

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
		t.Errorf("log carries rejected raw entry containing %q; malformed WT_ALLOWED_HOSTS values may hold credentials and must never be logged", secretEntry)
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
	awaitBootConvergence(eng, "no-such-job-id", func(v string) { verdicts = append(verdicts, v) }, filepath.Join(dir, "tools.json"))

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
	writeToolsManifest(t, dir, manifest)

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
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
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
	// The URL is empty here (no TOOL_CATALOG_URL), so the fetch fails.
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

// TestParseLogOSCText_warnsByNameOnly pins the PRODUCTION knob read, which is
// where the confidentiality property lives — and it is the ONLY test of it,
// deliberately: the read is envx.BoolStrict, which emits no records at all, so a
// test that captured slog around the library call alone would satisfy the "no raw
// value in the log" claim vacuously and would stay green if main went back to
// envx.Bool. This drives parseLogOSCText, the function main calls, so the
// assertions cover the real call path: envx.BoolStrict plus THIS function's
// diagnostics, which are the only log sites the knob has.
//
// Four properties, each a distinct regression:
//   - the accepted VOCABULARY is envx's (true/1/yes/on, false/0/no/off,
//     case-insensitive, padding ignored). It is asserted here rather than against
//     a local parser because there is no local parser any more: BoolStrict shares
//     one parser with envx.Bool, and this table is what notices if the read is
//     ever swapped for something with a different grammar (e.g. strconv.ParseBool,
//     which accepts "t"/"f" — pinned below as malformed);
//   - a malformed value fails CLOSED to false, so a typo cannot widen what
//     content reaches the log store;
//   - the malformed path emits exactly ONE Warn, naming the key and carrying no
//     copy of the raw value in its message or in any attribute. The returned
//     error is deliberately not logged either, so this holds however envx words
//     it;
//   - the ON path warns about the widened content, and the default path is
//     silent.
//
// Serial: capture.Default mutates the process-global default logger.
func TestParseLogOSCText_warnsByNameOnly(t *testing.T) {
	const token = "s3cr3t-token-abc123"
	const onMsg = "WT_LOG_OSC_TEXT is on"
	const badMsg = "unparseable WT_LOG_OSC_TEXT"
	cases := map[string]struct {
		raw       string
		wantValue bool
		wantWarns int
		wantMsg   string
		// rawMustStayOut asks for the confidentiality assertion. It is set only
		// for values distinctive enough that finding one in the log PROVES a
		// leak: "on", "0" and "t" occur as substrings of ordinary words in
		// these two warnings, so asserting their absence would fail on wording
		// alone and say nothing about the value.
		rawMustStayOut bool
	}{
		// The whole accepted vocabulary, both spellings of every truth value,
		// plus the case and padding tolerance.
		"true":                 {raw: "true", wantValue: true, wantWarns: 1, wantMsg: onMsg},
		"1":                    {raw: "1", wantValue: true, wantWarns: 1, wantMsg: onMsg},
		"yes":                  {raw: "yes", wantValue: true, wantWarns: 1, wantMsg: onMsg},
		"on":                   {raw: "on", wantValue: true, wantWarns: 1, wantMsg: onMsg},
		"TRUE uppercase":       {raw: "TRUE", wantValue: true, wantWarns: 1, wantMsg: onMsg},
		"yes padded":           {raw: "  yes  ", wantValue: true, wantWarns: 1, wantMsg: onMsg},
		"false":                {raw: "false", wantValue: false, wantWarns: 0},
		"0":                    {raw: "0", wantValue: false, wantWarns: 0},
		"no":                   {raw: "no", wantValue: false, wantWarns: 0},
		"off":                  {raw: "off", wantValue: false, wantWarns: 0},
		"OFF uppercase padded": {raw: " OFF ", wantValue: false, wantWarns: 0},

		// Unset and blank are not parse failures: they are the silent default.
		"unset is the silent default":       {raw: "", wantValue: false, wantWarns: 0},
		"whitespace-only is the same thing": {raw: "   ", wantValue: false, wantWarns: 0},

		// Malformed: fail closed, one Warn, no echo. The token case is the shape
		// that motivates BoolStrict over Bool (a compose expansion mistake).
		"token-shaped value fails closed and warns by name": {
			raw: token, wantValue: false, wantWarns: 1, wantMsg: badMsg, rawMustStayOut: true,
		},
		"a typo of true is malformed, not false": {
			raw: "ture", wantValue: false, wantWarns: 1, wantMsg: badMsg, rawMustStayOut: true,
		},
		"a word outside the vocabulary is malformed": {
			raw: "enabled", wantValue: false, wantWarns: 1, wantMsg: badMsg, rawMustStayOut: true,
		},
		// strconv.ParseBool accepts "t"; envx's grammar does not. This is the
		// case that fails if the read is swapped for the stdlib parser.
		"t is not a spelling of true": {
			raw: "t", wantValue: false, wantWarns: 1, wantMsg: badMsg,
		},
		"a number other than 0 or 1 is malformed": {
			raw: "2", wantValue: false, wantWarns: 1, wantMsg: badMsg,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)
			t.Setenv("WT_LOG_OSC_TEXT", tc.raw)

			if got := parseLogOSCText(); got != tc.wantValue {
				t.Errorf("parseLogOSCText() with %q = %v, want %v", tc.raw, got, tc.wantValue)
			}
			if got := records.CountLevel(slog.LevelWarn, ""); got != tc.wantWarns {
				t.Errorf("log = %q, want exactly %d Warn (got %d)", records.Messages(), tc.wantWarns, got)
			}
			if tc.wantMsg != "" && records.CountLevel(slog.LevelWarn, tc.wantMsg) != 1 {
				t.Errorf("log = %q, want a Warn containing %q", records.Messages(), tc.wantMsg)
			}
			if tc.rawMustStayOut && logContains(records, tc.raw) {
				t.Errorf("log = %q carries the raw WT_LOG_OSC_TEXT value; a compose expansion mistake can put a credential on this key, so the malformed path must warn by NAME only (this is why the read is envx.BoolStrict and not envx.Bool, whose malformed Warn carries the value)",
					records.Messages())
			}
		})
	}
}

// The KIRO_CLI_TOOLS_TAINTED warning, duplicated verbatim from parseToolsTainted
// (main.go) for the reason the WT_TRUSTED_PROXIES hints above it are duplicated: this
// record is the only thing an operator sees about a rejected value, the value
// itself can be a compose-interpolated credential (CWE-532), so message and hint
// must stay FIXED strings that cannot grow an input-derived tail. A deliberate
// rewording updates both sides; anything else is the regression these pins fail on.
const (
	taintedBadMsg  = "unusable KIRO_CLI_TOOLS_TAINTED; treating the kiro-cli tools tree as untainted, the same outcome as unset"
	taintedBadHint = "only entrypoint.sh sets this, and only to 1 (it found the tools tree group/other-writable) or 0 (it did not); any other value is not an observation, so it cannot arm the distrust-and-reinstall path"
)

// TestParseToolsTainted pins the accepted VOCABULARY of the entrypoint's
// tools-tree-was-writable handoff, which nothing checked before: the shell side
// (tests/shell/pins_export_test.sh) pins the variable's NAME, its export and its
// value expression, and the Go side pinned only that main.go mentions the name — so
// which values arm a trust boundary was untested from both ends, and a read swapped
// for envx.Bool/BoolStrict (true/yes/on, any case, padding trimmed) would have
// widened it with every other test still green.
//
// Four properties, each a distinct regression:
//   - the vocabulary is exactly "1" and "0". Every wider spelling the fleet's
//     boolean parser accepts is pinned here as NOT arming, which is what fails if
//     the decode is ever "unified" with envx.Bool/BoolStrict;
//   - a value outside it is treated as NOT tainted, i.e. identically to unset,
//     because the variable is an affirmative observation and the entrypoint only
//     ever writes 0 or 1: a value that is neither reports no observation, and
//     arming the reinstall-and-prune path on it would invent evidence;
//   - it still WARNS, because only one producer sets this key and a value it did
//     not write means that producer is broken. Unset is the ordinary
//     out-of-container run and stays silent, which is why the decode distinguishes
//     unset from set-but-empty at all;
//   - the warning names the KEY only. The needle sweep covers the values
//     distinctive enough for it, and assertAttrSchema covers the rest: it pins the
//     record's EXACT attr set, so a value reaching the log under any name, in any
//     shape, fails even where a needle would be vacuous (an empty or padded value).
//
// Serial: capture.Default mutates the process-global default logger.
func TestParseToolsTainted(t *testing.T) {
	const key = "KIRO_CLI_TOOLS_TAINTED"
	const token = "s3cr3t-token-abc123"
	cases := map[string]struct {
		raw       string
		unset     bool
		want      bool
		wantWarns int
		// rawMustStayOut asks for the needle form of the confidentiality
		// assertion, and is set only where finding the value in the log PROVES a
		// leak. The fixed hint necessarily contains "1", "0" (it names the two
		// accepted spellings), " 1 " and "on" (inside "only"/"observation"), and
		// the empty string is in every string, so asserting those absent would
		// fail on wording alone and say nothing about the value. assertAttrSchema
		// below is what covers those cases.
		rawMustStayOut bool
	}{
		// The whole accepted vocabulary: two values, no case or padding tolerance.
		"1 arms the taint":      {raw: "1", want: true},
		"0 does not arm it":     {raw: "0", want: false},
		"unset does not arm it": {unset: true, want: false},

		// Every spelling envx.Bool/BoolStrict would have accepted. These are the
		// cases that fail if this decode is ever widened back to that vocabulary:
		// each would arm a trust boundary there and must not here.
		"true does not arm it":       {raw: "true", want: false, wantWarns: 1, rawMustStayOut: true},
		"yes does not arm it":        {raw: "yes", want: false, wantWarns: 1, rawMustStayOut: true},
		"on does not arm it":         {raw: "on", want: false, wantWarns: 1},
		"TRUE does not arm it":       {raw: "TRUE", want: false, wantWarns: 1, rawMustStayOut: true},
		"On does not arm it":         {raw: "On", want: false, wantWarns: 1, rawMustStayOut: true},
		"a padded 1 does not arm it": {raw: " 1 ", want: false, wantWarns: 1},

		// A producer that wrote nothing is not the same as no producer: the
		// entrypoint always writes 0 or 1, so an empty value is a broken producer
		// and warns, while unset above is silent.
		"an empty value does not arm it": {raw: "", want: false, wantWarns: 1},

		// The shape that motivates naming the key only: a compose interpolation
		// mistake (KIRO_CLI_TOOLS_TAINTED: ${SOME_TOKEN}) puts a credential here.
		"an arbitrary token does not arm it": {raw: token, want: false, wantWarns: 1, rawMustStayOut: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)
			// t.Setenv first even for the unset case: it registers the restore of
			// whatever the ambient environment held, and the Unsetenv then makes
			// the key genuinely absent for this subtest rather than empty.
			t.Setenv(key, tc.raw)
			if tc.unset {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("unset %s: %v", key, err)
				}
			}

			if got := parseToolsTainted(); got != tc.want {
				t.Errorf("parseToolsTainted() with %s=%q (unset=%v) = %v, want %v", key, tc.raw, tc.unset, got, tc.want)
			}
			if got := records.CountLevel(slog.LevelWarn, ""); got != tc.wantWarns {
				t.Errorf("log = %q, want exactly %d Warn (got %d)", records.Messages(), tc.wantWarns, got)
			}
			if tc.wantWarns == 0 {
				return
			}
			// Exact message, not a substring: a regression that appends the
			// rejected value to the sentence keeps every substring match green.
			if got := records.CountExact(taintedBadMsg); got != 1 {
				t.Errorf("log = %q, want exactly one Warn whose message is exactly %q (got %d); the message must be a fixed string with no input-derived tail",
					records.Messages(), taintedBadMsg, got)
			}
			assertAttrSchema(t, records, slog.LevelWarn, taintedBadMsg, map[string]attrCheck{
				"hint": wantString(taintedBadHint),
			})
			if tc.rawMustStayOut && logContains(records, tc.raw) {
				t.Errorf("log = %q carries the raw %s value; a compose interpolation mistake can put a credential on this key, so the rejected-value path must warn by NAME only",
					records.Messages(), key)
			}
		})
	}
}

// The WT_TRUSTED_INSTALL_UIDS warning, duplicated verbatim from
// parseTrustedInstallUIDs (main.go). Duplicating the prose is the point, as it is
// for the WT_TRUSTED_PROXIES hints: this record is the ONLY thing an operator sees
// about a dropped entry, and an entry can be a compose-interpolated credential
// (CWE-532), so both strings must stay FIXED and cannot grow an input-derived
// tail. A deliberate rewording updates both sides; anything else is the
// regression these pins exist to fail.
const (
	trustedUIDsBadMsg  = "dropping unusable WT_TRUSTED_INSTALL_UIDS entries; the kiro-cli install keeps enforcing custody against those identities"
	trustedUIDsBadHint = "each entry is a single numeric uid greater than 0 (e.g. 1000,1001); root is trusted already, and every identity listed must be at least as privileged as this server"
)

// TestParseTrustedInstallUIDs pins the whole WT_TRUSTED_INSTALL_UIDS contract:
// the EMPTY default (no trust grant, so pinstall's custody check applies in
// full), the drop-the-unusable-keep-the-rest posture, the two numeric shapes that
// are rejected as well as non-numeric text (0 is root, which the library trusts
// anyway; a negative is not an identity), deduplication, first-seen order, and
// the by-name-and-count-only warning.
//
// Order is asserted exactly rather than as a set, because it is the property that
// makes the value handed to the library reproducible for an operator reading the
// list back.
//
// Two forms of the confidentiality assertion, for the reason
// TestParseToolsTainted uses both: a needle sweep proves a specific value stayed
// out, and assertAttrSchema pins the record's EXACT attr set so a value reaching
// the log under any name, in any shape, fails even where a needle would be
// vacuous (the fixed hint necessarily contains "1000", "1001" and "0").
//
// Serial: capture.Default mutates the process-global default logger.
func TestParseTrustedInstallUIDs(t *testing.T) {
	const key = "WT_TRUSTED_INSTALL_UIDS"
	const token = "s3cr3t-token-abc123"
	cases := map[string]struct {
		raw   string
		unset bool
		want  []int
		// wantInvalid is the dropped-entry count the warning must report; 0 means
		// no warning at all is expected.
		wantInvalid int
		// rawMustStayOut asks for the needle form of the confidentiality
		// assertion, and is set only where finding the value in the log would PROVE
		// a leak. It is off for the numeric cases, whose digits appear in the fixed
		// hint's own examples.
		rawMustStayOut bool
	}{
		// The default, in all three spellings of "the operator declared nothing":
		// no grant, and silence — the strict custody check is the expected
		// behaviour here, not a degraded one worth reporting.
		"unset grants nothing":            {unset: true},
		"empty grants nothing":            {raw: ""},
		"whitespace only grants nothing":  {raw: "   \t "},
		"a lone separator grants nothing": {raw: ","},

		// The usable shapes.
		"one uid":                       {raw: "1000", want: []int{1000}},
		"several uids":                  {raw: "1000,1001,1002", want: []int{1000, 1001, 1002}},
		"surrounding whitespace trims":  {raw: " 1000 ,\t1001 ", want: []int{1000, 1001}},
		"blank entries are skipped":     {raw: "1000,,1001,", want: []int{1000, 1001}},
		"a duplicate collapses":         {raw: "1000,1000,1001,1000", want: []int{1000, 1001}},
		"first-seen order is preserved": {raw: "1002,1000,1001", want: []int{1002, 1000, 1001}},

		// The rejected shapes, each dropped with one by-name warning rather than
		// failing the boot.
		"a non-numeric entry is dropped": {raw: "notauid", wantInvalid: 1, rawMustStayOut: true},
		"zero is dropped":                {raw: "0", wantInvalid: 1},
		"a negative uid is dropped":      {raw: "-1000", wantInvalid: 1},
		"a float is dropped":             {raw: "1000.5", wantInvalid: 1, rawMustStayOut: true},

		// The shape that motivates naming the key only: a compose interpolation
		// mistake (WT_TRUSTED_INSTALL_UIDS: ${SOME_TOKEN}) puts a credential here.
		"a token-shaped value is dropped": {raw: token, wantInvalid: 1, rawMustStayOut: true},

		// Mixed: the usable entries survive, and every dropped one is counted.
		"valid entries survive alongside invalid ones": {
			raw: "1000,notauid,0,-5,1001", want: []int{1000, 1001}, wantInvalid: 3, rawMustStayOut: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			records := capture.Default(t)
			// t.Setenv first even for the unset case: it registers the restore of
			// whatever the ambient environment held, and the Unsetenv then makes
			// the key genuinely absent for this subtest rather than empty.
			t.Setenv(key, tc.raw)
			if tc.unset {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("unset %s: %v", key, err)
				}
			}

			got := parseTrustedInstallUIDs()
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseTrustedInstallUIDs() with %s=%q (unset=%v) = %v, want %v", key, tc.raw, tc.unset, got, tc.want)
			}
			wantWarns := 0
			if tc.wantInvalid > 0 {
				wantWarns = 1
			}
			if n := records.CountLevel(slog.LevelWarn, ""); n != wantWarns {
				t.Errorf("log = %q, want exactly %d Warn (got %d)", records.Messages(), wantWarns, n)
			}
			if wantWarns == 0 {
				return
			}
			// Exact message, not a substring: a regression that appends the
			// rejected entries to the sentence keeps every substring match green.
			if n := records.CountExact(trustedUIDsBadMsg); n != 1 {
				t.Errorf("log = %q, want exactly one Warn whose message is exactly %q (got %d); the message must be a fixed string with no input-derived tail",
					records.Messages(), trustedUIDsBadMsg, n)
			}
			assertAttrSchema(t, records, slog.LevelWarn, trustedUIDsBadMsg, map[string]attrCheck{
				"invalid_count": wantInt(tc.wantInvalid),
				"hint":          wantString(trustedUIDsBadHint),
			})
			if tc.rawMustStayOut && logContains(records, tc.raw) {
				t.Errorf("log = %q carries the raw %s value; a compose interpolation mistake can put a credential on this key, so a dropped entry must be warned about by NAME and COUNT only",
					records.Messages(), key)
			}
		})
	}
}

// TestParseCatalogRefresh_warnsByNameOnly pins that no supplied
// TOOL_CATALOG_REFRESH value reaches a log record, and that every value toolbelt
// ACCEPTS still gets toolbelt's answer. The wrapper exists only because
// toolbelt's parser calls scheduler.ParseInterval WITHOUT
// scheduler.WithRedactedValue, so its own fallback warning echoes the raw string
// — the CWE-532 shape the WT_LOG_OSC_TEXT remedy closed on a knob of exactly
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
// whitespace-insensitive, and a token SUBSTRING must not match. This is now the
// app's ONLY upgrade-shaped predicate — the access log's skip is decided from
// the response by webhttp.WithSkipUpgrades — and a divergence here is silent,
// dropping the attach record for a request that presented a session capability
// token.
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

// accessLinesFor returns the webhttp access-log records captured for path, in
// order, as attribute maps. Pass "" to get every access line whatever its
// recorded path — needed for requests under the /api/sessions/ subtree, whose
// recorded path is the route template (or the "(unmatched)" marker) rather than
// the raw one, because WithTemplatePathsUnder keeps session tokens out of the
// log. The access line's message is webhttp's "http", so every other record the
// server emits (the engine's session lines, wsAttachLog's attach record) is
// filtered out. capture.Recorder is concurrency-safe, which is what makes it
// usable while a real httptest server is serving.
func accessLinesFor(rec *capture.Recorder, path string) []map[string]string {
	var out []map[string]string
	for _, r := range rec.Records() {
		if r.Message != "http" {
			continue
		}
		attrs := make(map[string]string, r.NumAttrs())
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		if path == "" || attrs["path"] == path {
			out = append(out, attrs)
		}
	}
	return out
}

// awaitAccessLines waits until at least want access records exist for path and
// returns them. Polling rather than reading once: the line is written from a
// DEFERRED call inside the middleware, so it can land after the client has
// already read the response, and for a hijacked stream it lands only when the
// handler returns. Counting is what makes each case's assertion exact — several
// refusal shapes share status 400, so "a 400 line exists" would be satisfied by
// an earlier case's line.
func awaitAccessLines(t *testing.T, rec *capture.Recorder, path string, want int) []map[string]string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if lines := accessLinesFor(rec, path); len(lines) >= want {
			return lines
		}
		if time.Now().After(deadline) {
			t.Fatalf("access log has %d lines for %s, want %d; a refused upgrade must keep its line (records: %v)",
				len(accessLinesFor(rec, path)), path, want, rec.Messages())
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAccessLogSkipsOnlyCompletedUpgrades is the payoff test for the access
// log's move from a local willUpgrade predicate (a request-shaped PREDICTION of
// what the engine's websocket.Accept would admit) to webhttp.WithSkipUpgrades (a
// response-shaped OUTCOME: a recorded 101 or a bare hijack). It drives a REAL
// handshake against the engine over a real server, because that is the only way
// the outcome exists at all: no fake mux can be skipped by this option, and a
// predicate test could only ever restate the app's own guess.
//
// One completed upgrade, then every refusal shape, then the count check that
// ties them together: the number of /ws access lines must equal the number of
// REFUSALS, so the completed upgrade contributed none and no refusal was
// swallowed. Two of the refusals are the cases the deleted predicate got WRONG
// and could not have got right without copying more of coder/websocket into this
// app — a malformed Sec-WebSocket-Key VALUE (Accept base64-decodes it and
// requires 16 bytes; the predicate only counted the field) and the cross-origin
// 403 (the predicate deliberately did not model the engine's origin policy).
// Both were suppressed as if they had upgraded, losing status, duration, request
// id and client ip for exactly the requests an operator greps for when a browser
// cannot attach.
//
// Serial: capture.Default mutates the process-global default logger.
func TestAccessLogSkipsOnlyCompletedUpgrades(t *testing.T) {
	rec := capture.Default(t)
	mux, _, csp, id := mustStartSession(t, newTestDeps(true))
	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	// A COMPLETED handshake: the one shape whose access line would be a lie
	// (status 101 recorded now, the line emitted hours later at socket close
	// with a session-length duration).
	resp, err := srv.Client().Do(newWSUpgradeRequest(t, srv.URL, id, srv.URL))
	if err != nil {
		t.Fatalf("/ws handshake: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		t.Fatalf("/ws handshake status = %d, want 101; without a real upgrade this test proves nothing about suppression", resp.StatusCode)
	}
	// Closing the hijacked connection is what makes the engine's handler return,
	// which is when the deferred access log runs for this request.
	resp.Body.Close()

	// 16 zero bytes, base64: structurally valid, so it isolates the OTHER
	// mangles from the key-validity refusal below.
	const key = "AAAAAAAAAAAAAAAAAAAAAA=="
	refusals := []struct {
		name       string
		mangle     func(*http.Request)
		wantStatus int
	}{
		{
			name:       "missing upgrade headers are answered 426 and logged",
			mangle:     func(r *http.Request) { r.Header.Del("Upgrade"); r.Header.Del("Connection") },
			wantStatus: http.StatusUpgradeRequired,
		},
		{
			name:       "a non-GET is answered 405 and logged",
			mangle:     func(r *http.Request) { r.Method = http.MethodPost },
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "a wrong Sec-WebSocket-Version is answered 400 and logged",
			mangle:     func(r *http.Request) { r.Header.Set("Sec-WebSocket-Version", "8") },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "a missing Sec-WebSocket-Key is answered 400 and logged",
			mangle:     func(r *http.Request) { r.Header.Del("Sec-WebSocket-Key") },
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "a DUPLICATED Sec-WebSocket-Key is answered 400 and logged",
			mangle:     func(r *http.Request) { r.Header.Add("Sec-WebSocket-Key", key) },
			wantStatus: http.StatusBadRequest,
		},
		{
			// The predicate counted this header; Accept decodes it. This 400 was
			// silently suppressed before.
			name:       "a malformed Sec-WebSocket-Key VALUE is answered 400 and logged",
			mangle:     func(r *http.Request) { r.Header.Set("Sec-WebSocket-Key", "not-base64-16-bytes") },
			wantStatus: http.StatusBadRequest,
		},
		{
			// The engine's own origin policy, which the predicate deliberately
			// did not model — so this 403 was suppressed too.
			name:       "a cross-origin upgrade is answered 403 and logged",
			mangle:     func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") },
			wantStatus: http.StatusForbidden,
		},
	}
	for i, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			req := newWSUpgradeRequest(t, srv.URL, id, srv.URL)
			tc.mangle(req)
			refused, doErr := srv.Client().Do(req)
			if doErr != nil {
				t.Fatalf("/ws request: %v", doErr)
			}
			defer refused.Body.Close()
			if refused.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d (the refusal shape this case pins is not the one the engine produced)", refused.StatusCode, tc.wantStatus)
			}
			line := awaitAccessLines(t, rec, terminal.WSPath, i+1)[i]
			if got := line["status"]; got != strconv.Itoa(tc.wantStatus) {
				t.Errorf("access line status = %s, want %d; a refusal must be logged with its REAL status (line: %v)", got, tc.wantStatus, line)
			}
		})
	}

	lines := accessLinesFor(rec, terminal.WSPath)
	if len(lines) != len(refusals) {
		t.Errorf("got %d /ws access lines for %d refusals plus one completed upgrade, want %d; an extra line means the admitted stream was logged (a bogus status with a session-length duration), a missing one means a refusal was swallowed (lines: %v)",
			len(lines), len(refusals), len(refusals), lines)
	}
	for _, line := range lines {
		if line["status"] == strconv.Itoa(http.StatusSwitchingProtocols) {
			t.Errorf("access log carries a 101 line (%v); a completed upgrade must leave no record", line)
		}
	}
}

// TestAccessLogKeepsStreamPathRefusals pins the half of the stream skip that the
// SSE path skip could quietly break. The skip rules are evaluated BEFORE the
// chain runs, so a BARE path skip (webhttp.WithSkipPaths) on the SSE route would
// also swallow the 403 hostPolicy.Middleware writes — WriteError logs nothing
// itself and the engine handler never runs — leaving a wrong-Host or DNS-rebound
// attempt on this unauthenticated PTY with no record anywhere (CWE-778). That is
// why the SSE skip is a predicate carrying a hostPolicy.Allows conjunct, and
// this test is the only thing standing between that conjunct and a simplifying
// edit.
//
// The /ws leg needs no conjunct and is asserted for the same reason from the
// other side: WithSkipUpgrades cannot suppress a 403, because a rejected request
// never switched protocols.
//
// Serial: capture.Default mutates the process-global default logger.
func TestAccessLogKeepsStreamPathRefusals(t *testing.T) {
	rec := capture.Default(t)
	t.Setenv("WT_ALLOWED_HOSTS", "webterm.example.com")

	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	mux.HandleFunc("GET "+terminal.WSPath, ok)
	mux.HandleFunc("GET "+terminal.SessionEventsPath, ok)
	h := buildHandler(mux, nil, "default-src 'self'", parseAllowedHosts())

	upgradeShaped := func(r *http.Request) {
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Connection", "keep-alive, Upgrade")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA==")
	}

	for _, tc := range []struct {
		name, url string
		// method is the request method; empty means GET. Only the cross-origin
		// case needs an UNSAFE method, because that is the only shape
		// CrossOriginProtection rejects.
		method   string
		decorate func(*http.Request)
		// wantPath is the path the LINE must carry, which is not always the
		// requested one: /api/sessions/events sits under the token-bearing
		// subtree, so WithTemplatePathsUnder records the matched template or the
		// "(unmatched)" marker for a request the mux never routed — a rejected
		// Host is exactly that.
		wantPath string
	}{
		{
			name:     "a rebound Host on the ws upgrade keeps its 403 line",
			url:      "http://attacker.evil:9848" + terminal.WSPath,
			decorate: upgradeShaped, wantPath: terminal.WSPath,
		},
		{
			name:     "a rebound Host on the SSE stream keeps its 403 line",
			url:      "http://attacker.evil:9848" + terminal.SessionEventsPath,
			decorate: func(*http.Request) {},
			wantPath: terminal.SessionsSubtreePath + "(unmatched)",
		},
		{
			// The sibling refusal shape on the same path, one gate further in:
			// CrossOriginProtection sits INSIDE the stream skip, so a skip keyed
			// on the path alone would delete this 403's only record. The GET
			// conjunct in the predicate is what keeps it.
			name:   "a cross-origin non-GET on the SSE stream keeps its 403 line",
			url:    "http://webterm.example.com:9848" + terminal.SessionEventsPath,
			method: http.MethodPost,
			decorate: func(r *http.Request) {
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			},
			wantPath: terminal.SessionsSubtreePath + "(unmatched)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(accessLinesFor(rec, ""))
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, tc.url, http.NoBody)
			tc.decorate(req)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (the host gate must reject this request, or the logging assertion below means nothing)", w.Code)
			}
			lines := accessLinesFor(rec, "")
			if len(lines) != before+1 {
				t.Fatalf("got %d access lines, want %d; a host-policy refusal on a stream path must stay logged (lines: %v)", len(lines), before+1, lines)
			}
			line := lines[len(lines)-1]
			if got := line["status"]; got != strconv.Itoa(http.StatusForbidden) {
				t.Errorf("access line status = %s, want 403 (line: %v)", got, line)
			}
			if got := line["path"]; got != tc.wantPath {
				t.Errorf("access line path = %s, want %s (line: %v)", got, tc.wantPath, line)
			}
		})
	}

	// The other half of the conjunct: with an ALLOWED Host the SSE stream is
	// skipped, which is the behavior the path skip exists to preserve. Without
	// it the status stream would emit one misleading line per connection, with a
	// session-length duration and a status decided at close.
	t.Run("an allowed Host on the SSE stream emits no line", func(t *testing.T) {
		before := len(accessLinesFor(rec, ""))
		req := httptest.NewRequest(http.MethodGet,
			"http://webterm.example.com:9848"+terminal.SessionEventsPath, http.NoBody)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (an allowed Host must reach the stream route)", w.Code)
		}
		if got := accessLinesFor(rec, ""); len(got) != before {
			t.Errorf("got %d access lines, want %d; the status stream must stay skipped (SSE never switches protocols, so WithSkipUpgrades cannot cover it — it needs the path skip) (lines: %v)", len(got), before, got[before:])
		}
	})
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
// header-matching predicate — wsAttachLog's "an attach was attempted" test —
// against the ONLY implementation that decides whether a /ws request really
// becomes a stream: the engine's coder/websocket handshake, driven over a real
// server. TestIsWebSocketUpgrade_requiresBothListTokens
// states what THIS app believes an upgrade is; nothing asserts the engine agrees,
// and every disagreement is silent -- a request the engine refuses that this
// predicate calls an attach records an attach that never happened, and one the
// engine upgrades that the predicate calls a plain request leaves the ONE request
// carrying a session capability token with no attach record at all (the CWE-778
// silence wsAttachLog exists to remove).
// The expectations here are DERIVED from the handshake rather than restated, so a
// coder/websocket or engine bump that changes header matching fails this test
// instead of quietly re-opening that silence.
//
// Only the two upgrade headers vary; method, Sec-WebSocket-Version,
// Sec-WebSocket-Key and Origin are held at the values a real handshake carries,
// because those are the engine's OTHER refusal reasons and this predicate
// deliberately does not model them. Nothing in this app models them any more:
// the access log stopped predicting admission when it adopted
// webhttp.WithSkipUpgrades, and TestAccessLogSkipsOnlyCompletedUpgrades covers
// each of those refusals from the outcome side.
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

// TestAwaitBootConvergence_cancellationIsNotAToolFailure pins the JobCancelled
// arm, the one boot-convergence outcome no other test reaches: toolbelt cancels
// the running job from Engine.Close, which is the path this app takes on every
// SIGTERM and on the Serve-error teardown. Three properties, each a distinct
// regression:
//
//   - the verdict is still recorded exactly once, so the syncing gate lifts and
//     session creation never answers 503 "tools installing" forever;
//   - the record stays Info. Reporting a shutdown cancellation at Warn as a
//     degraded reconcile is the false broken-install alert on every deploy, and
//     a first-boot restart is routine (the image budgets 20 minutes for it);
//   - the post-convergence tail is SKIPPED. On the shutdown path Update() can
//     only fail with "engine shutting down" and the LSP nudge has no reader, so
//     both would be noise attributed to a broken tools tree.
//
// Serial: capture.Default mutates the process-global default logger.
func TestAwaitBootConvergence_cancellationIsNotAToolFailure(t *testing.T) {
	records := capture.Default(t)
	dir := t.TempDir()
	// A manual-source install that blocks, so the job is guaranteed to be
	// unfinished when Close cancels it: the branch is reached deterministically
	// instead of racing the reconcile to completion.
	manifest := `{"version":2,"tools":{"sleepytool":{"source":"manual","version":"1.0.0",` +
		`"probe":"sleepytool","install":"sleep 300"}}}`
	if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	eng, err := toolbelt.New(&toolbelt.Config{
		ConfigDir:   dir,
		ToolsDir:    filepath.Join(dir, "tools"),
		CatalogPath: filepath.Join(dir, "absent-catalog.json"),
	})
	if err != nil {
		t.Fatalf("toolbelt.New: %v", err)
	}
	job, rerr := eng.Reconcile(toolbelt.ReconcileMissing)
	if rerr != nil || job == nil {
		t.Fatalf("Reconcile = %v, %v; want an enqueued job for Close to cancel", job, rerr)
	}
	eng.Close() // the SIGTERM shape: Engine.Close cancels the active job

	var verdicts []string
	awaitBootConvergence(eng, job.ID, func(v string) { verdicts = append(verdicts, v) }, filepath.Join(dir, "tools.json"))

	if !slices.Equal(verdicts, []string{toolsStateDegraded}) {
		t.Fatalf("verdicts = %v, want exactly one %q; the syncing gate must lift on a cancelled boot pass too",
			verdicts, toolsStateDegraded)
	}
	if got := records.CountLevel(slog.LevelInfo, "boot convergence cancelled"); got != 1 {
		t.Errorf("log = %q, want exactly one cancellation Info (got %d)", records.Messages(), got)
	}
	if got := records.CountLevel(slog.LevelWarn, "boot reconcile finished degraded"); got != 0 {
		t.Errorf("log = %q; a shutdown cancellation must not be reported as a tool failure -- that Warn is the false broken-install alert on every deploy (got %d)",
			records.Messages(), got)
	}
	for _, tail := range []string{"update pass not enqueued", "no language servers enabled"} {
		if got := records.CountLevel(slog.LevelWarn, tail); got != 0 {
			t.Errorf("log = %q; the post-convergence tail must be skipped on cancellation, but %q fired %d time(s)",
				records.Messages(), tail, got)
		}
	}
}

// TestStartTools_logsTheGatedWindowOpening pins the one record that marks the
// gated window OPENING. The terminal boot-convergence records (converged /
// degraded / cancelled) are all asserted elsewhere, but they only say when the
// gate lifted: without this Info line an operator staring at 503 "tools
// installing" answers has nothing saying the gate is closed, since when, or
// which toolbelt job to correlate with the engine's own job-timeout and
// job-failed warnings. The job attribute is what makes that correlation
// possible, so it is asserted as well as the message.
//
// Serial: capture.Default mutates the process-global default logger.
func TestStartTools_logsTheGatedWindowOpening(t *testing.T) {
	const msg = "tools: boot convergence started"
	records := capture.Default(t)
	dir := t.TempDir()

	rt := startTools(baseTools{configDir: dir, catalogPath: filepath.Join(dir, "absent-catalog.json")})
	if rt.engine == nil {
		t.Fatal("engine is nil for an existing config dir; want a running tools engine")
	}
	t.Cleanup(rt.close)

	if got := records.CountLevel(slog.LevelInfo, msg); got != 1 {
		t.Fatalf("log = %q, want exactly one %q Info (got %d); without it a 503 \"tools installing\" answer has no record of when the gate closed",
			records.Messages(), msg, got)
	}
	if got, ok := records.AttrValue(msg, "job"); !ok || got == "" {
		t.Errorf("gated-window record job = %q (present=%v), want the toolbelt job id the engine's own job warnings carry", got, ok)
	}

	deadline := time.Now().Add(10 * time.Second)
	for rt.syncing() {
		if time.Now().After(deadline) {
			t.Fatal("boot convergence gate never lifted")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWarnIfToolsBinUnreachable pins the PATH-reachability nudge added for h-f1:
// its CONDITION (both arms) and its level. Nothing else asserts it, so the check
// could invert, go silent, or move to Error with the suite green -- and it fires on
// every bare `go run`, which is a supported shape, so its wording has to name an
// action that shape's reader can take.
//
// Serial: capture.Default mutates the process-global default logger, and t.Setenv
// forbids t.Parallel.
func TestWarnIfToolsBinUnreachable(t *testing.T) {
	const warnMsg = "the tools tree is not on PATH: every tool the manifest installs will be invisible to kiro-cli and to terminal sessions, even though /api/health will report tools=ok"

	t.Run("tools bin on PATH stays silent", func(t *testing.T) {
		toolsDir := t.TempDir()
		// A second, unrelated entry alongside it: the check must scan the whole
		// list, not just the first entry.
		t.Setenv("PATH", "/usr/bin"+string(os.PathListSeparator)+filepath.Join(toolsDir, "bin"))
		records := capture.Default(t)
		warnIfToolsBinUnreachable(toolsDir)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 0 {
			t.Errorf("log = %q; a tools bin that IS on PATH must not warn (got %d)", records.Messages(), got)
		}
	})

	t.Run("tools bin absent from PATH warns once, and names the directory", func(t *testing.T) {
		toolsDir := t.TempDir()
		t.Setenv("PATH", "/usr/bin")
		records := capture.Default(t)
		warnIfToolsBinUnreachable(toolsDir)
		if got := records.CountLevel(slog.LevelWarn, warnMsg); got != 1 {
			t.Errorf("log = %q, want exactly one %q Warn (got %d)", records.Messages(), warnMsg, got)
		}
		// The directory is the actionable half: a hint telling the reader to add a
		// path must say WHICH path, and the tools_bin attr is where it appears.
		want := filepath.Join(toolsDir, "bin")
		named := false
		for _, r := range records.Records() {
			r.Attrs(func(a slog.Attr) bool {
				if strings.Contains(a.Value.String(), want) {
					named = true
				}
				return true
			})
		}
		if !named {
			t.Errorf("log = %q carries no attr naming the unreachable bin dir %q; the nudge asks the reader to add a directory to PATH, so it must say which", records.Messages(), want)
		}
	})
}

// The whole-tree convergence signal is a SECOND question from the tools field,
// and these tests pin the distinction that motivated adding it: the field
// answers "did the last job succeed", the count answers "is the tree
// converged", and a partial repair makes them disagree on purpose.

func TestCountMissingFromInventory(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		tools []toolbelt.ToolInfo
		want  int
	}{
		"no entries": {want: 0},
		"all installed": {
			tools: []toolbelt.ToolInfo{{Name: "gh", Installed: true}, {Name: "jq", Installed: true}},
			want:  0,
		},
		"one enabled entry missing": {
			tools: []toolbelt.ToolInfo{{Name: "gh", Installed: true}, {Name: "jq"}},
			want:  1,
		},
		// A disabled entry is a TEMPLATE: recorded intent that is deliberately
		// not installed. Counting one would make a freshly seeded volume report
		// its five seeded templates as missing forever.
		"disabled entries are not outstanding": {
			tools: []toolbelt.ToolInfo{{Name: "gopls", Disabled: true}, {Name: "pyright", Disabled: true}},
			want:  0,
		},
		"disabled and installed is still not outstanding": {
			tools: []toolbelt.ToolInfo{{Name: "gopls", Disabled: true, Installed: true}},
			want:  0,
		},
		// Not on PATH yet is exactly what the number is about, so an in-flight
		// install counts rather than being excused.
		"an installing entry still counts": {
			tools: []toolbelt.ToolInfo{{Name: "jq", Installing: true}},
			want:  1,
		},
		"mixed tree": {
			tools: []toolbelt.ToolInfo{
				{Name: "gh", Installed: true},
				{Name: "jq"},
				{Name: "rust-analyzer", Disabled: true},
				{Name: "pyright", Installing: true},
			},
			want: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := countMissingFromInventory(tc.tools); got != tc.want {
				t.Errorf("countMissingFromInventory() = %d, want %d", got, tc.want)
			}
		})
	}
}

// "Not counted yet" is a third state a bare integer cannot carry, and conflating
// it with zero would publish convergence for a tree nobody has looked at.
func TestToolsStatus_missingCountIsUnknownBeforeTheFirstRecount(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	if n, ok := s.missingCount(); ok {
		t.Errorf("missingCount() = (%d, true) before any recount, want ok=false", n)
	}
	s.missing.Store(0)
	if n, ok := s.missingCount(); !ok || n != 0 {
		t.Errorf("missingCount() = (%d, %v) after a zero recount, want (0, true)", n, ok)
	}
}

func TestToolsStatus_watchConvergenceRecountsOnPoke(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	counts := make(chan int, 8)
	next := 3
	go s.watchConvergence(t.Context(), func() (int, error) {
		n := next
		next--
		counts <- n
		return n, nil
	})

	// The watcher counts once at startup, without being asked: the question has
	// an answer before the first job transition arrives.
	select {
	case <-counts:
	case <-time.After(5 * time.Second):
		t.Fatal("watchConvergence never took an initial count")
	}
	waitForMissing(t, s, 3)

	s.requestRecount()
	waitForMissing(t, s, 2)
}

// A failed count must return the field to UNKNOWN rather than freeze the last
// answer: tools_missing is absent when the count is not known, so a stale number
// would assert a convergence the engine can no longer confirm.
func TestToolsStatus_watchConvergenceReturnsToUnknownOnAFailedRecount(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	var fail atomic.Bool
	// Unbuffered: each FAILING recount blocks inside the fake counter until the
	// test acknowledges it, and that ordering is what replaces the sleep this
	// test used to carry. A sleep cannot do this job: under load the watcher may
	// not process the poke in time, and the assertion then reads the
	// pre-failure (7, true) state and fails spuriously.
	entered := make(chan struct{})
	go s.watchConvergence(t.Context(), func() (int, error) {
		if fail.Load() {
			entered <- struct{}{}
			return 99, errors.New("inventory unavailable")
		}
		return 7, nil
	})
	waitForMissing(t, s, 7)

	// watchConvergence is ONE sequential goroutine, so observing it enter the
	// SECOND failing recount proves it already finished the first — including
	// the unknown store this test is about, which happens after count() returns.
	awaitFailingRecount := func() {
		t.Helper()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the convergence watcher never ran the failing recount, so the unknown branch was never exercised")
		}
	}
	fail.Store(true)
	s.requestRecount()
	awaitFailingRecount()
	s.requestRecount()
	awaitFailingRecount()
	if n, ok := s.missingCount(); ok {
		t.Errorf("missingCount() = (%d, %v) after a failed recount, want unknown (0, false)", n, ok)
	}
}

// requestRecount is called from OnJobChanged, which runs under toolbelt's job
// queue lock. If it could ever block, the engine would deadlock — Inventory()
// takes that same lock through InstallingSet(), which is why the counting lives
// in a goroutine at all.
func TestToolsStatus_requestRecountNeverBlocks(t *testing.T) {
	t.Parallel()
	s := newToolsStatus() // no watcher: nothing is draining the channel
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			s.requestRecount()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("requestRecount blocked with no watcher draining; under the queue lock this deadlocks the engine")
	}
}

// The count is a fact about the tree, not a verdict about this boot, so it is
// requested even before the boot verdict is recorded — unlike the tools field,
// whose live half stays disarmed until then.
func TestToolsStatus_observeJobRequestsARecountBeforeBootWithoutChangingTheField(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	s.observeJob(jobEvent(toolbelt.JobKindInstall, toolbelt.JobDone))

	if got := s.get(); got != toolsStateSyncing {
		t.Errorf("tools field = %q after a pre-verdict job, want %q (the live half must stay disarmed)", got, toolsStateSyncing)
	}
	select {
	case <-s.poke:
	default:
		t.Error("no recount was requested for a settled pre-verdict job; the count would stay unknown until the next transition")
	}
}

// An excluded job kind must not move the tools FIELD — the kind policy is the
// state verdict's alone. It must still provoke a recount: the count is a fact
// about the tree, and a disable, an uninstall or a half-finished update all
// change which enabled entries are installed without meaning the boot failed.
func TestToolsStatus_observeJobIgnoresUncountedKindsForTheVerdictOnly(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	s.recordBoot(toolsStateOK)
	drainPoke(s)

	s.observeJob(jobEvent(toolbelt.JobKindCatalogRefresh, toolbelt.JobFailed))
	if got := s.get(); got != toolsStateOK {
		t.Errorf("tools field = %q after an uncounted job, want %q", got, toolsStateOK)
	}
	select {
	case <-s.poke:
	default:
		t.Error("an uncounted but settled job did not request a convergence recount; the published count would assert a convergence the engine has not confirmed")
	}
}

// A CANCELLED job is settled: toolbelt cancels RUNNING jobs, so one that already
// changed the tree must provoke a recount even though cancellation is not a fault
// and so must not move the verdict field.
func TestToolsStatus_observeJobRecountsOnCancellation(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	s.recordBoot(toolsStateOK)
	drainPoke(s)

	s.observeJob(jobEvent(toolbelt.JobKindInstall, toolbelt.JobCancelled))
	if got := s.get(); got != toolsStateOK {
		t.Errorf("tools field = %q after a cancelled job, want %q (cancellation is not a fault)", got, toolsStateOK)
	}
	select {
	case <-s.poke:
	default:
		t.Error("a cancelled job did not request a convergence recount; a job cancelled after it changed the tree would leave the published count asserting the pre-job state")
	}
}

// recordBoot recounts because the boot pass is the largest single change to the
// tree; waiting for the next job transition would leave the count unknown on
// every healthy boot, which is most of them.
func TestToolsStatus_recordBootRequestsARecount(t *testing.T) {
	t.Parallel()
	s := newToolsStatus()
	drainPoke(s)
	s.recordBoot(toolsStateOK)
	select {
	case <-s.poke:
	default:
		t.Error("recordBoot did not request a convergence recount")
	}
}

func waitForMissing(t *testing.T, s *toolsStatus, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, ok := s.missingCount(); ok && n == want {
			return
		}
		if time.Now().After(deadline) {
			n, ok := s.missingCount()
			t.Fatalf("missingCount() = (%d, %v), want (%d, true)", n, ok, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func drainPoke(s *toolsStatus) {
	select {
	case <-s.poke:
	default:
	}
}

// The stage field is the discriminator that replaced five named ERROR messages.
// Consolidating them into one exit-site line removed the only thing a log query
// or alert rule could key on, and three of the five names do not even survive as
// substrings of the wrapped error. These tests pin the replacement: a stable
// VALUE per startup stage, always present.

func TestStageOf(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"nil error":                  {err: nil, want: stageUnknown},
		"unattributed error":         {err: errors.New("boom"), want: stageUnknown},
		"attributed":                 {err: atStage(stageListen, errors.New("boom")), want: stageListen},
		"attributed then re-wrapped": {err: fmt.Errorf("outer: %w", atStage(stageServe, errors.New("boom"))), want: stageServe},
		// The outermost attribution wins, which is what lets a caller re-attribute
		// a failure it has reinterpreted.
		"doubly attributed": {err: atStage(stageStatic, atStage(stageListen, errors.New("boom"))), want: stageStatic},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := stageOf(tc.err); got != tc.want {
				t.Errorf("stageOf() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Attribution must not change what the operator reads: the wrapped text IS the
// hint, and a stage wrapper that prefixed or reworded it would defeat the
// consolidation it exists to make queryable.
func TestAtStagePreservesTheMessageAndTheChain(t *testing.T) {
	t.Parallel()
	inner := errors.New("mount target is a file")
	wrapped := fmt.Errorf("work directory /workspace is not a directory: %w", inner)
	got := atStage(stageWorkDir, wrapped)

	if got.Error() != wrapped.Error() {
		t.Errorf("Error() = %q, want the wrapped text unchanged %q", got.Error(), wrapped.Error())
	}
	if !errors.Is(got, inner) {
		t.Error("attribution broke the error chain; errors.Is no longer reaches the cause")
	}
}

// Every startup failure path must be attributed, or the field it exists for
// reports unknown exactly when an operator needs it. checkWorkDir is the one
// path a test can drive end to end without binding a port or embedding a broken
// static tree.
func TestCheckWorkDirAttributesItsStage(t *testing.T) {
	t.Parallel()
	t.Run("missing directory", func(t *testing.T) {
		t.Parallel()
		err := checkWorkDir(filepath.Join(t.TempDir(), "absent"))
		if err == nil {
			t.Fatal("checkWorkDir accepted an absent directory")
		}
		if got := stageOf(err); got != stageWorkDir {
			t.Errorf("stage = %q, want %q", got, stageWorkDir)
		}
	})
	t.Run("path is a file", func(t *testing.T) {
		t.Parallel()
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if werr := os.WriteFile(file, []byte("x"), 0o600); werr != nil {
			t.Fatalf("write fixture: %v", werr)
		}
		err := checkWorkDir(file)
		if err == nil {
			t.Fatal("checkWorkDir accepted a plain file")
		}
		if got := stageOf(err); got != stageWorkDir {
			t.Errorf("stage = %q, want %q", got, stageWorkDir)
		}
	})
}

// The stage values are the log surface, so they are pinned as literals here:
// renaming one is a breaking change to an operator's query and must fail a test
// rather than pass silently.
func TestStageValuesAreStable(t *testing.T) {
	t.Parallel()
	for got, want := range map[string]string{
		stageWorkDir: "work_dir",
		stageStatic:  "static",
		stageListen:  "listen",
		stageServe:   "serve",
		stageUnknown: "unknown",
	} {
		if got != want {
			t.Errorf("stage value = %q, want %q (an operator's log query keys on this literal)", got, want)
		}
	}
}

// parseCatalogRefresh is deliberately STRICTER than the fleet's config-echo
// policy: envx states that config values are not secrets and its own tolerant
// warnings include the raw value, scheduler's steering doc says plain *_INTERVAL
// env reads should not redact, and 9 apps echo raw config values today. This app
// does not, because its compose file is the operator's whole config surface, it
// serves an unauthenticated root shell, and its README publishes a no-values
// promise. See "Settled review decisions".
//
// The cost of that deviation is the only thing worth guarding: the pre-parse
// duplicates scheduler's accept vocabulary, and nothing keeps the two in step.
// These tests derive the expected behaviour from the REAL library rather than
// from a copy of its rules, so a scheduler or toolbelt release that adds a
// sentinel fails here on the Renovate bump PR instead of silently changing what
// this app accepts.

// The invariant that makes the pre-parse safe to keep: it is OUTCOME-TRANSPARENT.
// It may change what is LOGGED and must never change what is RETURNED. Any
// divergence means the local vocabulary has drifted from the library's and this
// app is now rejecting (or accepting) something the library does not.
func TestParseCatalogRefreshIsOutcomeTransparent(t *testing.T) {
	for _, raw := range []string{
		"", " ", "off", "OFF", "disabled", "Disabled", "off ", " disabled ",
		"0", "0s", "24h", "90m", "1h30m", "24H", "1H30M", // case-sensitive units
		"-5m", "5", "5min", "abc", "24 h", "1e3s", "0x10s",
		"9999999h", "-0", "+24h", ".5h", "1.5h",
	} {
		t.Run("value="+raw, func(t *testing.T) {
			want := toolbelt.ParseCatalogRefresh(raw, catalogRefreshKey)
			if got := parseCatalogRefresh(raw); got != want {
				t.Errorf("parseCatalogRefresh(%q) = %v, library returns %v — the local pre-parse changed the OUTCOME, so its accept vocabulary has drifted from scheduler's",
					raw, got, want)
			}
		})
	}
}

// The protection itself: whatever the operator set must never reach the log. This
// is what the deviation buys, and it is the half a library change would have
// taken away. Mutates the process-global default logger, so no t.Parallel.
func TestParseCatalogRefreshNeverLogsTheValue(t *testing.T) {
	// Values chosen to look like a misrouted credential rather than a duration,
	// which is the case the deviation exists for: a compose expansion mistake
	// putting ${SOME_TOKEN} on this key.
	for _, secret := range []string{
		"hunter2-not-a-duration",
		"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
		"postgres://user:pa55w0rd@db:5432/app",
	} {
		t.Run(secret[:8], func(t *testing.T) {
			records := capture.Default(t)
			if got := parseCatalogRefresh(secret); got == 0 {
				t.Fatalf("parseCatalogRefresh(%q) = 0; an unusable value must fall back to a positive cadence", secret)
			}
			for _, r := range records.Records() {
				if strings.Contains(r.Message, secret) {
					t.Errorf("the rejected value reached a log MESSAGE: %q", r.Message)
				}
				r.Attrs(func(a slog.Attr) bool {
					if strings.Contains(a.Value.String(), secret) {
						t.Errorf("the rejected value reached log attr %q = %q", a.Key, a.Value)
					}
					return true
				})
			}
		})
	}
}

// The by-name-only warning must still FIRE, or the redaction has been achieved by
// saying nothing at all — which would leave an operator with a silently ignored
// setting.
func TestParseCatalogRefreshStillWarnsByName(t *testing.T) {
	records := capture.Default(t)
	parseCatalogRefresh("definitely-not-a-duration")

	for _, r := range records.Records() {
		if strings.Contains(r.Message, catalogRefreshKey) {
			return
		}
		found := false
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), catalogRefreshKey) {
				found = true
			}
			return true
		})
		if found {
			return
		}
	}
	t.Errorf("no warning named %s for an unusable value; the operator gets no diagnostic at all", catalogRefreshKey)
}

// setupLoggingStderr runs setupLogging with os.Stderr replaced by a pipe and
// returns everything the handler it INSTALLED wrote while doing so. Nothing
// cheaper works: setupLogging's own slogx.Setup replaces the default logger, so
// capture.Default's handler is gone before the warning is emitted, and
// slogx.NewHandler reads os.Stderr at construction — which is exactly why the
// swap has to happen before the call and is enough to observe it.
//
// Both globals are restored on cleanup, so a later test sees the process it
// started with.
func setupLoggingStderr(t *testing.T) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	prevStderr, prevLogger := os.Stderr, slog.Default()
	t.Cleanup(func() {
		os.Stderr = prevStderr
		slog.SetDefault(prevLogger)
		_ = r.Close()
	})
	os.Stderr = w

	setupLogging()

	// Close the write end so ReadAll terminates. The record is one short line and
	// a pipe buffers far more, so the write above never blocked on this read.
	if err := w.Close(); err != nil {
		t.Fatalf("close the pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the captured stderr: %v", err)
	}
	return string(out)
}

// TestSetupLoggingInstallsTheParsedLevelAndWarnsByNameOnly pins the one env read
// that had no test at all, and it is the read that decides which of this app's
// other diagnostics an operator can see. Two properties, each a silent
// regression:
//
//   - the parsed level actually reaches the INSTALLED handler, and an
//     unparseable value falls back to info rather than to debug. Nothing
//     asserted this, so reversing the default, or moving slogx.Setup above
//     ParseLevel (the doc comment says the order is the slogx contract, and the
//     zero Options.Level is info, so the swap compiles and pins every deployment
//     at info), silently decides for every deployment which lines exist —
//     including the classifyStatus trace this app's own steering names as the
//     WT_LOG_LEVEL=debug diagnosis path for stuck tab-status dots;
//   - the unparseable warning names the KEY and carries no copy of the VALUE.
//     That is the app's house rule, stated in the function's own comment and
//     applied at WT_TRUSTED_PROXIES, KIRO_CLI_CHAT_ARGS, WT_LOG_OSC_TEXT and
//     TOOL_CATALOG_REFRESH — the last two each with a test saying so. This key
//     was the only one where the claim was unchecked, and a compose
//     interpolation mistake is what puts a credential on it (CWE-532).
//
// Assertions name the specific record rather than counting all records: a PTY
// session left running by an earlier test can still be writing to the default
// logger, and a total count would make this test fail for someone else's line.
//
// Serial (no t.Parallel): it replaces the process-global default logger and
// os.Stderr, and t.Setenv forbids parallel anyway.
func TestSetupLoggingInstallsTheParsedLevelAndWarnsByNameOnly(t *testing.T) {
	const (
		token   = "s3cr3t-token-abc123"
		warnMsg = "unparseable WT_LOG_LEVEL"
	)
	cases := []struct {
		name      string
		raw       string
		absent    bool // the variable is not in the environment at all
		wantDebug bool // the installed handler admits Debug
		wantInfo  bool // ... and Info
		wantWarn  bool // the unparseable-level warning was emitted
		// rawMustStayOut asks for the confidentiality assertion, and is set only
		// for values distinctive enough that finding one PROVES a leak: "debug"
		// and "info" appear in this warning's own hint by design.
		rawMustStayOut bool
	}{
		{name: "absent installs the info default", absent: true, wantInfo: true},
		{name: "blank installs the info default", raw: "", wantInfo: true},
		{name: "debug installs debug", raw: "debug", wantDebug: true, wantInfo: true},
		{name: "error installs error", raw: "error"},
		{name: "case and padding are the library's tolerance, not a local one", raw: " DEBUG ", wantDebug: true, wantInfo: true},
		{
			name: "an unparseable level falls back to info and warns by name",
			raw:  "verbose", wantInfo: true, wantWarn: true, rawMustStayOut: true,
		},
		{
			name: "a token-shaped value cannot reach the log",
			raw:  token, wantInfo: true, wantWarn: true, rawMustStayOut: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv first either way: it records the pre-test value and
			// restores it at cleanup, so the Unsetenv below is safe (the shape
			// TestResolveScrollback uses for its absent case).
			t.Setenv("WT_LOG_LEVEL", tc.raw)
			if tc.absent {
				if err := os.Unsetenv("WT_LOG_LEVEL"); err != nil {
					t.Fatalf("Unsetenv(WT_LOG_LEVEL): %v", err)
				}
			}

			out := setupLoggingStderr(t)

			ctx := t.Context()
			if got := slog.Default().Enabled(ctx, slog.LevelDebug); got != tc.wantDebug {
				t.Errorf("with WT_LOG_LEVEL=%q the installed handler admits Debug = %v, want %v", tc.raw, got, tc.wantDebug)
			}
			if got := slog.Default().Enabled(ctx, slog.LevelInfo); got != tc.wantInfo {
				t.Errorf("with WT_LOG_LEVEL=%q the installed handler admits Info = %v, want %v", tc.raw, got, tc.wantInfo)
			}
			// Error is always admitted; asserting it makes "the handler is a real
			// leveled handler" explicit rather than assumed by the two above.
			if !slog.Default().Enabled(ctx, slog.LevelError) {
				t.Errorf("with WT_LOG_LEVEL=%q the installed handler drops Error records", tc.raw)
			}
			if got := strings.Count(out, warnMsg); (got > 0) != tc.wantWarn {
				t.Errorf("stderr = %q, want the %q warning present = %v", out, warnMsg, tc.wantWarn)
			}
			if tc.rawMustStayOut && strings.Contains(out, tc.raw) {
				t.Errorf("stderr = %q carries the raw WT_LOG_LEVEL value; a compose expansion mistake can put a credential on this key, so a rejected value must be warned about by NAME only",
					out)
			}
		})
	}
}
