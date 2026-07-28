// Package main serves Web Terminal for Kiro, a browser terminal around kiro-cli.
// Each created session launches one `kiro-cli chat` process in a PTY; WebSocket
// connections attach and reconnect to that session through web-terminal-engine.
// Terminal state and scrollback remain in memory for the session lifetime.
package main

// Build inputs for `go:embed static`. The Dockerfile invokes the same
// commands inline; running `go generate ./...` locally produces the
// same `static/` tree so `go run .` and `go build .` work without the
// container.
//
// The single step runs tsc (the TS7 native compiler, from static-src's
// @typescript/native devDependency) to build the JS bundle from static-src.
// The CSS bundle is concatenated by the Dockerfile at build time;
// no go:generate step for it.
//
//go:generate static-src/node_modules/.bin/tsc --project static-src/tsconfig.json

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cplieger/envx"
	"github.com/cplieger/slogx"
	"github.com/cplieger/toolbelt/v2"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
	"github.com/cplieger/webhttp"
)

// staticFS holds the served asset tree. This embeds the DIRECTORY, not an explicit
// file list, and that is deliberate rather than lazy: two of the assets (app.js, built
// by the generate step above; style.css, concatenated by the Dockerfile's CSS step) are
// build outputs that are gitignored, and go:embed fails the build on a pattern matching
// nothing -- so an explicit allowlist would break `go vet ./...` on a fresh checkout,
// which the shared CI template runs before anything generates those bundles.
//
// The consequence is that this edge accepts whatever the build tools leave in static/,
// so purity is enforced OUTSIDE the directive: .dockerignore keeps non-product output
// out of the build context (and therefore out of the image's embed), and .gitignore
// keeps it out of the repo. Those lists are load-bearing, not decoration -- an earlier
// tsconfig did emit app.test.js into static/, and .dockerignore is the only reason test
// code never reached a published image. Add a pattern to both before adding any new
// build step that writes into static/.
//
//go:embed static
var staticFS embed.FS

// parseTrustedProxies reads a comma-separated list of CIDRs / bare IPs from the
// TRUSTED_PROXIES env var into the trusted-proxy set the access log's client-IP
// resolver consults (webhttp.WithClientIP -> ClientIP). It delegates the
// CIDR/bare-IP parsing to the shared webhttp.ParseCIDRs helper, which trims
// whitespace, skips blanks, treats a bare IP as a single host (/32 or /128), and
// reports invalid entries separately.
//
// It is intentionally LENIENT: a malformed entry is logged (count-only; the
// raw value could carry a misplaced credential) at Warn and skipped, and the
// valid subset is used, rather than aborting startup — one typo
// in an operator's proxy list must not disable proxy awareness entirely, and it
// must never fall open. An unset or empty var yields nil, i.e. "trust nothing",
// so ClientIP ignores X-Forwarded-For and logs the spoof-proof socket peer — the
// correct default for a directly-exposed deployment. Behind a reverse proxy, set
// the var to the proxy's CIDR(s) so the access log records the real client.
func parseTrustedProxies() []*net.IPNet {
	const key = "TRUSTED_PROXIES"
	v := envx.String(key, "")
	if v == "" {
		return nil
	}
	nets, invalid := webhttp.ParseCIDRs(strings.Split(v, ","))
	if len(invalid) > 0 {
		// Count-only, like the KWEB_LOG_LEVEL and KIRO_CLI_CHAT_ARGS
		// treatment: a compose expansion mistake could put a credential in an
		// entry, so the rejected raw values never reach the log.
		slog.Warn("ignoring malformed "+key+" entries; using the valid proxy set",
			"invalid_count", len(invalid),
			"hint", "each entry must be a CIDR (e.g. 10.0.0.0/8) or a bare IP (e.g. 192.168.1.5)")
	}
	return nets
}

// parseAllowedHosts reads the comma-separated KWEB_ALLOWED_HOSTS list of exact
// hostnames / IPs this server answers for into a webhttp.HostPolicy — the
// shared exact-match Host allowlist that closes the DNS-rebinding hole
// same-origin checks alone leave open (a rebinding attack makes Origin and
// Host AGREE, so CrossOriginProtection admits it; only an exact-Host check
// breaks that chain, CWE-346). The library owns the mechanism
// (webhttp.CanonicalHost canonicalization, X-Forwarded-Host ignored, the
// loopback peer+Host carve-out that keeps the baked Docker healthcheck and
// in-container tools clients working under any allowlist); this parser owns
// the app policy: the carve-out is enabled, the 403 names KWEB_ALLOWED_HOSTS,
// and malformed entries are logged (count-only, like parseTrustedProxies) and
// dropped per ParseHostList's drop-and-report contract.
//
// An unset or all-blank var yields an INACTIVE policy — "any Host accepted",
// the backward-compatible default; main warns about the DNS-rebinding
// exposure that default leaves open. Any non-blank entry engages the gate, so
// a var whose entries are ALL malformed (a pasted URL, a lone ":9848") yields
// an active EMPTY policy: deny-all except the loopback carve-out, failing
// closed rather than silently unprotected — warned here by name, since every
// browser request would otherwise 403 with no hint why.
func parseAllowedHosts() *webhttp.HostPolicy {
	const key = "KWEB_ALLOWED_HOSTS"
	policy, invalid := webhttp.ParseHostList(strings.Split(envx.String(key, ""), ","),
		webhttp.WithLoopbackExempt(),
		webhttp.WithHostAllowlistError("",
			"host not allowed; add it to KWEB_ALLOWED_HOSTS to serve this hostname"))
	if len(invalid) > 0 {
		// Count-only, like parseTrustedProxies: the rejected raw values could
		// carry a misplaced credential, so only their count is logged.
		slog.Warn("dropping malformed "+key+" entries; they cannot match any browser-sent Host",
			"invalid_count", len(invalid),
			"hint", "use bare hostnames or IPs only (no scheme, path, or CIDR), e.g. localhost,192.168.1.5,webterm.example.com; a lone port like :9848 belongs in KWEB_ADDR")
	}
	if policy.Active() && policy.Size() == 0 {
		slog.Warn(key+" has no usable entries; rejecting every non-loopback request (fail closed)",
			"hint", "fix the malformed entries in "+key+" to restore browser access")
	}
	return policy
}

// parseBoolEnv reads a boolean env var, accepting the same vocabulary as
// envx.Bool (true/1/yes/on, false/0/no/off, case-insensitive) and reporting
// whether the value parsed. It exists so an unparseable value is warned about
// by NAME only: envx.Bool logs the RAW value on its malformed path, and a
// compose expansion mistake could put a credential there, so the raw string
// never reaches the log (see parseTrustedProxies for the same reasoning).
// An unset or blank value is not a parse failure — it yields the fallback.
func parseBoolEnv(key string, fallback bool) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(envx.String(key, ""))) {
	case "":
		return fallback, true
	case "true", "1", "yes", "on":
		return true, true
	case "false", "0", "no", "off":
		return false, true
	default:
		return fallback, false
	}
}

// parseLogOSCText reads the KWEB_LOG_OSC_TEXT knob (default false) and emits the
// startup warnings that go with it, returning whether notification TEXT may be
// logged.
//
// KWEB_LOG_OSC_TEXT is the confidentiality opt-in for terminal notification
// TEXT. An unrecognized OSC 9 notification is arbitrary child output — any
// program run in the terminal can emit `ESC ] 9 ; <text>` — and it can carry a
// token or a device code, so by default the classifier logs only a content-free
// fingerprint plus a rune count (see newStatusClassifier). Turning this on adds
// the full text to the Debug record, which is why it warns at startup rather
// than logging silently: raising KWEB_LOG_LEVEL alone must not widen what
// content reaches the log store.
//
// Parsed with parseBoolEnv rather than envx.Bool: envx warns with the RAW value
// on an unparseable boolean, and a compose expansion mistake could put a secret
// on this key -- the same reason KWEB_LOG_LEVEL is read as a string and parsed
// here. Unparseable falls back to false (off), the fail-closed direction.
//
// The read and its warnings live here, not inline in main, so a test can assert
// the malformed path emits exactly one Warn and no copy of the raw value: the
// property is the warning's, and parseBoolEnv itself logs nothing at all.
func parseLogOSCText() bool {
	logOSCText, ok := parseBoolEnv("KWEB_LOG_OSC_TEXT", false)
	if !ok {
		slog.Warn("unparseable KWEB_LOG_OSC_TEXT; keeping notification text out of the log (the default)",
			"hint", "use true or false")
	}
	if logOSCText {
		slog.Warn("KWEB_LOG_OSC_TEXT is on: terminal notification text is logged at debug level and may contain secrets (a token, a device code, a tokenised URL) emitted by any program running in the terminal",
			"hint", "leave it off outside an active diagnostic session; the default records a content-free fingerprint that still distinguishes kiro-cli wording drift")
	}
	return logOSCText
}

// sessionCommand builds the per-session PTY command: `kiro-cli chat` behind a
// sign-in guard. When no identity is present (`whoami` exits non-zero, verified
// against the pinned build: 0 logged in, 1 not), the guard first runs
// `kiro-cli login --use-device-flow` IN the terminal, then execs chat in the
// same PTY on success.
//
// The device flow is the only sign-in that works here. kiro-cli's default flow
// opens a browser on THIS host — a headless container, so the open fails and
// chat exits, leaving a dead session (historically: a stuck loading screen and
// a flashing "Reconnecting…" after the engine's 4001 close). Its PKCE localhost
// callback could not be reached from the user's machine even if a browser
// existed. The device flow instead prints a verification URL + code inline; the
// terminal UI linkifies URLs, so the user opens it in their OWN browser (any
// device), confirms, and the chat starts in the same tab. Method/license
// selection stays interactive inside the TUI — nothing org-specific is baked
// into the image.
//
// The script never interpolates cliPath or chatArgs: cliPath is passed as $0
// (the argument after -c's script) and chatArgs ride the positional params
// (`"$@"`), so a path or flag with spaces or shell metacharacters cannot break
// or inject into the script. chatArgs (operator flags from KIRO_CLI_CHAT_ARGS,
// e.g. --v3) are appended to the chat invocation only — login and whoami never
// see them.
func sessionCommand(cliPath string, chatArgs ...string) []string {
	const script = `if ! command -v "$0" >/dev/null 2>&1; then
printf '%s\n' 'kiro-cli is not installed or not on PATH. The first-boot install may have failed; check the container logs and /api/health.'
exit 1
fi
if ! "$0" whoami >/dev/null 2>&1; then
printf '%s\n' 'kiro-cli is not signed in. Starting the device-flow sign-in:' 'open the URL it prints (tap or click it), confirm the code there, and the chat starts here on its own.' ''
"$0" login --use-device-flow || exit 1
fi
exec "$0" chat "$@"`
	return append([]string{"/bin/sh", "-c", script, cliPath}, chatArgs...)
}

func main() {
	// Parse the level BEFORE Setup so the handler installs at the configured
	// level; warn AFTER Setup so the warning emits through the configured
	// handler (the slogx contract). KWEB_LOG_LEVEL=debug surfaces the
	// diagnostic lines that are invisible at the default info — e.g. the
	// newStatusClassifier trace for a kiro-cli notification-wording drift.
	logLevelRaw := envx.String("KWEB_LOG_LEVEL", "")
	logLevel, logLevelOK := slogx.ParseLevel(logLevelRaw, slog.LevelInfo)
	slogx.Setup(slogx.Options{Level: logLevel})
	if !logLevelOK {
		// Field-name-only: a compose expansion mistake could put a secret in
		// the value, so the raw string never reaches the log.
		slog.Warn("unparseable KWEB_LOG_LEVEL; using the info default",
			"hint", "use debug, info, warn, or error")
	}

	addr := envx.String("KWEB_ADDR", ":9848")
	// Warn for any bind reachable beyond loopback (wildcards, routable IPs,
	// hostnames — webhttp.ClassifyBind's exposure vocabulary): a client that
	// can reach this port gets an UNAUTHENTICATED kiro-cli PTY. The
	// fail-silent recipe — only a definite exposure warns; an unparseable
	// addr (BindInvalid) will fail at Listen anyway with its own error.
	if webhttp.ClassifyBind(addr) == webhttp.BindExposed {
		slog.Warn("serving an UNAUTHENTICATED kiro-cli shell on a non-loopback address; front it with an authenticating reverse proxy",
			"addr", addr,
			"hint", "any client that can reach this port gets a kiro-cli PTY with filesystem access to /workspace and the /config home (auth tokens, ssh keys, gitconfig)")
	}
	cliPath := envx.String("KIRO_CLI_PATH", "kiro-cli")
	workDir := envx.String("KWEB_WORK_DIR", "/workspace")
	// Readiness marker written by entrypoint.sh after it verifies a runnable,
	// correctly-versioned kiro-cli. Empty outside the container (bare `go run`,
	// tests) so /api/health keeps pure-listener readiness there.
	kiroReadyMarker := envx.String("KIRO_CLI_READY_MARKER", "")

	fi, statErr := os.Stat(workDir)
	switch {
	case statErr != nil:
		slog.Error("work directory missing",
			"work_dir", workDir, "error", statErr,
			"hint", "bind-mount a host directory to /workspace in compose.yaml")
		os.Exit(1)
	case !fi.IsDir():
		slog.Error("work directory is not a directory",
			"work_dir", workDir,
			"hint", "the mount target is a file or device, not a directory; bind-mount a host DIRECTORY to /workspace in compose.yaml")
		os.Exit(1)
	}

	// Tools engine (cplieger/toolbelt): declarative provisioning of the
	// /config/tools tree from the tools.json manifest, replacing the
	// retired setup-tools.sh. Constructed only when the config dir
	// exists (the container's /config bind mount); bare `go run` and
	// tests outside the container run without a tools surface.
	tools := startTools(baseTools{
		configDir:   envx.String("KWEB_CONFIG_DIR", "/config"),
		catalogPath: envx.String("TOOL_CATALOG_PATH", "/app/tool-catalog.json"),
		// Runtime catalog refresh: the baked catalog above is only the
		// first-boot/offline fallback; the engine fetches the published
		// catalog at boot and every TOOL_CATALOG_REFRESH (default 24h;
		// "off"/"0" disables the schedule, keeping the loopback API's
		// manual refresh). Every fetched catalog re-verifies the
		// embedded required-tools list before it replaces the current
		// one, and the last good catalog stands on any failure.
		catalogURL: envx.String("TOOL_CATALOG_URL", toolbelt.DefaultCatalogURL),
		refreshInterval: toolbelt.ParseCatalogRefresh(
			envx.String("TOOL_CATALOG_REFRESH", ""), "TOOL_CATALOG_REFRESH"),
	})

	// TRUSTED_PROXIES names the reverse proxies (CIDRs or bare IPs) whose
	// X-Forwarded-For the access log may trust to recover the real client IP.
	// Unset/empty ⇒ nil ⇒ trust nothing ⇒ log the unspoofable socket peer (the
	// spoof-safe default for a directly-exposed deployment). See parseTrustedProxies.
	trustedProxies := parseTrustedProxies()

	// KWEB_ALLOWED_HOSTS names the exact hostnames/IPs this server answers
	// for; anything else is rejected before the terminal routes (see
	// parseAllowedHosts for the DNS-rebinding rationale). Unset ⇒ inactive
	// policy ⇒ permissive (backward compatible), but that leaves rebinding
	// open even on a loopback/private bind — the attack rides the victim's
	// browser, so the README's "keep it loopback" mitigation does not cover
	// it. Warn.
	hostPolicy := parseAllowedHosts()
	if !hostPolicy.Active() {
		slog.Warn("KWEB_ALLOWED_HOSTS is unset or blank; any Host header is accepted, leaving DNS rebinding open even on loopback/private binds",
			"hint", "set KWEB_ALLOWED_HOSTS to the exact hostnames/IPs you browse to (e.g. localhost,192.168.1.5,webterm.example.com)")
	}

	// KWEB_LOG_OSC_TEXT (default false) is the confidentiality opt-in for
	// terminal notification TEXT; the knob's rationale, its fail-closed
	// direction and its startup warnings are all in parseLogOSCText.
	logOSCText := parseLogOSCText()

	// KIRO_CLI_CHAT_ARGS appends extra launch flags to the per-session
	// `kiro-cli chat` command (whitespace-separated, e.g. "--v3" or
	// "--agent-engine v3 --effort high"). Empty ⇒ no extra flags. The values
	// reach chat as positional shell params (see sessionCommand), never via
	// string splicing.
	chatArgs := strings.Fields(envx.String("KIRO_CLI_CHAT_ARGS", ""))
	if len(chatArgs) > 0 {
		// Field-count-only, like the KWEB_LOG_LEVEL warning above: a compose
		// expansion mistake or a value-bearing flag could put a secret in the
		// args, so the raw values never reach the log.
		slog.Info("appending extra kiro-cli chat flags", "chat_args_count", len(chatArgs))
	}

	// Concurrent kiro-cli chat sessions (browser tabs) are uncapped, like a
	// browser: managing tabs is the user's job. Idle reaping is deliberately OFF
	// too (the engine's WithIdleReaper is left at its zero default): terminal state
	// lives only in the server's in-memory VT buffer and replays on reconnect, so a
	// session outliving its browser IS the resume feature -- close the laptop, come
	// back tomorrow. Any reaper window short enough to bound a runaway creator is
	// short enough to break that, and the create-rate limiter in routes.go is the
	// bound we chose instead. Reviewed and re-affirmed 2026-07.
	cmd := sessionCommand(cliPath, chatArgs...)

	mux := http.NewServeMux()
	var ready webhttp.Ready

	mgr, cspPolicy, err := registerRoutes(mux, &routeDeps{
		staticFS:        staticFS,
		cmd:             cmd,
		workDir:         workDir,
		ready:           &ready,
		kiroReadyMarker: kiroReadyMarker,
		logOSCText:      logOSCText,
		tools:           tools.engine,
		toolsSyncing:    tools.syncing,
		toolsState:      tools.state,
	})
	if err != nil {
		slog.Error("route registration failed; the embedded static tree is unusable",
			"error", err,
			"hint", "this is a build defect, not a runtime setting: the embedded static/index.html must carry at least one inline <script> and exactly one inline <style> block; rebuild the image (go generate ./... plus the Dockerfile static build). The container will crash-loop under its restart policy until it is rebuilt.")
		tools.close()
		os.Exit(1)
	}

	// Bind the listener before building the base context + server so the
	// listen-failure os.Exit(1) runs with no pending defer (gocritic
	// exitAfterDefer).
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		slog.Error("listen failed", "addr", addr, "error", err)
		tools.close()
		os.Exit(1)
	}

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	// buildHandler wraps mux in the middleware stack (see its doc comment for the
	// ordering rationale). webhttp.NewServer supplies the streaming-safe defaults
	// (ReadHeaderTimeout 10s, IdleTimeout 120s, Read/WriteTimeout unset) that the
	// hijacked /ws stream needs.
	// WithErrorLog keeps net/http's OWN diagnostics (temporary accept failures,
	// malformed requests) inside the slog stream this app documents as its only
	// observability channel; a nil ErrorLog routes them through the legacy log
	// package instead, with a different timestamp/level shape that Loki cannot
	// query alongside the access log. Warn, not Error: net/http's principal
	// accept-error path retries itself, so a transient listener hiccup should not
	// page.
	srv := webhttp.NewServer(
		buildHandler(mux, trustedProxies, cspPolicy, hostPolicy),
		webhttp.WithErrorLog(slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)),
	)
	// BaseContext hands every request a context that the WithPreDrain hook below
	// cancels on shutdown; see that hook's comment for why cancelling baseCtx
	// (not srv.Shutdown) is what unblocks the always-open SSE stream.
	srv.BaseContext = func(net.Listener) context.Context { return baseCtx }

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("web-terminal-kiro listening", "addr", addr, "cli_path", cliPath, "work_dir", workDir)
	ready.Set(true)

	// The pre-drain hook flips readiness false and cancels in-flight request
	// contexts before webhttp.Run drains, so /api/health reports 503 during the
	// drain window. cancelBase unblocks the always-open /api/sessions/events SSE
	// handler (it returns only on r.Context().Done(); srv.Shutdown does not
	// interrupt an active stream, so without this the drain blocks the full
	// grace window whenever a tab is open).
	if err := webhttp.Run(ctx, srv, ln, func(context.Context) { mgr.Shutdown() },
		webhttp.WithShutdownGrace(5*time.Second),
		webhttp.WithPreDrain(func(context.Context) {
			ready.Set(false)
			cancelBase()
			slog.Info("shutting down", "cause", context.Cause(ctx))
		})); err != nil {
		slog.Error("http server exited", "error", err)
		// Clear readiness before shutting sessions down: the fast-death Warn
		// in registerRoutes keys on it to distinguish app-initiated process
		// cancellation from a spontaneous early child failure (the normal
		// SIGTERM path clears it in the pre-drain hook; this fatal path must
		// do the same or a teardown would emit a false broken-install alert).
		ready.Set(false)
		mgr.Shutdown()
		tools.close()
		os.Exit(1) //nolint:gocritic // exitAfterDefer: a failed Serve must exit non-zero; the deferred stop()/cancelBase() only release signal+context state the process exit reclaims anyway.
	}
	tools.close()
}

// baseTools carries startTools's inputs (env-resolved paths + the
// catalog-refresh knobs).
type baseTools struct {
	configDir   string
	catalogPath string
	// catalogURL is the published catalog the engine refreshes from.
	catalogURL string
	// refreshInterval is the engine refresh cadence under toolbelt's
	// canonical policy (default 24h; zero = schedule disabled, manual
	// refresh stays available via the loopback tools API).
	refreshInterval time.Duration
}

// requiredToolsList is the same required-tools.txt the image build
// verifies the baked catalog against, embedded so the RUNTIME refresh
// applies the identical gate to every fetched catalog: one source of
// truth, two enforcement points. Parsed by toolbelt.ParseRequireList
// (the same format cmd/toolcatalog verify reads).
//
//go:embed required-tools.txt
var requiredToolsList string

// toolsRuntime is the running tools subsystem handed to the routes: the
// engine (nil when disabled), the session-create gate predicate, and the
// health detail. A zero value (engine nil, funcs nil) means "no tools
// surface" — bare `go run` and tests outside the container.
type toolsRuntime struct {
	engine *toolbelt.Engine
	// syncing reports whether the boot convergence pass is still
	// running; session creation is gated on it so the first kiro-cli
	// never spawns before the manifest's tools are on PATH.
	syncing func() bool
	// state is the /api/health informational detail:
	// syncing | ok | degraded.
	state func() string
}

// toolsStateDegraded is the /api/health informational tools verdict for a tools
// subsystem that FAILED (as opposed to one deliberately absent, which omits the
// field entirely). Named once because startTools reports it from several
// distinct failures — an unusable config path, a failed engine start, a
// reconcile that could not be enqueued — and a health consumer keys on the
// literal. The same reasoning names the other two verdicts of the same field:
// "ok" is written from two functions since awaitBootConvergence was extracted,
// and "syncing" is the third documented value of the enum.
const (
	// toolsStateSyncing is the verdict while the boot convergence pass runs
	// (the window in which POST /api/sessions answers 503 "tools installing").
	toolsStateSyncing = "syncing"
	// toolsStateOK is the converged verdict, reported both when the boot
	// reconcile finishes clean and when an empty manifest leaves nothing to
	// converge.
	toolsStateOK       = "ok"
	toolsStateDegraded = "degraded"
)

// degradedRuntime is the engine-less runtime a startTools failure returns:
// engine and syncing stay nil (no /api/tools mount, sessions ungated) while
// state reports degraded so the failure is visible on /api/health instead of
// looking like a deliberate disable.
func degradedRuntime() toolsRuntime {
	return toolsRuntime{state: func() string { return toolsStateDegraded }}
}

func (t *toolsRuntime) close() {
	if t.engine != nil {
		t.engine.Close()
	}
}

// startTools builds the toolbelt engine and launches the boot
// convergence pass (bind-first: the listener comes up while installs
// run; only session CREATION waits, via the syncing gate). The gate
// lifts regardless of per-tool failures — degraded-not-dead, matching
// the retired setup-tools.sh warn-and-continue posture — and the
// health detail records the verdict. After convergence an async update
// pass refreshes unpinned tools, and a boot warning nudges when no
// language server is enabled (kiro-cli scans PATH for LSPs at session
// start).
func startTools(cfg baseTools) toolsRuntime {
	// Three distinct outcomes, deliberately NOT collapsed: only a genuinely
	// ABSENT directory is the intentionally-disabled out-of-container shape
	// (zero runtime, health omits the tools field). A stat failure for any
	// other reason (permission, I/O, ELOOP) or a non-directory mounted at
	// KWEB_CONFIG_DIR is a FAILED production subsystem, so it follows the
	// same degraded-not-dead contract as a failed toolbelt.New below —
	// otherwise the operator reads a broken mount as "tools deliberately off".
	fi, statErr := os.Stat(cfg.configDir)
	switch {
	case errors.Is(statErr, fs.ErrNotExist):
		slog.Warn("tools engine disabled: config dir missing",
			"config_dir", cfg.configDir,
			"hint", "bind-mount the persistent config volume (compose.yaml) or set KWEB_CONFIG_DIR")
		return toolsRuntime{}
	case statErr != nil:
		slog.Error("tools engine failed to inspect config dir; continuing without it",
			"config_dir", cfg.configDir, "error", statErr)
		return degradedRuntime()
	case !fi.IsDir():
		slog.Error("tools engine config path is not a directory; continuing without it",
			"config_dir", cfg.configDir)
		return degradedRuntime()
	}
	refresh := &toolbelt.CatalogRefresh{
		URL:      cfg.catalogURL,
		Require:  toolbelt.ParseRequireList(requiredToolsList),
		Interval: cfg.refreshInterval,
	}
	eng, err := toolbelt.New(&toolbelt.Config{
		ConfigDir:   cfg.configDir,
		ToolsDir:    filepath.Join(cfg.configDir, "tools"),
		CatalogPath: cfg.catalogPath,
		Refresh:     refresh,
		Seed:        toolbelt.DefaultSeed(),
		System:      []string{"git", "jq", "curl", "unzip", "xz", "ssh", "tar", "bash"},
		Logger:      slog.Default(),
	})
	if err != nil {
		slog.Error("tools engine failed to start; continuing without it", "error", err)
		// Unlike the missing-config-dir path (an intentionally disabled
		// subsystem: zero runtime, no health detail), a FAILED production
		// subsystem must stay visible: report state "degraded" so
		// /api/health carries the documented informational tools field.
		// engine and syncing stay nil so sessions remain ungated.
		return degradedRuntime()
	}

	var syncing atomic.Bool
	var verdict atomic.Value // string: syncing | ok | degraded
	verdict.Store(toolsStateSyncing)
	finish := func(v string) {
		verdict.Store(v)
		syncing.Store(false)
	}

	job, rerr := eng.Reconcile(toolbelt.ReconcileMissing)
	switch {
	case rerr != nil:
		slog.Warn("tools: boot reconcile not enqueued", "error", rerr)
		finish(toolsStateDegraded)
		warnIfNoLSPEnabled(eng)
	case job == nil: // empty manifest: nothing to converge
		finish(toolsStateOK)
		warnIfNoLSPEnabled(eng)
	default:
		syncing.Store(true)
		// Mark the gated window OPENING. Without this the only boot-convergence
		// records are the terminal ones (converged / degraded), so an operator
		// looking at 503 "tools installing" answers has no line saying the gate
		// is closed, since when, or which job to correlate with toolbelt's own
		// job-timeout/job-failed warnings.
		slog.Info("tools: boot convergence started; session creation is gated until it finishes",
			"job", job.ID,
			"hint", "POST /api/sessions answers 503 \"tools installing\" (Retry-After 5) and /api/health reports tools=syncing until this converges")
		go awaitBootConvergence(eng, job.ID, finish)
	}
	// Boot catalog fetch, explicitly AFTER the reconcile enqueue: the
	// engine's schedule deliberately has no fire-on-start (an immediate
	// enqueue inside New would land ahead of the boot-critical reconcile
	// on the single-flight queue and delay the session gate). Failure is
	// routine before the publisher is reachable; keep-last-good absorbs it.
	if _, rerr := eng.RefreshCatalog(); rerr != nil {
		slog.Warn("tools: boot catalog refresh not enqueued", "error", rerr)
	}
	return toolsRuntime{
		engine:  eng,
		syncing: syncing.Load,
		state:   func() string { s, _ := verdict.Load().(string); return s },
	}
}

// awaitBootConvergence blocks on the boot reconcile job, records the verdict
// (lifting the session-create gate via finish), then runs the original
// goroutine's post-convergence tail: the freshness pass for unpinned
// entries (off the boot path — version-check network never holds the session
// gate) and the language-server nudge.
func awaitBootConvergence(eng *toolbelt.Engine, jobID string, finish func(string)) {
	final, werr := eng.Wait(context.Background(), jobID)
	switch {
	case werr != nil:
		slog.Warn("tools: boot reconcile wait failed", "error", werr)
		finish(toolsStateDegraded)
	case final.State == toolbelt.JobCancelled:
		// Cancellation is not a fault: toolbelt cancels the active job from
		// Engine.Close (the shutdown path this app takes on SIGTERM and on the
		// Serve-error path), and otherwise only on an explicit operator
		// CancelJob. Reporting it at Warn as "degraded" is the same false
		// broken-install alert the session-side WithOnProcessExit hook gates
		// away on every deploy -- and a restart during a first-boot install is
		// routine, since the install window is budgeted at 20 minutes by the
		// image HEALTHCHECK and bounded only by toolbelt's 30-minute job
		// timeout. The verdict still degrades (the pass did not converge), but
		// the RECORD stays Info. The post-convergence tail is skipped: on the
		// shutdown path Update() can only fail with "engine shutting down" and
		// the LSP nudge has no reader, and after an operator cancel neither is
		// wanted either.
		slog.Info("tools: boot convergence cancelled; not a tool failure",
			"hint", "expected during shutdown (the engine cancels the running job on Close) or after an explicit tools-API job cancel")
		finish(toolsStateDegraded)
		return
	case final.State != toolbelt.JobDone:
		slog.Warn("tools: boot reconcile finished degraded",
			"state", final.State, "error", final.Error)
		finish(toolsStateDegraded)
	default:
		slog.Info("tools: boot reconcile converged")
		finish(toolsStateOK)
	}
	if _, uerr := eng.Update(); uerr != nil {
		slog.Warn("tools: update pass not enqueued", "error", uerr)
	}
	warnIfNoLSPEnabled(eng)
}

// warnIfNoLSPEnabled logs the code-intelligence nudge when no
// language-server entry is enabled: kiro-cli scans PATH for language
// servers at session start, so a box without one silently lacks code
// intelligence. Detection uses the inventory's catalog-derived Lsp
// marker, so any enabled LSP (seeded template or hand-added) silences
// it.
func warnIfNoLSPEnabled(e *toolbelt.Engine) {
	inv, err := e.Inventory()
	if err != nil {
		// Warn, not Debug: Inventory's only failure mode is an unreadable or
		// unparseable /config/tools.json, and toolbelt returns that error
		// without logging it (Engine.Inventory), so at the default level this
		// would be the one record of a manifest an operator has just broken.
		// The nudge below is skipped either way — its ABSENCE must not be read
		// as "a language server is enabled" when the answer is really unknown.
		// Deliberately NOT the "no language servers enabled" wording: that is a
		// different event, and TestWarnIfNoLSPEnabled's inventory-failure
		// subtest counts Warns by that message.
		slog.Warn("tools: manifest unreadable; cannot tell whether a language server is enabled",
			"error", err,
			"hint", "fix /config/tools.json (schema v2 JSON); an unreadable manifest fails the tools engine outright on the next restart")
		return
	}
	for i := range inv.Tools {
		if inv.Tools[i].Lsp && !inv.Tools[i].Disabled {
			return
		}
	}
	slog.Warn("no language servers enabled; kiro code intelligence will be limited",
		"hint", `enable gopls (Go), typescript-language-server (TypeScript), or pyright (Python): set "disabled": false in /config/tools.json and restart, or use the loopback tools API`)
}

// apiNoStore marks the JSON API surface uncacheable. GET /api/sessions returns
// live session ids, and a session id is the /ws attach + resume capability
// token — the same value routes.go's LogID truncates before logging and
// WithTemplatePathsUnder keeps out of the access log. A 200 JSON body carrying no
// freshness information is heuristically cacheable under RFC 9111, so with no
// directive that response is stored by the browser's disk cache (a live token
// persisted to disk, outliving the tab) and by a caching reverse proxy — the
// README's recommended deployment shape.
//
// The engine covers its OWN session routes as of v3.2.1 (terminal's writeJSON sets
// no-store on create/list, and the SSE stream sends "no-cache, no-store"), and
// handleHealth sets no-store itself, so on those paths this middleware only
// restates what the route owner already promises — setting the same header twice
// is idempotent. The surface it still covers ALONE is /api/tools: toolbelt's
// httpapi sets no Cache-Control at all. That is the reason to keep it, not the
// sessions surface it was originally written for.
//
// Gated on the /api/ prefix so the static surface keeps kiroCacheControl's
// ETag/immutable policy untouched.
func apiNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// buildHandler wraps the route mux in web-terminal-kiro's middleware stack via
// webhttp.Chain. Chain(h, A, B, C, D) == A(B(C(D(h)))), so the first entry is
// the outermost wrapper; a request flows Logging -> Recoverer -> wsAttachLog ->
// SecurityHeaders -> apiNoStore -> host allowlist -> CrossOriginProtection ->
// mux, and the response unwinds the other way.
//
//   - Logging — webhttp's access logger. Outermost so it observes every final
//     status on logged routes, including a recovered 500 and a cross-origin
//     403. Its four policies are configured, and each justified, at the call
//     sites in the body below: the stream skips (an ADMITTED /ws upgrade or SSE
//     stream emits no access line; one rejected by the Host allowlist still
//     does, since it never becomes a stream), ProbeLogLevel for /api/health, the
//     WithTemplatePathsUnder redaction that keeps a live session id out of
//     the token-bearing /api/sessions/ subtree's lines, and WithClientIP over
//     the TRUSTED_PROXIES set (see parseTrustedProxies for the trust-nothing
//     default). The request id is minted, echoed and threaded even on the
//     skipped stream paths.
//   - Recoverer — turns a downstream panic into a logged 500 (inside the logger
//     so the access line records the 500, not the recorder's default 200).
//   - wsAttachLog — one Info record per /ws upgrade attempt, at request START
//     (see wsAttachLog: the access logger skips admitted streams and the engine
//     logs no attach, so the request that presents the session capability token
//     would otherwise be the only unrecorded request on this server). Outside
//     the host and origin gates so a rejected Host still leaves a record (the
//     origin gate cannot reject one: an RFC 6455 upgrade is a GET, and
//     CrossOriginProtection always allows the safe methods), inside Logging so
//     the request id matches the access log's.
//   - SecurityHeaders — the fleet baseline (nosniff, X-Frame-Options: DENY,
//     Referrer-Policy) plus Cross-Origin-Opener-Policy, a Permissions-Policy
//     denying the browser features a terminal never uses, and the app's
//     hash-pinned Content-Security-Policy (csp, built fail-loud by
//     buildCSPPolicy from the embedded index.html); each value's rationale and
//     its secure-context caveats are at the call site below. X-Frame-Options
//     DENY is the default and is consistent with the CSP's frame-ancestors
//     'none' — web-terminal-kiro is never embedded in a frame. Placed outside
//     CrossOriginProtection so even a rejected cross-origin request still
//     carries the headers.
//   - apiNoStore — Cache-Control: no-store on the /api/ surface (see
//     apiNoStore for the capability-token rationale). Scoped to the /api/
//     prefix so the static surface keeps kiroCacheControl's policy, and placed
//     outside the host/origin gates so even a rejected request is uncacheable.
//   - hostPolicy.Middleware — the KWEB_ALLOWED_HOSTS exact-host check
//     (webhttp.HostPolicy; see parseAllowedHosts for the DNS-rebinding
//     rationale). Placed before CrossOriginProtection because rebinding makes
//     Origin and Host agree, so the origin check alone cannot reject it; kept
//     inside SecurityHeaders so even a rejected host gets the baseline headers
//     and — on logged routes — an access-log line. An inactive policy (env
//     unset/blank) collapses
//     to a pass-through per the library's off-contract.
//   - CrossOriginProtection — the stdlib cross-origin/CSRF guard, kept
//     innermost (its long-standing position directly in front of the routes) so
//     it rejects a forged cross-origin unsafe request with 403.
func buildHandler(mux http.Handler, trustedProxies []*net.IPNet, csp string, hostPolicy *webhttp.HostPolicy) http.Handler {
	return webhttp.Chain(mux,
		webhttp.Logging(
			webhttp.WithLogger(slog.Default()),
			// SSE stays blanket-skipped: a plain GET is indistinguishable from the
			// stream itself, so there is no non-stream shape to keep. /ws HAS one —
			// the upgrade headers — so only real upgrade attempts are skipped and a
			// request that arrives WITHOUT them (the classic reverse-proxy
			// misconfiguration: no `proxy_set_header Upgrade`) is logged with the
			// 426 the engine's websocket.Accept writes.
			// Skip only a request that will actually REACH the stream handler.
			// The skip is decided before the chain runs (Logging returns early
			// without a StatusRecorder), so an unconditional skip also swallows
			// the 403 hostPolicy.Middleware writes below -- WriteError logs
			// nothing itself and the engine handler never runs -- leaving a
			// wrong-Host or DNS-rebound attempt on this unauthenticated PTY with
			// no record anywhere, the same silence this predicate exists to
			// remove for the non-upgrade 426. Allows is nil- and inactive-safe
			// (it returns true), so an unset KWEB_ALLOWED_HOSTS keeps today's
			// behavior exactly.
			webhttp.WithSkipFunc(func(r *http.Request) bool {
				stream := r.URL.Path == terminal.SessionEventsPath ||
					(r.URL.Path == terminal.WSPath && isWebSocketUpgrade(r))
				return stream && hostPolicy.Allows(r)
			}),
			// /api/health is probed every 30s (Docker HEALTHCHECK curl +
			// Gatus); the fleet-standard ProbeLogLevel keeps healthy probes
			// at Debug (out of the shipped stream, visible under
			// KWEB_LOG_LEVEL=debug) while a FAILING probe — the readiness
			// 503 when kiro-cli is broken — surfaces at Warn/Error with its
			// status and request id. The streams above stay fully skipped:
			// one open-to-close line per WebSocket/SSE would be misleading
			// by shape, not merely noisy.
			webhttp.ProbeLogLevel(healthPath),
			// The session-id-bearing subtree logs the route template the mux
			// actually matched instead of the raw path, so a live capability
			// token never reaches the access log. The prefix comes from the
			// engine -- the package that DECLARES those routes and already
			// treats the id as a credential (terminal.LogID) -- rather than a
			// literal here, and the template comes from r.Pattern, so a route
			// the engine adds in a future version logs correctly with no change
			// in this app. This replaced a local transform that re-derived the
			// engine's route table by string-parsing the path: it was a second
			// copy of upstream knowledge with nothing keeping the two in step,
			// and a new engine subroute would have silently logged every request
			// to it as "(path-redaction-failed)", losing method/status/duration/
			// client_ip attribution with no test or build failing.
			webhttp.WithTemplatePathsUnder(terminal.SessionsSubtreePath),
			webhttp.WithClientIP(trustedProxies...),
		),
		webhttp.Recoverer(webhttp.WithRecoverLogger(slog.Default())),
		wsAttachLog(trustedProxies),
		webhttp.SecurityHeaders(
			webhttp.WithCSP(csp),
			// Cross-Origin-Opener-Policy: same-origin severs window.opener for
			// any cross-origin page a session opens. The terminal renders
			// clickable OSC 8 hyperlinks and server-stamped autolinks straight
			// out of untrusted child output, so a session can be induced to
			// open an attacker page; the vendored UI already passes
			// rel="noopener noreferrer" on every anchor and window.open, and
			// this header makes that tabnabbing guarantee independent of the
			// Renovate-bumped web-terminal-ui/engine pins. Referrer-Policy is
			// tightened from webhttp's default (strict-origin-when-cross-origin,
			// which still discloses this server's origin) to same-origin for the
			// SAME reason and against the same pins: the `rel="noreferrer"` half
			// of that anchor contract is what suppresses the Referer today, so a
			// UI bump that drops the attribute would otherwise leak the
			// terminal's internal hostname to whatever attacker-chosen page the
			// link points at. Nothing here reads Referer, so the tightening is
			// inert for the app. same-origin rather than no-referrer to match
			// what vibekit already pins (webhttp's default is what the two
			// non-terminal consumers keep) — one fleet value, not a fourth.
			// Permissions-Policy denies the browser features a terminal never
			// uses (same values subflux ships). COOP is secure-context gated, so
			// it is inert on a non-secure origin (plain-HTTP LAN bind) and active
			// on localhost / behind a TLS-terminating proxy — the README's
			// recommended deployment; the three features Permissions-Policy names
			// are themselves secure-context-only, so denying them there is moot
			// too. Referrer-Policy is NOT gated: a plain-HTTP origin honors it,
			// which is exactly the bind where suppressing the Referer matters
			// most, since that is where the internal hostname would otherwise
			// leak.
			webhttp.WithCOOP("same-origin"),
			webhttp.WithReferrerPolicy("same-origin"),
			webhttp.WithPermissionsPolicy("camera=(), microphone=(), geolocation=()"),
		),
		apiNoStore,
		hostPolicy.Middleware(),
		http.NewCrossOriginProtection().Handler,
	)
}

// wsAttachMsg is the message of the /ws attach record wsAttachLog emits. A
// const so a test can pin the exact wording without a second copy of the
// literal (goconst) drifting from this one.
const wsAttachMsg = "terminal attach attempt"

// wsAttachLog records one line per /ws UPGRADE attempt. The access logger
// deliberately skips those (a hijacked stream would log a bogus 200 with an
// hours-long duration), and neither the engine's WebSocketHandler nor the
// per-session Handler logs an attach — the engine's "process started" line is
// emitted at CREATE time by the eager start, not on attach. So without this the
// request that PRESENTS the session capability token is the only request to this
// server with no record at all: an id leaked through a fronting proxy's access
// log can be replayed with nothing to show an operator afterwards (CWE-778).
// Logged at request start, so the line exists for a rejected Host or an
// unknown-session close too (an origin rejection is not reachable here: the
// upgrade is a GET and CrossOriginProtection always allows the safe methods);
// the id is LogID-truncated, the same
// treatment the session logger and the engine give it. The session query param
// is attacker-chosen (LogID only truncates), so it stays an attribute value the
// slog handler quotes and is never interpolated into the message.
func wsAttachLog(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == terminal.WSPath && isWebSocketUpgrade(r) {
				slog.Info(wsAttachMsg,
					"session", terminal.LogID(r.URL.Query().Get("session")),
					"client_ip", webhttp.ClientIP(r, trustedProxies...),
					"request_id", webhttp.RequestIDFromContext(r.Context()))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isWebSocketUpgrade reports whether r carries the RFC 6455 upgrade signal
// (Upgrade: websocket plus the Upgrade connection option). It is the access
// log's "this is a long-lived stream" test for /ws: a real upgrade is skipped
// (one open-to-close line would report a bogus 200 with an hours-long
// duration, since the handler hijacks the connection), while a request that
// reaches /ws WITHOUT the upgrade headers is a short request whose refusal
// deserves an access line — today it produces NO record anywhere, in either
// the app or the engine, so a proxy that strips the upgrade headers presents
// as a page that loads normally, a UI stuck reconnecting, and a silent log.
func isWebSocketUpgrade(r *http.Request) bool {
	return headerHasToken(r, "Upgrade", "websocket") &&
		headerHasToken(r, "Connection", "upgrade")
}

// headerHasToken reports whether any field value of the named header carries
// token as a comma-separated element, case-insensitively. Both headers are
// comma-lists that may also arrive as repeated field lines (RFC 7230 3.2.2),
// and the engine's websocket.Accept matches them exactly this way — so this
// predicate must too, or the access-log skip and the actual upgrade disagree.
func headerHasToken(r *http.Request, name, token string) bool {
	for _, v := range r.Header.Values(name) {
		for opt := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(opt), token) {
				return true
			}
		}
	}
	return false
}
