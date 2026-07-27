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
	if fi, err := os.Stat(cfg.configDir); err != nil || !fi.IsDir() {
		slog.Warn("tools engine disabled: config dir missing",
			"config_dir", cfg.configDir,
			"hint", "bind-mount the persistent config volume (compose.yaml) or set KWEB_CONFIG_DIR")
		return toolsRuntime{}
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
		return toolsRuntime{state: func() string { return "degraded" }}
	}

	var syncing atomic.Bool
	var verdict atomic.Value // string: syncing | ok | degraded
	verdict.Store("syncing")
	finish := func(v string) {
		verdict.Store(v)
		syncing.Store(false)
	}

	job, rerr := eng.Reconcile(toolbelt.ReconcileMissing)
	switch {
	case rerr != nil:
		slog.Warn("tools: boot reconcile not enqueued", "error", rerr)
		finish("degraded")
		warnIfNoLSPEnabled(eng)
	case job == nil: // empty manifest: nothing to converge
		finish("ok")
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
		finish("degraded")
	case final.State != toolbelt.JobDone:
		slog.Warn("tools: boot reconcile finished degraded",
			"state", final.State, "error", final.Error)
		finish("degraded")
	default:
		slog.Info("tools: boot reconcile converged")
		finish("ok")
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
		slog.Debug("tools: inventory read failed; skipping the language-server nudge", "error", err)
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
// WithPathFunc keeps out of the access log. Neither the engine's REST handler
// nor webhttp's JSON helpers set Cache-Control, so today that response is
// stored by the browser's disk cache (a live token persisted to disk,
// outliving the tab) and is heuristically cacheable by a caching reverse proxy
// — the README's recommended deployment shape. Gated on the /api/ prefix so
// the static surface keeps kiroCacheControl's ETag/immutable policy untouched;
// the SSE handler sets its own Cache-Control: no-cache downstream, which wins.
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
// the outermost wrapper; a request flows Logging -> Recoverer ->
// SecurityHeaders -> apiNoStore -> host allowlist -> CrossOriginProtection ->
// mux, and the response unwinds the other way.
//
//   - Logging — webhttp's access logger. Outermost so it observes every final
//     status on logged routes, including a recovered 500 and a cross-origin
//     403 — subject to the skip list below (/ws and the SSE stream emit no
//     access lines), the ProbeLogLevel policy (/api/health logs at Debug
//     when healthy, Warn/Error when failing), and the WithPathFunc redaction
//     (the token-bearing /api/sessions/ subtree logs its route template,
//     never a session id). WithClientIP is
//     passed the TRUSTED_PROXIES set (parseTrustedProxies) as the `client_ip`
//     field's trusted-proxy ranges: unset/empty ⇒ trust nothing, so `client_ip`
//     is the unspoofable socket peer and X-Forwarded-For is ignored — the
//     spoof-safe default for a directly-exposed deployment. Behind a reverse
//     proxy, TRUSTED_PROXIES names the proxy CIDR(s) so `client_ip` resolves to
//     the real client from a trusted XFF instead of the proxy's own address.
//     This replaces the former app-side api.RequestLogger, whose only reason to
//     exist was the `remote` (host:port) field; `client_ip` (host only, no port)
//     is its successor. Skips the long-lived streams (/ws and the
//     /api/sessions/events SSE) so neither emits a misleading open-time access
//     line; the request id is still minted, echoed, and threaded on those paths.
//     /api/health is NOT skipped: ProbeLogLevel keeps the every-30s Docker
//     HEALTHCHECK probe's healthy 2xx at Debug (out of the shipped stream)
//     and promotes a failing probe to Warn/Error; the token-bearing
//     /api/sessions/ subtree stays logged with its recorded path rewritten
//     to the route template via WithPathFunc below.
//   - Recoverer — turns a downstream panic into a logged 500 (inside the logger
//     so the access line records the 500, not the recorder's default 200).
//   - SecurityHeaders — the fleet baseline (nosniff, X-Frame-Options: DENY,
//     Referrer-Policy) plus Cross-Origin-Opener-Policy: same-origin (severs
//     window.opener for any cross-origin page a session opens from an OSC 8 /
//     autolinked URL taken from untrusted child output, making the vendored
//     UI's rel="noopener noreferrer" a defence-in-depth pair rather than the
//     only tabnabbing guard), a Permissions-Policy denying the browser
//     features a terminal never uses (camera, microphone, geolocation), and
//     the app's hash-pinned Content-Security-Policy
//     (csp, built fail-loud by buildCSPPolicy from the embedded index.html —
//     the same script-src sha256 pinning web-terminal-server ships, closing
//     the family-drift gap where this app served the same embedded-static +
//     inline-importmap pattern with no CSP at all). X-Frame-Options DENY is
//     the default and is consistent with the CSP's frame-ancestors 'none' —
//     web-terminal-kiro is never embedded in a frame. Placed outside
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
			webhttp.WithSkipPaths(terminal.SessionEventsPath),
			webhttp.WithSkipFunc(func(r *http.Request) bool {
				return r.URL.Path == terminal.WSPath && isWebSocketUpgrade(r)
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
			// The session-id-bearing subtree logs its token-free route
			// template instead of the raw path; see redactSessionPath.
			webhttp.WithPathFunc(redactSessionPath),
			webhttp.WithClientIP(trustedProxies...),
		),
		webhttp.Recoverer(webhttp.WithRecoverLogger(slog.Default())),
		webhttp.SecurityHeaders(
			webhttp.WithCSP(csp),
			// Cross-Origin-Opener-Policy: same-origin severs window.opener for
			// any cross-origin page a session opens. The terminal renders
			// clickable OSC 8 hyperlinks and server-stamped autolinks straight
			// out of untrusted child output, so a session can be induced to
			// open an attacker page; the vendored UI already passes
			// rel="noopener noreferrer" on every anchor and window.open, and
			// this header makes that tabnabbing guarantee independent of the
			// Renovate-bumped web-terminal-ui/engine pins. Permissions-Policy
			// denies the browser features a terminal never uses (same values
			// subflux ships). Both are ignored on a non-secure origin
			// (plain-HTTP LAN bind) and active on localhost / behind a
			// TLS-terminating proxy — the README's recommended deployment.
			webhttp.WithCOOP("same-origin"),
			webhttp.WithPermissionsPolicy("camera=(), microphone=(), geolocation=()"),
		),
		apiNoStore,
		hostPolicy.Middleware(),
		http.NewCrossOriginProtection().Handler,
	)
}

// redactSessionPath is the access log's recorded-path policy for the
// session-id-bearing subtree — DELETE /api/sessions/{id}, PUT
// /api/sessions/{id}/title, and PUT + DELETE /api/sessions/{id}/pinned-title
// (the engine's rename routes, which the vendored UI's tab rename calls) —
// each of which embeds the FULL session id (the /ws attach/resume capability
// token that routes.go truncates to safeID before logging). Their access lines
// are KEPT, with the recorded path rewritten to the token-free route template,
// so operators keep method/status/duration/request_id/client_ip for title
// updates, renames, deletes, and rejected subtree requests without a live token
// ever reaching log-read consumers.
//
// Matching is EXACT-SHAPE, not suffix-based: only a single id segment, or an id
// segment followed by exactly "title" or "pinned-title", maps to a template.
// Every template must name a route the server actually serves, or the line
// misreports which call was made — a suffix test would report a malformed
// /api/sessions/{id}/extra/title as the legitimate title route and every other
// malformed subtree path as the plain {id} route, hiding route probing from
// access telemetry and pointing an operator diagnosing a 404 at the wrong
// handler. Anything that is not one of the served shapes returns the empty
// string, which webhttp records fail-closed as its
// "(path-redaction-failed)" placeholder — never the raw path, so the token in
// a malformed request is not leaked either.
//
// The exact-path create/list lines (POST/GET /api/sessions) miss the prefix and
// log unchanged; the SSE stream shares the prefix but carries no id, so it maps
// to itself (it is skip-listed in buildHandler, so no line is emitted for it
// either way).
func redactSessionPath(r *http.Request) string {
	p := r.URL.Path
	if !strings.HasPrefix(p, terminal.SessionsSubtreePath) {
		return p
	}
	if p == terminal.SessionEventsPath {
		return p
	}
	parts := strings.Split(strings.TrimPrefix(p, terminal.SessionsSubtreePath), "/")
	switch {
	case len(parts) == 1 && parts[0] != "":
		return terminal.SessionsSubtreePath + "{id}"
	case len(parts) == 2 && parts[0] != "" && parts[1] == "title":
		return terminal.SessionsSubtreePath + "{id}/title"
	case len(parts) == 2 && parts[0] != "" && parts[1] == "pinned-title":
		return terminal.SessionsSubtreePath + "{id}/pinned-title"
	default:
		return ""
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
