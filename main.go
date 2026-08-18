// Package main serves Web Terminal for Kiro, a browser terminal around kiro-cli.
// Each created session launches one `kiro-cli chat` process in a PTY; WebSocket
// connections attach and reconnect to that session through web-terminal-engine.
package main

// Builds the JS bundle for `go:embed static`. The CSS bundle is concatenated by
// the Dockerfile instead, so no go:generate step covers it.
//
//go:generate static-src/node_modules/.bin/tsc --project static-src/tsconfig.json

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"fmt"
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

	"github.com/cplieger/envx/v2"
	"github.com/cplieger/pinstall/v3"
	"github.com/cplieger/pinstall/v3/kirocli"
	"github.com/cplieger/slogx"
	"github.com/cplieger/toolbelt/v3"
	"github.com/cplieger/web-terminal-engine/v5/terminal"
	"github.com/cplieger/webhttp/v2"
)

// staticFS holds the served asset tree. It embeds the DIRECTORY rather than a file
// list because app.js and style.css are gitignored build outputs and go:embed fails
// on a pattern matching nothing, so an allowlist would break `go vet ./...` on a
// fresh checkout. Purity is enforced outside the directive instead: add a pattern to
// BOTH .dockerignore and .gitignore before adding a step that writes into static/.
//
//go:embed static
var staticFS embed.FS

// parseTrustedProxies reads a comma-separated list of CIDRs / bare IPs from
// TRUSTED_PROXIES into the trusted-proxy set the access log's client-IP resolver
// consults. Intentionally LENIENT — a malformed entry is dropped and the valid
// subset used, so one typo cannot disable proxy awareness entirely — and it never
// fails open: unset yields nil, "trust nothing", which logs the unspoofable socket
// peer.
func parseTrustedProxies() []*net.IPNet {
	const key = "TRUSTED_PROXIES"
	v := envx.String(key)
	if v == "" {
		return nil
	}
	nets, invalid := webhttp.ParseCIDRs(strings.Split(v, ","))
	if len(invalid) > 0 {
		// Count-only: a compose expansion mistake could put a credential in an
		// entry, so the rejected raw values never reach the log.
		slog.Warn("ignoring malformed "+key+" entries; using the valid proxy set",
			"invalid_count", len(invalid),
			"hint", "each entry must be a CIDR (e.g. 10.0.0.0/8) or a bare IP (e.g. 192.168.1.5)")
	}
	// A default route (0.0.0.0/0 or ::/0) parses cleanly but can never describe a proxy
	// SET, and it breaks client-IP resolution both ways: a same-family chain exhausts the
	// trusted-hop walk and falls back to the socket peer (the proxy — exactly what setting
	// this var was meant to stop logging), while an entry of the OTHER address family is
	// never skipped, so a forged X-Forwarded-For becomes the logged client_ip. Warn by
	// PREFIX LENGTH only, never the raw entry.
	for _, n := range nets {
		if ones, _ := n.Mask.Size(); ones == 0 {
			slog.Warn(key+" contains a default route (0.0.0.0/0 or ::/0); every peer counts as a proxy, so client_ip logs the proxy itself and a forged X-Forwarded-For of the other address family can choose the logged client",
				"hint", "list only the reverse proxy's own address(es), e.g. 10.0.0.0/8 or 192.0.2.10; leave "+key+" unset to log the unspoofable socket peer")
			break
		}
	}
	return nets
}

// parseAllowedHosts reads the comma-separated ALLOWED_HOSTS list of exact hostnames
// / IPs this server answers for into a webhttp.HostPolicy. It closes the DNS-rebinding
// hole a same-origin check alone leaves open: rebinding makes Origin and Host AGREE, so
// CrossOriginProtection admits it (CWE-346). Unset yields an INACTIVE policy, the
// backward-compatible default main warns about; entries that are ALL malformed yield an
// active EMPTY policy — deny-all but the loopback carve-out, warned by name since every
// request would otherwise 403 unexplained.
func parseAllowedHosts() *webhttp.HostPolicy {
	const key = "ALLOWED_HOSTS"
	policy, invalid := webhttp.ParseHostList(strings.Split(envx.String(key), ","),
		webhttp.WithLoopbackExempt(true),
		webhttp.WithHostAllowlistError("host_not_allowed",
			"host not allowed; add it to ALLOWED_HOSTS to serve this hostname"))
	if len(invalid) > 0 {
		// Count-only, like parseTrustedProxies.
		slog.Warn("dropping malformed "+key+" entries; they cannot match any browser-sent Host",
			"invalid_count", len(invalid),
			"hint", "use bare hostnames or IPs only (no scheme, path, or CIDR), e.g. localhost,192.168.1.5,webterm.example.com; a lone port like :9848 belongs in LISTEN_ADDR")
	}
	if policy.Active() && policy.Size() == 0 {
		slog.Warn(key+" has no usable entries; rejecting every non-loopback request (fail closed)",
			"hint", "fix the malformed entries in "+key+" to restore browser access")
	}
	return policy
}

// resolveScrollback reads the retained-history depth from the env var the ENGINE
// owns (terminal.ScrollbackEnvVar), returning nil when the operator set nothing so
// the session factory omits the option and the engine's own default applies. The
// variable is shared with web-terminal-server and vibekit, so its name and its
// clamping policy live in the engine. This app owns only the failure posture: warn
// by NAME and fall back, because retained history is not a safety property.
func resolveScrollback() *int {
	// The error is deliberately NOT logged — it wraps *strconv.NumError, which
	// carries the rejected value.
	n, ok, err := envx.IntStrict(terminal.ScrollbackEnvVar)
	if err != nil {
		slog.Warn("ignoring a malformed retained-history depth; using the engine default",
			"env", terminal.ScrollbackEnvVar, "default_lines", terminal.DefaultScrollbackCapacity)
		return nil
	}
	if !ok {
		return nil
	}
	capacity, reason := terminal.ClampScrollbackCapacity(n)
	if reason != "" {
		slog.Warn(reason)
	}
	return &capacity
}

// catalogRefreshKey is the env var parseCatalogRefresh interprets and names in its
// by-name-only warning. main() reads the value under the same name from here, so
// the key has one home.
const catalogRefreshKey = "TOOL_CATALOG_REFRESH"

// parseCatalogRefresh reads TOOL_CATALOG_REFRESH and delegates to toolbelt's
// canonical parser — but only for values that parser ACCEPTS. toolbelt calls
// scheduler.ParseInterval without WithRedactedValue, so its fallback warning
// echoes the RAW value, and a compose expansion mistake could put a credential on
// this key. A value the library would reject is warned about HERE by name only and
// replaced with "" so the library applies its documented default silently.
// Accepted values pass through untouched, so the disable words and the clamp stay
// toolbelt's policy alone.
func parseCatalogRefresh(raw string) time.Duration {
	trimmed := strings.TrimSpace(raw)
	switch strings.ToLower(trimmed) {
	case "", "off", "disabled":
	default:
		// Parse the TRIMMED but NOT lowercased value: scheduler.ParseInterval
		// lowercases only for the off/disabled sentinels and hands the trimmed
		// string to time.ParseDuration, whose units are case-sensitive. Gating on
		// a lowercased copy would pass "24H" through to the library's
		// value-echoing warning.
		if d, err := time.ParseDuration(trimmed); err != nil || d < 0 {
			slog.Warn("unusable "+catalogRefreshKey+"; using the built-in catalog refresh cadence",
				"hint", `use a Go duration (e.g. 24h, 90m) or "off" to disable the schedule`)
			raw = ""
		}
	}
	return toolbelt.ParseCatalogRefresh(toolbelt.RefreshEnv(raw), catalogRefreshKey)
}

// parseLogOSCText reads the LOG_OSC_TEXT knob (default false), reporting whether
// an unrecognized OSC 9 notification's TEXT may be logged. That text is arbitrary
// child output — any program in the terminal can emit `ESC ] 9 ; <text>` — so it can
// carry a token or a device code; hence the content-free default.
//
// envx.BoolStrict, NOT envx.Bool, and that is the confidentiality property rather
// than a style choice: Bool's malformed path Warns with the RAW value (CWE-532), while
// BoolStrict shares its parser but logs nothing.
func parseLogOSCText() bool {
	const key = "LOG_OSC_TEXT"
	logOSCText, _, err := envx.BoolStrict(key)
	if err != nil {
		// Fail closed, stated rather than inherited from BoolStrict's zero value.
		// err itself is never logged.
		logOSCText = false
		slog.Warn("unparseable "+key+"; keeping notification text out of the log (the default)",
			"hint", "use true or false")
	}
	if logOSCText {
		slog.Warn(key+" is on: terminal notification text is logged at debug level and may contain secrets (a token, a device code, a tokenised URL) emitted by any program running in the terminal",
			"hint", "leave it off outside an active diagnostic session; the default records a content-free fingerprint that still distinguishes kiro-cli wording drift")
	}
	return logOSCText
}

// parseTrustedInstallUIDs decodes TRUSTED_INSTALL_UIDS, a comma-separated list of
// numeric uids, into the identities pinstall may find with write access to the kiro-cli
// installation tree without treating custody as broken. EMPTY BY DEFAULT, and the
// default is the point: setting it asserts what the library's field doc requires — every
// uid listed is already at least as privileged as this server — because one that is NOT
// can escalate through a binary this app installs and then executes. A malformed entry
// is DROPPED, which is fail-closed: a uid that never lands keeps the check enforcing.
func parseTrustedInstallUIDs() []int {
	const key = "TRUSTED_INSTALL_UIDS"
	uids, rejected := pinstall.ParseIdentities(envx.String(key))
	if rejected > 0 {
		slog.Warn("dropping unusable "+key+" entries; the kiro-cli install keeps enforcing custody against those identities",
			"invalid_count", rejected,
			"hint", "each entry is a single numeric uid greater than 0 (e.g. 1000,1001); root is trusted already, and every identity listed must be at least as privileged as this server")
	}
	return uids
}

// sessionCommand builds the per-session PTY command: `kiro-cli chat` behind a sign-in
// guard that runs `kiro-cli login --use-device-flow` in the terminal first when `whoami`
// exits non-zero. The device flow is the only sign-in that works here: kiro-cli's
// default flow opens a browser on THIS host, a headless container.
//
// The script never interpolates cliPath or chatArgs — cliPath is $0 and chatArgs ride
// the positional params — so shell metacharacters cannot inject into it. Called once per
// SESSION, because cliPath is the manager's ACTIVE version directory.
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

// loopbackHint renders the address an in-container caller uses to reach this
// server, for the loopback surfaces' refusal messages. Derived from LISTEN_ADDR so a
// deployment that moved the port is not told to curl the default one — the 403 is
// the whole of what a refused caller is told. A port-less or malformed addr
// degrades to the bare host rather than to a broken URL.
func loopbackHint(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return "localhost:" + port
	}
	return "localhost"
}

// main is the process's ONLY exit site. Everything else lives in run, which
// reports failure by returning an error, so no startup branch can exit past a
// pending defer and skip the subsystem teardown.
func main() {
	if err := run(); err != nil {
		// Rendered once, here: the failure branches in run carry their operator hint
		// inside the returned error, so a startup failure produces exactly one ERROR
		// line. stage is what a log query keys on, and a stable VALUE beats prose names:
		// prose is rewritten by any edit to the message, a stage token is not.
		slog.Error("web-terminal-kiro exited with error", "stage", stageOf(err), "error", err)
		os.Exit(1)
	}
}

// shutdownGrace bounds the whole graceful stop: the drain, then the session
// teardown inside whatever the drain left. The engine's own budget guidance is
// larger than this (it bounds a stubborn child's reap at 5s, and the containment
// and marker ladders each spend several grace windows on top), so a stop with
// many live tabs can overrun it. That is the deliberate choice: this server would
// rather log the overrun than hold the container past its stop timeout.
const shutdownGrace = 5 * time.Second

// The startup stages a failure can be attributed to. Values, not messages: these
// are the strings an operator's log query or alert rule matches, so changing one
// is a breaking change to the log surface.
const (
	stageWorkDir = "work_dir" // the /workspace mount is absent or not a directory
	stageStatic  = "static"   // the embedded static tree is unusable
	stageListen  = "listen"   // the listener could not bind
	stageServe   = "serve"    // the HTTP server exited with an error
	// stageUnknown is emitted for a failure nobody attributed, so the field is
	// ALWAYS present: an absent field would make a query distinguish "no stage"
	// from "no match", and a new failure path that forgets to attribute itself
	// shows up as an explicit unknown rather than as silence.
	stageUnknown = "unknown"
)

// stageError attributes a startup failure to a stage without changing what the
// error says. It carries no message of its own precisely so the wrapped text stays
// the operator's hint, unchanged.
type stageError struct {
	err   error
	stage string
}

func (e *stageError) Error() string { return e.err.Error() }

func (e *stageError) Unwrap() error { return e.err }

// atStage attributes err to a stage.
func atStage(stage string, err error) error {
	return &stageError{stage: stage, err: err}
}

// stageOf reports the stage a failure was attributed to, or stageUnknown.
func stageOf(err error) string {
	var se *stageError
	if errors.As(err, &se) {
		return se.stage
	}
	return stageUnknown
}

// setupLogging installs the slog handler. Parse the level BEFORE Setup so the
// handler installs at the configured level; warn AFTER Setup so the warning emits
// through the configured handler (the slogx contract).
func setupLogging() {
	logLevel, ok := slogx.ParseLevel(envx.String("LOG_LEVEL"), slog.LevelInfo)
	slogx.Setup(slogx.Options{Level: logLevel})
	if !ok {
		// Field-name-only: a compose expansion mistake could put a secret in the
		// value, so the raw string never reaches the log.
		slog.Warn("unparseable LOG_LEVEL; using the info default",
			"hint", "use debug, info, warn, or error")
	}
}

// checkWorkDir refuses a work directory in any of three distinct shapes: absent,
// present but unstattable, or not a directory. They are deliberately NOT collapsed
// — only an ABSENT directory is a missing-mount mistake, and the other two would
// send the operator to add a mount that is already there — so each returned error
// carries its own remedy.
func checkWorkDir(workDir string) error {
	fi, err := os.Stat(workDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return atStage(stageWorkDir, fmt.Errorf("work directory %s is missing (bind-mount a host directory to /workspace in compose.yaml): %w", workDir, err))
	case err != nil:
		// Present but unstattable: EACCES on a parent, ELOOP on a symlinked
		// target, an EIO from the backing volume. The mount IS configured, so the
		// missing-mount remedy above would send the operator to add one that is
		// already there.
		return atStage(stageWorkDir, fmt.Errorf("work directory %s could not be inspected: the mount exists but is unreadable to this process; check the bind source's permissions and its parent directories: %w", workDir, err))
	case !fi.IsDir():
		return atStage(stageWorkDir, fmt.Errorf("work directory %s is not a directory: the mount target is a file or device, not a directory; bind-mount a host DIRECTORY to /workspace in compose.yaml", workDir))
	}
	return nil
}

// run is the composition root: it wires the tools engine, the kiro-cli install
// manager, the route table and the HTTP server, then blocks on the signal-driven
// lifecycle. Keeping the body here rather than in main is what lets the deferred
// teardown run on every failure path.
func run() error {
	setupLogging()

	// The shutdown context every long-lived goroutine in run() keys its exit
	// off: the tools convergence watcher and the boot-convergence waiter (both
	// started inside startTools), the session-title poller, and the request
	// contexts the server derives via BaseContext. The pre-drain hook cancels
	// it. Created HERE rather than beside the server because startTools runs
	// first, and a goroutine handed context.Background() for want of a shutdown
	// signal has an exit path that can never fire (go-rulebook C20).
	//
	// Not every context in this process: startKiroCLI's own root is separate,
	// and readSmallFile's callers thread the poller's context, not this one
	// directly.
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	addr := cmp.Or(envx.String("LISTEN_ADDR"), ":9848")
	// Warn for any bind reachable beyond loopback: a client that can reach this
	// port gets an UNAUTHENTICATED kiro-cli PTY. Only a definite exposure warns; an
	// unparseable addr will fail at Listen with its own error.
	if webhttp.ClassifyBind(addr) == webhttp.BindExposed {
		slog.Warn("serving an UNAUTHENTICATED kiro-cli shell on a non-loopback address; front it with an authenticating reverse proxy",
			"addr", addr,
			"hint", "any client that can reach this port gets a kiro-cli PTY with filesystem access to /workspace and the /config home (auth tokens, ssh keys, gitconfig)")
	}
	workDir := cmp.Or(envx.String("WORK_DIR"), "/workspace")
	if err := checkWorkDir(workDir); err != nil {
		return err
	}
	scrollback := resolveScrollback()

	// ONE read for the ONE tools root, handed to both co-owners below: the toolbelt
	// engine (its ConfigDir and ToolsDir) and the kiro-cli install manager (its
	// install Root). A SECOND derivation is what previously split toolbelt's
	// manifest from the tree it describes. Empty outside the container, where
	// startTools falls back to <configDir>/tools.
	kiroToolsDir := envx.String("KIRO_CLI_TOOLS_DIR")

	tools := startTools(baseCtx, baseTools{
		configDir:   configMountDir,
		toolsDir:    kiroToolsDir,
		catalogPath: cmp.Or(envx.String("TOOL_CATALOG_PATH"), "/app/tool-catalog.json"),
		// The baked catalog above is only the first-boot/offline fallback; the
		// engine fetches the published catalog at boot and every
		// TOOL_CATALOG_REFRESH, re-verifying the embedded required-tools list
		// before a swap, and the last good catalog stands on any failure.
		catalogURL:      cmp.Or(envx.String("TOOL_CATALOG_URL"), toolbelt.DefaultCatalogURL),
		refreshInterval: parseCatalogRefresh(envx.String(catalogRefreshKey)),
	})

	trustedProxies := parseTrustedProxies()

	// Unset ⇒ inactive policy ⇒ permissive (backward compatible), but that leaves
	// rebinding open even on a loopback/private bind — the attack rides the
	// victim's browser, so the README's "keep it loopback" mitigation does not
	// cover it. Warn.
	hostPolicy := parseAllowedHosts()
	if !hostPolicy.Active() {
		slog.Warn("ALLOWED_HOSTS is unset or blank; any Host header is accepted, leaving DNS rebinding open even on loopback/private binds",
			"hint", "set ALLOWED_HOSTS to the exact hostnames/IPs you browse to (e.g. localhost,192.168.1.5,webterm.example.com)")
	}

	logOSCText := parseLogOSCText()

	// KIRO_CLI_CHAT_ARGS appends extra launch flags to the per-session `kiro-cli
	// chat` command (whitespace-separated, e.g. "--v3"). The values reach chat as
	// positional shell params (see sessionCommand), never via string splicing.
	chatArgs := strings.Fields(envx.String("KIRO_CLI_CHAT_ARGS"))
	if len(chatArgs) > 0 {
		// Field-count-only: a compose expansion mistake or a value-bearing flag
		// could put a secret in the args.
		slog.Info("appending extra kiro-cli chat flags", "chat_args_count", len(chatArgs))
	}

	// Concurrent sessions are uncapped, like browser tabs, and idle reaping is deliberately
	// OFF: terminal state lives only in the in-memory VT buffer and replays on reconnect,
	// so a session outliving its browser IS the resume feature. Any reaper window short
	// enough to bound a runaway creator is short enough to break that; the create-rate
	// limiter in routes.go is the bound chosen instead.
	tainted := os.Getenv("KIRO_CLI_TOOLS_TAINTED") == "1"
	kiro := startKiroCLI(&baseKiro{
		version:            envx.String("KIRO_CLI_VERSION"),
		sha256:             envx.String("KIRO_CLI_SHA256"),
		sha256ARM64:        envx.String("KIRO_CLI_SHA256_ARM64"),
		toolsDir:           kiroToolsDir,
		tainted:            tainted,
		chatArgs:           chatArgs,
		trustedInstallUIDs: parseTrustedInstallUIDs(),
	})

	mux := http.NewServeMux()
	var ready webhttp.Ready

	// Tab names come from kiro-cli's own session record. The state root is
	// container-local on purpose: a mapping is only meaningful for a LIVE tab, and
	// this app persists no session state, so nothing here should outlive the
	// container. A refused directory is a warn, and it is AUTHORITATIVE for both
	// consumers: no tab gets the title variables, the poller never starts, and the
	// engine's automatic ladder names every tab.
	titles := newSessionTitleSync(titleStateRoot, envx.String("HOME"))
	sessionTitleEnv := enableSessionTitles(titles)

	// The subsystem teardown, named once and deferred once, so a third subsystem is
	// added in one place. Every return below runs it.
	defer func() {
		kiro.stop()
		tools.close()
	}()

	// The static tree's two derivatives, assembled together and fail-loud, then
	// handed to their own consumers: the serving handler to the route table, the
	// hash-pinned CSP to buildHandler's SecurityHeaders layer. The root builds them
	// because it is the only place that consumes both.
	staticSrv, cspPolicy, err := buildStaticSurface(staticFS)
	if err != nil {
		return atStage(stageStatic, fmt.Errorf("the embedded static tree is unusable: %w"+
			" (this is a build defect, not a runtime setting: the embedded static/index.html must carry at least one inline <script> and exactly one inline <style> block;"+
			" rebuild the image — go generate ./... plus the Dockerfile static build. The container will crash-loop under its restart policy until it is rebuilt.)", err))
	}

	// Orphan reaping is the CONTAINER INIT's job (`init: true`, tini at pid 1), so no
	// reaper is installed here — and the engine's terminal.StartZombieReaper is not
	// merely redundant, it is INCOMPATIBLE: it sets PR_SET_CHILD_SUBREAPER, which
	// re-parents orphans onto this server even behind an init shim, and its sweep
	// exempts only pids in the engine's own spawn registry. This app also spawns
	// through os/exec outside that registry, so the sweep can win the race for one of
	// THOSE exit statuses and make successful work report as failed. Measured without
	// an init on borgcube 2026-08-09: 17,323 zombies against 88 live processes.
	if os.Getpid() == 1 {
		slog.Warn("running as PID 1 with no init: orphaned session processes will accumulate as zombies for the container's lifetime",
			"hint", "add `init: true` to the compose service (or run with `docker run --init`) so an init at PID 1 reaps orphans; the shipped compose.yaml marks it required")
	}

	mgr := registerRoutes(mux, &routeDeps{
		static:          staticSrv,
		listenHint:      loopbackHint(addr),
		cmd:             kiro.cmd,
		sessionEnv:      kiro.env,
		sessionTitleEnv: sessionTitleEnv,
		workDir:         workDir,
		scrollback:      scrollback,
		ready:           &ready,
		kiroReady:       kiro.ready,
		kiroRescan:      kiro.rescan,
		logOSCText:      logOSCText,
		tools:           tools.engine,
		toolsSyncing:    tools.syncing,
		toolsState:      tools.state,
		toolsMissing:    tools.missing,
		containment:     startContainment(),
	})

	// The engine's blocking teardown, on whatever budget the caller hands it. An
	// expiry means a session's teardown (reaping the child, ending its cgroup,
	// sweeping /proc for escapees) did not finish inside the grace, which is
	// otherwise silent: there is no branch to take, because the process is
	// stopping either way, so the only useful thing to do is say so. It is also
	// the one place that reports a stranded session tree at shutdown, which this
	// container carries no mem_limit to catch later.
	shutdownSessions := func(ctx context.Context) {
		if teardownErr := mgr.Shutdown(ctx); teardownErr != nil {
			slog.Warn("session teardown did not finish within the shutdown grace",
				"grace", shutdownGrace, "error", teardownErr)
		}
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return atStage(stageListen, fmt.Errorf("listen on %s: %w", addr, err))
	}

	// webhttp.NewServer supplies the streaming-safe timeout defaults the hijacked /ws
	// stream needs. WithSlogErrorLog keeps net/http's OWN diagnostics inside the slog
	// stream this app documents as its only observability channel; a nil ErrorLog routes
	// them through the legacy log package instead, in a shape Loki cannot query alongside
	// the access log. Warn, not Error: net/http's accept path retries itself.
	srv := webhttp.NewServer(
		buildHandler(mux, trustedProxies, cspPolicy, hostPolicy),
		webhttp.WithSlogErrorLog(slog.LevelWarn),
	)
	// BaseContext hands every request a context the WithPreDrain hook below
	// cancels on shutdown; see that hook for why cancelling baseCtx rather than
	// srv.Shutdown is what unblocks the always-open SSE stream.
	srv.BaseContext = func(net.Listener) context.Context { return baseCtx }

	// Bound to baseCtx, which the pre-drain hook cancels. Skipped entirely when the
	// state directory was refused: the poller's sweep is os.ReadDir + os.Remove over
	// that path, so running it against a rejected one is the delete loop the
	// verification exists to prevent.
	if sessionTitleEnv != nil {
		go titles.Run(baseCtx, mgr)
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("web-terminal-kiro listening", "addr", addr, "work_dir", workDir)
	ready.Set(true)

	// The pre-drain hook flips readiness false and cancels in-flight request
	// contexts before webhttp.Run drains, so /api/health reports 503 during the
	// drain window. cancelBase unblocks the always-open /api/sessions/events SSE
	// handler (it returns only on r.Context().Done(); srv.Shutdown does not
	// interrupt an active stream, so without this the drain blocks the full
	// grace window whenever a tab is open).
	if err := webhttp.Run(ctx, srv, ln, shutdownSessions,
		webhttp.WithShutdownGrace(shutdownGrace),
		webhttp.WithPreDrain(func(context.Context) {
			ready.Set(false)
			cancelBase()
			slog.Info("shutting down", "cause", context.Cause(ctx))
		})); err != nil {
		// Clear readiness before shutting sessions down: the fast-death Warn in
		// registerRoutes keys on it to distinguish app-initiated process
		// cancellation from a spontaneous early child failure, so this fatal path
		// must clear it too or a teardown emits a false broken-install alert.
		ready.Set(false)
		// This path gets its own budget: webhttp builds a teardown context only
		// on the graceful path, and it returns before the pre-drain hook here.
		tctx, cancelTeardown := context.WithTimeout(context.Background(), shutdownGrace)
		shutdownSessions(tctx)
		cancelTeardown()
		return atStage(stageServe, fmt.Errorf("http server exited: %w", err))
	}
	return nil
}

// The layout facts this app brings to the kiro-cli install: where the convenience
// symlink goes, and what its own SHELL-era installer left on the volume.
const (
	// kiroLinkDir holds the non-authoritative `docker exec … kiro-cli` convenience
	// symlink. It is co-owned by the toolbelt engine, which publishes bin/<tool>
	// symlinks of its own — which is why the legacy sweep names its targets instead
	// of scanning it.
	kiroLinkDir = "bin"
	// legacyStagePrefix prefixed the shell installer's staging trees directly under
	// the tools dir, so anything matching this is an orphan its EXIT trap missed on
	// a SIGKILL. It ends in a dot so it cannot match the install root or the marker
	// below.
	legacyStagePrefix = ".kiro-cli-stage."
	// legacyPurgeMarker records that the one-time migration sweep completed, so it
	// runs ONCE rather than walking the co-owned bin directory every boot.
	// Dot-prefixed and directly under the tools dir, where the toolbelt engine never
	// looks and where neither the stage sweep nor the entrypoint's write-probe
	// cleanup can match it.
	legacyPurgeMarker = ".kiro-cli-legacy-purged"
)

// baseKiro carries startKiroCLI's inputs: the three Renovate-pinned literals the
// entrypoint exports, the tools tree they install into, the taint observation only
// the entrypoint can make, this deployment's extra chat flags, and the operator's
// install-custody trust list.
type baseKiro struct {
	version     string
	sha256      string
	sha256ARM64 string
	toolsDir    string
	chatArgs    []string
	// trustedInstallUIDs are the operator-declared identities whose write access
	// to the installation tree does not break custody. Empty by default.
	trustedInstallUIDs []int
	tainted            bool
}

// kiroRuntime is the running kiro-cli subsystem handed to the routes. Every field
// is a function because the answers CHANGE while the server runs: the install
// completes after the listener binds, so an argv or a PATH captured at boot would
// freeze the first (empty) answer forever.
type kiroRuntime struct {
	// cmd builds one session's argv. Called per session, so the next tab picks up
	// a version switch.
	cmd func() []string
	// env is the per-session environment overlay, or nil when there is nothing to
	// add. The engine appends it last, so PATH here wins.
	env func() []string
	// ready is the /api/health and session-create verdict plus its 503 reason, or
	// nil when this app does not own the install (a bare `go run` with no pins)
	// and readiness stays pure-listener.
	ready func() (bool, string)
	// rescan re-derives the active version from disk without downloading, or nil
	// when there is no manager. It backs the loopback repair endpoint.
	rescan func(context.Context) (bool, error)
	// stop cancels the background install.
	stop func()
}

// unmanagedKiroRuntime is the runtime for a process with no pins in its
// environment: a bare `go run` outside the container. kiro-cli is resolved by bare
// name through the developer's own PATH and there is no install to gate on, so the
// readiness policy is total and permissive. In the image entrypoint.sh always
// exports the pins, so this shape is unreachable there.
func unmanagedKiroRuntime(chatArgs []string) kiroRuntime {
	argv := sessionCommand(kirocli.Name, chatArgs...)
	return kiroRuntime{
		cmd:   func() []string { return argv },
		env:   func() []string { return nil },
		ready: func() (bool, string) { return true, "" },
		stop:  func() {},
	}
}

// unavailableKiroRuntime is the runtime for a container that CANNOT install
// kiro-cli: the pins it was handed are unusable, so no version can ever be
// activated. It reports unready rather than pretending, which gates session
// creation and surfaces the fault on /api/health instead of letting every terminal
// die one by one. Degraded, never fatal: the HTTP surface and the `docker exec`
// repair path stay alive, per this app's failure posture.
func unavailableKiroRuntime() kiroRuntime {
	return kiroRuntime{
		cmd:   func() []string { return sessionCommand(kirocli.Name) },
		env:   func() []string { return nil },
		ready: func() (bool, string) { return false, reasonUnavailable },
		stop:  func() {},
	}
}

// The readiness reasons this app puts on the wire, one per operator situation.
//
// The install manager reports a TYPED reason because the wording a consumer shows
// its users is the consumer's. These four literals ARE that wording, and they are a
// published contract: an operator reads them from `docker inspect` and a monitoring
// probe, they are the 503 body of POST /api/sessions, and they are the reason text
// /api/health serves. kiroReasonText is the single place they are produced.
const (
	reasonInstalling = "kiro-cli installing"
	reasonRetrying   = "kiro-cli install retrying"
	// reasonUnavailable is also the fallback for a rescan with no verdict to read,
	// and for a reason a future library version adds: a state we cannot name still
	// blocks sessions.
	reasonUnavailable = "kiro-cli unavailable"
	// reasonSettings is pinstall.ReasonAssertion in this app's terms. The only
	// REQUIRED assertion here is the profile's mandatory app.disableAutoupdates, so
	// a withheld verdict means exactly that the binary may replace itself and
	// invalidate the verified digest.
	reasonSettings = "kiro-cli required settings not enforced"
)

// kiroReasonText renders the install manager's typed reason as the reason
// /api/health, the session-create gate and the repair hook serve. ReasonReady maps
// to "", which every one of those surfaces omits.
func kiroReasonText(why pinstall.Reason) string {
	switch why {
	case pinstall.ReasonReady:
		return ""
	case pinstall.ReasonInstalling:
		return reasonInstalling
	case pinstall.ReasonRetrying:
		return reasonRetrying
	case pinstall.ReasonUnavailable:
		return reasonUnavailable
	case pinstall.ReasonAssertion:
		return reasonSettings
	}
	return reasonUnavailable
}

// startKiroCLI builds the kiro-cli install manager and starts the install in the
// background, bind-first: the listener comes up immediately and only readiness and
// SESSION CREATION wait, so a first-boot download answers 503 with a reason instead
// of refusing connections. Three shapes come out of it — no pins (a bare `go run`),
// pins the manager cannot use (unready, so the fault is reported rather than
// hidden), and the managed install — and no operator input selects among them.
func startKiroCLI(cfg *baseKiro) kiroRuntime {
	if cfg.version == "" || cfg.toolsDir == "" {
		slog.Warn("no kiro-cli pins in the environment: resolving kiro-cli by bare name and installing nothing",
			"hint", "expected outside the container (bare `go run`); in the image entrypoint.sh exports KIRO_CLI_VERSION, both digests and KIRO_CLI_TOOLS_DIR")
		return unmanagedKiroRuntime(cfg.chatArgs)
	}
	mgr, err := pinstall.New(kiroInstallConfig(cfg))
	if err != nil {
		slog.Error("kiro-cli install manager could not be built from the exported pins; no version can be installed, so sessions stay gated",
			"error", err,
			"hint", "this is an image defect: check the KIRO_CLI_VERSION / KIRO_CLI_SHA256 / KIRO_CLI_SHA256_ARM64 literals in entrypoint.sh")
		return unavailableKiroRuntime()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// EnsureWithRetry already logs the error with the attempt count and the
		// in-container repair hint, and nothing here could act on it: the server
		// must stay up either way.
		_ = mgr.EnsureWithRetry(ctx)
	}()
	// Copied out of cfg so the long-lived closure below owns its own value rather
	// than a pointer into the composition root's config.
	chatArgs := cfg.chatArgs
	return kiroRuntime{
		cmd: func() []string { return sessionCommand(mgr.Path(), chatArgs...) },
		env: mgr.PathEnv,
		ready: func() (bool, string) {
			ok, why := mgr.Ready()
			return ok, kiroReasonText(why)
		},
		rescan: mgr.Rescan,
		stop:   cancel,
	}
}

// kiroInstallConfig is this app's deployment of the kiro-cli release: the pins, the
// tools tree, the taint observation and the local policy. The release PROFILE — URL,
// arch tokens, in-archive installer, probe argv, licence notice and the mandatory
// auto-update assertion — is kirocli.Release()'s, shared with every other consumer.
//
// A function rather than an inline literal so the namespace test can build a manager
// from the EXACT configuration production runs: the collision it guards is a property
// of these values, not of a copy of them.
func kiroInstallConfig(cfg *baseKiro) *pinstall.Config {
	return &pinstall.Config{
		Release: kirocli.Release(),
		Version: cfg.version,
		// Both pins travel, whatever this container runs on; the library validates
		// the digest for the resolved GOARCH and ignores the other.
		Digests: map[string]string{
			"amd64": cfg.sha256,
			"arm64": cfg.sha256ARM64,
		},
		Root:    cfg.toolsDir,
		LinkDir: kiroLinkDir,
		// The chat sidecar is REQUIRED because `kiro-cli chat` over a PTY IS the product: a
		// version directory holding only the main dispatcher answers --version correctly
		// and then kills every terminal at chat. The library always requires the release's
		// primary artifact, so this names only the addition. No Optional set, so
		// kiro-cli-term is not installed here at all; vibekit's set differs, and neither
		// should be copied across without a caller that needs it.
		Require: []string{kirocli.Name + "-chat"},
		Assert:  kiroSettings(),
		Purge:   kiroLegacyPurge(),
		// With the taint set, no pre-existing version directory may be activated at
		// all: a forgeable sentinel is worthless evidence on a tree another host
		// user could write. vibekit deliberately leaves this UNSET — it has no
		// hardening pass that could make the observation.
		Untrusted: cfg.tainted,
		// Empty by default so the library's custody check applies in full; setting
		// it asserts what the library's own field doc requires.
		TrustedUIDs: cfg.trustedInstallUIDs,
	}
}

// kiroSettings is this app's kiro-cli settings set, re-asserted against the active
// binary on every boot. Every one is best-effort: a failure warns and readiness is
// unaffected.
//
// app.disableAutoupdates is deliberately NOT here: kirocli.Release() declares it
// Mandatory, so the library forces it Required whatever a deployment passes and the
// integrity gate cannot be weakened from this list. The two notification settings are
// load-bearing for the per-tab status dots.
func kiroSettings() []pinstall.Assertion {
	return []pinstall.Assertion{
		kirocli.Setting("telemetry.enabled", false),
		kirocli.Setting("chat.enableNotifications", true),
		// Raw because the value is not a boolean.
		kirocli.SettingRaw("chat.notificationMethod", "osc9"),
		kirocli.Setting("chat.terminalTitle", false),
		// A settings assertion is the ONLY way to reach this: kiro-cli exposes no `chat`
		// flag and no env var for it (checked against 2.18.0). Without it kiro-cli emits
		// ED3 on every full-viewport repaint and the engine honors it by CLEARING the
		// ring, which made the engine's 100000-line default unreachable (2294-3185 lines
		// retained across 5 real sessions). It does not fix resizes, because kiro-cli's
		// debounced resize callback writes CLEAR_ALL unconditionally (upstream
		// Kiro#10780). Needs 2.17.0+, which is why best-effort is right.
		kirocli.Setting("chat.preserveScrollback", true),
	}
}

// kiroLegacyPurge describes the layout THIS APP's shell installer left on the tools
// volume — caller data, since the residue is a fact about this app's history rather
// than about the release. Nothing in the list is read by anything any more.
//
// Larger than vibekit's on purpose (this installer promoted in place, so it wrote a
// journal, `.prev` backups and three markers), so do not copy it there. The dispatcher
// NAMES come from the library profile, which is what makes the sweep safe in a
// directory toolbelt co-owns: a `kiro-cli*` prefix sweep deleted a live symlink.
func kiroLegacyPurge() *pinstall.Purge {
	return &pinstall.Purge{
		Artifacts: []string{
			".kiro-cli-update-in-progress",
			".kiro-cli-installed",
			".kiro-cli-installed.prev",
			".kiro-cli-ready",
			kiroLinkDir + "/.kiro-cli.prev",
			kiroLinkDir + "/.kiro-cli.prev.absent",
			kiroLinkDir + "/.kiro-cli-chat.prev",
			kiroLinkDir + "/.kiro-cli-chat.prev.absent",
			kiroLinkDir + "/.kiro-cli-term.prev",
			kiroLinkDir + "/.kiro-cli-term.prev.absent",
		},
		Names:       kirocli.ShellEraDispatchers(),
		StagePrefix: legacyStagePrefix,
		Marker:      legacyPurgeMarker,
	}
}

// configMountDir is the persistent bind mount every deployment gives this
// container, fixed by the image rather than configurable. The env knob that used to
// name it is DELETED and the deletion is guarded (tests/shell/pins_export_test.sh):
// it relocated only toolbelt's three metadata files while the artifacts they
// describe, $HOME and the kiro-cli install root all stayed put, so its only
// reachable effect was splitting one subsystem across two volumes. What this path
// still decides is whether this process has a /config to persist into at all, plus
// the base the tools root is derived from when no entrypoint exported one.
const configMountDir = "/config"

// baseTools carries startTools's inputs (resolved paths + the catalog-refresh
// knobs).
type baseTools struct {
	// configDir is the persistence mount (configMountDir in the container, a temp
	// dir in tests). It is NOT toolbelt's ConfigDir: the engine's config and tools
	// dirs are both the tools root below, since the manifest, the machine state and
	// the catalog cache describe the tree they now sit in.
	configDir string
	// toolsDir is the tools tree both co-owners write to: the entrypoint's exported
	// KIRO_CLI_TOOLS_DIR when present, else derived from configDir. One resolution
	// site, so the toolbelt engine and the kiro-cli install manager cannot disagree
	// about where the tree is.
	toolsDir    string
	catalogPath string
	catalogURL  string
	// refreshInterval is the engine refresh cadence under toolbelt's canonical
	// policy (zero = schedule disabled, manual refresh stays available via the
	// loopback tools API).
	refreshInterval time.Duration
}

// requiredToolsList is the same required-tools.txt the image build verifies the
// baked catalog against, embedded so the RUNTIME refresh applies the identical gate
// to every fetched catalog: one source of truth, two enforcement points.
//
//go:embed required-tools.txt
var requiredToolsList string

// toolsRuntime is the running tools subsystem handed to the routes. A zero value
// (engine nil, funcs nil) means "no tools surface" — bare `go run` and tests
// outside the container.
type toolsRuntime struct {
	engine *toolbelt.Engine
	// syncing reports whether the boot convergence pass is still running; session
	// creation is gated on it so the first kiro-cli never spawns before the
	// manifest's tools are on PATH.
	syncing func() bool
	// state is the /api/health informational detail: syncing | ok | degraded. LIVE,
	// not boot-only: after the boot verdict it tracks the engine's counted jobs.
	state func() string
	// missing is the WHOLE-TREE convergence signal, deliberately a second question
	// from state: state answers "did the last job succeed, or are we still booting",
	// which keeps monitoring from flapping through a long first-boot install, while
	// this answers "is the tree actually converged". Reporting one as the other made
	// state=ok readable as whole-tree health after a partial repair. ok is false until
	// the first recount lands, so a premature zero cannot read as convergence.
	missing func() (n int, ok bool)
}

// The three documented values of /api/health's informational tools field. Each is
// named rather than inlined because every one is written from more than one site
// and a health consumer keys on the literal.
const (
	// toolsStateSyncing is the verdict while the boot convergence pass runs (the
	// window in which POST /api/sessions answers 503 "tools installing").
	toolsStateSyncing = "syncing"
	toolsStateOK      = "ok"
	// toolsStateDegraded is the verdict for a tools subsystem that FAILED, as
	// opposed to one deliberately absent (which omits the field entirely).
	toolsStateDegraded = "degraded"
)

// toolsStatus is the app-owned reducer behind /api/health's INFORMATIONAL tools field,
// fed by the boot reconcile's verdict once and by the engine's OnJobChanged callback
// thereafter — so a repair through the loopback API heals the field without a restart.
//
// `syncing` is the initial state and the only one never re-entered, which is what makes
// it safe for the session-create gate to be derived from this same cell. `booted`
// orders the two phases, because the boot reconcile's own terminal callback can fire up
// to one Wait poll BEFORE recordBoot and would otherwise lift the gate early.
type toolsStatus struct {
	// state is the current value, and — through the syncing state — the
	// session-create gate's only predicate. atomic rather than a mutex because
	// OnJobChanged fires under toolbelt's own queue lock and must not block.
	state atomic.Value // string: syncing | ok | degraded
	// poke asks the convergence watcher for a recount. Buffered depth 1 and
	// written with a NON-BLOCKING send, because every writer either runs under
	// toolbelt's queue lock or is recordBoot. Coalescing is the intent: several job
	// transitions in a burst need one recount, not one each.
	poke chan struct{}
	// missing is the whole-tree convergence count: enabled manifest entries not
	// installed. Negative means "not counted yet", a THIRD state a plain count
	// cannot carry — a premature 0 would read as convergence.
	missing atomic.Int64
	// booted reports whether the boot verdict has been recorded. Set last by
	// recordBoot so a job transition can never overtake the verdict.
	booted atomic.Bool
}

// newToolsStatus returns a reducer parked in the pre-verdict boot state.
func newToolsStatus() *toolsStatus {
	s := &toolsStatus{poke: make(chan struct{}, 1)}
	s.state.Store(toolsStateSyncing)
	s.missing.Store(-1) // not counted yet, which is not the same as "none"
	return s
}

// get reads the current value for /api/health.
func (s *toolsStatus) get() string {
	v, _ := s.state.Load().(string)
	return v
}

// missingCount reports the whole-tree convergence count, and whether one has
// been taken at all.
func (s *toolsStatus) missingCount() (int, bool) {
	n := s.missing.Load()
	if n < 0 {
		return 0, false
	}
	return int(n), true
}

// requestRecount asks the watcher for a fresh convergence count without ever
// blocking the caller.
//
// Non-blocking is not an optimisation, it is the whole reason this indirection
// exists: the natural place to recount is OnJobChanged, but that fires under
// toolbelt's job-queue lock and Engine.Inventory() takes the same lock, so counting
// there deadlocks the engine. The callback pokes; a goroutine that holds no lock
// does the counting.
func (s *toolsStatus) requestRecount() {
	select {
	case s.poke <- struct{}{}:
	default: // a recount is already pending, and it will see the newer state
	}
}

// watchConvergence owns every convergence recount for the process, which is what
// makes them serialized: one goroutine, so two counts can never interleave and
// store each other's answer out of order.
//
// count returns the number of enabled manifest entries that are not installed.
func (s *toolsStatus) watchConvergence(ctx context.Context, count func() (int, error)) {
	recount := func() {
		n, err := count()
		if err != nil {
			// Return the field to UNKNOWN rather than freezing the last answer: the
			// published contract is that tools_missing is absent when the count is
			// not known, so a frozen 0 would assert a convergence the engine can no
			// longer confirm. Warn, not Debug: Inventory's failure mode is an
			// unreadable or unparseable manifest, which is persistent and
			// operator-fixable.
			s.missing.Store(-1)
			slog.Warn("tools: convergence recount failed; /api/health omits tools_missing until one succeeds",
				"error", err,
				"hint", "fix the manifest (schema v2 JSON); an unreadable manifest also fails the tools engine outright on the next restart")
			return
		}
		s.missing.Store(int64(n))
	}
	recount() // answer the question before the first job transition arrives
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.poke:
			recount()
		}
	}
}

// countMissingTools reports how many ENABLED manifest entries are not installed.
func countMissingTools(eng *toolbelt.Engine) func() (int, error) {
	return func() (int, error) {
		inv, err := eng.Inventory()
		if err != nil {
			return 0, err
		}
		return countMissingFromInventory(inv.Tools), nil
	}
}

// countMissingFromInventory is the counting RULE, split from the engine call so the
// policy is testable without standing up a toolbelt tree.
//
// Disabled entries are excluded because in toolbelt v2 a disabled entry is a
// TEMPLATE — recorded intent that is deliberately not installed — so counting one
// as outstanding would make a freshly seeded volume report five missing tools
// forever. An entry still installing DOES count: it is not on PATH yet.
func countMissingFromInventory(tools []toolbelt.ToolInfo) int {
	n := 0
	// Indexed rather than a value range: ToolInfo is 160 bytes, so copying one per
	// entry is pure waste on a tree that can hold hundreds.
	for i := range tools {
		if !tools[i].Disabled && !tools[i].Installed {
			n++
		}
	}
	return n
}

// recordBoot stores the boot convergence pass's verdict and arms the live half.
// Called once; storing a terminal verdict is also what lifts the session-create
// gate. The store order is load-bearing: state first, then booted, so no job
// transition can land between them and be mistaken for the boot outcome.
func (s *toolsStatus) recordBoot(v string) {
	s.state.Store(v)
	s.booted.Store(true)
	// The boot pass is the largest single change to the tree, so recount as soon as
	// its verdict is in rather than waiting for the next job transition.
	s.requestRecount()
}

// observeJob is the Config.OnJobChanged reducer: it folds one job state transition
// into the field. Fires from toolbelt's job worker under the queue lock, so it does
// exactly one atomic store, one non-blocking poke, and never blocks.
func (s *toolsStatus) observeJob(j *toolbelt.Job) {
	// The convergence count is a fact about the TREE, so EVERY settled job asks for a
	// recount — deliberately not filtered by toolsStatusCounts, which is the state
	// VERDICT's policy. A disable, an uninstall and a half-finished update all change
	// which enabled entries are installed without meaning the boot was degraded.
	// Cancelled is settled too: a job cancelled after it already changed the tree
	// would otherwise leave the count asserting the pre-job state.
	switch j.State {
	case toolbelt.JobDone, toolbelt.JobFailed, toolbelt.JobCancelled:
		s.requestRecount()
	}
	if !toolsStatusCounts(j.Kind) || !s.booted.Load() {
		return
	}
	switch j.State {
	case toolbelt.JobDone:
		s.state.Store(toolsStateOK)
	case toolbelt.JobFailed:
		s.state.Store(toolsStateDegraded)
	}
	// JobQueued/JobRunning are in-flight, and JobCancelled is not a fault
	// (Engine.Close cancels the active job on every shutdown) — both leave the last
	// settled value in place.
}

// toolsStatusCounts is the job-kind policy for the informational tools field,
// enumerated rather than defaulted to "anything that failed", so a kind toolbelt adds
// later counts only once someone decides it should. It governs the state VERDICT only,
// never the convergence recount. Counted: install (also the REPAIR path, which is what
// makes recovery observable) and reconcile. Excluded: catalog-refresh and update, whose
// common failures change nothing on disk; uninstall and disable, which are removal —
// disable also on SUCCESS, since a clean removal storing "ok" whitewashes an unrelated
// install failure.
func toolsStatusCounts(kind string) bool {
	switch kind {
	case toolbelt.JobKindInstall, toolbelt.JobKindReconcile:
		return true
	default:
		return false
	}
}

// degradedRuntime is the engine-less runtime a startTools failure returns: engine
// stays nil (no /api/tools mount) and syncing reports false (sessions ungated) while
// state reports degraded so the failure is visible on /api/health instead of looking
// like a deliberate disable.
func degradedRuntime() toolsRuntime {
	return toolsRuntime{
		syncing: func() bool { return false },
		state:   func() string { return toolsStateDegraded },
		// Not zero: zero would claim convergence for a subsystem that failed to
		// start.
		missing: func() (int, bool) { return 0, false },
	}
}

func (t *toolsRuntime) close() {
	if t.engine != nil {
		t.engine.Close()
	}
}

// warnIfToolsBinUnreachable warns when the engine's single PATH directory
// (<toolsDir>/bin) is absent from this process's PATH. Every tool then provisions
// successfully and /api/health reports tools=ok while no session, and therefore no
// kiro-cli PATH scan, can see any of it. Sessions inherit this process's environment,
// so this process's PATH is the right thing to test. Warn, never fatal: in the
// container the cause is a compose PATH override or an image whose ENV PATH dropped
// the segment, and outside it a bare `go run` is expected to lack the derived tree.
func warnIfToolsBinUnreachable(toolsDir string) {
	binDir := filepath.Clean(filepath.Join(toolsDir, "bin"))
	for entry := range strings.SplitSeq(os.Getenv("PATH"), string(os.PathListSeparator)) {
		// No empty-entry carve-out: binDir is the Clean of a Join ending in "bin",
		// so it can never be ".", the value Clean returns for both an empty element
		// and ".".
		if filepath.Clean(entry) == binDir {
			return
		}
	}
	slog.Warn("the tools tree is not on PATH: every tool the manifest installs will be invisible to kiro-cli and to terminal sessions, even though /api/health will report tools=ok",
		"tools_bin", binDir,
		"hint", "add "+binDir+" to this process's PATH. In the container that means the image's ENV PATH (or a compose override of it) no longer leads with the tools tree entrypoint.sh hardened and exported; outside it, a bare `go run` inherits the developer's PATH, so the derived tree is expected to be absent from it.")
}

// logRootIntegrityFindings turns a toolbelt root-integrity refusal into one
// operator-queryable line per offending root. toolbelt logs the refusal too, but as
// a single joined string, so without this the degraded /api/health verdict is backed
// only by a message nothing can be filtered on.
func logRootIntegrityFindings(err error) {
	var unfit *toolbelt.RootIntegrityError
	if !errors.As(err, &unfit) {
		return
	}
	// ConfigDir and ToolsDir are the SAME directory for this app, and toolbelt
	// judges each of its two arguments in turn, so a finding about the root ITSELF
	// arrives twice. The library sorts findings by path then reason, which puts any
	// such pair adjacent.
	var prev toolbelt.RootIntegrityFinding
	for i, f := range unfit.Findings {
		if i > 0 && f == prev {
			continue
		}
		prev = f
		slog.Error("tools engine refused a managed root as unfit to execute from; it stays unmanaged until the volume is repaired",
			"root", f.Path, "reason", f.Reason)
	}
}

// startTools builds the toolbelt engine and launches the boot convergence pass
// (bind-first: the listener comes up while installs run; only session CREATION
// waits, via the syncing gate). The gate lifts regardless of per-tool failures —
// degraded-not-dead — and the health detail records the verdict, then keeps tracking
// the engine's counted jobs for the rest of the run. After convergence an async
// update pass refreshes unpinned tools, and a boot warning nudges when no language
// server is enabled (kiro-cli scans PATH for LSPs at session start).
func startTools(ctx context.Context, cfg baseTools) toolsRuntime {
	// Three distinct outcomes, deliberately NOT collapsed: only a genuinely ABSENT
	// directory is the intentionally-disabled out-of-container shape. A stat failure
	// for any other reason, or a non-directory mounted at the config path, is a
	// FAILED production subsystem — otherwise the operator reads a broken mount as
	// "tools deliberately off".
	fi, statErr := os.Stat(cfg.configDir)
	switch {
	case errors.Is(statErr, fs.ErrNotExist):
		slog.Warn("tools engine disabled: config dir missing",
			"config_dir", cfg.configDir,
			"hint", "bind-mount the persistent config volume (compose.yaml)")
		// No tools surface: engine stays nil while the policies stay callable; ""
		// keeps health's omitempty tools field absent.
		return toolsRuntime{
			syncing: func() bool { return false },
			state:   func() string { return "" },
			// "not counted" is not convergence, so the health field stays ABSENT
			// rather than reporting 0.
			missing: func() (int, bool) { return 0, false },
		}
	case statErr != nil:
		slog.Error("tools engine failed to inspect config dir; continuing without it",
			"config_dir", cfg.configDir, "error", statErr)
		return degradedRuntime()
	case !fi.IsDir():
		slog.Error("tools engine config path is not a directory; continuing without it",
			"config_dir", cfg.configDir)
		return degradedRuntime()
	}
	// The tool subsystem's ONE root: the engine's ToolsDir, the directory whose bin/
	// every session must find on PATH, AND the engine's ConfigDir. Those last two
	// are the same path on purpose — toolbelt's three metadata files all describe
	// the artifacts under ToolsDir, so a layout that let them sit in different
	// volumes was one subsystem with two homes. Prefer the path the entrypoint
	// hardened and exported; the derivation is the out-of-container fallback only.
	toolsRoot := cfg.toolsDir
	if toolsRoot == "" {
		toolsRoot = filepath.Join(cfg.configDir, "tools")
	}
	manifestPath := manifestPathFor(toolsRoot)
	warnIfToolsBinUnreachable(toolsRoot)
	refresh := &toolbelt.CatalogRefresh{
		URL:      cfg.catalogURL,
		Require:  toolbelt.ParseRequireList(requiredToolsList),
		Interval: cfg.refreshInterval,
	}
	// Built BEFORE the engine so it can be wired as the engine's job-transition
	// callback: from here on the health field follows live job outcomes, not just
	// the boot verdict.
	status := newToolsStatus()
	eng, err := toolbelt.New(&toolbelt.Config{
		ConfigDir:    toolsRoot,
		ToolsDir:     toolsRoot,
		CatalogPath:  cfg.catalogPath,
		Refresh:      refresh,
		Seed:         toolbelt.DefaultSeed(),
		System:       []string{"git", "jq", "curl", "unzip", "xz", "ssh", "tar", "bash"},
		Logger:       slog.Default(),
		OnJobChanged: status.observeJob,
		// Refuse to construct an engine over a managed root that is a symlink, is not a
		// directory, is group/other-writable, or resolves outside the tree. The tree is an
		// operator-controlled persistent volume, this process runs as root, and toolbelt's
		// install probe EXECUTES what it finds in <ToolsDir>/bin with that dir first on PATH.
		// ADDITIVE to entrypoint.sh: only the entrypoint can chmod and re-stat to prove a
		// tightening took, and only the library covers a root reshaped AFTER it ran.
		VerifyRootIntegrity: true,
	})
	if err != nil {
		slog.Error("tools engine failed to start; continuing without it", "error", err)
		// A root-integrity refusal names every offending path; break those out into
		// their own lines so "degraded" is diagnosable (no-op for any other error
		// class).
		logRootIntegrityFindings(err)
		// Unlike the missing-config-dir path, a FAILED production subsystem must
		// stay visible on /api/health. The engine stays nil and syncing reports
		// false, so sessions remain ungated.
		return degradedRuntime()
	}

	// recordBoot BOTH arms the live reducer and lifts the session-create gate: the
	// gate is derived from the reducer's one-way "syncing" state rather than kept in
	// a second cell, so a request cannot observe tools=ok while session creation
	// still refuses with "tools installing". A post-boot job failure stores only ok
	// or degraded, so it can update the field without re-closing session creation.
	// Boot failure lifting the gate is deliberate (degraded-not-dead).
	job, enqueued, rerr := eng.Reconcile(toolbelt.ReconcileMissing)
	switch {
	case rerr != nil:
		slog.Warn("tools: boot reconcile not enqueued", "error", rerr)
		status.recordBoot(toolsStateDegraded)
		warnIfNoLSPEnabled(eng, manifestPath)
	case !enqueued: // empty manifest: nothing to converge (v3 reports this directly)
		status.recordBoot(toolsStateOK)
		warnIfNoLSPEnabled(eng, manifestPath)
	default:
		// Mark the gated window OPENING. Without this the only boot-convergence
		// records are the terminal ones, so an operator looking at 503 "tools
		// installing" answers has no line saying the gate is closed, since when, or
		// which job to correlate with toolbelt's own job warnings.
		slog.Info("tools: boot convergence started; session creation is gated until it finishes",
			"job", job.ID,
			"hint", "POST /api/sessions answers 503 \"tools installing\" (Retry-After 5) and /api/health reports tools=syncing until this converges")
		go awaitBootConvergence(ctx, eng, job.ID, status.recordBoot, manifestPath)
	}
	// Boot catalog fetch, explicitly AFTER the reconcile enqueue: the engine's
	// schedule deliberately has no fire-on-start, because an immediate enqueue
	// inside New would land ahead of the boot-critical reconcile on the
	// single-flight queue and delay the session gate. Failure is routine before the
	// publisher is reachable; keep-last-good absorbs it.
	if _, rerr := eng.RefreshCatalog(); rerr != nil {
		slog.Warn("tools: boot catalog refresh not enqueued", "error", rerr)
	}
	// The convergence watcher is started here rather than beside the reducer, so
	// it exists only for a runtime that actually has an engine to count. It gets
	// the SHUTDOWN context, not context.Background(): the callee selects on
	// ctx.Done() to return, and a Background context defeats that exit path at
	// the call site, so the goroutine outlived every shutdown and the select arm
	// was unreachable code.
	go status.watchConvergence(ctx, countMissingTools(eng))

	return toolsRuntime{
		engine:  eng,
		syncing: func() bool { return status.get() == toolsStateSyncing },
		state:   status.get,
		missing: status.missingCount,
	}
}

// awaitBootConvergence blocks on the boot reconcile job, records the verdict
// (lifting the session-create gate via finish), then runs the post-convergence
// tail: the freshness pass for unpinned entries (off the boot path — version-check
// network never holds the session gate) and the language-server nudge. manifestPath
// is threaded through purely for that nudge's operator-facing `manifest` field.
//
// ctx is the process shutdown context, not context.Background(): a goroutine
// blocked on Wait for a job budgeted at up to 30 minutes must not survive the
// signal that ends the process. A cancelled Wait is not a fault — the engine's
// own Close cancels the running job on the same path — so it lands on the
// same not-a-tool-failure record as JobCancelled.
func awaitBootConvergence(ctx context.Context, eng *toolbelt.Engine, jobID string, finish func(string), manifestPath string) {
	final, werr := eng.Wait(ctx, jobID)
	switch {
	case errors.Is(werr, context.Canceled), errors.Is(werr, context.DeadlineExceeded):
		// Shutdown won the race with convergence. Keyed on the ERROR Wait
		// returned, not on ctx.Err(): Wait checks for a terminal job BEFORE it
		// selects on ctx.Done() (toolbelt jobs.go), so a job that finished in
		// the same instant SIGTERM arrived comes back as (job, nil) with a
		// cancelled ctx — and a bare ctx.Err() arm would have recorded that
		// SUCCESS as an abandoned, degraded pass.
		//
		// The verdict still degrades (this pass did not converge) but the
		// RECORD stays Info for the same reason the JobCancelled arm below
		// does: a restart during a first-boot install is routine, and a Warn
		// here is the false broken-install alert every deploy would fire.
		//
		// Returns, like the JobCancelled arm: the post-convergence tail must
		// not run. Update() enqueues a real network pass, and the pre-drain
		// hook cancels this ctx while tools.close() is still pending in the
		// deferred teardown, so the engine is still OPEN here and the enqueue
		// would SUCCEED on a draining process.
		slog.Info("tools: boot convergence abandoned at shutdown; not a tool failure",
			"cause", context.Cause(ctx))
		finish(toolsStateDegraded)
		return
	case werr != nil:
		slog.Warn("tools: boot reconcile wait failed", "error", werr)
		finish(toolsStateDegraded)
	case final.State == toolbelt.JobCancelled:
		// Cancellation is not a fault: toolbelt cancels the active job from Engine.Close, and
		// otherwise only on an explicit operator CancelJob. Reporting it at Warn would be the
		// same false broken-install alert the session-side exit hook gates away on every
		// deploy. The verdict still degrades — the pass did not converge — but the RECORD
		// stays Info, and the post-convergence tail is skipped because on the shutdown path
		// Update() can only fail and the LSP nudge has no reader.
		slog.Info("tools: boot convergence cancelled; not a tool failure",
			"cause", final.CancelCause.String(),
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
	warnIfNoLSPEnabled(eng, manifestPath)
}

// manifestPathFor names toolbelt's manifest inside a tools root, mirroring the
// library's documented <ConfigDir>/tools.json layout. ONE derivation site, so an
// operator-facing record cannot name a different file than the engine reads — the
// drift that left the hints pointing at the pre-move /config/tools.json.
func manifestPathFor(toolsRoot string) string {
	return filepath.Join(toolsRoot, "tools.json")
}

// warnIfNoLSPEnabled logs the code-intelligence nudge when no language-server entry
// is enabled: kiro-cli scans PATH for language servers at session start, so a box
// without one silently lacks code intelligence.
//
// manifestPath is threaded through as its own field rather than spelled into the hint
// prose, because a restated path drifts — these hints named /config/tools.json
// literally and went stale when the manifest moved. The hint text stays FIXED so it
// cannot grow an input-derived tail (CWE-532).
func warnIfNoLSPEnabled(e *toolbelt.Engine, manifestPath string) {
	inv, err := e.Inventory()
	if err != nil {
		// Warn, not Debug: Inventory's only failure mode is an unreadable manifest, and
		// toolbelt returns that error without logging it, so at the default level this
		// would be the one record of a manifest an operator has just broken. Deliberately
		// NOT the "no language servers enabled" wording — that is a different event, and a
		// test counts Warns by that message.
		slog.Warn("tools: manifest unreadable; cannot tell whether a language server is enabled",
			"error", err,
			"manifest", manifestPath,
			"hint", "fix the manifest (schema v2 JSON); an unreadable manifest fails the tools engine outright on the next restart")
		return
	}
	for i := range inv.Tools {
		if inv.Tools[i].Lsp && !inv.Tools[i].Disabled {
			return
		}
	}
	slog.Warn("no language servers enabled; kiro code intelligence will be limited",
		"manifest", manifestPath,
		"hint", `enable gopls (Go), typescript-language-server (TypeScript), or pyright (Python): set "disabled": false in the manifest and restart, or use the loopback tools API`)
}

// canonicalPathRefusal is the message the canonical-path guard writes. A const so a
// test can pin the exact wording without a second copy of the literal (goconst)
// drifting from this one.
//
// It names the remedy and stops there. It deliberately does NOT echo the path the
// caller sent, nor the cleaned one: net/http carries up to MaxHeaderBytes (1 MiB by
// default) of request line, so reflecting either turns a one-line refusal into a
// caller-sized response body, and the sender already has the value.
const canonicalPathRefusal = "request path is not canonical; resend it with no empty, \".\" or \"..\" path segments " +
	"(this route refuses rather than redirecting, because a redirect is a success status to a client without -L)"

// canonicalPathGuardedRoute reports whether p is one of the routes whose caller must
// be REFUSED a non-canonical spelling rather than redirected. p is the CLEANED path,
// which is what makes this work at all: the spellings the guard exists to catch are
// exactly the ones that do not carry a guarded prefix literally ("/api//tools" does
// not begin with "/api/tools"). The set is this app's own control plane and its probe
// — the surfaces whose callers are documented `curl` without -L — named by the
// constants registerRoutes mounts them under so a rename moves both.
func canonicalPathGuardedRoute(p string) bool {
	switch p {
	case healthPath, kiroRescanPath, toolsPath:
		return true
	}
	return strings.HasPrefix(p, toolsPath+"/")
}

// canonicalPathGuard refuses a request whose path http.ServeMux would REWRITE before
// routing, when the path it would rewrite to is one of canonicalPathGuardedRoute's.
// ServeMux answers 307 when the cleaned path differs, and to a `curl` without -L a 307
// is a SUCCESS, so the mutation never ran or the probe never consulted readiness.
//
// Chain middleware, not a mount wrapper, because the cleaning runs BEFORE pattern
// selection. Fed the DECODED r.URL.Path, deliberately wider than EscapedPath, because
// ServeMux matches patterns on unescaped segments: "/api/%74ools" is served 200.
func canonicalPathGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean, canonical := webhttp.CanonicalRequestPath(r.URL.Path)
		if canonical || !canonicalPathGuardedRoute(clean) {
			next.ServeHTTP(w, r)
			return
		}
		webhttp.WriteError(w, r, http.StatusBadRequest, "non_canonical_path", canonicalPathRefusal)
	})
}

// buildHandler wraps the route mux in the middleware stack: Logging -> Recoverer ->
// wsAttachLog -> SecurityHeaders -> host allowlist -> CrossOriginProtection ->
// canonicalPathGuard -> mux. The order is the contract: Logging outermost so it sees
// every final status; Recoverer inside it so the line records the 500; wsAttachLog
// outside the host gate so a rejected Host still leaves a record; SecurityHeaders
// outside the origin gate so a rejected request still carries the headers; the host
// allowlist BEFORE the origin gate, since rebinding makes Origin and Host agree.
func buildHandler(mux http.Handler, trustedProxies []*net.IPNet, csp string, hostPolicy *webhttp.HostPolicy) http.Handler {
	return webhttp.Chain(mux,
		webhttp.Logging(
			webhttp.WithLogger(slog.Default()),
			// The /ws skip decides on an OUTCOME rather than a prediction: it
			// suppresses the record only for a response that actually switched
			// protocols, which is the state that makes the line a lie — the exchange
			// ENDED at the handshake, so a line emitted hours later at socket close
			// would carry a session-length duration and a status net/http never sent.
			// Every refusal therefore keeps its line by construction, including the
			// 426 for missing upgrade headers (the classic reverse-proxy
			// misconfiguration).
			webhttp.WithSkipUpgrades(true),
			// SSE needs its own path-shaped skip because it never switches protocols: it
			// is a plain 200 that does not return until the client disconnects, so
			// WithSkipUpgrades cannot see it and its record would START being emitted.
			//
			// A predicate rather than WithSkipPaths, for the two conjuncts: skip rules run
			// BEFORE the chain, so a bare path skip would also swallow the 403s
			// hostPolicy.Middleware and CrossOriginProtection write — WriteError logs
			// neither — leaving an attack on this unauthenticated PTY unrecorded (CWE-778).
			webhttp.WithSkipFunc(func(r *http.Request) bool {
				return r.Method == http.MethodGet &&
					r.URL.Path == terminal.SessionEventsPath && hostPolicy.Allows(r)
			}),
			// /api/health is probed every 30s. ProbeLogLevel keeps healthy probes at
			// Debug while a FAILING probe surfaces at Warn/Error with its status and
			// request id.
			webhttp.ProbeLogLevel(healthPath),
			// The session-id-bearing subtree logs the route template the mux actually
			// matched instead of the raw path, so a live capability token never reaches the
			// access log. The prefix comes from the engine — the package that DECLARES those
			// routes — and the template from r.Pattern, so a route the engine adds in a
			// future version logs correctly with no change here.
			webhttp.WithTemplatePathsUnder(terminal.SessionsSubtreePath),
			webhttp.WithClientIP(trustedProxies...),
		),
		webhttp.Recoverer(webhttp.WithRecoverLogger(slog.Default())),
		wsAttachLog(trustedProxies),
		webhttp.SecurityHeaders(
			webhttp.WithCSP(csp),
			// COOP severs window.opener for any cross-origin page a session opens. The
			// terminal renders clickable OSC 8 hyperlinks straight out of untrusted child
			// output, so a session can be induced to open an attacker page; the vendored UI
			// already sets rel="noopener noreferrer", and this header plus the tightened
			// Referrer-Policy make that guarantee independent of the Renovate-bumped UI pin.
			// COOP and the Permissions-Policy features are secure-context-gated, so inert on
			// a plain-HTTP LAN bind; Referrer-Policy is not, which is why it is useful there.
			webhttp.WithCOOP("same-origin"),
			webhttp.WithReferrerPolicy("same-origin"),
			webhttp.WithPermissionsPolicy("camera=(), microphone=(), geolocation=()"),
		),
		hostPolicy.Middleware(),
		http.NewCrossOriginProtection().Handler,
		canonicalPathGuard,
	)
}

// wsAttachMsg is the message of the /ws attach record wsAttachLog emits. A const so
// a test can pin the exact wording without a second copy of the literal (goconst).
const wsAttachMsg = "terminal attach attempt"

// wsAttachLog records one line per /ws UPGRADE attempt. The access logger skips
// admitted streams and neither the engine's WebSocketHandler nor the per-session
// Handler logs an attach, so without this the request that PRESENTS the session
// capability token is the only request to this server with no record at all: a
// leaked id could be replayed with nothing to show an operator afterwards (CWE-778).
// Logged at request start, so a rejected Host or unknown-session close is recorded
// too, and the attacker-chosen session param stays an attribute the handler quotes.
func wsAttachLog(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == terminal.WSPath && isWebSocketUpgrade(r) {
				slog.Info(wsAttachMsg,
					"session", terminal.LogID(terminal.SessionID(r.URL.Query().Get("session"))),
					"client_ip", webhttp.ClientIP(r, trustedProxies...),
					"request_id", webhttp.RequestIDFromContext(r.Context()))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isWebSocketUpgrade reports whether r carries the RFC 6455 upgrade signal. It is
// wsAttachLog's ATTEMPT predicate, which is a different question from the access
// log's: that one asks whether a request ENDED as a stream, after the fact. This
// asks whether a request is trying to attach, BEFORE the handshake runs, because the
// session capability token is in the query string and every attempt that looks like
// an attach must leave its audit record even when the handshake is malformed. An
// attempt predicate cannot be replaced by an outcome: by the time the outcome is
// known, the request that presented the token may already have been refused.
func isWebSocketUpgrade(r *http.Request) bool {
	return headerHasToken(r, "Upgrade", "websocket") &&
		headerHasToken(r, "Connection", "upgrade")
}

// headerHasToken reports whether any field value of the named header carries token
// as a comma-separated element, case-insensitively. Both headers are comma-lists
// that may also arrive as repeated field lines (RFC 7230 3.2.2), and the engine's
// websocket.Accept matches them exactly this way — so this predicate must too, or
// wsAttachLog's attach record and the actual upgrade disagree about which requests
// were trying to attach.
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

// containCgroupRoot is the container's own cgroup v2 root under a private cgroup
// namespace, and containCgroupPrefix namespaces every cgroup this server creates
// beneath it.
//
// Not an env var, deliberately: a knob whose only effect is to silently disable a
// correctness feature does not belong in a config table. The entrypoint decides
// whether containment is possible (it owns the one-time remount), and the server
// discovers the answer by trying.
const (
	containCgroupRoot   = "/sys/fs/cgroup"
	containCgroupPrefix = "wt-"
)

// startContainment prepares per-session process containment, or returns nil after one
// warning when this host cannot support it. Nil is a fully supported outcome with
// ordinary causes: a `go run` outside the container, a kernel older than 5.19, a seccomp
// profile refusing clone3, or an entrypoint whose cgroup remount did not run. It costs
// ONLY the per-session peak numbers, because the engine reaps a closed session's
// surviving tree from an inherited environment marker with no host support — which is
// also why this container no longer asks for CAP_SYS_ADMIN.
func startContainment() *terminal.Containment {
	c, err := terminal.NewContainment(containCgroupRoot, containCgroupPrefix, slog.Default())
	if err != nil {
		// WARN, not Info, and the level is the whole point of the line.
		//
		// This reports that a layer the operator asked for is not running. At Info it
		// sat in the same stream as routine boot chatter, six seconds after
		// entrypoint.sh had already logged `cgroup tree remounted rw; per-session
		// process containment available` — which is a claim about the MOUNT, not
		// about containment. An operator reading the first line saw success, and the
		// contradiction below it was not loud enough to correct them.
		//
		// The cost of missing it is measured, not hypothetical: containment ran
		// silently off on borgcube while 28 stranded session trees accumulated
		// 16.2 GB, and the incident reached 32.6 GB with 17,290 zombies before
		// anyone read this line. Nothing else announces the state, and this
		// container deliberately carries no mem_limit, so the fleet's
		// ContainerMemoryHigh rule is structurally exempt from catching the
		// consequence (see web-terminal-kiro.md, "No mem_limit, on purpose").
		//
		// It stays a warning rather than a fatal because the app's failure posture
		// says so: reaping closes the process leak without containment, so the
		// terminal must keep serving.
		slog.Warn("per-session cgroup containment unavailable; session trees are still reaped, but per-session peak memory and task counts will not be reported",
			"error", err,
			"hint", "containment needs a writable cgroup v2 root, which needs CAP_SYS_ADMIN for a one-time remount. Not granted by default: the engine's marker-based reaping closes the process leak without it.")
		return nil
	}
	return c
}
