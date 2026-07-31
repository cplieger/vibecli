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
	"github.com/cplieger/pinstall"
	"github.com/cplieger/pinstall/kirocli"
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
// must never fall open. A DEFAULT ROUTE is kept on the same terms: it parses,
// so it is used, but it can never describe a proxy set and it is warned about
// once per boot (see the loop below). An unset or empty var yields nil, i.e.
// "trust nothing", so ClientIP ignores X-Forwarded-For and logs the spoof-proof
// socket peer — the correct default for a directly-exposed deployment. Behind a
// reverse proxy, set the var to the proxy's CIDR(s) so the access log records
// the real client.
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
	// A default route (0.0.0.0/0 or ::/0) parses cleanly but can never describe a
	// proxy SET, and it breaks client-IP resolution both ways: ClientIP skips every
	// X-Forwarded-For hop it considers trusted, so a same-family chain exhausts the
	// walk and falls back to the socket peer (the proxy — exactly what setting this
	// var was meant to stop logging), while an entry of the OTHER address family is
	// never skipped, so a forged `X-Forwarded-For: 2001:db8::1` becomes the logged
	// client_ip of an unauthenticated PTY request and outranks the true client
	// address the real proxy appended. Warn by PREFIX LENGTH only, never the raw
	// entry, for the same reason the malformed-entry warning above is count-only.
	for _, n := range nets {
		if ones, _ := n.Mask.Size(); ones == 0 {
			slog.Warn(key+" contains a default route (0.0.0.0/0 or ::/0); every peer counts as a proxy, so client_ip logs the proxy itself and a forged X-Forwarded-For of the other address family can choose the logged client",
				"hint", "list only the reverse proxy's own address(es), e.g. 10.0.0.0/8 or 192.0.2.10; leave "+key+" unset to log the unspoofable socket peer")
			break
		}
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

// catalogRefreshKey is the env var parseCatalogRefresh interprets and names in its
// by-name-only warning. main() reads the value under the same name from here, so the
// key has one home. (Package scope beside the function rather than inside the
// kiro-cli layout const block below, which is scoped to install-layout facts.)
const catalogRefreshKey = "TOOL_CATALOG_REFRESH"

// parseCatalogRefresh reads TOOL_CATALOG_REFRESH and delegates to toolbelt's
// canonical parser — but only for values that parser ACCEPTS. toolbelt calls
// scheduler.ParseInterval without scheduler.WithRedactedValue, so its fallback
// warning echoes the RAW value (scheduler warnFallback), and a compose expansion
// mistake could put a credential on this key — the same reason KWEB_LOG_LEVEL is
// read as a string and KWEB_LOG_OSC_TEXT goes through envx.BoolStrict. A value the
// library would reject is warned about HERE by name only and replaced with "" so
// the library applies its documented default silently. Accepted values are passed
// through untouched, so the default, the "off"/"disabled"/"0" disable words and
// the [MinCatalogRefresh, MaxCatalogRefresh] clamp stay toolbelt's policy alone
// (its clamp warning echoes only a duration that already parsed, which cannot be
// a secret).
func parseCatalogRefresh(raw string) time.Duration {
	trimmed := strings.TrimSpace(raw)
	switch strings.ToLower(trimmed) {
	case "", "off", "disabled":
	default:
		// Parse the TRIMMED but NOT lowercased value: scheduler.ParseInterval
		// lowercases only for the off/disabled sentinels and hands the trimmed
		// string to time.ParseDuration, whose units are case-sensitive. Gating on
		// a lowercased copy would pass "24H" through to the library's
		// value-echoing warnFallback.
		if d, err := time.ParseDuration(trimmed); err != nil || d < 0 {
			slog.Warn("unusable "+catalogRefreshKey+"; using the built-in catalog refresh cadence",
				"hint", `use a Go duration (e.g. 24h, 90m) or "off" to disable the schedule`)
			raw = ""
		}
	}
	return toolbelt.ParseCatalogRefresh(raw, catalogRefreshKey)
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
// Read with envx.BoolStrict, NOT envx.Bool, and that choice is the
// confidentiality property rather than a style preference: a compose expansion
// mistake can put a secret on this key (`KWEB_LOG_OSC_TEXT: ${SOME_TOKEN}`), and
// envx.Bool's malformed path emits a Warn carrying the RAW value — a durable,
// queryable copy of that secret in the log store (CWE-532). BoolStrict shares
// ONE parser with Bool, so the accepted vocabulary (true/1/yes/on,
// false/0/no/off, case-insensitive, padding ignored) cannot drift from the
// fleet's, but it logs nothing at all and hands the parse result back instead:
// the error it returns names only the key and the accepted spellings, never the
// value. Do NOT "simplify" this to envx.Bool — the two differ only in who owns
// the diagnostic, and Bool's diagnostic is the leak. The same reasoning keeps
// KWEB_LOG_LEVEL a string read and TOOL_CATALOG_REFRESH behind
// parseCatalogRefresh.
//
// This function owns all the policy around that read, and every part of it is
// load-bearing: an unreadable value falls back to false (off — the fail-closed
// direction, so a typo cannot widen what content is logged), the failure emits
// exactly ONE Warn naming the KEY only (the returned error is deliberately not
// logged, so no future change to its text can reach a log record either), and
// the ON state warns separately about the widened content. A test drives THIS
// function — the one main calls — to assert the malformed path emits one Warn
// with no copy of the raw value anywhere in it.
func parseLogOSCText() bool {
	const key = "KWEB_LOG_OSC_TEXT"
	// The ok result is unused on purpose: the fallback is false and BoolStrict
	// returns false when the key is unset, so "unset" and "set to false" need no
	// distinguishing here.
	logOSCText, _, err := envx.BoolStrict(key)
	if err != nil {
		// Fail closed, stated rather than inherited from BoolStrict's zero
		// value. err itself is never logged: the warning must name the key and
		// nothing else.
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
//
// Called once per SESSION, not once per process: cliPath is the manager's active
// version directory path, which changes when the active version does, so a boot
// constant would pin every tab to whatever was installed first. An empty cliPath
// (no version active) degrades into the guard's own "not installed" message, which
// only a caller that bypassed the session-create gate can reach.
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
	workDir := envx.String("KWEB_WORK_DIR", "/workspace")

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
		configDir: configMountDir,
		// The SAME env var startKiroCLI reads below, so the tools tree has one
		// source of truth: entrypoint.sh exports the path it created and
		// hardened, and both co-owners write to that one. Empty outside the
		// container, where startTools falls back to <configDir>/tools.
		toolsDir:    envx.String("KIRO_CLI_TOOLS_DIR", ""),
		catalogPath: envx.String("TOOL_CATALOG_PATH", "/app/tool-catalog.json"),
		// Runtime catalog refresh: the baked catalog above is only the
		// first-boot/offline fallback; the engine fetches the published
		// catalog at boot and every TOOL_CATALOG_REFRESH (default 24h;
		// "off"/"0" disables the schedule, keeping the loopback API's
		// manual refresh). Every fetched catalog re-verifies the
		// embedded required-tools list before it replaces the current
		// one, and the last good catalog stands on any failure.
		catalogURL:      envx.String("TOOL_CATALOG_URL", toolbelt.DefaultCatalogURL),
		refreshInterval: parseCatalogRefresh(envx.String(catalogRefreshKey, "")),
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
	//
	// kiro-cli itself is installed and selected by the manager startKiroCLI builds:
	// the per-session argv and PATH come from it, so a version switch is picked up by
	// the next tab rather than being frozen at boot.
	// The entrypoint's taint observation goes through the fleet's ONE boolean
	// parser rather than a local == "1": envx.Bool/BoolStrict share a single
	// vocabulary (true/1/yes/on, false/0/no/off, case-insensitive, trimmed), so
	// the shell-to-Go boundary cannot drift on spelling or padding. BoolStrict,
	// not Bool, for the same reason parseLogOSCText uses it: Bool's
	// malformed-value Warn echoes the RAW value, and this key crosses a compose
	// boundary. An unreadable value keeps today's outcome (false = trust the
	// tree's own sentinels); the error is deliberately dropped rather than
	// logged, so no future error text can carry a value fragment either.
	tainted, _, _ := envx.BoolStrict("KIRO_CLI_TOOLS_TAINTED")
	kiro := startKiroCLI(&baseKiro{
		version:     envx.String("KIRO_CLI_VERSION", ""),
		sha256:      envx.String("KIRO_CLI_SHA256", ""),
		sha256ARM64: envx.String("KIRO_CLI_SHA256_ARM64", ""),
		toolsDir:    envx.String("KIRO_CLI_TOOLS_DIR", ""),
		tainted:     tainted,
		chatArgs:    chatArgs,
	})

	mux := http.NewServeMux()
	var ready webhttp.Ready

	mgr, cspPolicy, err := registerRoutes(mux, &routeDeps{
		staticFS:     staticFS,
		cmd:          kiro.cmd,
		sessionEnv:   kiro.env,
		workDir:      workDir,
		ready:        &ready,
		kiroReady:    kiro.ready,
		kiroRescan:   kiro.rescan,
		logOSCText:   logOSCText,
		tools:        tools.engine,
		toolsSyncing: tools.syncing,
		toolsState:   tools.state,
	})
	if err != nil {
		slog.Error("route registration failed; the embedded static tree is unusable",
			"error", err,
			"hint", "this is a build defect, not a runtime setting: the embedded static/index.html must carry at least one inline <script> and exactly one inline <style> block; rebuild the image (go generate ./... plus the Dockerfile static build). The container will crash-loop under its restart policy until it is rebuilt.")
		kiro.stop()
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
		kiro.stop()
		tools.close()
		os.Exit(1)
	}

	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	// buildHandler wraps mux in the middleware stack (see its doc comment for the
	// ordering rationale). webhttp.NewServer supplies the streaming-safe defaults
	// (ReadHeaderTimeout 10s, IdleTimeout 120s, Read/WriteTimeout unset) that the
	// hijacked /ws stream needs.
	// WithSlogErrorLog keeps net/http's OWN diagnostics (temporary accept
	// failures, malformed requests) inside the slog stream this app documents as
	// its only observability channel; a nil ErrorLog routes them through the
	// legacy log package instead, with a different timestamp/level shape that
	// Loki cannot query alongside the access log. Warn, not Error: net/http's
	// principal accept-error path retries itself, so a transient listener hiccup
	// should not page — the level is the app's call, which is why the library
	// takes it as an argument rather than defaulting it. It resolves
	// slog.Default() as NewServer applies it, so the slogx.Setup above must
	// already have run; it has. Replaces the hand-rolled slog.NewLogLogger
	// recipe this app shared verbatim with its sibling servers.
	srv := webhttp.NewServer(
		buildHandler(mux, trustedProxies, cspPolicy, hostPolicy),
		webhttp.WithSlogErrorLog(slog.LevelWarn),
	)
	// BaseContext hands every request a context that the WithPreDrain hook below
	// cancels on shutdown; see that hook's comment for why cancelling baseCtx
	// (not srv.Shutdown) is what unblocks the always-open SSE stream.
	srv.BaseContext = func(net.Listener) context.Context { return baseCtx }

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
		kiro.stop()
		tools.close()
		os.Exit(1) //nolint:gocritic // exitAfterDefer: a failed Serve must exit non-zero; the deferred stop()/cancelBase() only release signal+context state the process exit reclaims anyway.
	}
	kiro.stop()
	tools.close()
}

// The layout facts this app brings to the kiro-cli install: where the convenience
// symlink goes, and what its own SHELL-era installer left on the volume.
const (
	// kiroLinkDir is the directory under the tools dir holding the
	// non-authoritative `docker exec … kiro-cli` convenience symlink. It is
	// co-owned by the toolbelt engine, which publishes bin/<tool> symlinks of its
	// own — which is why the legacy sweep names its targets instead of scanning it.
	kiroLinkDir = "bin"
	// legacyStagePrefix prefixed the shell installer's staging trees directly under
	// the tools dir. The managed staging trees live under the install root instead,
	// so anything matching this is an orphan its EXIT trap missed on a SIGKILL. It
	// ends in a dot so it cannot match the install root or the marker below.
	legacyStagePrefix = ".kiro-cli-stage."
	// legacyPurgeMarker records on the volume that the one-time migration sweep
	// completed, so it runs ONCE rather than walking the co-owned bin directory on
	// every boot. Dot-prefixed and directly under the tools dir, where the toolbelt
	// engine never looks (it enumerates only bin/, opt/, npm/ and python/) and
	// where neither the stage sweep nor the entrypoint's write-probe cleanup
	// (".write-probe.*") can match it.
	legacyPurgeMarker = ".kiro-cli-legacy-purged"
)

// baseKiro carries startKiroCLI's inputs: the three Renovate-pinned literals the
// entrypoint exports, the tools tree they install into, the taint observation only
// the entrypoint can make, and this deployment's extra chat flags.
type baseKiro struct {
	version     string
	sha256      string
	sha256ARM64 string
	toolsDir    string
	chatArgs    []string
	// tainted carries the entrypoint's tools-tree-was-writable observation.
	tainted bool
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
// environment: a bare `go run` outside the container. kiro-cli is resolved by
// bare name through the developer's own PATH, there is no PATH overlay, and
// there is no install to gate on — so the readiness policy is total and
// permissive and /api/health reflects only that the listener is up. In the image
// entrypoint.sh always exports the pins, so this shape is unreachable there.
func unmanagedKiroRuntime(chatArgs []string) kiroRuntime {
	argv := sessionCommand(kirocli.Name, chatArgs...)
	return kiroRuntime{
		cmd: func() []string { return argv },
		env: func() []string { return nil },
		// No install to gate on: the policy is total and permissive, so the
		// route layer never re-derives what an absent manager means.
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
// The install manager reports a TYPED reason (pinstall.Reason) that names only the
// distinction — "installing", "unavailable" — because the wording a consumer shows
// its own users is the consumer's. These four literals ARE that wording, and they
// are a published contract: an operator reads them from `docker inspect` and a
// monitoring probe, they are the 503 body of POST /api/sessions, and they are the
// reason text /api/health serves. Renaming one silently changes what
// every one of those consumers sees, so kiroReasonText is the single place they are
// produced and TestKiroReasonTextIsTheClientContract pins the exact strings.
const (
	reasonInstalling = "kiro-cli installing"
	reasonRetrying   = "kiro-cli install retrying"
	// reasonUnavailable is also the fallback for a rescan with no verdict to read,
	// and for a reason a future library version adds: a state we cannot name still
	// blocks sessions, and the terminal wording says so.
	reasonUnavailable = "kiro-cli unavailable"
	// reasonSettings is pinstall.ReasonAssertion in this app's terms. The only
	// REQUIRED assertion here is the profile's mandatory app.disableAutoupdates
	// (every setting kiroSettings passes is best-effort), so a withheld verdict
	// means exactly that the binary may replace itself and invalidate the verified
	// digest.
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
// SESSION CREATION wait, the same shape startTools uses for the toolbelt boot
// reconcile. A first-boot download therefore answers 503 with a reason instead of
// refusing connections, and an operator can reach /api/health, the static UI and the
// loopback APIs throughout.
//
// Three shapes come out of it: no pins at all (a bare `go run` outside the
// container), pins the manager cannot use (unready, so the fault is reported
// rather than hidden), and the managed install. There is no operator input that
// selects among them and no way to stand the manager down: inside the container
// the pins are always exported, so a managed install is the only kiro-cli this
// server ever runs, and the manager is the only source of its path.
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
		// The error is already logged by EnsureWithRetry (with the attempt count
		// and the in-container repair hint), and there is nothing here that could
		// act on it: the server must stay up either way.
		_ = mgr.EnsureWithRetry(ctx)
	}()
	// Copied out of cfg so the long-lived closure below owns its own value rather
	// than a pointer into the composition root's config.
	chatArgs := cfg.chatArgs
	return kiroRuntime{
		cmd: func() []string { return sessionCommand(mgr.Path(), chatArgs...) },
		env: func() []string { return sessionPathEnv(mgr.PathEntry()) },
		// The library reports a typed reason; this is the ONE place it becomes the
		// wording an operator reads, so every surface below serves the same text.
		ready: func() (bool, string) {
			ok, why := mgr.Ready()
			return ok, kiroReasonText(why)
		},
		rescan: mgr.Rescan,
		stop:   cancel,
	}
}

// kiroInstallConfig is this app's whole deployment of the kiro-cli release: the
// pins from the entrypoint, the tools tree, the taint observation and the local
// policy. The release PROFILE — the archive URL, the arch tokens, the in-archive
// installer, the probe argv, the licence notice and the mandatory auto-update
// assertion — is kirocli.Release()'s, shared with every other consumer of the same
// upstream.
//
// It is a function rather than an inline literal so the namespace test can build a
// manager from the EXACT configuration production runs (see
// kirocli_namespace_test.go): the collision it guards is a property of these
// values, not of a copy of them.
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
		// The chat sidecar is REQUIRED here because `kiro-cli chat` over a PTY IS
		// the product: a version directory holding only the main dispatcher answers
		// --version correctly and then kills every terminal at chat. The library
		// always requires the release's primary artifact, so this names only the
		// addition. No Optional set: kiro-cli-term is not installed at all here,
		// and the archive's copy is discarded with the staging home. vibekit's
		// required set has cardinality ONE for the mirror-image reason; do not copy
		// either set into the other repo without a caller that needs it.
		Require: []string{kirocli.Name + "-chat"},
		Assert:  kiroSettings(),
		Purge:   kiroLegacyPurge(),
		// The entrypoint's tools-tree-was-writable observation, which only the
		// entrypoint can make (secure_tools_dir). With it set, no pre-existing
		// version directory may be activated at all: a forgeable sentinel is
		// worthless evidence on a tree another host user could write, so only a
		// version this process installed from a digest-verified archive counts.
		// vibekit deliberately leaves this UNSET — it has no hardening pass that
		// could make the observation.
		Untrusted: cfg.tainted,
	}
}

// kiroSettings is this app's kiro-cli settings set, re-asserted against the active
// binary on every boot. Every one is best-effort: a failure warns and readiness is
// unaffected.
//
// app.disableAutoupdates is deliberately NOT in this list: kirocli.Release()
// declares it Mandatory, so the library forces it Required and merges it in
// whatever a deployment passes — the integrity gate cannot be weakened, reworded or
// dropped from here. The two notification settings are load-bearing for the per-tab
// status dots (routes.go's OSC 9 classifier only sees a notification kiro-cli was
// told to emit inline), and terminalTitle=false is what lets the tabs feature name
// each tab after the user's own input instead of the cwd.
func kiroSettings() []pinstall.Assertion {
	return []pinstall.Assertion{
		kirocli.Setting("telemetry.enabled", false),
		kirocli.Setting("chat.enableNotifications", true),
		// Raw because the value is not a boolean.
		kirocli.SettingRaw("chat.notificationMethod", "osc9"),
		kirocli.Setting("chat.terminalTitle", false),
	}
}

// kiroLegacyPurge describes the layout THIS APP's shell installer left on the tools
// volume, which is caller data: the residue is a fact about this app's history, not
// about the kiro-cli release. Nothing in this list is read by anything any more, so
// deleting it outright is the resolution of the inherited-open-journal state —
// deletion, not a journal decoder, a rollback path or a legacy ready-fallback.
//
// The artifact list is larger than vibekit's on purpose: this app's shell installer
// promoted in place, so it DID write an update journal, `.prev` hard-link backups
// with their `.absent` tombstones, both install-completion markers and a readiness
// marker. vibekit's promotion was single-commit-point and wrote none of them; do
// not copy this list there.
//
// The dispatcher names come from the library profile rather than a local slice:
// they are the set a shell-era kiro-cli installer promoted, which is release
// knowledge. Naming three targets is also what makes the sweep safe in a directory
// the toolbelt engine co-owns — a `kiro-cli*` prefix sweep deleted every match,
// including another owner's live symlink.
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

// sessionPathEnv returns the per-session environment overlay that puts the active
// kiro-cli version directory FIRST on PATH, or nil when no version is active.
//
// Leading is the point, not a detail. That directory holds only kiro-cli's own
// dispatchers, so it shadows nothing else, while $TOOLS/bin is co-owned by the
// toolbelt engine and $TOOLS/go/bin is GOPATH/bin, where a `go install` can land
// anything -- including a stale kiro-cli-chat from a restored backup volume. With the
// version directory first, `kiro-cli chat` resolves its sidecar out of the same
// verified install whether it looks for a sibling of its own executable or for a bare
// name on PATH.
func sessionPathEnv(entry string) []string {
	if entry == "" {
		return nil
	}
	if inherited := os.Getenv("PATH"); inherited != "" {
		return []string{"PATH=" + entry + string(os.PathListSeparator) + inherited}
	}
	// No inherited PATH: return the version directory ALONE. Appending an empty
	// value would leave a trailing separator, and an empty PATH element resolves to
	// the child's cwd (KWEB_WORK_DIR, the user's own checkouts), so the degenerate
	// case would widen the search path instead of narrowing it.
	return []string{"PATH=" + entry}
}

// configMountDir is the persistent bind mount every deployment gives this
// container, fixed by the image rather than configurable. The env knob that used
// to name it is DELETED, and the deletion is guarded (see
// tests/shell/pins_export_test.sh): it relocated only toolbelt's three metadata
// files (tools.json, tools-state.json, tool-catalog.cached.json) while the
// artifacts they describe, $HOME (/config/home, fixed by the Dockerfile and
// refused outside /config by entrypoint.sh) and the kiro-cli install root all
// stayed put — so its only reachable effect was splitting one subsystem across
// two volumes. The one thing this path still decides is whether this process has
// a /config to persist into at all (startTools' stat gate), plus the base the
// tools root is derived from when no entrypoint exported one.
const configMountDir = "/config"

// baseTools carries startTools's inputs (resolved paths + the
// catalog-refresh knobs).
type baseTools struct {
	// configDir is the persistence mount (configMountDir in the container, a
	// temp dir in tests). It is NOT toolbelt's ConfigDir: the engine's config
	// and tools dirs are both the tools root below, since the manifest, the
	// machine state and the catalog cache describe the tree they now sit in.
	configDir string
	// toolsDir is the tools tree both co-owners write to: the entrypoint's
	// exported, hardened KIRO_CLI_TOOLS_DIR when present, else derived from
	// configDir for out-of-container runs (bare `go run`, tests). One
	// resolution site, so the toolbelt engine and the kiro-cli install
	// manager cannot disagree about where the tree is.
	toolsDir    string
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
	// syncing | ok | degraded. LIVE, not boot-only: after the boot
	// verdict it tracks the tools engine's counted jobs (see toolsStatus).
	state func() string
}

// The three documented values of /api/health's informational tools field. Each is
// named rather than inlined because every one of them is written from more than
// one site and a health consumer keys on the literal.
const (
	// toolsStateSyncing is the verdict while the boot convergence pass runs
	// (the window in which POST /api/sessions answers 503 "tools installing").
	toolsStateSyncing = "syncing"
	// toolsStateOK is the converged verdict, reported both when the boot
	// reconcile finishes clean and when an empty manifest leaves nothing to
	// converge.
	toolsStateOK = "ok"
	// toolsStateDegraded is the verdict for a tools subsystem that FAILED, as
	// opposed to one deliberately absent (which omits the field entirely).
	// Reported from an unusable config path, a failed engine start and a
	// reconcile that could not be enqueued (startTools), from a wait
	// failure, a cancellation and a non-Done job (awaitBootConvergence),
	// and from a failed counted job (toolsStatus.observeJob).
	toolsStateDegraded = "degraded"
)

// toolsStatus is the app-owned reducer behind /api/health's INFORMATIONAL
// tools field. It is fed by the boot reconcile's verdict once and by the
// toolbelt engine's Config.OnJobChanged callback for the rest of the
// process's life, so the field reports LIVE tool state instead of latching
// the boot outcome until the container is recreated: an operator whose boot
// reconcile failed can repair the tools through the loopback tools API and
// watch the field leave "degraded" (a signal that can only get worse trains
// its reader to ignore it).
//
// STATE MACHINE — three states in one cell, written by two phases:
//
//	syncing   the initial value, and the only one never re-entered. It means
//	          "the boot convergence pass has not produced a verdict yet",
//	          which is exactly the window in which the session-create gate is
//	          closed and POST /api/sessions answers 503 "tools installing". A
//	          post-boot job running does NOT return the field here, because a
//	          health consumer reads "syncing" as that gated window.
//	ok        the tools tree last converged with intent. Entered from any
//	          state by the boot verdict (clean reconcile, or an empty manifest
//	          with nothing to converge) or by a COUNTED job reaching "done".
//	degraded  the last counted attempt to converge FAILED, or the subsystem
//	          never started. Entered from any state by the boot verdict or by
//	          a COUNTED job reaching "failed".
//
// Transitions: syncing -> {ok, degraded} by the boot verdict only, then
// ok <-> degraded freely for the rest of the run. degraded -> ok is the whole
// point of the type — a successful repair heals the field, where the boot-only
// latch it replaced could only ever get worse. Non-terminal transitions
// (queued, running) and cancellations are ignored: the engine cancels the
// running job from Close on every SIGTERM, so treating a cancel as a fault
// would report shutdown as breakage.
//
// The two phases are ORDERED rather than racing, which is why `booted` exists.
// The boot reconcile is itself a counted kind, and its terminal callback fires
// (under toolbelt's queue lock) up to one Wait poll BEFORE startTools' finish
// closure runs — so without the flag a converged boot would publish "ok" while
// the session gate was still closed, contradicting what "syncing" promises a
// health consumer above. The boot verdict is therefore authoritative until it
// is recorded, and the live reducer starts only after.
//
// This type is deliberately IGNORANT of the session-create gate and of
// kiro-cli readiness. It holds no reference to either, so a post-boot job
// failure cannot re-close session creation (the gate lifts on boot failure by
// design — degraded-not-dead — and that decision stays made) and cannot touch
// the install manager's separate verdict.
type toolsStatus struct {
	// state is the current value. atomic rather than a mutex to match the
	// syncing gate beside it, and because OnJobChanged fires under
	// toolbelt's own queue lock and must not block: the health handler
	// reads it on request goroutines.
	state atomic.Value // string: syncing | ok | degraded
	// booted reports whether the boot verdict has been recorded, i.e.
	// whether the live half of the reducer is armed. Set last by recordBoot
	// so a job transition can never overtake the verdict.
	booted atomic.Bool
}

// newToolsStatus returns a reducer parked in the pre-verdict boot state.
func newToolsStatus() *toolsStatus {
	s := &toolsStatus{}
	s.state.Store(toolsStateSyncing)
	return s
}

// get reads the current value for /api/health.
func (s *toolsStatus) get() string {
	v, _ := s.state.Load().(string)
	return v
}

// recordBoot stores the boot convergence pass's verdict and arms the live
// half. Called once, from startTools' finish closure, which separately lifts
// the session-create gate; the reducer half below never sees that gate. The
// store order is load-bearing: state first, then booted, so no job transition
// can land between them and be mistaken for the boot outcome.
func (s *toolsStatus) recordBoot(v string) {
	s.state.Store(v)
	s.booted.Store(true)
}

// observeJob is the Config.OnJobChanged reducer: it folds one job state
// transition into the field. Fires from toolbelt's job worker under the queue
// lock, so it does exactly one atomic store and never blocks.
func (s *toolsStatus) observeJob(j *toolbelt.Job) {
	if j == nil || !s.booted.Load() || !toolsStatusCounts(j.Kind) {
		return
	}
	switch j.State {
	case toolbelt.JobDone:
		s.state.Store(toolsStateOK)
	case toolbelt.JobFailed:
		s.state.Store(toolsStateDegraded)
	}
	// JobQueued/JobRunning are in-flight, and JobCancelled is not a fault
	// (Engine.Close cancels the active job on every shutdown) — both leave
	// the last settled value in place.
}

// toolsStatusCounts is the job-kind policy for the informational tools field,
// enumerated rather than defaulted to "anything that failed" — the excluded
// kinds are excluded for stated reasons, not by omission, and a job kind
// toolbelt adds later counts only once someone decides it should.
//
// COUNTED — a failure means a tool the manifest says should be on PATH is not
// there, which is the only thing this field claims:
//
//	install    provisioning one entry, and the REPAIR path. An operator fixing
//	           a failed boot through the loopback tools API produces exactly
//	           these, so this kind is what makes recovery observable at all.
//	reconcile  converge disk to intent: the boot pass, and any later one.
//
// EXCLUDED, one reason each:
//
//	catalog-refresh  fetch/verify/swap of the PUBLISHED CATALOG, not of any
//	                 installed tool. Failure is routine because keep-last-good
//	                 keeps serving the cached (or baked) catalog, and
//	                 startTools fires one at boot before the publisher is
//	                 necessarily reachable — counting it would report a fully
//	                 converged container as degraded on a network hiccup.
//	update           the unpinned-freshness pass awaitBootConvergence enqueues
//	                 after every boot. Its common failure is upstream version
//	                 resolution (network, rate limit), which changes nothing on
//	                 disk: the installed version stays on PATH. Counting it
//	                 would flip an offline box to degraded on every boot. A
//	                 bump that fails mid-install leaves a real gap, and the
//	                 next reconcile reports it.
//	uninstall        removal, not provisioning. A failed footprint removal
//	                 leaves an EXTRA binary behind, which does not stop the
//	                 tools tree from serving sessions.
//	disable          the same removal, keeping the manifest entry. Also
//	                 excluded on the SUCCESS side: letting a clean removal
//	                 store "ok" would whitewash an earlier real install
//	                 failure it proves nothing about.
func toolsStatusCounts(kind string) bool {
	switch kind {
	case toolbelt.JobKindInstall, toolbelt.JobKindReconcile:
		return true
	default:
		return false
	}
}

// degradedRuntime is the engine-less runtime a startTools failure returns:
// engine stays nil (no /api/tools mount) and syncing reports false (sessions
// ungated) while state reports degraded so the failure is visible on
// /api/health instead of looking like a deliberate disable.
func degradedRuntime() toolsRuntime {
	return toolsRuntime{
		syncing: func() bool { return false },
		state:   func() string { return toolsStateDegraded },
	}
}

func (t *toolsRuntime) close() {
	if t.engine != nil {
		t.engine.Close()
	}
}

// warnIfToolsBinUnreachable warns when the engine's single PATH directory
// (<toolsDir>/bin) is absent from this process's PATH. Every tool the manifest
// installs then provisions successfully — /api/health reports tools=ok and the
// language-server nudge stays silent because an LSP entry IS enabled — while no
// session, and therefore no kiro-cli PATH scan, can see any of it. Sessions
// inherit this process's environment plus the kiro-cli version overlay, so this
// process's PATH is the right thing to test.
//
// In the container the tools root is not configurable (entrypoint.sh hardens
// /config/tools and exports it as KIRO_CLI_TOOLS_DIR), so the reachable cause is
// a PATH that no longer contains it: a compose-level PATH override, or an image
// whose ENV PATH dropped the segment. Outside the container a bare `go run`
// inherits the developer's PATH, where the derived tree is expected to be absent.
//
// Warn, never fatal: a mismatch is the operator's to resolve (adjust PATH, or
// move the mount), and this app's failure posture keeps a misconfigured dev box
// reachable rather than aborting boot on persistent-volume layout.
func warnIfToolsBinUnreachable(toolsDir string) {
	binDir := filepath.Clean(filepath.Join(toolsDir, "bin"))
	for entry := range strings.SplitSeq(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if entry != "" && filepath.Clean(entry) == binDir {
			return
		}
	}
	slog.Warn("the tools tree is not on PATH: every tool the manifest installs will be invisible to kiro-cli and to terminal sessions, even though /api/health will report tools=ok",
		"tools_bin", binDir,
		"hint", "add "+binDir+" to this process's PATH. In the container that means the image's ENV PATH (or a compose override of it) no longer leads with the tools tree entrypoint.sh hardened and exported; outside it, a bare `go run` inherits the developer's PATH, so the derived tree is expected to be absent from it.")
}

// logRootIntegrityFindings turns a toolbelt root-integrity refusal into one
// operator-queryable line per offending root. toolbelt logs the refusal too, but
// as a single joined string, so without this the degraded /api/health verdict is
// backed only by a message nothing can be filtered on: which root and why are
// the two things an operator needs, and they belong in fields.
//
// A non-integrity error is not this function's business (its caller logs every
// error the same way it always did); errors.As simply finds nothing and returns.
func logRootIntegrityFindings(err error) {
	var unfit *toolbelt.RootIntegrityError
	if !errors.As(err, &unfit) {
		return
	}
	// ConfigDir and ToolsDir are the SAME directory for this app (one
	// subsystem, one root), and toolbelt judges each of its two arguments in
	// turn, so a finding about the root ITSELF arrives twice. The library sorts
	// findings by path then reason, which puts any such pair adjacent.
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

// startTools builds the toolbelt engine and launches the boot
// convergence pass (bind-first: the listener comes up while installs
// run; only session CREATION waits, via the syncing gate). The gate
// lifts regardless of per-tool failures — degraded-not-dead, matching
// the retired setup-tools.sh warn-and-continue posture — and the
// health detail records the verdict. That detail then keeps tracking the
// engine's counted jobs for the rest of the run (toolsStatus), so a repair
// through the loopback tools API heals it without a restart; the gate is a
// separate cell the reducer cannot reach. After convergence an async update
// pass refreshes unpinned tools, and a boot warning nudges when no
// language server is enabled (kiro-cli scans PATH for LSPs at session
// start).
func startTools(cfg baseTools) toolsRuntime {
	// Three distinct outcomes, deliberately NOT collapsed: only a genuinely
	// ABSENT directory is the intentionally-disabled out-of-container shape
	// (zero runtime, health omits the tools field). A stat failure for any
	// other reason (permission, I/O, ELOOP) or a non-directory mounted at
	// the config path is a FAILED production subsystem, so it follows the
	// same degraded-not-dead contract as a failed toolbelt.New below —
	// otherwise the operator reads a broken mount as "tools deliberately off".
	fi, statErr := os.Stat(cfg.configDir)
	switch {
	case errors.Is(statErr, fs.ErrNotExist):
		slog.Warn("tools engine disabled: config dir missing",
			"config_dir", cfg.configDir,
			"hint", "bind-mount the persistent config volume (compose.yaml)")
		// No tools surface: engine stays nil (no /api/tools mount) while the
		// policies stay callable; "" keeps health's omitempty tools field absent.
		return toolsRuntime{
			syncing: func() bool { return false },
			state:   func() string { return "" },
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
	// The tool subsystem's ONE root, named once: it is the engine's ToolsDir,
	// the directory whose bin/ every session must find on PATH, AND the engine's
	// ConfigDir. Those last two are the same path on purpose. toolbelt keeps
	// three metadata files under ConfigDir — tools.json (hand-authored intent),
	// tools-state.json (engine-owned machine state) and
	// tool-catalog.cached.json — and every one of them describes the artifacts
	// under ToolsDir, so a layout that let them sit in different volumes was one
	// subsystem with two homes: state describing a tree that might not be there.
	// Prefer the path the entrypoint hardened and exported; the derivation is the
	// out-of-container fallback only.
	toolsRoot := cfg.toolsDir
	if toolsRoot == "" {
		toolsRoot = filepath.Join(cfg.configDir, "tools")
	}
	warnIfToolsBinUnreachable(toolsRoot)
	refresh := &toolbelt.CatalogRefresh{
		URL:      cfg.catalogURL,
		Require:  toolbelt.ParseRequireList(requiredToolsList),
		Interval: cfg.refreshInterval,
	}
	// The informational-status reducer is built BEFORE the engine so it can be
	// wired as the engine's job-transition callback: from here on the health
	// field follows live job outcomes, not just the boot verdict.
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
		// The library's opt-in prerequisite check: refuse to construct an engine
		// over a managed root that is a symlink, is not a directory, is
		// group/other-writable, or resolves outside the tree. It fits this app's
		// premises exactly — the tree is an operator-controlled persistent
		// volume, this process runs as root, and toolbelt's install probe
		// EXECUTES what it finds in <ToolsDir>/bin with that dir first on PATH.
		//
		// ADDITIVE to entrypoint.sh, which stays as it is: only the entrypoint
		// can chmod and re-stat to prove a tightening took, produce the
		// KIRO_CLI_TOOLS_TAINTED observation the kiro-cli install manager
		// consumes, cover the trees outside toolbelt's four roots
		// ($TOOLS/kiro-cli-versions, $TOOLS/go{,/bin}, /config, /config/home),
		// and apply this app's fatal-vs-warn policy per directory. What the
		// library adds is the window the entrypoint cannot cover: a root
		// reshaped AFTER the entrypoint ran. It reports only, never repairs, so
		// a refusal here degrades (below) and leaves the repair with the
		// operator, per this app's failure posture.
		VerifyRootIntegrity: true,
	})
	if err != nil {
		slog.Error("tools engine failed to start; continuing without it", "error", err)
		// A root-integrity refusal names every offending path; break those out
		// into their own lines so "degraded" is diagnosable (no-op for any
		// other error class, which keeps the single line above).
		logRootIntegrityFindings(err)
		// Unlike the missing-config-dir path (an intentionally disabled
		// subsystem: no engine, empty state, no health detail), a FAILED
		// production subsystem must stay visible: report state "degraded" so
		// /api/health carries the documented informational tools field.
		// The engine stays nil and syncing reports false, so sessions remain
		// ungated.
		return degradedRuntime()
	}

	var syncing atomic.Bool
	// finish is the ONLY function that touches both halves: it records the boot
	// convergence verdict (arming the live reducer) and lifts the session-create
	// gate. The gate is a separate cell from the health field on purpose — the
	// live reducer (status.observeJob, wired above) closes over no gate state at
	// all, so a post-boot job failure can update the informational field without
	// ever re-closing session creation. Boot failure lifting the gate is
	// deliberate (degraded-not-dead), and nothing may put it back.
	finish := func(v string) {
		status.recordBoot(v)
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
		state:   status.get,
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
		// cause is the engine's own attribution (CancelShutdown from Engine.Close,
		// CancelCaller from an explicit CancelJob, "unknown" for a path that names
		// none): the two readings of this line call for different operator responses,
		// so record which one it was instead of listing both in the hint.
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

// sessionNoStore marks the ENGINE's session surface uncacheable on the responses
// the engine itself does not cover. It is what remains of the app's former
// /api/-wide apiNoStore middleware, narrowed to the one place a header would
// otherwise be lost.
//
// Why any wrapper is still here. A session id is the /ws attach + resume
// capability token — the same value routes.go's LogID truncates before logging
// and WithTemplatePathsUnder keeps out of the access log — and a response with no
// freshness information is heuristically cacheable under RFC 9111 §4.2.2 (200,
// 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501), so with no directive it
// is stored by the browser's disk cache and by a caching reverse proxy, the
// README's recommended deployment shape.
//
// Why it is scoped HERE and nowhere else, measured rather than assumed against
// engine v3.2.1 (the enumeration is TestAPICachePolicy_EveryAPIPathSetsNoStore,
// which fails if any row's owner stops setting the header):
//
//   - /api/tools + subtree — toolbelt's httpapi sets no-store on every response
//     of its own as of v2.3.0, upstream of its mux, so its 404s and 405s are
//     covered too. This is what let the /api/-wide wrapper go.
//   - /api/health, POST /api/kiro-cli/rescan — each handler sets it itself.
//   - /api/sessions, POST /api/sessions, /api/sessions/events — the engine sets
//     it: terminal's writeJSON on create/list, "no-cache, no-store" on the SSE
//     stream.
//   - EVERYTHING ELSE under /api/sessions — NOT covered by the engine. writeJSON
//     is reached only by create and list, so the REST handler's 204s (close,
//     set/clear title), its http.Error 400/404s, and its inner mux's own 404/405
//     (e.g. GET on a session path that only serves DELETE) all carry no
//     Cache-Control at all. That is this wrapper's entire remaining job.
//
// Most of that uncovered set is unreachable by a cache anyway — RFC 9111 §3
// forbids storing a response to a method a cache does not understand as
// cacheable, which excludes every DELETE/PUT/PATCH — so the genuinely cacheable
// remainder is the GET/HEAD 404s and 405s in the subtree, whose bodies are
// net/http's constant error text and carry no session data. The header is kept
// anyway rather than reasoned away: this costs one map write on a surface that
// issues capability tokens, and the argument that a 405 is harmless has to be
// re-derived correctly by every future reader.
//
// This is the ENGINE's gap to close, not the app's. When the engine adopts the
// same upstream-of-mux default toolbelt just did, delete this wrapper and its
// chain entry — the enumeration test then holds with no app middleware at all.
// Scoped by the engine's own exported path constant (a prefix, so it covers the
// exact path and the subtree) so the static surface keeps kiroCacheControl's
// ETag/immutable policy untouched.
func sessionNoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, terminal.SessionsPath) {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// buildHandler wraps the route mux in web-terminal-kiro's middleware stack via
// webhttp.Chain. Chain(h, A, B, C, D) == A(B(C(D(h)))), so the first entry is
// the outermost wrapper; a request flows Logging -> Recoverer -> wsAttachLog ->
// SecurityHeaders -> sessionNoStore -> host allowlist -> CrossOriginProtection ->
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
//   - sessionNoStore — Cache-Control: no-store on the responses the ENGINE's
//     session surface leaves without one (see sessionNoStore for the measured
//     enumeration and the capability-token rationale). Scoped to the engine's
//     session path so the static surface keeps kiroCacheControl's policy, and
//     placed outside the host/origin gates so even a rejected request is
//     uncacheable.
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
			// The /ws access-log skip is webhttp's WithSkipUpgrades, and the
			// decision it makes is an OUTCOME rather than a prediction: it
			// suppresses the record only for a response that actually switched
			// protocols (a recorded 101, or a hijack with nothing recorded), which
			// is the state that makes the line a lie — the exchange ENDED at the
			// handshake, so the line emitted hours later at socket close carries a
			// session-length duration and a status net/http never sent. This
			// replaced a local willUpgrade predicate that re-implemented every
			// pre-hijack precondition of the engine's websocket.Accept (GET,
			// HTTP/1.1, Sec-WebSocket-Version: 13, exactly one Sec-WebSocket-Key)
			// in order to GUESS the same answer before the handler ran. That
			// coupled this app to another library's internals with nothing keeping
			// the copy in step, and it was already wrong in two places it could not
			// see: Accept base64-decodes the key and requires 16 bytes, so a
			// malformed-key 400 was suppressed as if it had upgraded, as was the
			// cross-origin 403 the predicate deliberately did not model. Both are
			// now logged with their real status, because the outcome test cannot
			// mistake a refusal for a stream: the 426 for missing upgrade headers
			// (the classic reverse-proxy misconfiguration, no `proxy_set_header
			// Upgrade`), the 405 for a non-GET, the 400 for a bad version or key,
			// the 403 for a rejected Host — every one of them keeps its line by
			// construction rather than by a predicate remembering to.
			webhttp.WithSkipUpgrades(),
			// SSE needs its own path-shaped skip, and the asymmetry with /ws is not
			// obvious enough to leave unstated: WithSkipUpgrades cannot cover the
			// status stream, because SSE never switches protocols. It is a plain
			// 200 that simply does not return until the client disconnects, so
			// switchedProtocol() is false for it and its record would START being
			// emitted — one misleading line per stream, with a session-length
			// duration, exactly what the /ws skip exists to prevent. /ws HAS a
			// non-stream shape worth logging (a handshake Accept answers short);
			// SSE has none, because a plain GET to this path is indistinguishable
			// from the stream itself. So the stream half is decided by the
			// response for /ws and by the path for SSE.
			//
			// A predicate rather than WithSkipPaths, for the hostPolicy.Allows
			// conjunct alone: skip rules are evaluated BEFORE the chain runs
			// (Logging returns early with no StatusRecorder), so a bare path skip
			// would also swallow the 403 hostPolicy.Middleware writes below --
			// WriteError logs nothing itself and the engine handler never runs --
			// leaving a wrong-Host or DNS-rebound attempt on this unauthenticated
			// PTY with no record anywhere (CWE-778). Asking the SAME policy object
			// that will decide the request is not the prediction problem
			// WithSkipUpgrades solved: webhttp exports Allows for this, and it is
			// the app's own gate rather than a re-implementation of a library's
			// internals. Allows is nil- and inactive-safe (it returns true), so an
			// unset KWEB_ALLOWED_HOSTS keeps today's behavior exactly.
			// The GET conjunct is the same reasoning as the hostPolicy one, one
			// layer further in. A skip predicate is evaluated BEFORE the chain
			// runs, so it deletes the record whatever status the request ends
			// with -- and CrossOriginProtection, which sits inside this skip,
			// rejects an UNSAFE cross-origin request with a 403 that WriteError
			// logs nowhere. Only a GET can become the stream this skip exists to
			// suppress (SSE is a GET, and the safe methods are the ones the
			// origin gate always admits), so restricting the skip to GET keeps
			// every reachable refusal on this path logged: the cross-origin 403,
			// the engine's 503 at the subscriber cap, its 500 for an
			// unflushable writer. The trade is that a non-GET request that IS
			// admitted (curl -X POST with no Origin -- the engine's
			// EventsHandler does not check the method) now emits one
			// close-time line with a session-length duration; a misleading line
			// for an abnormal client is the lesser cost against deleting an
			// attack's only record (CWE-778, and webhttp's own
			// WithSkipUpgrades doc says so in as many words).
			webhttp.WithSkipFunc(func(r *http.Request) bool {
				return r.Method == http.MethodGet &&
					r.URL.Path == terminal.SessionEventsPath && hostPolicy.Allows(r)
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
		sessionNoStore,
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
// (Upgrade: websocket plus the Upgrade connection option). It is wsAttachLog's
// "this request is trying to attach" test — an ATTEMPT predicate, which is why
// it survived the access-log skip's move to webhttp.WithSkipUpgrades: the two
// answer different questions. The access log now asks whether a request ENDED as
// a stream, after the fact, and nothing in this app predicts that any more (the
// willUpgrade mirror of websocket.Accept's preconditions is deleted). This asks
// whether a request is trying to attach, BEFORE the handshake runs, because the
// session capability token is in the query string and every attempt that looks
// like an attach must leave its audit record even when the handshake is
// malformed in some other way — including the shapes Accept refuses short (426
// without these headers, 405/400 with them but not a valid GET/13/keyed
// handshake), which now ALSO keep their access line. An attempt predicate cannot
// be replaced by an outcome: by the time the outcome is known, the request that
// presented the token may have been refused and there would be nothing to
// record.
func isWebSocketUpgrade(r *http.Request) bool {
	return headerHasToken(r, "Upgrade", "websocket") &&
		headerHasToken(r, "Connection", "upgrade")
}

// headerHasToken reports whether any field value of the named header carries
// token as a comma-separated element, case-insensitively. Both headers are
// comma-lists that may also arrive as repeated field lines (RFC 7230 3.2.2),
// and the engine's websocket.Accept matches them exactly this way — so this
// predicate must too, or wsAttachLog's attach record and the actual upgrade
// disagree about which requests were trying to attach (pinned against the real
// handshake by TestIsWebSocketUpgrade_agreesWithTheEngineHandshake).
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
