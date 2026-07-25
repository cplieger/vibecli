package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cplieger/toolbelt/v2"
	"github.com/cplieger/toolbelt/v2/httpapi"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
	"github.com/cplieger/webhttp"
)

// App-owned route paths. Every engine route comes from the engine's exported
// terminal.* path constants (WSPath, SessionsPath, SessionsSubtreePath,
// SessionEventsPath); these are the surfaces this app mounts itself, named
// once so a mount, a handler's declared base path, and the middleware policy
// that keys on the same path cannot drift apart across files.
const (
	// apiPrefix scopes the JSON API surface apiNoStore marks uncacheable.
	apiPrefix = "/api/"
	// healthPath is the readiness route; buildHandler's ProbeLogLevel policy
	// must name the same path the mux registers, or a healthy probe stops
	// being demoted to Debug and a failing one stops being promoted.
	healthPath = apiPrefix + "health"
	// toolsPath is the loopback tools API mount; httpapi.Handler is told the
	// same base path so its own routing matches where it is mounted.
	toolsPath = apiPrefix + "tools"
)

type routeDeps struct {
	staticFS fs.FS
	ready    *webhttp.Ready
	// tools, when non-nil, mounts the toolbelt httpapi projection at
	// /api/tools behind the loopback gate; toolsSyncing gates session
	// creation on the boot convergence pass; toolsState feeds the
	// /api/health informational tools field. All nil outside the
	// container (see startTools).
	tools        *toolbelt.Engine
	toolsSyncing func() bool
	toolsState   func() string
	workDir      string
	// kiroReadyMarker, when non-empty, is a file the entrypoint touches only
	// after verifying a runnable, correctly-versioned kiro-cli is installed
	// (see entrypoint.sh). /api/health Stats it to reflect web-terminal-kiro's core
	// dependency. Empty (e.g. `go run`/tests outside the container) skips the
	// gate, preserving pure-listener readiness semantics.
	kiroReadyMarker string
	cmd             []string
}

// buildStaticSurface assembles the embedded-static serving surface: the
// static handler and the hash-pinned CSP policy string built from the same
// static tree, fail-loud on a malformed embed. webhttp.StaticHandler supplies
// the embedded-static mechanism (per-file content-hash ETags — embed.FS
// reports a zero ModTime, so a bare http.FileServer emits no validator and
// every load re-downloads the bundle — plus precomputed gzip and
// Vary: Accept-Encoding); the per-path cache POLICY stays this app's
// (kiroCacheControl below). Same helper as web-terminal-server, so the two
// family shells cannot drift on the mechanism again.
func buildStaticSurface(staticFS fs.FS) (http.Handler, string, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, "", err
	}
	cspPolicy, err := buildCSPPolicy(sub)
	if err != nil {
		return nil, "", err
	}
	staticSrv, err := webhttp.StaticHandler(sub, webhttp.WithStaticCacheControl(kiroCacheControl))
	if err != nil {
		return nil, "", err
	}
	return staticSrv, cspPolicy, nil
}

// registerRoutes wires the full route table on mux and returns the session
// manager (for shutdown) plus the hash-pinned CSP policy string built from the
// embedded index.html (for buildHandler's SecurityHeaders layer) — both derive
// from the same static tree, so they are assembled together, fail-loud.
func registerRoutes(mux *http.ServeMux, deps *routeDeps) (*terminal.SessionManager, string, error) {
	staticSrv, cspPolicy, err := buildStaticSurface(deps.staticFS)
	if err != nil {
		return nil, "", err
	}
	mux.Handle("/", staticSrv)

	mgr := terminal.NewSessionManager(newSessionFactory(deps),
		terminal.WithManagerLogger(slog.Default()),
		terminal.WithStatusClassifier(classifyStatus),
	)

	// The engine owns its route topology: MountAPI wires exactly its documented
	// set — /ws, /api/sessions (+ subtree), /api/sessions/events — and nothing
	// else, so no engine-internal route can appear on this unauthenticated
	// surface unannounced. The create gate rides webhttp's shared
	// session-create preset (burst 6, 1/s refill, standard 429 envelope): a
	// caller cannot fork kiro-cli processes without bound — a kiro-cli chat is
	// heavy, so this matters more here than for a plain shell — and this app
	// cannot drift from web-terminal-server on tuning, path, or envelope. The
	// topology lives in the engine, the throttle policy in webhttp; this app
	// just composes the two.
	//
	// The create gate composes two layers: the fleet-standard create
	// rate limit (inner), and — checked before it while the tools boot convergence runs —
	// a 503 that keeps the FIRST kiro-cli session from spawning before
	// the manifest's language servers are on PATH (kiro-cli scans PATH
	// once at session start). Static assets, /api/health, and the tools
	// API stay reachable throughout: the container is observable during
	// installs instead of connection-refused (the old blocking
	// setup-tools.sh window).
	createGate := webhttp.SessionCreateRateLimit(terminal.SessionsPath)
	if deps.toolsSyncing != nil {
		createGate = composeGate(createGate, deps.toolsSyncing)
	}
	mgr.MountAPI(mux, terminal.WithCreateGate(createGate))

	// Tools REST surface: the toolbelt httpapi projection, loopback-only.
	// The consumer is an agent inside the container (kiro-cli's ! shell
	// escape + curl localhost:9848); remote callers — LAN browsers
	// included — get 403. The gate checks the socket peer (RemoteAddr),
	// never forwarded headers, so it cannot be spoofed through a proxy.
	// Config-file edits + restart remain the primary toggle path; this
	// API is the no-restart alternative.
	if deps.tools != nil {
		toolsAPI := loopbackOnly(httpapi.Handler(deps.tools, toolsPath))
		mux.Handle(toolsPath, toolsAPI)
		mux.Handle(toolsPath+"/", toolsAPI)
	}

	mux.HandleFunc(healthPath, handleHealth(deps))

	return mgr, cspPolicy, nil
}

// newSessionFactory builds the per-session handler factory the session manager
// calls once per tab: one independent PTY-backed kiro-cli chat process with its
// own VT screen and scrollback. It owns three session-scoped policies — the
// LogID-truncated per-session logger (the session id is the /ws attach/resume
// capability token), the WithCommandLogValue argv redaction (deps.cmd carries
// operator KIRO_CLI_CHAT_ARGS values), and the fast-death Warn hook that
// surfaces a broken kiro-cli install.
func newSessionFactory(deps *routeDeps) func(string) *terminal.Handler {
	// Scrollback 5000 covers a /chat
	// transcript restore on reconnect (matches the client store's retained-line
	// cap). WithKeepUnfocused pins the process to the DEC 1004 "unfocused" state so
	// kiro-cli keeps emitting its focus-gated OSC 9 notifications (which drive the
	// classifier) even though no browser tab claims focus (design 7.2);
	// web-terminal-server deliberately does NOT use this, since a generic
	// shell/editor wants real focus reporting.
	//
	// No TERM_PROGRAM override here: the engine now advertises TERM_PROGRAM=
	// iTerm.app (>= 3.6.6), which puts kiro-cli in its OSC 9;4 progress allowlist
	// (driving the tab's "working" dot) and enables DEC 2026 synchronized output.
	// That is the same identity web-terminal-server gets, so web-terminal-kiro inherits it
	// from the engine rather than pinning its own (it formerly set WezTerm; both
	// unlock kiro-cli, and iTerm.app additionally covers other agents like Claude
	// Code). Anything the engine can't render (inline images) is consumed silently.
	return func(id string) *terminal.Handler {
		start := time.Now()
		// The session id doubles as the /ws attach + resume capability token,
		// so only the engine's LogID-truncated form is ever bound to a
		// logger: the full value would hand terminal access to anyone with
		// log-read access and network reach. LogID is the engine's own
		// definition (one fleet-wide answer for how much of a session token
		// may be logged), test-pinned there.
		safeID := terminal.LogID(id)
		// The engine logs the session's full argv as the "command" attr when
		// the process starts (Handler.ensureStarted), and deps.cmd carries
		// the operator's KIRO_CLI_CHAT_ARGS values — a value-bearing flag
		// there could hold a credential from a compose interpolation mistake
		// (CWE-532) — so the engine is told to record the fixed "[redacted]"
		// marker instead (WithCommandLogValue), the same way main.go's own
		// startup line logs only chat_args_count.
		sessionLogger := slog.Default().With("session", safeID)
		return terminal.NewHandler(deps.cmd,
			terminal.WithWorkDir(deps.workDir),
			terminal.WithScrollbackCapacity(5000),
			terminal.WithKeepUnfocused(),
			terminal.WithLogger(sessionLogger),
			terminal.WithCommandLogValue("[redacted]"),
			// A session whose process dies within seconds of spawn is the
			// kiro-cli-missing/broken signature (the sign-in guard exits 1
			// when the binary is absent or login fails instantly). The
			// engine logs child exit at Info by design; this app-level hook
			// raises the fast-death case to Warn so a broken install on the
			// persistent volume is visible to operators, not only in the PTY.
			// Gated on deps.ready: an app-initiated shutdown (SIGTERM
			// pre-drain, or the Serve-error path) clears readiness before
			// mgr.Shutdown cancels the child processes, whose killed/canceled
			// wait errors would otherwise fire this warning as a false
			// broken-install alert on every deploy. Only spontaneous early
			// exits while still serving are promoted to Warn; intentional
			// shutdowns keep the engine's normal INFO exit record.
			terminal.WithOnProcessExit(func(err error) {
				if err != nil && deps.ready.Ready() && time.Since(start) < 10*time.Second {
					sessionLogger.Warn("session process exited almost immediately after start; kiro-cli may be missing or broken",
						"error", err,
						"hint", "check /api/health and the kiro-cli install under /config/tools/bin")
				}
			}),
		)
	}
}

// handleHealth returns the /api/health readiness handler. It reflects, in
// order: listener readiness (deps.ready), the env-gated kiro-cli readiness
// marker (deps.kiroReadyMarker; see the entrypoint), and the INFORMATIONAL
// tools field (deps.toolsState) — tool convergence never gates readiness.
func handleHealth(deps *routeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		unready := func(reason string) {
			webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unready",
				"reason": reason,
			})
		}
		if !deps.ready.Ready() {
			unready("starting up or shutting down")
			return
		}
		// kiro-cli readiness (env-gated via kiroReadyMarker). web-terminal-kiro's core job
		// is spawning kiro-cli chat PTYs, but the HTTP listener comes up even when
		// the first-boot install failed (degraded-not-dead start). Reflect the
		// entrypoint's boot-time verdict here so a broken kiro-cli surfaces as
		// unready to `docker ps` and the monitoring probe. A cheap Stat keeps this
		// spawn-free: kiro-cli was verified once at boot via --version, never
		// relaunched per probe (a per-probe spawn of a heavy PTY process would be
		// an anti-pattern). This is a READINESS signal, not liveness — under
		// `restart: unless-stopped` nothing restarts on the resulting unhealthy
		// state, so there is no restart loop; if ever run under Swarm/k8s, wire
		// this to a readinessProbe, not a livenessProbe.
		if deps.kiroReadyMarker != "" {
			if _, err := os.Stat(deps.kiroReadyMarker); err != nil {
				unready("kiro-cli unavailable")
				return
			}
		}
		// The tools field is INFORMATIONAL: tool convergence never gates
		// readiness (kiro-cli is the only core dependency), so monitoring
		// stays green during a long first-boot install window while
		// operators can still see it (syncing | ok | degraded).
		body := map[string]string{"status": "ok"}
		if deps.toolsState != nil {
			body["tools"] = deps.toolsState()
		}
		webhttp.WriteJSON(w, body)
	}
}

// unrecognizedNotifyOnce promotes the FIRST unrecognized OSC 9 notification of
// the process to Warn, so a kiro-cli notification-wording drift is visible in the
// DEFAULT (info) log stream instead of only under KWEB_LOG_LEVEL=debug. Bounded to
// one line per process: a build that legitimately emits some other notification
// cannot flood the shipped stream, and the Debug trace below still records every
// occurrence.
var unrecognizedNotifyOnce sync.Once

// classifyStatus maps kiro-cli's OSC 9 notification text to a latched session
// status for the tab activity dots: "Response complete" at the end of an agent
// turn latches the done (green) state, and "Permission required" when a tool
// call is blocked on approval latches the needs-input (amber) state (confirmed
// against the pinned 2.14.1 build's kiro-cli-chat notifier strings — the
// strings live in the kiro-cli-chat sidecar binary, not the kiro-cli
// dispatcher, so re-verify both strings there after every kiro-cli bump, in
// the same PR as the pin move). A new
// working phase (the OSC 9;4 progress
// signal, enabled by the factory's TERM_PROGRAM) clears the latch. Any other
// message is ignored. This mapping is the only kiro-cli-specific coupling; the
// engine stays generic (a plain shell server sets no classifier and derives
// working/idle from output activity).
func classifyStatus(msg string) (string, bool) {
	switch msg {
	case "Response complete":
		return terminal.StatusDone, true
	case "Permission required":
		return terminal.StatusInput, true
	default:
		// Any OSC 9 text the pinned kiro-cli build does not emit for turn-end or
		// tool-approval. If a kiro-cli bump reworded "Response complete"/"Permission
		// required", every notification lands here and the per-tab status dots
		// silently stop latching. The FIRST occurrence warns (visible at the
		// default info level, bounded to one line per process); the Debug line
		// records every occurrence, so KWEB_LOG_LEVEL=debug is what shows the
		// full set of unrecognized strings after a version bump.
		// msg is safe to log raw: the engine's sanitizeNotification strips
		// every runesafe-unsafe rune (C0/C1 controls, Bidi controls, U+2028/29)
		// and rune-caps the text before the classifier ever sees it.
		unrecognizedNotifyOnce.Do(func() {
			slog.Warn("unrecognized kiro-cli OSC 9 notification; tab status dots will not latch (kiro-cli notification wording may have changed on a version bump)",
				"message", msg,
				"hint", `re-verify the "Response complete" / "Permission required" strings in the pinned kiro-cli-chat binary and update classifyStatus; set KWEB_LOG_LEVEL=debug for every occurrence`)
		})
		slog.Debug("unrecognized kiro-cli OSC 9 notification; tab status dots will not latch (kiro-cli notification wording may have changed on a version bump)", "message", msg)
		return "", false
	}
}

// kiroCacheControl is the per-asset Cache-Control policy handed to
// webhttp.StaticHandler (which supplies the ETag/gzip mechanism; asset paths
// arrive normalized, no leading slash):
//   - fonts (vendor/fonts/**): immutable, 30 days. The Monaspace .otf
//     files are large (~2.4 MB each, ~9.4 MB total) and their glyphs are
//     fixed for a given vendored web-terminal-ui version, so immutable
//     avoids re-downloading them on every visit. CAVEAT: the filenames
//     are NOT content-addressed (no hash), and immutable suppresses even
//     reload revalidation — a font whose bytes change under the SAME
//     filename is served stale for up to 30 days. A font swap must change
//     the path/filename (or hash it at vendor time) to bust the cache.
//   - everything else (HTML/JS/CSS, ~1–30 KB modules): no-cache +
//     must-revalidate so deployments take effect immediately. The helper's
//     content-hash ETag lets unchanged files revalidate with a cheap 304;
//     the hash changes only when the bundle bytes change, busting the cache
//     exactly on a deploy and keeping the TS engine bundle in lockstep with
//     the server wire protocol.
func kiroCacheControl(assetPath string) string {
	if strings.HasPrefix(assetPath, "vendor/fonts/") {
		return "public, max-age=2592000, immutable"
	}
	return "no-cache, must-revalidate"
}

// cspTemplate is the Content-Security-Policy applied to every response, with a
// %s placeholder for the script-src hash tokens and a second one for the
// style-src hash token. It is deliberately the SAME policy shape as
// web-terminal-server's (both apps serve the same engine/UI bundle, so their
// needs are identical):
//
//	style-src 'self' <hash>     index.html's single loading-overlay <style> is
//	                            hash-pinned like the inline scripts, so an
//	                            injected style block or style attribute cannot
//	                            obscure or spoof the terminal UI. The renderer
//	                            itself needs no relaxation: it styles via CSSOM
//	                            property setters, which style-src does not
//	                            govern, and neither the UI nor the engine
//	                            template emits a style= attribute
//	img-src 'self' data:        favicon/icon data URIs
//	connect-src 'self'          same-origin HTTP + the /ws WebSocket PTY
//	frame-ancestors 'none'      blocks clickjacking of the interactive terminal
const cspTemplate = "default-src 'self'; " +
	"script-src 'self' %s; " +
	"style-src 'self' %s; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; object-src 'none'; " +
	"form-action 'none'"

// buildCSPPolicy reads index.html from sub, hashes every inline <script> in it
// (via webhttp.InlineScriptHashes) plus its single inline <style> block (via
// webhttp.InlineStyleHashes) — both the byte-precise scanners that hash exactly
// the content a browser hashes — and assembles the full CSP string.
// web-terminal-kiro's index.html carries TWO inline scripts -- the importmap
// and the bootstrap watchdog (the script-load-failure alertdialog) -- both
// hashed; the external /app.js module is covered by script-src 'self'. FAIL
// LOUD: a
// malformed build — a nil FS, an unreadable index.html, zero inline scripts, or
// anything other than exactly one <style> block
// — aborts startup rather than silently dropping the script-src or style-src
// hardening or
// serving a hash set that would block the importmap and break ES module
// loading. (This ports web-terminal-server's hash-pinned CSP; web-terminal-kiro
// previously shipped no CSP at all — the family-drift item the 2026-07
// judgement run flagged.)
//
// The one-block assertion stays HERE rather than in the library: "exactly one"
// is this app's contract about its own page, not a property of style hashing.
// The local byte scanner this used to carry (its own index-preserving ASCII fold
// duplicating webhttp's) is gone now that the library owns the style half too.
func buildCSPPolicy(sub fs.FS) (string, error) {
	if sub == nil {
		return "", errors.New("buildCSPPolicy: nil static FS")
	}
	html, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return "", fmt.Errorf("buildCSPPolicy: read index.html: %w", err)
	}
	hashes := webhttp.InlineScriptHashes(html)
	if len(hashes) == 0 {
		return "", errors.New("buildCSPPolicy: no inline <script> blocks in index.html")
	}
	styleHashes := webhttp.InlineStyleHashes(html)
	if len(styleHashes) != 1 {
		return "", fmt.Errorf(
			"buildCSPPolicy: want exactly one inline <style> block in index.html, found %d",
			len(styleHashes),
		)
	}
	return fmt.Sprintf(cspTemplate, strings.Join(hashes, " "), styleHashes[0]), nil
}

// composeGate wraps the session-create gate with the tools-syncing
// check: while the boot convergence pass runs, only SESSION CREATION
// (POST terminal.SessionsPath) answers 503, so kiro-cli never spawns
// before the manifest's tools are on PATH; list/close/title requests
// routed through the same doubly-mounted handler pass through, matching
// the engine's WithCreateGate contract. The inner gate (the create rate
// limit) applies once syncing is over. The 503 speaks the standard
// webhttp.WriteError envelope with an empty code, like every app-owned
// error response here (the two 403 gates), plus a Retry-After hint, like the
// inner rate limit's 429; /api/health's
// {status, reason} document is a health-probe contract, not an error.
func composeGate(inner func(http.Handler) http.Handler, syncing func() bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		gated := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if syncing() && r.Method == http.MethodPost && r.URL.Path == terminal.SessionsPath {
				// Retry-After matches the inner rate limit's 429 contract
				// (webhttp.SessionCreateRateLimit sets it too), so both arms of
				// this gate tell a client, a proxy, and the UI's retry logic when
				// to come back instead of leaving them to poll blind. A fixed
				// short hint: convergence has no predictable remaining time (the
				// only bound is toolbelt's 30-minute job timeout), so a cheap
				// re-poll beats an HTTP-date the server cannot honestly compute.
				w.Header().Set("Retry-After", "5")
				webhttp.WriteError(w, r, http.StatusServiceUnavailable, "", "tools installing")
				return
			}
			gated.ServeHTTP(w, r)
		})
	}
}

// loopbackPeer reports whether an http.Request.RemoteAddr belongs to a
// loopback socket peer. Forwarded headers play no part — RemoteAddr is set
// by the server from the accepted connection. Malformed values fail closed.
// (The KWEB_ALLOWED_HOSTS gate's loopback carve-out lives in
// webhttp.HostPolicy; this local helper serves only the loopbackOnly tools
// gate below.)
func loopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackOnly admits only requests whose SOCKET PEER is a loopback
// address. Forwarded headers are deliberately ignored — they are
// client-controlled, and this gate is the tools API's only boundary on
// an otherwise-unauthenticated port. In-container consumers (kiro-cli's
// ! escape hitting curl localhost:9848) pass; everything routed in from
// outside — LAN browsers, the reverse proxy — is refused.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackPeer(r.RemoteAddr) {
			webhttp.WriteError(w, r, http.StatusForbidden, "",
				"tools API is loopback-only; call it from inside the container (curl localhost:9848)")
			return
		}
		next.ServeHTTP(w, r)
	})
}
