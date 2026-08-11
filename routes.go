package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	// apiPrefix is the JSON API surface's shared prefix. It names the app's own
	// API mounts below; it is no longer a middleware scope, and no app middleware
	// sets the header any more. Every route owner covers itself: toolbelt's
	// httpapi upstream of its own mux, handleHealth and handleKiroRescan at the
	// top of the handler, and the engine's session surface through
	// terminal.MountSessionRoutes' own withNoStore (applied to the REST handler
	// at both mounts and outside the create gate, so it reaches the statuses no
	// handler writes). TestAPICachePolicy_EveryAPIPathSetsNoStore enumerates them.
	apiPrefix = "/api/"
	// healthPath is the readiness route; buildHandler's ProbeLogLevel policy
	// must name the same path the mux registers, or a healthy probe stops
	// being demoted to Debug and a failing one stops being promoted.
	healthPath = apiPrefix + "health"
	// toolsPath is the loopback tools API mount; httpapi.Handler is told the
	// same base path so its own routing matches where it is mounted.
	toolsPath = apiPrefix + "tools"
	// kiroRescanPath is the loopback kiro-cli repair hook: it makes an install
	// fixed INSIDE the container observable to the running server. Admitted
	// exactly like toolsPath (loopback socket peers only) and registered with a
	// method pattern, so anything but POST is a 405 rather than a silent no-op.
	kiroRescanPath = apiPrefix + "kiro-cli/rescan"
)

type routeDeps struct {
	// static is the embedded-static serving handler, built by the composition
	// root (buildStaticSurface) together with the hash-pinned CSP the same tree
	// produces: the root keeps the CSP for buildHandler's SecurityHeaders layer
	// and hands the handler here, so neither derivative travels through the
	// route registrar to reach its consumer.
	static http.Handler
	ready  *webhttp.Ready
	// listenHint is "localhost[:port]" for THIS deployment, derived from the
	// address the server actually listens on (KWEB_ADDR). The loopback surfaces'
	// refusals quote it so the remedy they name works on a server that did not
	// keep the default port. Empty (a test building routeDeps by hand) yields
	// today's message minus the address, so no consumer is required to set it.
	listenHint string
	// nil is reserved for the two MOUNTING decisions (tools, kiroRescan); every
	// policy function below is always non-nil, defaulted by the composition
	// root's off-shape constructors (main.go's unmanagedKiroRuntime,
	// unavailableKiroRuntime, degradedRuntime and startTools' absent-config-dir
	// arm), so no consumer here re-derives what an absent subsystem means.
	//
	// tools, when non-nil, mounts the toolbelt httpapi projection at
	// /api/tools behind the loopback gate; toolsSyncing gates session
	// creation on the boot convergence pass; toolsState feeds the
	// /api/health informational tools field ("" outside the container, which
	// the omitempty tag drops); toolsMissing feeds the separate whole-tree
	// convergence count beside it, and its second return distinguishes "none
	// outstanding" from "not counted yet" (see healthBody).
	tools        *toolbelt.Engine
	toolsSyncing func() bool
	toolsState   func() string
	toolsMissing func() (int, bool)
	// containment, when non-nil, puts each tab's kiro-cli process tree in its own
	// cgroup so ending the session ends the tree, and reports the session's peak
	// memory in the logs. Nil is the off-shape and the only shape outside the
	// container: the composition root logs one warning and passes nil when the
	// host has no writable cgroup v2 root, which leaves sessions behaving exactly
	// as they did before the feature existed.
	//
	// This app needs it more than its siblings because `kiro-cli chat` is a
	// four-deep tree whose agent server calls setsid() and installs no stdin-EOF
	// exit path, so it can outlive the session that spawned it; measured at 13
	// stranded processes holding 1.35 GB on a two-tab container.
	containment *terminal.Containment
	// kiroReady is the kiro-cli install manager's readiness verdict plus the
	// reason to report when it is false (installing, retrying, terminally
	// unavailable, or required settings unenforced). It gates /api/health AND
	// session creation. Outside the container (a bare `go run` or a test with no
	// pins) this server does not own the install, and the root's off-shape
	// constructor supplies the permissive (true, "") default so readiness stays
	// pure-listener. Every container boot wires the real manager.
	kiroReady func() (bool, string)
	// kiroRescan, when non-nil, re-derives the active kiro-cli version from disk
	// without downloading anything. It backs kiroRescanPath.
	kiroRescan func(context.Context) (bool, error)
	// cmd builds one session's argv. A FUNCTION, not a slice: the active kiro-cli
	// version can change while the server runs, so the factory below must ask at
	// session-create time rather than close over a boot constant.
	cmd func() []string
	// sessionEnv returns the per-session environment overlay (the active version
	// directory leading PATH). A nil result leaves the child with the server's
	// own environment, which is what the root's off-shape constructors return.
	sessionEnv func() []string
	// sessionTitleEnv returns the per-session variables a kiro-cli hook needs to
	// report which kiro session this tab is running: the tab's TITLE HANDLE (a
	// minted value, deliberately not the session id — see sessiontitle.go's
	// sessionEnv) and the state directory to write the pairing into. Takes the
	// session id because the handle is derived per tab. A nil function (the root's
	// off-shape constructors) leaves tabs on the engine's automatic name ladder.
	sessionTitleEnv func(id string) []string
	// scrollback is the operator's retained-history depth from
	// terminal.ScrollbackEnvVar, or nil when they set nothing — in which case the
	// option is OMITTED and the engine's own default applies. The engine owns
	// both the variable's name and the sizing decision, because this app,
	// web-terminal-server and vibekit share the knob and a number copied into
	// each is three numbers that drift.
	//
	// A POINTER, so that "unset" is the ZERO VALUE. An int sentinel cannot be:
	// 0 is a legal depth meaning "retain nothing", so a routeDeps built by hand
	// — every test here does — would have silently disabled scrollback, which is
	// exactly how this was caught.
	scrollback *int
	workDir    string
	// logOSCText is the KWEB_LOG_OSC_TEXT opt-in: when true, an unrecognized
	// OSC 9 notification's full text is logged at Debug. Default false — the
	// text is arbitrary child output that may carry a token or device code, so
	// the log otherwise carries only a content-free fingerprint (see
	// newStatusClassifier).
	logOSCText bool
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
// manager (for shutdown). The static handler and the hash-pinned CSP policy
// string both derive from the embedded static tree, and buildStaticSurface
// assembles them together, fail-loud; the composition root calls it and gives
// each derivative to its own consumer — the handler here as deps.static, the
// CSP to buildHandler's SecurityHeaders layer.
func registerRoutes(mux *http.ServeMux, deps *routeDeps) *terminal.SessionManager {
	mux.Handle("/", deps.static)

	mgr := terminal.NewSessionManager(newSessionFactory(deps),
		terminal.WithManagerLogger(slog.Default()),
		terminal.WithStatusClassifier(newStatusClassifier(deps.logOSCText)),
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
	// The create gate composes three layers, checked outermost first: the kiro-cli
	// install gate, then — while the tools boot convergence runs — a 503 that keeps
	// the FIRST kiro-cli session from spawning before the manifest's language
	// servers are on PATH (kiro-cli scans PATH once at session start), then the
	// fleet-standard create rate limit (innermost). kiro-cli is checked first
	// because it is the dependency a session cannot start without at all, and its
	// reason distinguishes installing from retrying from terminally unavailable.
	//
	// Without the kiro-cli layer every session created during the first-boot
	// download would run the sign-in guard, print "kiro-cli is not installed" and
	// exit 1, which reads to a user as "the app loads and every terminal dies
	// instantly" and to an operator as one broken-install alert per tab. 503 with a
	// reason is the honest answer. Static assets, /api/health, and the tools API
	// stay reachable throughout: the container is observable during installs
	// instead of connection-refused.
	createGate := webhttp.SessionCreateRateLimit(terminal.SessionsPath)
	createGate = composeGate(createGate, func() (bool, string) {
		return deps.toolsSyncing(), "tools installing"
	})
	createGate = composeGate(createGate, func() (bool, string) {
		ready, reason := deps.kiroReady()
		return !ready, reason
	})
	mgr.MountAPI(mux, terminal.WithCreateGate(createGate))

	// Tools REST surface: the toolbelt httpapi projection, loopback-only.
	// The consumer is an agent inside the container (kiro-cli's ! shell
	// escape + curl localhost:9848); remote callers — LAN browsers
	// included — get 403. The gate checks the socket peer (RemoteAddr) and
	// the Host header, never forwarded headers, so it cannot be spoofed
	// through a proxy nor reached by a DNS-rebound page.
	// Config-file edits + restart remain the primary toggle path; this
	// API is the no-restart alternative.
	if deps.tools != nil {
		toolsAPI := loopbackOnly("tools API", deps.listenHint, httpapi.Handler(deps.tools, toolsPath))
		mux.Handle(toolsPath, toolsAPI)
		mux.Handle(toolsPath+"/", toolsAPI)
	}

	// kiro-cli repair hook, admitted the same way and for the same consumer: an
	// agent or operator INSIDE the container (kiro-cli's ! shell escape + curl
	// localhost:9848). A one-shot background install that exhausted its retries
	// leaves the server answering 503 forever, and a repair made inside the
	// container — a restored version directory, a replaced binary — is invisible to
	// it until the container is recreated. This is the endpoint that makes such a
	// repair observable without a recreate. It downloads nothing.
	if deps.kiroRescan != nil {
		mux.Handle("POST "+kiroRescanPath, loopbackOnly("kiro-cli rescan hook", deps.listenHint, handleKiroRescan(deps)))
		// ServeMux synthesizes 405 only when NO pattern matches the request, and
		// the "/" static mount matches every path — so without this mount a GET or
		// PUT here is answered by the static handler's bare 404, which reads as "no
		// such endpoint" on the one route that exists to repair a broken install
		// (verified against a three-pattern mux: GET -> 404 static, with this mount
		// -> 405 Allow: POST). This pattern is less specific than the POST one
		// above, so POST still reaches the handler, and it sits behind the same
		// loopback gate so a remote caller learns nothing new.
		mux.Handle(kiroRescanPath, loopbackOnly("kiro-cli rescan hook", deps.listenHint,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Allow", http.MethodPost)
				webhttp.WriteError(w, r, http.StatusMethodNotAllowed, "",
					"kiro-cli rescan is POST-only (curl -X POST "+deps.listenHint+kiroRescanPath+")")
			})))
	}

	mux.HandleFunc(healthPath, handleHealth(deps))

	return mgr
}

// kiroRescanBody is the repair hook's response envelope, matching healthBody's key
// order (status first, then the reason) so an operator reads the same shape from
// both surfaces. The status VOCABULARY is only partly shared: "ok" and "unready"
// mean what they mean on /api/health, while "abandoned" is this hook's own and
// /api/health never serves it -- only a rescan can fail to reach a verdict at all.
type kiroRescanBody struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// reasonRescanAbandoned is the repair hook's 503 reason when the request was
// abandoned before pinstall reached any verdict. It is deliberately NOT one of
// main.go's kiroReasonText strings: those NAME the install manager's readiness
// state, and this response reaches no verdict about the install at all -- it
// reports only that the request was not serviced.
const reasonRescanAbandoned = "kiro-cli rescan not performed: request abandoned before any verdict"

// handleKiroRescan re-derives the active kiro-cli version from what is on disk right
// now and reports the resulting readiness. 200 when a version is active afterwards,
// 503 with the manager's own reason when none is: the same verdict /api/health will
// serve from the next probe, so a caller gets its answer without polling. A request
// abandoned before any verdict was reached also answers 503, under its own
// "abandoned" status rather than a readiness verdict about the install.
func handleKiroRescan(deps *routeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A rescan probes the candidate binary and reasserts the required
		// settings, so it is not free; it is also not cacheable under any
		// circumstances.
		w.Header().Set("Cache-Control", "no-store")
		// The request context goes straight through. pinstall >= v1.1.0 owns both
		// halves this handler used to hand-roll: WAITING for its operation slot
		// honours this context (a queued caller that goes away is dropped, and
		// nothing has entered the library on its behalf), while an ADMITTED rescan
		// runs detached, so a Ctrl-C or --max-time cannot make every candidate
		// probe fail and have the manager record "no usable version". The
		// app-local admission channel and context.WithoutCancel wrapper that
		// stood in for those are gone; vibekit, which had neither, gained them on
		// the same bump.
		ok, err := deps.kiroRescan(r.Context())
		if ok {
			webhttp.WriteJSON(w, kiroRescanBody{Status: "ok"})
			return
		}
		// A context error means the request was ABANDONED before pinstall reached
		// any verdict, and there are TWO sources of it, not one. The caller's own
		// cancellation while queued for pinstall's operation slot is the obvious
		// one (an ADMITTED rescan runs detached -- Rescan calls
		// context.WithoutCancel once it holds the slot -- so it can never surface
		// the caller's cancellation). The second is this server's own shutdown:
		// the pre-drain hook cancels baseCtx, which is the BaseContext of EVERY
		// request, so a rescan still queued behind a first-boot install holding
		// that slot is abandoned with a live client on the other end.
		//
		// Either way nothing entered the library on this caller's behalf and no
		// verdict was reached. Reporting it as "no usable version" would be a
		// false broken-install record on the one endpoint an operator uses while
		// the manager is ALREADY unready (EnsureWithRetry holds the same slot for
		// a whole first-boot download), the same false-alert class the session
		// fast-death hook gates away on every deploy. So this answers 503 under its
		// own "abandoned" status, with a reason naming it -- the request was not
		// serviced -- and says nothing about the install. "unready" is wrong here
		// even as a hedge: it IS a weak verdict, and it is not provably true, since
		// a rescan queued behind another rescan can be abandoned on a manager that
		// is perfectly ready. A distinct status carries that discrimination in the
		// field a consumer switches on, instead of resting it all on the reason
		// string. Writing nothing (the shape this replaced) left
		// net/http to synthesize an implicit 200 with an empty body, so an
		// operator's `curl -sfS -X POST` exited 0, reporting success for a repair
		// that never ran.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			slog.Debug("kiro-cli rescan abandoned before a verdict was reached",
				"error", err)
			webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable,
				kiroRescanBody{Status: "abandoned", Reason: reasonRescanAbandoned})
			return
		}
		// The manager has already logged the specific fault (and every path it
		// took) at Warn or Error, so this reports the verdict rather than the
		// error text: err can name a filesystem path, and this response is not
		// the place to widen what a caller learns about the volume.
		reason := reasonUnavailable
		if _, why := deps.kiroReady(); why != "" {
			reason = why
		}
		// pinstall.Rescan's ordinary failure is (false, nil): no candidate was selected
		// and recording that verdict succeeded. A nil error attribute would put
		// "error":null on that common path, making it indistinguishable from a rescan
		// whose own state write failed -- the one case that needs a different remedy.
		attrs := []any{"reason", reason}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		slog.Warn("kiro-cli rescan found no usable version", attrs...)
		webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable,
			kiroRescanBody{Status: "unready", Reason: reason})
	}
}

// childEnv is the environment overlay for one tab's kiro-cli process: the active
// version's PATH lead, plus the two variables a hook needs to report which kiro
// session this tab is running. Built as a fresh slice rather than appending to
// sessionEnv's return, so one session's overlay can never alias another's backing
// array. A nil sessionTitleEnv (the root's off-shape constructors, and tests with
// no title syncer) contributes nothing and leaves the tab on the engine's
// automatic name ladder.
func (d *routeDeps) childEnv(id string) []string {
	base := d.sessionEnv()
	var extra []string
	if d.sessionTitleEnv != nil {
		extra = d.sessionTitleEnv(id)
	}
	if len(extra) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}

// newSessionFactory builds the per-session handler factory the session manager
// calls once per tab: one independent PTY-backed kiro-cli chat process with its
// own VT screen and scrollback. It owns four session-scoped policies — the
// argv and PATH resolved from the install manager AT session-create time, the
// LogID-truncated per-session logger (the session id is the /ws attach/resume
// capability token), the WithCommandLogValue argv redaction (the argv carries
// operator KIRO_CLI_CHAT_ARGS values), and the fast-death Warn hook that
// surfaces a broken kiro-cli install.
func newSessionFactory(deps *routeDeps) func(string) *terminal.Handler {
	// Retained-history depth carries no app-owned number any more. The option is
	// appended at the BOTTOM of this factory only when resolveScrollback returns
	// a valid operator override; unset, blank, or malformed values omit the
	// option, so the engine's own terminal.DefaultScrollbackCapacity applies.
	// This app used to pass its own constant, which made the sizing decision in
	// three places across the family; the engine documents it once.
	//
	// WithKeepUnfocused pins the process to the DEC 1004 "unfocused" state so
	// kiro-cli keeps emitting its focus-gated OSC 9 notifications (which drive
	// the classifier) even though no browser tab claims focus;
	// web-terminal-server deliberately does NOT use this, since a generic
	// shell/editor wants real focus reporting.
	//
	// No TERM_PROGRAM override here: the engine advertises TERM_PROGRAM=
	// iTerm.app (>= 3.6.6), which puts kiro-cli in its OSC 9;4 progress allowlist
	// (driving the tab's "working" dot) and enables DEC 2026 synchronized output
	// -- the same identity web-terminal-server gets, so this app inherits it
	// instead of pinning its own. Anything the engine can't render (inline
	// images) is consumed silently.
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
		// the process starts (Handler.ensureStarted), and the argv carries
		// the operator's KIRO_CLI_CHAT_ARGS values — a value-bearing flag
		// there could hold a credential from a compose interpolation mistake
		// (CWE-532) — so the engine is told to record the fixed "[redacted]"
		// marker instead (WithCommandLogValue), the same way main.go's own
		// startup line logs only chat_args_count.
		sessionLogger := slog.Default().With("session", safeID)
		opts := []terminal.Option{
			terminal.WithWorkDir(deps.workDir),
			terminal.WithKeepUnfocused(),
			terminal.WithLogger(sessionLogger),
			terminal.WithCommandLogValue("[redacted]"),
			// The active kiro-cli version's own directory first on the child's
			// PATH, plus the two variables that let a kiro-cli hook report which
			// kiro session this tab is running (childEnv composes both). The
			// engine appends WithEnv LAST when it composes os.Environ() plus its
			// TERM identity, so this PATH wins — which is what makes `kiro-cli
			// chat` dispatch its sidecar out of the same digest-verified install
			// rather than out of a stale $TOOLS/bin copy left by a restored
			// backup volume. With no version active (or no manager) the PATH
			// entry is simply absent; childEnv still carries the title variables,
			// and an empty result leaves the server's own environment untouched.
			// Tab names come from kiro-cli's own session
			// record, so the engine's input-stream deriver (WithInputTitle) is
			// deliberately NOT requested here: reconstructing a submitted line
			// from raw bytes means modelling the agent shell's composer, and
			// every discard key it does not model (Escape dismissing the
			// slash-command menu, Ctrl-U, Ctrl-W) fuses abandoned text onto the
			// next prompt and latches that for the session's life. kiro-cli
			// already knows the answer and keeps improving it as the
			// conversation goes; see sessiontitle.go for the mapping and why it
			// needs a hook.
			terminal.WithEnv(deps.childEnv(id)),
			// Per-session process containment. Closing a tab (or the process
			// dying) must end the whole tree, and for this app it otherwise does
			// not: `kiro-cli chat` runs kiro-cli -> kiro-cli-chat -> the TUI ->
			// the agent server, and that last process calls setsid(), so it
			// leaves both the process group and the session and no signal the
			// engine can aim reaches it. A nil containment is a no-op, so this
			// line is safe on a host that cannot support the feature.
			terminal.WithContainment(deps.containment, id),
			// One cost line per session per interval. A dev-box tab can live for
			// days, and the state worth seeing is a tab whose agent connection
			// died while its TUI is still alive: containment reclaims at teardown
			// and never earlier, so that tab keeps holding its memory for as long
			// as it stays open, deliberately. The log line is what makes that
			// visible so the decision to close it stays the user's; nothing here
			// ends a session on a timer.
			terminal.WithContainmentSampleInterval(sessionCostInterval),
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
				kiroReady, _ := deps.kiroReady()
				if err != nil && deps.ready.Ready() && kiroReady && time.Since(start) < 10*time.Second {
					sessionLogger.Warn(sessionFastDeathMsg,
						"error", err,
						"hint", "check /api/health and the kiro-cli install under /config/tools/kiro-cli-versions")
				}
			}),
		}
		if deps.scrollback != nil {
			opts = append(opts, terminal.WithScrollbackCapacity(*deps.scrollback))
		}
		return terminal.NewHandler(deps.cmd(), opts...)
	}
}

// healthBody is /api/health's response envelope. A struct, not a map, for the
// reason webhttp.ReadinessHandler's own readinessResponse is one: encoding/json
// sorts map keys, so a map emits {"reason":…,"status":…} while the library — and
// therefore web-terminal-server and subflux, which use its handler — emits
// {"status":…,"reason":…}. Three apps served one envelope in two key orders.
//
// This app cannot use the library handler outright: its verdict is COMPOSITE (a
// second reason for the env-gated kiro-cli marker, plus the informational tools
// field), and the library's ReadinessChecker is Ready() bool. Extending the
// library to absorb a composite verdict was considered and rejected as a wide
// public surface for a six-line envelope; matching its wire shape exactly is the
// cheap half that actually removes the divergence.
//
// Tools is omitempty because it is INFORMATIONAL and absent when no tools engine
// is wired (a bare `go run`), where an empty string would read as a state.
//
// ToolsMissing is the SECOND, independent tools question, and the pair is the
// point: Tools answers "did the last install or reconcile succeed, or are we
// still booting" — which is what keeps a long first-boot install from flapping
// monitoring — while ToolsMissing answers "is the tree actually converged". They
// disagree legitimately: repairing one of two missing tools through the loopback
// tools API makes Tools "ok" (the repair DID succeed, exactly as README
// documents) while ToolsMissing stays 1. Before this field existed that
// disagreement had nowhere to live, so "ok" was readable as whole-tree health.
//
// A POINTER so the field is absent rather than 0 when the count is unknown — no
// engine wired, or the first recount has not landed. Zero means converged, and
// it must not be possible to read "not known yet" as that.
//
// FIELD ORDER IS THE WIRE CONTRACT, which is why fieldalignment is silenced here
// rather than obeyed. encoding/json emits fields in DECLARATION order, so the
// alignment-optimal layout (the pointer first) emits
// {"tools_missing":…,"status":…} and breaks the key order this app shares with
// web-terminal-server and subflux — the very divergence this struct exists to
// remove. Attempted, and TestHealthEndpoint_envelopeMatchesTheLibrary caught it
// byte-exactly. The trade is 8 bytes of padding on a value built once per health
// request against a published envelope; the padding loses.
//
//nolint:govet // fieldalignment: declaration order is the JSON key order (above)
type healthBody struct {
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	Tools        string `json:"tools,omitempty"`
	ToolsMissing *int   `json:"tools_missing,omitempty"`
}

// handleHealth returns the /api/health readiness handler. It reflects, in
// order: listener readiness (deps.ready), the kiro-cli install manager's verdict
// (deps.kiroReady), and the INFORMATIONAL tools field (deps.toolsState) — tool
// convergence never gates readiness.
func handleHealth(deps *routeDeps) http.HandlerFunc {
	// One constructor for both outcomes, so the INFORMATIONAL tools field cannot
	// diverge between them (and neither can any field added later). It belongs on
	// the 503 bodies too: tool convergence never GATES readiness, but an operator
	// diagnosing a 503 needs to see whether tools are still syncing or already
	// degraded — and that is exactly the moment the field used to disappear,
	// because both unready paths returned before it was attached.
	healthResponse := func(status, reason string) healthBody {
		body := healthBody{Status: status, Reason: reason}
		body.Tools = deps.toolsState()
		if n, ok := deps.toolsMissing(); ok {
			body.ToolsMissing = &n
		}
		return body
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		// Set here rather than by middleware, so the handler carries its own
		// contract wherever it is mounted: a readiness verdict must never be
		// cached (a 200 with no explicit freshness is heuristically cacheable
		// under RFC 9111, and a cached "ok" keeps traffic arriving at an instance
		// that has begun draining). This is the only thing setting it on THIS
		// route — the app carries no no-store middleware at all now that every
		// route owner covers itself (the engine's session surface included, via
		// terminal.MountSessionRoutes' withNoStore), which is exactly the
		// independence this line already had. The same header comes from
		// webhttp.ReadinessHandler for the apps that use it directly.
		w.Header().Set("Cache-Control", "no-store")
		unready := func(reason string) {
			webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable, healthResponse("unready", reason))
		}
		if !deps.ready.Ready() {
			unready("starting up or shutting down")
			return
		}
		// kiro-cli readiness, straight from the install manager. web-terminal-kiro's
		// core job is spawning kiro-cli chat PTYs, and the HTTP listener now binds
		// BEFORE the install runs (bind-first, so a first-boot download is
		// observable rather than connection-refused), so this is what tells
		// `docker ps` and the monitoring probe apart from "serving". The manager's
		// reason distinguishes installing / retrying / terminally unavailable /
		// required settings unenforced, so a 503 says which. Reading it is a mutex
		// and two field loads: the version was probed once when it was selected,
		// never per probe (spawning a heavy PTY process on every health check would
		// be an anti-pattern). This is a READINESS signal, not liveness — under
		// `restart: unless-stopped` nothing restarts on the resulting unhealthy
		// state, so there is no restart loop; if ever run under Swarm/k8s, wire
		// this to a readinessProbe, not a livenessProbe.
		if ok, reason := deps.kiroReady(); !ok {
			unready(reason)
			return
		}
		// The tools field is INFORMATIONAL: tool convergence never gates
		// readiness (kiro-cli is the only core dependency), so monitoring
		// stays green during a long first-boot install window while
		// operators can still see it (syncing | ok | degraded).
		webhttp.WriteJSON(w, healthResponse("ok", ""))
	}
}

// sessionFastDeathMsg is the fast-death Warn's wording, named for the same reason
// the classifier's messages are: session_exit_warn_test.go asserts on it, and its
// quiet branch asserts an ABSENCE, which a reworded literal would satisfy
// vacuously.
const sessionFastDeathMsg = "session process exited almost immediately after start; kiro-cli may be missing or broken"

// unrecognizedNotifyMsg is the one wording both the bounded Warn and the
// per-occurrence Debug emit, so the two records a log search correlates cannot
// drift apart.
const unrecognizedNotifyMsg = "unrecognized kiro-cli OSC 9 notification; tab status dots will not latch (kiro-cli notification wording may have changed on a version bump)"

// unrecognizedNotifyCapMsg is emitted once, when the distinct-message budget is
// exhausted, so a silent stop is never mistaken for "nothing new appeared".
// Deliberately does NOT contain unrecognizedNotifyMsg as a substring: these are two
// different events and a log search (or a test) matching on one must not also match
// the other.
const unrecognizedNotifyCapMsg = "kiro-cli OSC 9 notification warn budget exhausted; further distinct wordings are Debug-only (set KWEB_LOG_LEVEL=debug)"

// recognizedNotifyMsg is the POSITIVE half of the classifier trace. Without it
// the classifier is observable only when it fails to match, so a debug session
// that sees no classifier records cannot tell "kiro-cli emitted no OSC 9
// notification at all" (the notifier's focus gate, the engine's DEC 1004
// unfocused pin, or kiro-cli's TERM_PROGRAM allowlist) from "notifications
// mapped fine, so the dot is lost downstream" — two different owners. That
// negative is the only signal that separates them, and it is what still answers
// the question once the unrecognizedNotifyCap warn budget is spent. Deliberately
// shares no substring with unrecognizedNotifyMsg so a log search or a test
// matching one never matches the other. The value logged is the matched literal
// from the closed switch in newStatusClassifier, never arbitrary child output.
const recognizedNotifyMsg = "kiro-cli OSC 9 notification mapped to a tab status"

// unrecognizedNotifyCap bounds how many DISTINCT unrecognized notifications are
// promoted to Warn. It bounds two things, and the second is why a cap is
// mandatory rather than tidy: log volume (at most this many lines per container
// lifetime), and the memory of the seen-set below — its key comes from child
// process output, so an unbounded set would let a chatty or hostile session grow
// it without limit. Insertion stops at the cap; the map never exceeds it.
const unrecognizedNotifyCap = 8

// unrecognizedNotifyCapRearm is how long the budget-exhausted announcement stays
// silent before it may fire again. The seen-set is keyed on CHILD output, so the
// budget can be spent entirely on benign wordings; re-arming is what keeps a
// kiro-cli rewording that begins AFTER exhaustion visible in the default log
// stream, while still bounding volume to one line per window.
const unrecognizedNotifyCapRearm = 6 * time.Hour

// unrecognizedNotifyHint is the operator-facing next step both Warn arms carry:
// what to re-verify after a kiro-cli bump, and the two levers that surface the
// notification's actual TEXT (raising the level alone is no longer enough —
// KWEB_LOG_OSC_TEXT is the deliberate confidentiality opt-in).
const unrecognizedNotifyHint = `re-verify the "Response complete" / "Permission required" / "Input required" strings in the pinned kiro-cli-chat binary and update newStatusClassifier; set KWEB_LOG_OSC_TEXT=true with KWEB_LOG_LEVEL=debug to log the notification text itself (it is arbitrary child output and may contain a token or device code)`

// notifyFingerprintHexDigits bounds the fingerprint written in place of the
// notification text. 16 hex digits (64 bits of HMAC-SHA-256) is far more than
// enough to tell a handful of distinct wordings apart — the warn budget is
// unrecognizedNotifyCap — while staying short enough to read in a log line.
const notifyFingerprintHexDigits = 16

// notifyFingerprintKeyBytes is the width of the per-classifier HMAC key. 32
// bytes is SHA-256's block-appropriate full-strength key; the key is generated
// at classifier construction and NEVER logged, so nothing in the log stream
// helps an attacker reproduce a fingerprint.
const notifyFingerprintKeyBytes = 32

// notifyFingerprinter renders the stable, content-free identifier the log
// carries INSTEAD of an unrecognized notification's text.
//
// The text is arbitrary child output — a program run in the terminal can emit
// `ESC ] 9 ; <text>` — and the engine's sanitizeNotification only guarantees
// INTEGRITY (it drops unsafe runes and rune-caps at 256, so a record cannot be
// forged); it redacts nothing. A bounded EXCERPT was the first answer and does
// not redact: a short token or a device code fits inside any excerpt, so the
// always-on stream still ended up holding a durable, queryable copy of a
// credential in Loki (CWE-532), which retains far longer and is far more
// searchable than PTY scrollback.
//
// An UNKEYED digest was the second answer and does not redact either, which is
// why the key exists: the plaintext here is low-entropy by nature (a device
// code, a short token, a templated URL with a code in it), so a reader holding
// SHA-256(msg) can enumerate candidates offline and compare — a password-hash
// problem, and "message_runes" hands the search its length. Keying with a
// secret the log never contains removes the offline oracle: without the key no
// amount of guessing confirms a candidate (CWE-760, unsalted one-way hash).
//
// What the identifier keeps is every diagnostic property the always-on record
// actually needs — "a wording this app does not recognize appeared", "here are
// N DISTINCT ones", "this is the same one as before / a different one", "it was
// this many runes long" — while carrying none of the content. The key's
// lifetime is the classifier INSTANCE (one per process in production), so
// fingerprints correlate across the Warn and Debug records of one run and
// deliberately do NOT correlate across restarts; recovering the text itself is
// a deliberate two-lever opt-in (KWEB_LOG_OSC_TEXT plus KWEB_LOG_LEVEL=debug),
// not a side effect of raising the log level.
type notifyFingerprinter struct {
	key []byte
}

// newNotifyFingerprinter draws the per-classifier key. crypto/rand.Read never
// returns an error: it calls io.ReadFull on Reader and crashes the program
// irrecoverably if the OS source fails, so there is no keyless state to degrade
// into and the identifier is always present.
func newNotifyFingerprinter() notifyFingerprinter {
	key := make([]byte, notifyFingerprintKeyBytes)
	_, _ = rand.Read(key) // documented never to fail; it crashes the process instead
	return notifyFingerprinter{key: key}
}

// fingerprint returns the leading notifyFingerprintHexDigits hex digits of
// HMAC-SHA-256(key, msg).
func (f notifyFingerprinter) fingerprint(msg string) string {
	mac := hmac.New(sha256.New, f.key)
	// hash.Hash.Write is documented never to return an error.
	_, _ = mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))[:notifyFingerprintHexDigits]
}

// metadata is the content-free description of a notification both the Warn arm
// and the default (text-disabled) Debug arm log: which distinct wording it was,
// and how long it was. Both attributes are always present, so a record never
// degrades to "something unrecognized happened, no detail at all".
func (f notifyFingerprinter) metadata(msg string) []any {
	return []any{
		"message_fingerprint", f.fingerprint(msg),
		"message_runes", utf8.RuneCountInString(msg),
	}
}

// notifyWarningState is newStatusClassifier's bounded warn budget for
// unrecognized OSC 9 notifications, extracted so the classifier maps messages
// and emits records while the synchronized bookkeeping (distinct-message
// seen-set, cap exhaustion, announce-once) lives in one place: changing the cap
// or the repeat behavior no longer means re-reading the mapping and logging
// branches. One instance per classifier instance (never a package var), so its
// lifetime is the classifier the composition root wires and a test gets a fresh
// budget.
type notifyWarningState struct {
	warned map[string]struct{}
	// lastCapWarn is when the budget-exhausted announcement last fired; the zero
	// value means never, so the first one always fires.
	lastCapWarn time.Time
	// mu guards warned and lastCapWarn.
	mu sync.Mutex
}

// observe records msg against the warn budget and reports which record (if any)
// the caller should emit: warnFirst for the first occurrence of a DISTINCT
// message while budget remains, warnCapped at most once per
// unrecognizedNotifyCapRearm window for a distinct message the cap turns away
// (so a silent stop is distinguishable from "nothing new appeared", and a
// wording drift that begins after exhaustion still reaches the default stream).
// Both false means the message is Debug-only. The engine shares
// one classifier across every session and calls it from per-session goroutines,
// so the state is mutex guarded; the caller logs OUTSIDE the lock.
func (s *notifyWarningState) observe(msg string) (warnFirst, warnCapped bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.warned[msg]; seen {
		return false, false
	}
	if len(s.warned) < unrecognizedNotifyCap {
		s.warned[msg] = struct{}{}
		return true, false
	}
	// The announcement re-arms rather than firing once per process: the seen-set is
	// filled first-come by arbitrary child output, so announcing exhaustion a single
	// time leaves a LATER kiro-cli rewording -- the drift this Warn exists to catch
	// -- with no default-level record at all. The set still never grows past the
	// cap, and log volume is still bounded (one line per window).
	// The zero value needs no carve-out: time.Since saturates to the maximum
	// Duration for it, so this comparison is already false and the FIRST
	// turned-away message announces.
	if time.Since(s.lastCapWarn) < unrecognizedNotifyCapRearm {
		return false, false
	}
	s.lastCapWarn = time.Now()
	return false, true
}

// newStatusClassifier returns the kiro-cli OSC 9 -> session-status mapping the
// composition root injects into the engine (terminal.WithStatusClassifier),
// with its own bounded warn latch: the first occurrence of each DISTINCT
// unrecognized notification is promoted to Warn (up to unrecognizedNotifyCap),
// so a kiro-cli notification-wording drift is visible in the DEFAULT (info) log
// stream instead of only under KWEB_LOG_LEVEL=debug, while the Debug trace still
// records every occurrence — a build that legitimately emits some other
// notification cannot flood the shipped stream.
//
// Per-DISTINCT rather than one-per-classifier, which is what this used to be: a
// single sync.Once was consumed by the first unrecognized message of ANY kind, so
// one benign extra notification (kiro-cli 2.14 added structured user-input
// prompts, exactly this shape) spent the whole budget, and a LATER bump rewording
// "Response complete" or "Permission required" then warned NOTHING while every
// turn-end silently stopped latching. That is the failure the Warn exists to
// surface, so the bound now keys on the message rather than on the count of
// messages. Log volume is still bounded (the cap), which was the original intent.
//
// The latch lives in the closure rather than in a package var so its lifetime is
// the classifier INSTANCE the root wires (exactly one per process in production)
// instead of the process, and a test constructs a fresh classifier instead of
// reassigning package state. The engine shares one classifier across every
// session and calls it from per-session goroutines, so the seen-set is mutex
// guarded; the logging happens outside the lock.
//
// The returned mapping: "Response complete" at the end of an agent turn latches
// the done (green) state, and BOTH "Permission required" (a tool call blocked on
// approval) and "Input required" (a structured user question, the notifier's
// pendingQuestion arm) latch the needs-input (amber) state (confirmed against the
// pinned kiro-cli build's kiro-cli-chat notifier strings; the pin is
// entrypoint.sh's KIRO_CLI_VERSION, the single source of truth, so do not copy
// the version number here — it drifts on the next Renovate bump — the strings
// live in the kiro-cli-chat sidecar binary, not the kiro-cli dispatcher, so
// re-verify all three strings there after every kiro-cli bump, in the same PR as
// the pin move; a notifier arm this switch does not name is a status dot that
// never latches). A new
// working phase (the OSC 9;4 progress
// signal, enabled by the factory's TERM_PROGRAM) clears the latch. Any other
// message is ignored. This mapping is the only kiro-cli-specific coupling; the
// engine stays generic (a plain shell server sets no classifier and derives
// working/idle from output activity).
//
// logText is the KWEB_LOG_OSC_TEXT opt-in (default false) and governs ONE thing:
// whether an UNRECOGNIZED notification's TEXT may be logged at all. Off, every
// unrecognized-arm record is content-free metadata (see notifyFingerprinter);
// on, the Debug arm — and only the Debug arm — carries the full sanitized text,
// alongside the same metadata so the record still pairs with its Warn.
// Notification content never reaches the default Warn stream in either mode. The
// recognized arms' Debug trace (recognizedNotifyMsg) is outside this lever: it
// logs the matched literal from the closed switch below, which is this app's own
// compile-time string and not the arbitrary child bytes logText guards.
func newStatusClassifier(logText bool) func(string) (string, bool) {
	warnings := notifyWarningState{warned: make(map[string]struct{}, unrecognizedNotifyCap)}
	fingerprints := newNotifyFingerprinter()
	return func(msg string) (string, bool) {
		switch msg {
		case "Response complete":
			slog.Debug(recognizedNotifyMsg, "notification", msg, "status", terminal.StatusDone)
			return terminal.StatusDone, true
		case "Permission required", "Input required":
			slog.Debug(recognizedNotifyMsg, "notification", msg, "status", terminal.StatusInput)
			return terminal.StatusInput, true
		default:
			// Any OSC 9 text the pinned kiro-cli build does not emit for turn-end or
			// tool-approval. If a kiro-cli bump reworded "Response complete"/"Permission
			// required", every notification lands here and the per-tab status dots
			// silently stop latching. The first occurrence of each DISTINCT message
			// warns (visible at the default info level, up to unrecognizedNotifyCap
			// distinct strings); the Debug line records every occurrence, so
			// KWEB_LOG_LEVEL=debug is what shows the full set after a version bump.
			//
			// Neither record carries the notification TEXT by default, and the Warn
			// never does. The text is arbitrary child output: the engine's
			// sanitizeNotification guarantees the record cannot be FORGED (it drops
			// every runesafe-unsafe rune -- C0/C1 controls, Bidi controls,
			// U+2028/29 -- and rune-caps at 256 before the classifier sees it) but
			// it redacts NOTHING, so a token or a device code in that text would
			// otherwise land in a log store that outlives and out-queries the PTY
			// scrollback. A bounded excerpt was the previous answer and did not
			// redact either (a short secret fits), so what ships now is a
			// KEYED, content-free fingerprint plus a rune count -- enough to tell
			// the distinct wordings apart and correlate repeats within this
			// process, carrying none of the content and offering no offline
			// guessing oracle. Recovering the text is the explicit
			// KWEB_LOG_OSC_TEXT opt-in below, at Debug only.
			//
			// Decide under the lock, log outside it: slog handlers can block on I/O and
			// this runs on every session's event goroutine, so holding the mutex across
			// the write would serialize them all behind the log sink.
			warnFirst, warnCapped := warnings.observe(msg)

			switch {
			case warnFirst:
				slog.Warn(unrecognizedNotifyMsg,
					append(fingerprints.metadata(msg), "hint", unrecognizedNotifyHint)...)
			case warnCapped:
				// The fingerprint of the message that hit the full budget, so a
				// re-armed announcement identifies WHICH wording drove it and pairs
				// with the Debug record. Without it two firings six hours apart are
				// indistinguishable from the same rejected wording arriving twice --
				// and this line is the only default-level signal of a drift that
				// begins AFTER the budget filled. Content-free and keyed, the same
				// attribute the warnFirst arm carries.
				slog.Warn(unrecognizedNotifyCapMsg,
					append(fingerprints.metadata(msg),
						"distinct_limit", unrecognizedNotifyCap,
						"hint", unrecognizedNotifyHint)...)
			}
			// ONE Debug record either way; the KWEB_LOG_OSC_TEXT opt-in only ADDS
			// the text. Whoever set BOTH it and the debug level accepted (and was
			// warned at startup) that terminal notification text may contain
			// secrets. The metadata rides along rather than being replaced: the
			// fingerprint is what pairs this record with the Warn that sent the
			// operator here, so the opt-in must not trade the correlation key for
			// the text.
			attrs := fingerprints.metadata(msg)
			if logText {
				attrs = append(attrs, "message", msg)
			}
			slog.Debug(unrecognizedNotifyMsg, attrs...)
			return "", false
		}
	}
}

// kiroCacheControl is the per-asset Cache-Control policy handed to
// webhttp.StaticHandler (which supplies the ETag/gzip mechanism; asset paths
// arrive normalized, no leading slash):
//   - fonts (vendor/fonts/**): public, 30 days, NOT immutable. The Monaspace
//     .woff2 files are sizable (~1.3 MB each, ~5.1 MB total) and their glyphs
//     are fixed for a given vendored web-terminal-ui version, so a long max-age
//     keeps an ordinary navigation from re-requesting them at all. `immutable`
//     is deliberately absent: the filenames are NOT content-addressed and this
//     app cannot make them so (the four @font-face URLs come from the vendored
//     UI's page.css, and Dockerfile's MONASPACE_VERSION step fetches the same
//     fixed names), so the bytes DO change under one filename on a Monaspace
//     bump. Without `immutable` a reload revalidates against the helper's
//     content-hash ETag — a ~200-byte 304 when nothing changed, the new face
//     when it did — which is the operator's and the user's only lever after a
//     bump. Remaining exposure: a returning browser that never reloads keeps
//     the old face until max-age expires. Closing that fully means hashing the
//     font filenames at vendor time and rewriting the library CSS URLs (a
//     Dockerfile change), after which `immutable` can come back.
//   - everything else (HTML/JS/CSS, ~1–30 KB modules): no-cache +
//     must-revalidate so deployments take effect immediately. The helper's
//     content-hash ETag lets unchanged files revalidate with a cheap 304;
//     the hash changes only when the bundle bytes change, busting the cache
//     exactly on a deploy and keeping the TS engine bundle in lockstep with
//     the server wire protocol.
func kiroCacheControl(assetPath string) string {
	if strings.HasPrefix(assetPath, "vendor/fonts/") {
		return "public, max-age=2592000"
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
// web-terminal-kiro's index.html carries TWO inline scripts — the importmap and
// the bootstrap watchdog (the script-load-failure alertdialog) — both hashed;
// the external /app.js module is covered by script-src 'self'.
//
// FAIL LOUD: a malformed build — an unreadable index.html, zero
// inline scripts, or anything other than exactly one <style> block — aborts
// startup rather than silently dropping the script-src or style-src hardening,
// or serving a hash set that would block the importmap and break ES module
// loading.
//
// The one-block assertion stays HERE rather than in the library: "exactly one"
// is this app's contract about its own page, not a property of style hashing.
func buildCSPPolicy(sub fs.FS) (string, error) {
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

// composeGate wraps a session-create gate with one more blocking check:
// while `blocked` reports true, only SESSION CREATION
// (POST terminal.SessionsPath) answers 503 — so kiro-cli never spawns
// before its own install finishes or before the manifest's tools are on PATH;
// list/close/title requests routed through the same doubly-mounted handler pass
// through, matching the engine's WithCreateGate contract. The inner gate applies
// once this layer clears, which is how the two blocking checks and the create rate
// limit stack into one gate without knowing about each other. `blocked` returns its
// own reason so each layer names the dependency it is waiting on. The 503 speaks the
// standard webhttp.WriteError envelope with an empty code, like every app-owned
// error response here (the two 403 gates), plus a Retry-After hint, like the
// inner rate limit's 429; /api/health's
// {status, reason} document is a health-probe contract, not an error.
func composeGate(inner func(http.Handler) http.Handler, blocked func() (bool, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		gated := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != terminal.SessionsPath {
				gated.ServeHTTP(w, r)
				return
			}
			if block, reason := blocked(); block {
				// Retry-After matches the inner rate limit's 429 contract
				// (webhttp.SessionCreateRateLimit sets it too), so both arms of
				// this gate tell a client, a proxy, and the UI's retry logic when
				// to come back instead of leaving them to poll blind. A fixed
				// short hint: neither a tools convergence nor a kiro-cli download
				// has a predictable remaining time, so a cheap re-poll beats an
				// HTTP-date the server cannot honestly compute.
				w.Header().Set("Retry-After", "5")
				webhttp.WriteError(w, r, http.StatusServiceUnavailable, "", reason)
				return
			}
			gated.ServeHTTP(w, r)
		})
	}
}

// loopbackOnly admits only requests whose SOCKET PEER and Host header are both
// loopback and which carry no proxy/browser provenance header, and is now a thin
// naming wrapper over webhttp.LoopbackOnly.
//
// The whole decision moved into the library (webhttp >= v1.23.0): the two-legged
// predicate, the seven-header provenance deny this app used to own, and the
// reasoning for both. What stays here is only what is genuinely this app's — the
// refusal wording, which names the guarded surface and the deployment's own
// listen hint, because the 403 is the whole of what a refused caller is told and
// must not name a port the operator moved away from.
//
// It moved because webhttp's own rule said when it should: bindclass.go names the
// reopen conditions as "a second peer-gating consumer appears or the app/library
// copies are ever found diverging", and both had happened — vibekit gates the
// same way with NO provenance deny, on the hook that spawns processes. That gap
// closes on its bump.
func loopbackOnly(surface, hint string, next http.Handler) http.Handler {
	refuse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhttp.WriteError(w, r, http.StatusForbidden, "",
			surface+" is loopback-only; call it from inside the container (curl "+hint+")")
	})
	return webhttp.LoopbackOnly(refuse)(next)
}

// sessionCostInterval is how often a contained session logs what it is currently
// costing (memory, pid count, unreaped-task count, age).
//
// Fifteen minutes because the question this answers is "what is this tab costing
// me", not "watch a leak develop": the moment a session strands a process is
// already reported the instant it happens, by the engine's reclaim WARN at
// teardown. At the observed concurrency of a personal dev box this is single-digit
// lines per hour, which is why it is on by default here rather than behind a knob.
const sessionCostInterval = 15 * time.Minute
