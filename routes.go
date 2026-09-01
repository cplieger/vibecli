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

	"github.com/cplieger/toolbelt/v3"
	"github.com/cplieger/toolbelt/v3/httpapi"
	"github.com/cplieger/web-terminal-engine/v5/terminal"
	"github.com/cplieger/webhttp/v2"
)

// App-owned route paths. Every engine route comes from the engine's exported
// terminal.* path constants; these are the surfaces this app mounts itself, named once
// so a mount, a handler's declared base path, and the middleware policy that keys on
// the same path cannot drift apart across files.
const (
	apiPrefix = "/api/"
	// healthPath is the readiness route; buildHandler's ProbeLogLevel policy must name
	// the same path the mux registers, or a healthy probe stops being demoted to Debug
	// and a failing one stops being promoted.
	healthPath = apiPrefix + "health"
	// toolsPath is the loopback tools API mount; httpapi.Handler is told the same base
	// path so its own routing matches where it is mounted.
	toolsPath = apiPrefix + "tools"
	// kiroRescanPath is the loopback kiro-cli repair hook: it makes an install fixed
	// INSIDE the container observable to the running server. Registered with a method
	// pattern, so anything but POST is a 405 rather than a silent no-op.
	kiroRescanPath = apiPrefix + "kiro-cli/rescan"
)

type routeDeps struct {
	// static is the embedded-static serving handler, built by the composition root
	// together with the hash-pinned CSP the same tree produces.
	static http.Handler
	ready  *webhttp.Ready
	// listenHint is "localhost[:port]" for THIS deployment; loopback refusals quote
	// it so the remedy works on a server that did not keep the default port.
	listenHint string
	// nil is reserved for the two MOUNTING decisions (tools, kiroRescan); every other
	// policy function below is always non-nil, defaulted by the composition root's
	// off-shape constructors. toolsMissing's second return distinguishes "none
	// outstanding" from "not counted yet".
	tools        *toolbelt.Engine
	toolsSyncing func() bool
	toolsState   func() string
	toolsMissing func() (int, bool)
	// containment, when non-nil, puts each tab's kiro-cli process tree in its own
	// cgroup so ending the session ends the tree. `kiro-cli chat` is a four-deep tree
	// whose agent server calls setsid() and installs no stdin-EOF exit path, so it
	// can outlive the session that spawned it (measured: 13 stranded processes
	// holding 1.35 GB on a two-tab container).
	containment *terminal.Containment
	// kiroReady is the install manager's readiness verdict plus the reason to report
	// when false; gates /api/health and session creation.
	kiroReady func() (bool, string)
	// kiroRescan, when non-nil, re-derives the active kiro-cli version from disk
	// without downloading anything. Backs kiroRescanPath.
	kiroRescan func(context.Context) (bool, error)
	// cmd builds one session's argv. A FUNCTION, not a slice: the active kiro-cli
	// version can change while the server runs.
	cmd func() []string
	// sessionEnv returns the per-session environment overlay (the active version
	// directory leading PATH). A nil result leaves the child with the server's own
	// environment.
	sessionEnv func() []string
	// sessionTitleEnv returns the per-session variables a kiro-cli hook needs to
	// report which kiro session this tab is running (the tab's TITLE HANDLE, not the
	// session id — see sessiontitle.go). A nil function leaves tabs on the engine's
	// automatic name ladder.
	sessionTitleEnv func(id terminal.SessionID) []string
	// scrollback is the operator's retained-history depth, or nil when unset (the
	// option is then OMITTED and the engine's own default applies). A POINTER
	// because 0 is a legal depth meaning "retain nothing" — an int sentinel would
	// silently disable scrollback in every hand-built routeDeps.
	scrollback *int
	workDir    string
	// logOSCText is the LOG_OSC_TEXT opt-in: when true, an unrecognized OSC 9
	// notification's full text is logged at Debug. Default false — arbitrary child
	// output that may carry a token or device code.
	logOSCText bool
}

// buildStaticSurface assembles the embedded-static serving surface: the static handler
// and the hash-pinned CSP policy built from the same tree, fail-loud on a malformed
// embed. webhttp.StaticHandler supplies content-hash ETags (embed.FS reports a zero
// ModTime, so a bare http.FileServer emits no validator) plus precomputed gzip; the
// per-path cache POLICY stays this app's (kiroCacheControl).
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

// registerRoutes wires the full route table on mux and returns the session manager (for
// shutdown).
func registerRoutes(mux *http.ServeMux, deps *routeDeps) *terminal.SessionManager {
	mux.Handle("/", deps.static)

	mgr := terminal.NewSessionManager(newSessionFactory(deps),
		terminal.WithManagerLogger(slog.Default()),
		terminal.WithStatusClassifier(newStatusClassifier(deps.logOSCText)),
	)

	// The engine owns its route topology: MountAPI wires exactly its documented set,
	// so no engine-internal route can appear on this unauthenticated surface
	// unannounced.
	//
	// The create gate composes three layers, outermost first: kiro-cli install, then
	// the tools boot convergence (kiro-cli scans PATH for language servers once at
	// session start), then the rate limit. kiro-cli is first because without that
	// layer every session created during the first-boot download exits 1.
	createGate := webhttp.SessionCreateRateLimit(terminal.SessionsPath)
	createGate = composeGate(createGate, func() (bool, string) {
		return deps.toolsSyncing(), "tools installing"
	})
	createGate = composeGate(createGate, func() (bool, string) {
		ready, reason := deps.kiroReady()
		return !ready, reason
	})
	mgr.MountAPI(mux, terminal.WithCreateGate(createGate))

	// Tools REST surface, loopback-only. The consumer is an agent inside the
	// container via kiro-cli's `!` shell escape; the gate checks the socket peer and
	// the Host header, never forwarded headers, so it cannot be spoofed through a
	// proxy nor reached by a DNS-rebound page.
	if deps.tools != nil {
		toolsAPI := loopbackOnly("tools API", deps.listenHint, httpapi.Handler(deps.tools, toolsPath))
		mux.Handle(toolsPath, toolsAPI)
		mux.Handle(toolsPath+"/", toolsAPI)
	}

	// kiro-cli repair hook, admitted the same way and for the same consumer: a
	// one-shot background install that exhausted its retries leaves the server
	// answering 503 forever, and a repair made inside the container is invisible to
	// it until recreated. Downloads nothing.
	if deps.kiroRescan != nil {
		mux.Handle("POST "+kiroRescanPath, loopbackOnly("kiro-cli rescan hook", deps.listenHint, handleKiroRescan(deps)))
		// ServeMux synthesizes 405 only when NO pattern matches, and the "/" static mount
		// matches every path — so without this mount a GET here gets a bare 404. Less
		// specific than the POST pattern above, so POST still reaches the handler.
		mux.Handle(kiroRescanPath, loopbackOnly("kiro-cli rescan hook", deps.listenHint,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Allow", http.MethodPost)
				webhttp.WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
					"kiro-cli rescan is POST-only (curl -X POST "+deps.listenHint+kiroRescanPath+")")
			})))
	}

	mux.HandleFunc(healthPath, handleHealth(deps))

	return mgr
}

// kiroRescanBody is the repair hook's response envelope, matching healthBody's key order.
// The status vocabulary is only partly shared: "ok"/"unready" mean what they mean on
// /api/health; "abandoned" is this hook's own — only a rescan can fail to reach a verdict.
type kiroRescanBody struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// reasonRescanAbandoned is the repair hook's 503 reason when the request was abandoned
// before pinstall reached any verdict. Deliberately NOT one of main.go's kiroReasonText
// strings: those name the install manager's readiness state, and this reaches no verdict
// about the install at all.
const reasonRescanAbandoned = "kiro-cli rescan not performed: request abandoned before any verdict"

// handleKiroRescan re-derives the active kiro-cli version from what is on disk right now
// and reports the resulting readiness: 200 when a version is active afterwards, 503 with
// the manager's own reason when none is.
func handleKiroRescan(deps *routeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// pinstall owns both halves this handler used to hand-roll: WAITING for its
		// operation slot honours this context, while an ADMITTED rescan runs detached, so
		// a Ctrl-C or --max-time cannot make every candidate probe fail and have the
		// manager record "no usable version".
		ok, err := deps.kiroRescan(r.Context())
		if ok {
			webhttp.WriteJSON(w, kiroRescanBody{Status: "ok"})
			return
		}
		// A context error means the request was ABANDONED before pinstall reached any
		// verdict (the caller's own cancellation, or this server's shutdown). Reporting
		// that as "no usable version" would be a false broken-install record, and
		// "unready" is wrong too — a rescan queued behind another can abandon on a
		// perfectly ready manager.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			slog.Debug("kiro-cli rescan abandoned before a verdict was reached",
				"error", err)
			webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable,
				kiroRescanBody{Status: "abandoned", Reason: reasonRescanAbandoned})
			return
		}
		// The manager has already logged the specific fault; report the verdict rather
		// than the error text, which can name a filesystem path.
		reason := reasonUnavailable
		if _, why := deps.kiroReady(); why != "" {
			reason = why
		}
		// pinstall.Rescan's ordinary failure is (false, nil); a nil error attribute would
		// put "error":null there, indistinguishable from a state-write failure.
		attrs := []any{"reason", reason}
		if err != nil {
			attrs = append(attrs, "error", err)
		}
		slog.Warn("kiro-cli rescan found no usable version", attrs...)
		webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable,
			kiroRescanBody{Status: "unready", Reason: reason})
	}
}

// childEnv is the environment overlay for one tab's kiro-cli process: the active version's
// PATH lead, plus the two variables a hook needs to report which kiro session this tab is
// running. Built as a fresh slice rather than appending to sessionEnv's return, so one
// session's overlay can never alias another's backing array.
func (d *routeDeps) childEnv(id terminal.SessionID) []string {
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

// newSessionFactory builds the per-session handler factory the session manager calls once
// per tab: one independent PTY-backed kiro-cli chat process with its own VT screen and
// scrollback. It owns four session-scoped policies — the argv and PATH resolved from the
// install manager AT session-create time, the LogID-truncated per-session logger, the
// argv redaction, and the fast-death Warn hook that surfaces a broken kiro-cli install.
func newSessionFactory(deps *routeDeps) func(terminal.SessionID) *terminal.Handler {
	// WithKeepUnfocused pins the process to the DEC 1004 "unfocused" state so kiro-cli
	// keeps emitting its focus-gated OSC 9 notifications even though no browser tab
	// claims focus; web-terminal-server deliberately does not use this.
	//
	// No TERM_PROGRAM override: the engine advertises iTerm.app, which puts kiro-cli in
	// its OSC 9;4 progress allowlist and enables DEC 2026 synchronized output.
	return func(id terminal.SessionID) *terminal.Handler {
		start := time.Now()
		// The session id doubles as the /ws attach + resume capability token, so only
		// the engine's LogID-truncated form is ever bound to a logger.
		safeID := terminal.LogID(id)
		// The argv carries the operator's KIRO_CLI_CHAT_ARGS values, which could hold a
		// credential from a compose interpolation mistake (CWE-532), so the engine is
		// told to log a fixed marker instead.
		sessionLogger := slog.Default().With("session", safeID)
		opts := []terminal.Option{
			terminal.WithWorkDir(deps.workDir),
			terminal.WithKeepUnfocused(true),
			terminal.WithLogger(sessionLogger),
			terminal.WithCommandLogValue("[redacted]"),
			// The active kiro-cli version's own directory first on the child's PATH, plus
			// the two variables that let a kiro-cli hook report which kiro session this
			// tab is running. The engine appends WithEnv LAST, so this PATH wins.
			//
			// The engine's input-stream title deriver is deliberately NOT requested: every
			// discard key it does not model fuses abandoned text onto the next prompt.
			terminal.WithEnv(deps.childEnv(id)),
			// kiro-cli colours a markdown link with SGR 34 (palette slot 4); under the
			// engine's earlier VGA palette that slot was #0000aa, 1.58:1 against black.
			// 4.5 is the WCAG AA floor for body text; backgrounds and default foregrounds
			// are never touched.
			terminal.WithMinimumContrast(4.5),
			// Closing a tab must end the whole tree, and for this app it otherwise does
			// not: `kiro-cli chat` runs kiro-cli -> kiro-cli-chat -> the TUI -> the agent
			// server, and that last process calls setsid(), so no signal the engine can
			// aim reaches it. A nil containment is a no-op.
			terminal.WithContainment(deps.containment, id),
			// A dev-box tab can live for days; containment reclaims only at teardown, so
			// a tab whose agent connection died while its TUI stays alive keeps holding
			// memory for as long as it stays open, deliberately. This log line is what
			// keeps closing it the user's decision.
			terminal.WithContainmentSampleInterval(sessionCostInterval),
			// A session whose process dies within seconds of spawn is the
			// kiro-cli-missing/broken signature; raise it to Warn (the engine logs child
			// exit at Info by design).
			//
			// Gated on deps.ready: an app-initiated shutdown clears readiness before
			// mgr.Shutdown cancels the children, whose killed/canceled wait errors would
			// otherwise fire this as a false broken-install alert on every deploy.
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

// healthBody is /api/health's response envelope. A struct, not a map, because
// encoding/json sorts map keys, and webhttp's own readiness handler (and therefore
// web-terminal-server and subflux) emits {"status":…,"reason":…}. ToolsMissing is a
// POINTER so it is absent rather than 0 when unknown, since zero means converged.
// FIELD ORDER IS THE WIRE CONTRACT, which is why fieldalignment is silenced.
//
//nolint:govet // fieldalignment: declaration order is the JSON key order (above)
type healthBody struct {
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	Tools        string `json:"tools,omitempty"`
	ToolsMissing *int   `json:"tools_missing,omitempty"`
}

// handleHealth returns the /api/health readiness handler. It reflects, in order: listener
// readiness, the kiro-cli install manager's verdict, and the INFORMATIONAL tools fields —
// tool convergence never gates readiness.
func handleHealth(deps *routeDeps) http.HandlerFunc {
	// One constructor for both outcomes, so the informational fields cannot diverge
	// between them; they belong on the 503 bodies too, since an operator diagnosing a
	// 503 needs to see tools state as much as a healthy caller does.
	healthResponse := func(status, reason string) healthBody {
		body := healthBody{
			Status: status,
			Reason: reason,
			Tools:  deps.toolsState(),
		}
		if n, ok := deps.toolsMissing(); ok {
			body.ToolsMissing = &n
		}
		return body
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		// Set here rather than by middleware, so the handler carries its own contract
		// wherever it is mounted: a 200 with no explicit freshness is heuristically
		// cacheable under RFC 9111, and a cached "ok" keeps traffic arriving at an
		// instance that has begun draining.
		w.Header().Set("Cache-Control", "no-store")
		unready := func(reason string) {
			webhttp.WriteJSONStatus(w, http.StatusServiceUnavailable, healthResponse("unready", reason))
		}
		if !deps.ready.Ready() {
			unready("starting up or shutting down")
			return
		}
		// kiro-cli readiness, straight from the install manager. The listener binds
		// BEFORE the install runs, so this is what tells `docker ps` and the monitoring
		// probe apart from "serving". A READINESS signal, not liveness: under Swarm or
		// k8s, wire this to a readinessProbe, never a livenessProbe.
		if ok, reason := deps.kiroReady(); !ok {
			unready(reason)
			return
		}
		// The tools field is INFORMATIONAL: kiro-cli is the only core dependency, so
		// monitoring stays green during a long first-boot install while operators can
		// still see it.
		webhttp.WriteJSON(w, healthResponse("ok", ""))
	}
}

// sessionFastDeathMsg is the fast-death Warn's wording; a test asserts on it, and its
// quiet branch asserts an ABSENCE, which a reworded literal would satisfy vacuously.
const sessionFastDeathMsg = "session process exited almost immediately after start; kiro-cli may be missing or broken"

// unrecognizedNotifyMsg is the one wording both the bounded Warn and the per-occurrence
// Debug emit, so the two records a log search correlates cannot drift apart.
const unrecognizedNotifyMsg = "unrecognized kiro-cli OSC 9 notification; tab status dots will not latch (kiro-cli notification wording may have changed on a version bump)"

// unrecognizedNotifyCapMsg is emitted once the distinct-message budget is exhausted, so a
// silent stop is never mistaken for "nothing new appeared". Shares no substring with
// unrecognizedNotifyMsg — the two log searches must not match each other.
const unrecognizedNotifyCapMsg = "kiro-cli OSC 9 notification warn budget exhausted; further distinct wordings are Debug-only (set LOG_LEVEL=debug)"

// recognizedNotifyMsg is the POSITIVE half of the classifier trace. Without it a debug
// session that sees no classifier records cannot tell "kiro-cli emitted no notification"
// from "notifications mapped fine, the dot is lost downstream". Logs only the matched
// literal from the closed switch, never arbitrary child output.
const recognizedNotifyMsg = "kiro-cli OSC 9 notification mapped to a tab status"

// unrecognizedNotifyCap bounds how many DISTINCT unrecognized notifications are promoted
// to Warn: log volume, and the seen-set below, whose key comes from child process output
// and would otherwise grow without limit under a chatty or hostile session.
const unrecognizedNotifyCap = 8

// unrecognizedNotifyCapRearm is how long the budget-exhausted announcement stays silent
// before firing again. The seen-set is keyed on CHILD output, so the budget can be spent
// entirely on benign wordings; re-arming keeps a rewording that begins AFTER exhaustion
// visible in the default log stream.
const unrecognizedNotifyCapRearm = 6 * time.Hour

// unrecognizedNotifyHint is the operator-facing next step both Warn arms carry.
const unrecognizedNotifyHint = `re-verify the "Response complete" / "Permission required" / "Input required" strings in the pinned kiro-cli-chat binary and update newStatusClassifier; set LOG_OSC_TEXT=true with LOG_LEVEL=debug to log the notification text itself (it is arbitrary child output and may contain a token or device code)`

// notifyFingerprintHexDigits bounds the fingerprint written in place of the notification
// text. 64 bits of HMAC-SHA-256 is far more than enough to tell a handful of distinct
// wordings apart while staying short enough to read in a log line.
const notifyFingerprintHexDigits = 16

// notifyFingerprintKeyBytes is the width of the per-classifier HMAC key, generated at
// classifier construction and never logged.
const notifyFingerprintKeyBytes = 32

// notifyFingerprinter renders the stable, content-free identifier the log carries INSTEAD
// of an unrecognized notification's text.
//
// A bounded EXCERPT does not redact — a short token or device code fits inside any excerpt
// (CWE-532). An UNKEYED digest does not either: the plaintext is low-entropy, so a reader
// holding SHA-256(msg) can enumerate candidates offline. Keying with a secret the log
// never contains removes that oracle (CWE-760).
type notifyFingerprinter struct {
	key []byte
}

// newNotifyFingerprinter draws the per-classifier key. crypto/rand.Read never returns an
// error — it crashes the program irrecoverably if the OS source fails — so there is no
// keyless state to degrade into.
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

// metadata is the content-free description both the Warn arm and the default Debug arm
// log: which distinct wording it was, and how long it was.
func (f notifyFingerprinter) metadata(msg string) []any {
	return []any{
		"message_fingerprint", f.fingerprint(msg),
		"message_runes", utf8.RuneCountInString(msg),
	}
}

// notifyWarningState is newStatusClassifier's bounded warn budget for unrecognized OSC 9
// notifications. One instance per classifier instance, never a package var, so a test
// gets a fresh budget.
type notifyWarningState struct {
	warned map[string]struct{}
	// lastCapWarn is when the budget-exhausted announcement last fired; the zero value
	// means never, so the first one always fires.
	lastCapWarn time.Time
	// mu guards warned and lastCapWarn.
	mu sync.Mutex
}

// observe records msg against the warn budget and reports which record the caller should
// emit: warnFirst for the first occurrence of a DISTINCT message while budget remains,
// warnCapped at most once per unrecognizedNotifyCapRearm window for a distinct message the
// cap turns away. Both false means Debug-only. The engine shares one classifier across
// every session and calls it from per-session goroutines, so state is mutex guarded and
// the caller logs OUTSIDE the lock.
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
	// Re-arms rather than firing once per process: the seen-set fills first-come from
	// arbitrary child output, so a single announcement would leave a LATER rewording with
	// no default-level record at all. time.Since saturates for the zero value, so the
	// first turned-away message announces with no carve-out.
	if time.Since(s.lastCapWarn) < unrecognizedNotifyCapRearm {
		return false, false
	}
	s.lastCapWarn = time.Now()
	return false, true
}

// newStatusClassifier returns the kiro-cli OSC 9 -> session-status mapping the composition
// root injects into the engine, with a bounded warn latch on DISTINCT unrecognized
// notifications. Per-DISTINCT rather than one-per-classifier: a single sync.Once was
// consumed by the first unrecognized message of ANY kind, so a later bump rewording
// "Response complete" warned NOTHING while every turn-end silently stopped latching.
//
// Those three strings live in the kiro-cli-chat SIDECAR binary, not the dispatcher, so
// re-verify them there on every kiro-cli bump, in the same PR as the pin move.
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
			// tool-approval. If a bump reworded one of the three, every notification lands
			// here and the per-tab status dots silently stop latching. The Warn never
			// carries the TEXT: it is arbitrary child output, and sanitizeNotification
			// guarantees the record cannot be FORGED but redacts NOTHING. Decide under the
			// lock, log outside it — slog handlers can block on I/O.
			warnFirst, warnCapped := warnings.observe(msg)

			switch {
			case warnFirst:
				slog.Warn(unrecognizedNotifyMsg,
					append(fingerprints.metadata(msg), "hint", unrecognizedNotifyHint)...)
			case warnCapped:
				// The fingerprint of the message that hit the full budget, so a re-armed
				// announcement identifies WHICH wording drove it — otherwise two firings
				// six hours apart are indistinguishable from the same wording twice.
				slog.Warn(unrecognizedNotifyCapMsg,
					append(fingerprints.metadata(msg),
						"distinct_limit", unrecognizedNotifyCap,
						"hint", unrecognizedNotifyHint)...)
			}
			// ONE Debug record either way; the opt-in only ADDS the text. The fingerprint
			// rides along so this record pairs with whichever Warn sent the operator here.
			attrs := fingerprints.metadata(msg)
			if logText {
				attrs = append(attrs, "message", msg)
			}
			slog.Debug(unrecognizedNotifyMsg, attrs...)
			return "", false
		}
	}
}

// kiroCacheControl is the per-asset Cache-Control policy handed to webhttp.StaticHandler,
// which supplies the ETag/gzip mechanism (asset paths arrive normalized, no leading slash).
//
// Fonts get 30 days but NOT `immutable`: the @font-face URLs come from the vendored UI's
// own CSS under fixed names, so the bytes DO change under one filename on a Monaspace
// bump, and without `immutable` a reload revalidates against the content-hash ETag.
func kiroCacheControl(assetPath string) string {
	if strings.HasPrefix(assetPath, "vendor/fonts/") {
		return "public, max-age=2592000"
	}
	return "no-cache, must-revalidate"
}

// cspTemplate is the Content-Security-Policy applied to every response, with a %s
// placeholder for the script-src hash tokens and a second for the style-src hash token.
//
// index.html's single loading-overlay <style> is hash-pinned like the inline scripts, so
// an injected style block or style attribute cannot obscure or spoof the terminal UI. The
// renderer itself needs no relaxation: it styles via CSSOM property setters, which
// style-src does not govern, and neither the UI nor the engine emits a style= attribute.
const cspTemplate = "default-src 'self'; " +
	"script-src 'self' %s; " +
	"style-src 'self' %s; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; object-src 'none'; " +
	"form-action 'none'"

// buildCSPPolicy reads index.html from sub, hashes every inline <script> in it plus its
// single inline <style> block, and assembles the full CSP string. This app's index.html
// carries TWO inline scripts, the importmap and the bootstrap watchdog.
//
// FAIL LOUD: a malformed build aborts startup rather than silently dropping the hardening.
// The one-block assertion stays HERE rather than in the library: "exactly one" is this
// app's contract about its own page, not a property of style hashing.
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

// composeGate wraps a session-create gate with one more blocking check: while `blocked`
// reports true, only SESSION CREATION answers 503, so kiro-cli never spawns before its
// own install finishes or before the manifest's tools are on PATH. List/close/title
// requests through the same doubly-mounted handler pass through, and the inner gate
// applies once this layer clears — which is how the two blocking checks and the rate
// limit stack without knowing about each other.
func composeGate(inner func(http.Handler) http.Handler, blocked func() (bool, string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		gated := inner(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != terminal.SessionsPath {
				gated.ServeHTTP(w, r)
				return
			}
			if block, reason := blocked(); block {
				// Retry-After matches the inner rate limit's 429 contract. A fixed short
				// hint: neither a tools convergence nor a kiro-cli download has a
				// predictable remaining time, so a cheap re-poll beats a computed date.
				w.Header().Set("Retry-After", "5")
				webhttp.WriteError(w, r, http.StatusServiceUnavailable, "not_ready", reason)
				return
			}
			gated.ServeHTTP(w, r)
		})
	}
}

// loopbackOnly admits only requests whose SOCKET PEER and Host header are both loopback
// and which carry no proxy/browser provenance header (mechanism: webhttp.LoopbackOnly).
// What stays here is the refusal wording, which names the guarded surface and the
// deployment's own listen hint — the 403 is the whole of what a refused caller is told.
func loopbackOnly(surface, hint string, next http.Handler) http.Handler {
	refuse := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhttp.WriteError(w, r, http.StatusForbidden, "loopback_only",
			surface+" is loopback-only; call it from inside the container (curl "+hint+")")
	})
	return webhttp.LoopbackOnly(refuse)(next)
}

// sessionCostInterval is how often a contained session logs what it is currently costing.
// Fifteen minutes because the question it answers is "what is this tab costing me", not
// "watch a leak develop" — a stranded process is already reported the instant it happens,
// by the engine's reclaim WARN at teardown.
const sessionCostInterval = 15 * time.Minute
