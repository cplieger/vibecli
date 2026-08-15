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

	"github.com/cplieger/envx"
	"github.com/cplieger/pinstall/v2"
	"github.com/cplieger/pinstall/v2/kirocli"
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
// WT_TRUSTED_PROXIES env var into the trusted-proxy set the access log's client-IP
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
	const key = "WT_TRUSTED_PROXIES"
	v := envx.String(key, "")
	if v == "" {
		return nil
	}
	nets, invalid := webhttp.ParseCIDRs(strings.Split(v, ","))
	if len(invalid) > 0 {
		// Count-only, like the WT_LOG_LEVEL and KIRO_CLI_CHAT_ARGS
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

// parseAllowedHosts reads the comma-separated WT_ALLOWED_HOSTS list of exact
// hostnames / IPs this server answers for into a webhttp.HostPolicy — the
// shared exact-match Host allowlist that closes the DNS-rebinding hole
// same-origin checks alone leave open (a rebinding attack makes Origin and
// Host AGREE, so CrossOriginProtection admits it; only an exact-Host check
// breaks that chain, CWE-346). The library owns the mechanism
// (webhttp.CanonicalHost canonicalization, X-Forwarded-Host ignored, the
// loopback peer+Host carve-out that keeps the baked Docker healthcheck and
// in-container tools clients working under any allowlist); this parser owns
// the app policy: the carve-out is enabled, the 403 names WT_ALLOWED_HOSTS,
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
	const key = "WT_ALLOWED_HOSTS"
	policy, invalid := webhttp.ParseHostList(strings.Split(envx.String(key, ""), ","),
		webhttp.WithLoopbackExempt(),
		webhttp.WithHostAllowlistError("",
			"host not allowed; add it to WT_ALLOWED_HOSTS to serve this hostname"))
	if len(invalid) > 0 {
		// Count-only, like parseTrustedProxies: the rejected raw values could
		// carry a misplaced credential, so only their count is logged.
		slog.Warn("dropping malformed "+key+" entries; they cannot match any browser-sent Host",
			"invalid_count", len(invalid),
			"hint", "use bare hostnames or IPs only (no scheme, path, or CIDR), e.g. localhost,192.168.1.5,webterm.example.com; a lone port like :9848 belongs in WT_ADDR")
	}
	if policy.Active() && policy.Size() == 0 {
		slog.Warn(key+" has no usable entries; rejecting every non-loopback request (fail closed)",
			"hint", "fix the malformed entries in "+key+" to restore browser access")
	}
	return policy
}

// resolveScrollback reads the retained-history depth from the env var the ENGINE
// owns (terminal.ScrollbackEnvVar), returning scrollbackUnset when the operator
// set nothing so the session factory omits the option and the engine's own
// default applies.
//
// The variable is shared with web-terminal-server and vibekit, which is why its
// name and its awkward-middle policy both live in the engine rather than here: a
// knob spelled or interpreted three ways is three knobs. This app's only local
// decision is the failure posture, and it is this app's usual one — warn by NAME
// and fall back rather than abort, because retained history is not a safety
// property and a dev box must be able to boot with a typo'd compose value (see
// the same reasoning on WT_LOG_LEVEL). The value is deliberately not echoed:
// this app publishes a no-values promise for its whole env surface.
func resolveScrollback() *int {
	// envx.IntStrict is the read the engine's ScrollbackEnvVar doc names, and the
	// same three states parseLogOSCText's BoolStrict returns: unset or blank
	// (ok=false, no error), malformed (an error), or a value. The error is
	// deliberately NOT logged — it wraps *strconv.NumError, which carries the
	// rejected value, and this app warns by name only.
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
// by-name-only warning. main() reads the value under the same name from here, so the
// key has one home. (Package scope beside the function rather than inside the
// kiro-cli layout const block below, which is scoped to install-layout facts.)
const catalogRefreshKey = "TOOL_CATALOG_REFRESH"

// parseCatalogRefresh reads TOOL_CATALOG_REFRESH and delegates to toolbelt's
// canonical parser — but only for values that parser ACCEPTS. toolbelt calls
// scheduler.ParseInterval without scheduler.WithRedactedValue, so its fallback
// warning echoes the RAW value (scheduler warnFallback), and a compose expansion
// mistake could put a credential on this key — the same reason WT_LOG_LEVEL is
// read as a string and WT_LOG_OSC_TEXT goes through envx.BoolStrict. A value the
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

// parseLogOSCText reads the WT_LOG_OSC_TEXT knob (default false) and emits the
// startup warnings that go with it, returning whether notification TEXT may be
// logged.
//
// WT_LOG_OSC_TEXT is the confidentiality opt-in for terminal notification
// TEXT. An unrecognized OSC 9 notification is arbitrary child output — any
// program run in the terminal can emit `ESC ] 9 ; <text>` — and it can carry a
// token or a device code, so by default the classifier logs only a content-free
// fingerprint plus a rune count (see newStatusClassifier). Turning this on adds
// the full text to the Debug record, which is why it warns at startup rather
// than logging silently: raising WT_LOG_LEVEL alone must not widen what
// content reaches the log store.
//
// Read with envx.BoolStrict, NOT envx.Bool, and that choice is the
// confidentiality property rather than a style preference: a compose expansion
// mistake can put a secret on this key (`WT_LOG_OSC_TEXT: ${SOME_TOKEN}`), and
// envx.Bool's malformed path emits a Warn carrying the RAW value — a durable,
// queryable copy of that secret in the log store (CWE-532). BoolStrict shares
// ONE parser with Bool, so the accepted vocabulary (true/1/yes/on,
// false/0/no/off, case-insensitive, padding ignored) cannot drift from the
// fleet's, but it logs nothing at all and hands the parse result back instead:
// the error it returns names only the key and the accepted spellings, never the
// value. Do NOT "simplify" this to envx.Bool — the two differ only in who owns
// the diagnostic, and Bool's diagnostic is the leak. The same reasoning keeps
// WT_LOG_LEVEL a string read and TOOL_CATALOG_REFRESH behind
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
	const key = "WT_LOG_OSC_TEXT"
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

// parseToolsTainted decodes KIRO_CLI_TOOLS_TAINTED, the entrypoint's
// tools-tree-was-writable observation, into the flag that makes the kiro-cli
// install manager distrust every version directory already on the volume
// (pinstall's Untrusted) and activate only one it installed from the
// digest-verified archive this boot. Only the entrypoint can make the
// observation — it is the half that chmods and re-stats (secure_tools_dir) — so
// this is a handoff with exactly one producer, not an operator knob.
//
// The accepted vocabulary is exactly "1" and "0", and that narrowness is the
// property rather than strictness for its own sake. The variable is an
// AFFIRMATIVE OBSERVATION ("the entrypoint looked, and the tree was writable"),
// and the entrypoint only ever writes 0 or 1, so a value that is NEITHER means no
// such observation was made — the same epistemic state as unset, and unset already
// reads as clean. Arming the taint on garbage would be inventing evidence rather
// than acting on it, and the cost is not merely a download: the recovery it forces
// replaces the pinned version directory and then prunes everything beyond the
// active version plus one predecessor, and that retained pair is what stands in
// for a rollback path in this app (pinstall's retainedVersions; "Exactly one
// predecessor is retained").
//
// So: "1" arms, "0" does not, unset does not, anything else does not AND warns.
//
// Deliberately NOT envx.Bool/BoolStrict, and do not "unify" it with them: that
// shared vocabulary also accepts true/yes/on in any capitalisation with
// surrounding whitespace, which widens the set of values that can arm a trust
// boundary. The accepted spellings of a security-relevant flag are never widened
// as cleanup; the narrow vocabulary IS the property. The shell-to-Go boundary is
// protected from the other side instead: tests/shell/pins_export_test.sh asserts
// every assignment to the producer's taint variable is the literal 0 or 1, which
// is what makes this side safe to keep narrow rather than merely strict.
//
// The warning names the KEY and nothing else — not the value, not its length, not
// a fragment — for the reason parseTrustedProxies, parseAllowedHosts,
// parseLogOSCText and parseCatalogRefresh all log by name or count only: a compose
// interpolation mistake can put a credential on ANY variable
// (`KIRO_CLI_TOOLS_TAINTED: ${SOME_TOKEN}`), and echoing it would leave a durable,
// queryable copy in the log store (CWE-532). The hint is a FIXED string for the
// same reason: it must not grow an input-derived tail.
//
// os.LookupEnv rather than envx.String, because unset and set-but-empty must not
// behave alike here: unset is the ordinary out-of-container run (a bare `go run`,
// the tests) and has to stay silent, while an empty value came from the one
// producer that was supposed to write 0 or 1 and is exactly the malformed case
// worth reporting. That set-vs-unset distinction is envx's documented escape hatch
// from its empty-equals-unset rule.
func parseToolsTainted() bool {
	const key = "KIRO_CLI_TOOLS_TAINTED"
	raw, set := os.LookupEnv(key)
	switch {
	case !set, raw == "0":
		// The only silent path, and the two spellings of the same fact: nothing
		// reported the tree as writable, so a pre-existing version directory is
		// still trusted on the strength of its own sentinel.
		return false
	case raw == "1":
		return true
	default:
		slog.Warn("unusable "+key+"; treating the kiro-cli tools tree as untainted, the same outcome as unset",
			"hint", "only entrypoint.sh sets this, and only to 1 (it found the tools tree group/other-writable) or 0 (it did not); any other value is not an observation, so it cannot arm the distrust-and-reinstall path")
		return false
	}
}

// parseTrustedInstallUIDs decodes WT_TRUSTED_INSTALL_UIDS, a comma-separated
// list of numeric uids, into the identities pinstall may find with write access
// to the kiro-cli installation tree without treating custody as broken
// (pinstall.Config.TrustedUIDs).
//
// It is EMPTY BY DEFAULT, and the default is the point: unset or blank grants
// nothing, so the library's custody check applies in full and refuses an install
// root some other identity can write. Setting the variable is an ASSERTION about
// the deployment, and the library's field doc states the contract it has to meet
// — every uid listed is already at least as privileged as this server process,
// so its write access to the tree gains that identity nothing. An identity that
// is NOT (the unprivileged account another service runs as) can escalate through
// a binary this app installs and then executes, so naming it defeats the check
// rather than tuning it. Only the operator can answer this: nothing in the image
// can know which identities a given volume's ownership, mode or ACL grants.
//
// A malformed entry is DROPPED and the usable ones are kept, the warn-and-drop
// posture WT_ALLOWED_HOSTS and WT_TRUSTED_PROXIES already use: one typo in a list
// must not fail the boot, and dropping is the fail-closed direction here, because
// a uid that never lands leaves the check enforcing against it. Which entries are
// refused, and why a blank between separators is not one of them, is
// pinstall.ParseIdentities' contract: the rule follows from what the library's own
// field means, so it lives beside that field rather than in a copy here. This app
// keeps the two things that ARE its own — the variable's name, and every word an
// operator reads about it.
//
// The warning names the KEY and a COUNT only, never an entry, for the reason
// parseTrustedProxies, parseAllowedHosts, parseToolsTainted, parseLogOSCText and
// parseCatalogRefresh all log by name or count: a compose interpolation mistake
// can put a credential on any variable (`WT_TRUSTED_INSTALL_UIDS:
// ${SOME_TOKEN}`), and echoing it would leave a durable, queryable copy in the
// log store (CWE-532). The hint is a FIXED string for the same reason — it must
// not grow an input-derived tail. The library returns a count rather than the
// refused text precisely so this promise cannot be broken by accident.
//
// Carries the WT_ family prefix, like every other operator knob this app reads
// and like the engine's own WT_SCROLLBACK: the knob is not specific to this app.
// Every app that installs kiro-cli through pinstall faces the same custody
// question about the same volume, and a knob spelled one way per app is several
// knobs. A shared spelling is also the one a shared README can document.
func parseTrustedInstallUIDs() []int {
	const key = "WT_TRUSTED_INSTALL_UIDS"
	uids, rejected := pinstall.ParseIdentities(envx.String(key, ""))
	if rejected > 0 {
		slog.Warn("dropping unusable "+key+" entries; the kiro-cli install keeps enforcing custody against those identities",
			"invalid_count", rejected,
			"hint", "each entry is a single numeric uid greater than 0 (e.g. 1000,1001); root is trusted already, and every identity listed must be at least as privileged as this server")
	}
	return uids
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

// loopbackHint renders the address an in-container caller uses to reach this
// server, for the loopback surfaces' refusal messages (routeDeps.listenHint).
// Derived from the listen address (WT_ADDR) so a deployment that moved the port
// is not told to curl the default one — the 403 is the whole of what a refused
// caller is told. A port-less or malformed addr degrades to the bare host rather
// than to a broken URL.
func loopbackHint(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return "localhost:" + port
	}
	return "localhost"
}

// main is the process's ONLY exit site. Everything else lives in run, which
// reports failure by returning an error, so no startup branch can exit past a
// pending defer and skip the subsystem teardown — the hazard the four
// hand-coordinated os.Exit calls this replaced each had to remember.
func main() {
	if err := run(); err != nil {
		// Rendered once, here: the failure branches in run carry their operator
		// hint inside the returned error rather than logging it themselves, so a
		// startup failure produces exactly one ERROR line.
		//
		// stage is what a log query keys on. Consolidating five named ERROR
		// messages into this one line removed the only discriminator an alert
		// rule had, and three of those five names do not even survive as
		// substrings of the wrapped error (an interpolated path interrupts two of
		// them, and "listen failed" became "listen on <addr>"). A stable VALUE is
		// strictly better than the prose names it replaces: prose is rewritten by
		// any edit to the message, a stage token is not.
		slog.Error("web-terminal-kiro exited with error", "stage", stageOf(err), "error", err)
		os.Exit(1)
	}
}

// The startup stages a failure can be attributed to. Values, not messages: these
// are the strings an operator's log query or alert rule matches, so they are
// enumerated here and changing one is a breaking change to the log surface.
const (
	stageWorkDir = "work_dir" // the /workspace mount is absent or not a directory
	stageStatic  = "static"   // the embedded static tree is unusable
	stageListen  = "listen"   // the listener could not bind
	stageServe   = "serve"    // the HTTP server exited with an error
	// stageUnknown is emitted for a failure nobody attributed, so the field is
	// ALWAYS present. An absent field would make a query have to distinguish
	// "no stage" from "no match", and a new failure path that forgets to attribute
	// itself then shows up as an explicit unknown rather than as silence.
	stageUnknown = "unknown"
)

// stageError attributes a startup failure to a stage without changing what the
// error says. It carries no message of its own precisely so the wrapped text
// stays the operator's hint, unchanged.
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

// setupLogging installs the slog handler this app's whole observability story
// rests on. Parse the level BEFORE Setup so the handler installs at the
// configured level; warn AFTER Setup so the warning emits through the configured
// handler (the slogx contract). WT_LOG_LEVEL=debug surfaces the diagnostic
// lines that are invisible at the default info — e.g. the newStatusClassifier
// trace for a kiro-cli notification-wording drift.
func setupLogging() {
	logLevel, ok := slogx.ParseLevel(envx.String("WT_LOG_LEVEL", ""), slog.LevelInfo)
	slogx.Setup(slogx.Options{Level: logLevel})
	if !ok {
		// Field-name-only: a compose expansion mistake could put a secret in
		// the value, so the raw string never reaches the log.
		slog.Warn("unparseable WT_LOG_LEVEL; using the info default",
			"hint", "use debug, info, warn, or error")
	}
}

// checkWorkDir refuses a work directory in any of three distinct shapes:
// absent, present but unstattable, or not a directory. They are deliberately
// NOT collapsed — only an ABSENT directory is a missing-mount mistake, and the
// other two would send the operator to add a mount that is already there — so
// each returned error carries its own remedy: main renders it as the process's
// single ERROR line.
func checkWorkDir(workDir string) error {
	fi, err := os.Stat(workDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return atStage(stageWorkDir, fmt.Errorf("work directory %s is missing (bind-mount a host directory to /workspace in compose.yaml): %w", workDir, err))
	case err != nil:
		// Present but unstattable: EACCES on a parent, ELOOP on a symlinked target,
		// an EIO from the backing volume. The mount IS configured, so the
		// missing-mount remedy above would send the operator to add one that is
		// already there — the same collapse startTools refuses to make for its
		// config dir, and this branch ends the process rather than degrading.
		return atStage(stageWorkDir, fmt.Errorf("work directory %s could not be inspected: the mount exists but is unreadable to this process; check the bind source's permissions and its parent directories: %w", workDir, err))
	case !fi.IsDir():
		return atStage(stageWorkDir, fmt.Errorf("work directory %s is not a directory: the mount target is a file or device, not a directory; bind-mount a host DIRECTORY to /workspace in compose.yaml", workDir))
	}
	return nil
}

// run is the composition root: it wires the tools engine, the kiro-cli install
// manager, the route table and the HTTP server, then blocks on the
// signal-driven lifecycle. It returns nil on a clean shutdown and a wrapped
// error on any startup or serve failure; main turns that into the exit code.
// Keeping the body here rather than in main is what lets the deferred teardown
// run on every failure path.
func run() error {
	setupLogging()

	addr := envx.String("WT_ADDR", ":9848")
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
	workDir := envx.String("WT_WORKDIR", "/workspace")
	if err := checkWorkDir(workDir); err != nil {
		return err
	}
	scrollback := resolveScrollback()

	// Tools engine (cplieger/toolbelt): declarative provisioning of the
	// /config/tools tree from the tools.json manifest, replacing the
	// retired setup-tools.sh. Constructed only when the config dir
	// exists (the container's /config bind mount); bare `go run` and
	// tests outside the container run without a tools surface.
	// ONE read for the ONE tools root, handed to both co-owners below: the toolbelt
	// engine (its ConfigDir and ToolsDir) and the kiro-cli install manager (its
	// install Root). entrypoint.sh exports the path it created and hardened, and a
	// SECOND derivation is what previously split toolbelt's manifest from the tree it
	// describes (the deleted config-dir knob), so the value is resolved here rather
	// than at each consumer. Empty outside the container, where startTools falls back
	// to <configDir>/tools.
	kiroToolsDir := envx.String("KIRO_CLI_TOOLS_DIR", "")

	tools := startTools(baseTools{
		configDir:   configMountDir,
		toolsDir:    kiroToolsDir,
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

	// WT_TRUSTED_PROXIES names the reverse proxies (CIDRs or bare IPs) whose
	// X-Forwarded-For the access log may trust to recover the real client IP.
	// Unset/empty ⇒ nil ⇒ trust nothing ⇒ log the unspoofable socket peer (the
	// spoof-safe default for a directly-exposed deployment). See parseTrustedProxies.
	trustedProxies := parseTrustedProxies()

	// WT_ALLOWED_HOSTS names the exact hostnames/IPs this server answers
	// for; anything else is rejected before the terminal routes (see
	// parseAllowedHosts for the DNS-rebinding rationale). Unset ⇒ inactive
	// policy ⇒ permissive (backward compatible), but that leaves rebinding
	// open even on a loopback/private bind — the attack rides the victim's
	// browser, so the README's "keep it loopback" mitigation does not cover
	// it. Warn.
	hostPolicy := parseAllowedHosts()
	if !hostPolicy.Active() {
		slog.Warn("WT_ALLOWED_HOSTS is unset or blank; any Host header is accepted, leaving DNS rebinding open even on loopback/private binds",
			"hint", "set WT_ALLOWED_HOSTS to the exact hostnames/IPs you browse to (e.g. localhost,192.168.1.5,webterm.example.com)")
	}

	// WT_LOG_OSC_TEXT (default false) is the confidentiality opt-in for
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
		// Field-count-only, like the WT_LOG_LEVEL warning above: a compose
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
	// KIRO_CLI_TOOLS_TAINTED is the entrypoint's tools-tree-was-writable
	// observation; the two-value vocabulary that may arm it, the
	// treat-anything-else-as-unset outcome and the by-name-only warning are all
	// parseToolsTainted's. WT_TRUSTED_INSTALL_UIDS is the operator's own
	// declaration of which identities may write the installation tree without
	// breaking custody, empty by default so the library's check applies in full;
	// see parseTrustedInstallUIDs.
	tainted := parseToolsTainted()
	kiro := startKiroCLI(&baseKiro{
		version:            envx.String("KIRO_CLI_VERSION", ""),
		sha256:             envx.String("KIRO_CLI_SHA256", ""),
		sha256ARM64:        envx.String("KIRO_CLI_SHA256_ARM64", ""),
		toolsDir:           kiroToolsDir,
		tainted:            tainted,
		chatArgs:           chatArgs,
		trustedInstallUIDs: parseTrustedInstallUIDs(),
	})

	mux := http.NewServeMux()
	var ready webhttp.Ready

	// Tab names come from kiro-cli's own session record. The state root is
	// container-local on purpose: a mapping is only meaningful for a LIVE tab, and
	// this app persists no session state (terminal state is the in-memory VT
	// buffer), so nothing here should outlive the container. A refused directory is
	// a warn, not fatal — and it is AUTHORITATIVE for both consumers: no tab gets
	// WT_TITLE_HANDLE or WT_TITLE_STATE_DIR, the poller never starts, and the
	// engine's automatic ladder names every tab (see enableSessionTitles for why a
	// warn-only verdict left the refused path in use).
	titles := newSessionTitleSync(titleStateRoot, envx.String("HOME", ""))
	sessionTitleEnv := enableSessionTitles(titles)

	// The subsystem teardown, named once and deferred once: both background
	// owners, in the order the four hand-coordinated exit paths this replaced
	// used. Every return below runs it, and a third subsystem is then added in
	// one place instead of four.
	defer func() {
		kiro.stop()
		tools.close()
	}()

	// The static tree's two derivatives, assembled together and fail-loud
	// (buildStaticSurface), then handed to their own consumers: the serving
	// handler to the route table, the hash-pinned CSP to buildHandler's
	// SecurityHeaders layer. The root builds them because it is the only place
	// that consumes both.
	staticSrv, cspPolicy, err := buildStaticSurface(staticFS)
	if err != nil {
		return atStage(stageStatic, fmt.Errorf("the embedded static tree is unusable: %w"+
			" (this is a build defect, not a runtime setting: the embedded static/index.html must carry at least one inline <script> and exactly one inline <style> block;"+
			" rebuild the image — go generate ./... plus the Dockerfile static build. The container will crash-loop under its restart policy until it is rebuilt.)", err))
	}

	// Orphan reaping is the CONTAINER INIT's job, not this server's, and that is
	// why no reaper is installed here. Compose runs the image with `init: true`, so
	// tini is pid 1 and this server is pid 2: every process whose own parent died —
	// each language server, each git a session forked — re-parents onto tini, which
	// owns no child anyone else waits on and therefore collects it safely, while
	// this process waits only for the children it created. Without an init the
	// server IS pid 1 and Go's os/exec collects nothing it did not spawn: measured
	// on borgcube 2026-08-09, 17,323 zombies against 88 live processes.
	//
	// The engine's in-process terminal.StartZombieReaper is DELIBERATELY not used,
	// and it is not merely redundant here — it is incompatible. It sets
	// PR_SET_CHILD_SUBREAPER, which re-parents orphans onto this server even behind
	// an init shim, so it would take the orphans back off tini and then sweep them
	// itself, excluding only the pids in the engine's own private spawn registry.
	// This app also spawns through os/exec outside that registry (pinstall's version
	// probes and settings assertions, toolbelt's package managers, decompressors, gh
	// and bash), so the sweep can win the race for one of THOSE exit statuses and
	// make successful work report as failed.
	//
	// SESSION reaping is a different engine mechanism and stays on by default: it
	// ends a closed session's still-ALIVE descendants from an inherited environment
	// marker, needs no capability, and is unaffected by which process is pid 1.
	//
	// Because reaping is the init's job, its ABSENCE is detectable here in one
	// comparison: with `init: true` tini is pid 1 and this server is not; without
	// it the entrypoint's exec chain makes this server pid 1, where os/exec
	// collects only its own children and every re-parented orphan stays a zombie
	// for the container's lifetime (measured: 17,323 zombies, 32.6 GB). Warn, not
	// fatal, per this app's failure posture: the container still serves and the
	// fix is one compose line.
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

	// The listener is bound before the base context + server are built, which
	// used to be forced by gocritic exitAfterDefer (a listen-failure os.Exit had
	// to run with no pending defer). The exit is gone, so the ordering is now
	// only what it always read as: nothing request-scoped exists until there is
	// something to serve on.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return atStage(stageListen, fmt.Errorf("listen on %s: %w", addr, err))
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

	// Poll kiro-cli session titles onto the engine's client title rung for as long
	// as the server serves. Bound to baseCtx, which the pre-drain hook cancels, so
	// this stops with the rest of the request-scoped work. Skipped entirely when the
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
	if err := webhttp.Run(ctx, srv, ln, func(context.Context) { mgr.Shutdown() },
		webhttp.WithShutdownGrace(5*time.Second),
		webhttp.WithPreDrain(func(context.Context) {
			ready.Set(false)
			cancelBase()
			slog.Info("shutting down", "cause", context.Cause(ctx))
		})); err != nil {
		// Clear readiness before shutting sessions down: the fast-death Warn
		// in registerRoutes keys on it to distinguish app-initiated process
		// cancellation from a spontaneous early child failure (the normal
		// SIGTERM path clears it in the pre-drain hook; this fatal path must
		// do the same or a teardown would emit a false broken-install alert).
		ready.Set(false)
		mgr.Shutdown()
		return atStage(stageServe, fmt.Errorf("http server exited: %w", err))
	}
	return nil
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
// the entrypoint can make, this deployment's extra chat flags, and the operator's
// install-custody trust list.
type baseKiro struct {
	version     string
	sha256      string
	sha256ARM64 string
	toolsDir    string
	chatArgs    []string
	// trustedInstallUIDs are the operator-declared identities whose write access
	// to the installation tree does not break custody. Empty by default; see
	// parseTrustedInstallUIDs.
	trustedInstallUIDs []int
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
		env: mgr.PathEnv,
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
		// The identities an operator has declared may write the installation tree
		// without breaking custody (WT_TRUSTED_INSTALL_UIDS), empty by default so
		// the library's check applies in full. Setting it asserts what the library's
		// own field doc requires: each identity is already at least as privileged as
		// this process, so its write access to the tree gains it nothing.
		TrustedUIDs: cfg.trustedInstallUIDs,
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
		// The retained-history recovery, and a settings assertion is the ONLY way to
		// reach it: kiro-cli exposes no `chat` flag and no TWINKI_* env var for it
		// (checked against 2.18.0), so KIRO_CLI_CHAT_ARGS cannot carry it and there
		// is nothing for a compose file to set.
		//
		// Without it kiro-cli emits ED3 ("\x1b[3J", Erase Saved Lines) on every
		// full-viewport repaint and the engine honors it by CLEARING the ring, which
		// made WT_SCROLLBACK and the engine's 100000-line default unreachable:
		// 2294-3185 lines retained across 5 real sessions, roughly 3%. With it the
		// streaming and overflow repaint emits zero ED3 (measured 3 -> 0 over three
		// `!seq 1 200` bursts in a fixed 14x100 viewport) and each redraw is about
		// half the bytes, which is WebSocket traffic in this app.
		//
		// It does NOT fix resizes, height-only included: 4 ED3 with the setting and 4
		// without, over 14x100 -> 30x100 -> 10x100, because kiro-cli's debounced
		// resize callback writes its CLEAR_ALL unconditionally and its width-changed
		// redraw branch is ungated (upstream Kiro#10780, reopened 2026-08-15). So
		// this recovers the full depth on a fixed viewport and buys a phone nothing,
		// since a soft keyboard opening is a height change.
		//
		// Needs kiro-cli 2.17.0+. On anything older the key is unknown and the
		// assertion warns, which is exactly why best-effort is the right class here:
		// a retained predecessor selected after a failed install must still serve.
		kirocli.Setting("chat.preserveScrollback", true),
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
	// missing is the WHOLE-TREE convergence signal, and it is deliberately a
	// second question from state: state answers "did the last job succeed, or
	// are we still booting", which is what keeps monitoring from flapping
	// through a long first-boot install, while this answers "is the tree
	// actually converged" — how many enabled manifest entries are still not
	// installed. Reporting one of them as the other is what made state=ok
	// readable as whole-tree health after a partial repair.
	//
	// ok is false until the first recount lands (and for an engine-less
	// runtime), so a consumer can tell "nothing outstanding" from "not known
	// yet" instead of reading a premature zero as convergence.
	missing func() (n int, ok bool)
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
// (under toolbelt's queue lock) up to one Wait poll BEFORE startTools calls
// recordBoot — so without the flag a converged boot would publish "ok", and
// with it lift the session-create gate derived from this same cell, before the
// boot pass's own verdict was recorded. The boot verdict is therefore
// authoritative until it is recorded, and the live reducer starts only after.
//
// This type is deliberately IGNORANT of kiro-cli readiness: it holds no
// reference to the install manager's separate verdict. The session-create gate
// IS derived from it — startTools' predicate is `get() == syncing` — which is
// safe precisely because syncing is never re-entered: a post-boot job failure
// stores degraded, so it cannot re-close session creation (the gate lifts on
// boot failure by design — degraded-not-dead — and that decision stays made).
// Deriving both from one cell is what keeps them from contradicting each other
// mid-boot; two cells could not be stored simultaneously.
type toolsStatus struct {
	// state is the current value, and — through the syncing state — the
	// session-create gate's only predicate. atomic rather than a mutex
	// because OnJobChanged fires under toolbelt's own queue lock and must
	// not block: the health handler and the session-create gate read it on
	// request goroutines.
	state atomic.Value // string: syncing | ok | degraded
	// poke asks the convergence watcher for a recount. Buffered depth 1 and
	// written with a NON-BLOCKING send, because every writer is either
	// OnJobChanged (which runs under toolbelt's queue lock and must never
	// block) or recordBoot. Coalescing is the intent: several job
	// transitions in a burst need one recount, not one each.
	poke chan struct{}
	// missing is the whole-tree convergence count: enabled manifest entries not
	// installed. Negative means "not counted yet", which is a THIRD state a
	// plain count cannot carry — a premature 0 would read as convergence.
	missing atomic.Int64
	// booted reports whether the boot verdict has been recorded, i.e.
	// whether the live half of the reducer is armed. Set last by recordBoot
	// so a job transition can never overtake the verdict.
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
// toolbelt's job-queue lock and Engine.Inventory() takes the same lock through
// InstallingSet(), so counting there deadlocks the engine. The callback pokes;
// a goroutine that holds no lock does the counting.
func (s *toolsStatus) requestRecount() {
	select {
	case s.poke <- struct{}{}:
	default: // a recount is already pending, and it will see the newer state
	}
}

// watchConvergence owns every convergence recount for the process, which is
// what makes them serialized: one goroutine, so two counts can never interleave
// and store each other's answer out of order.
//
// count is the engine-backed counter; it returns the number of enabled manifest
// entries that are not installed. A failed count returns the field to UNKNOWN
// (-1) rather than leaving the previous answer in place: the published contract
// is that tools_missing is absent when the count is not known, so a stale count
// would assert a convergence the engine can no longer confirm.
func (s *toolsStatus) watchConvergence(ctx context.Context, count func() (int, error)) {
	recount := func() {
		n, err := count()
		if err != nil {
			// Return the field to UNKNOWN rather than freezing the last answer: the
			// published contract is that tools_missing is absent when the count is
			// not known, so that a number always means what it says (README, Tools).
			// A frozen 0 asserts convergence the engine can no longer confirm.
			// Warn, not Debug: Inventory's failure mode is an unreadable or
			// unparseable manifest, which is persistent and operator-fixable, so
			// Debug would keep the only record of it out of the shipped stream.
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

// countMissingFromInventory is the counting RULE, split from the engine call so
// the policy below is testable without standing up a toolbelt tree.
//
// Disabled entries are excluded because in toolbelt v2 a disabled entry is a
// TEMPLATE — recorded intent that is deliberately not installed — so counting
// one as outstanding would make a freshly seeded volume report five missing
// tools forever. An entry still installing DOES count: it is not on PATH yet,
// which is what this number is about.
func countMissingFromInventory(tools []toolbelt.ToolInfo) int {
	n := 0
	// Indexed rather than a value range: ToolInfo is 160 bytes, so copying one
	// per entry is pure waste on a tree that can hold hundreds.
	for i := range tools {
		if !tools[i].Disabled && !tools[i].Installed {
			n++
		}
	}
	return n
}

// recordBoot stores the boot convergence pass's verdict and arms the live
// half. Called once, from startTools' boot-verdict switch; storing a terminal
// verdict is also what lifts the session-create gate, since that gate reads
// this same cell for the syncing state. The store order is load-bearing: state
// first, then booted, so no job transition can land between them and be
// mistaken for the boot outcome.
func (s *toolsStatus) recordBoot(v string) {
	s.state.Store(v)
	s.booted.Store(true)
	// The boot pass is the largest single change to the tree, so recount as soon
	// as its verdict is in rather than waiting for the next job transition.
	s.requestRecount()
}

// observeJob is the Config.OnJobChanged reducer: it folds one job state
// transition into the field. Fires from toolbelt's job worker under the queue
// lock, so it does exactly one atomic store, one non-blocking poke, and never
// blocks.
func (s *toolsStatus) observeJob(j *toolbelt.Job) {
	// The convergence count is a fact about the TREE, so EVERY settled job asks for
	// a recount — deliberately not filtered by toolsStatusCounts, which is the
	// state VERDICT's policy. A disable flips Disabled in the manifest, an
	// uninstall drops the entry, and an update that fails mid-install leaves a tool
	// off PATH; none of those kinds counts toward degraded, and all three change
	// which enabled entries are installed. Asked for before the boot verdict too:
	// there is nothing to arm and nothing a job transition could overtake. A
	// catalog-refresh transition pokes as well and is simply a no-op answer — one
	// coalesced, lock-free Inventory read at boot and per refresh interval, which
	// is cheaper than a second kind policy to keep in step with this one.
	switch j.State {
	case toolbelt.JobDone, toolbelt.JobFailed, toolbelt.JobCancelled:
		// Cancelled is settled too: toolbelt cancels RUNNING jobs (the loopback
		// tools API's CancelJob), so a job cancelled after it already changed the
		// tree would otherwise leave the published count asserting the pre-job
		// state until the next settled job or catalog refresh. A cancelled job
		// that never ran changed nothing, and its poke is one coalesced no-op
		// Inventory read — the same cost this comment already accepts for
		// catalog-refresh transitions.
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
	// (Engine.Close cancels the active job on every shutdown) — both leave
	// the last settled value in place.
}

// toolsStatusCounts is the job-kind policy for the informational tools field,
// enumerated rather than defaulted to "anything that failed" — the excluded
// kinds are excluded for stated reasons, not by omission, and a job kind
// toolbelt adds later counts only once someone decides it should.
//
// The exclusions govern the state VERDICT only, never the convergence recount:
// observeJob pokes on every settled job whatever its kind, because a disable, an
// uninstall or a half-finished update all change which enabled entries are
// installed without meaning the boot was degraded.
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
		// No engine, so there is no tree to count and nothing to report. Not
		// zero: zero would claim convergence for a subsystem that failed to
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
		// No empty-entry carve-out: binDir is the Clean of a Join ending in
		// "bin", so it can never be "." — the value Clean returns for both an
		// empty element and ".", the two spellings of the child's cwd.
		if filepath.Clean(entry) == binDir {
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
// through the loopback tools API heals it without a restart; the gate reads
// the same cell's one-way "syncing" state, which recordBoot replaces once
// and observeJob can never restore. After convergence an async update
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
			// Total, like every other off-shape arm: there is no tree to count,
			// and "not counted" is not convergence, so the health field stays
			// ABSENT rather than reporting 0 (the reason degradedRuntime spells
			// this out too).
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
	manifestPath := manifestPathFor(toolsRoot)
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

	// recordBoot records the boot convergence verdict, which BOTH arms the live
	// reducer and lifts the session-create gate: the gate is derived from the
	// reducer's one-way "syncing" state rather than kept in a second cell, so a
	// request cannot observe tools=ok while session creation still refuses with
	// "tools installing" (the two stores could not be made simultaneous, and
	// either order contradicts what "syncing" promises a health consumer). A
	// post-boot job failure stores only ok or degraded (observeJob), so it can
	// update the informational field without ever re-closing session creation.
	// Boot failure lifting the gate is deliberate (degraded-not-dead), and
	// nothing may put it back.
	job, rerr := eng.Reconcile(toolbelt.ReconcileMissing)
	switch {
	case rerr != nil:
		slog.Warn("tools: boot reconcile not enqueued", "error", rerr)
		status.recordBoot(toolsStateDegraded)
		warnIfNoLSPEnabled(eng, manifestPath)
	case job == nil: // empty manifest: nothing to converge
		status.recordBoot(toolsStateOK)
		warnIfNoLSPEnabled(eng, manifestPath)
	default:
		// No gate store: newToolsStatus already parks the reducer at "syncing",
		// which IS the closed gate until recordBoot replaces it.
		// Mark the gated window OPENING. Without this the only boot-convergence
		// records are the terminal ones (converged / degraded), so an operator
		// looking at 503 "tools installing" answers has no line saying the gate
		// is closed, since when, or which job to correlate with toolbelt's own
		// job-timeout/job-failed warnings.
		slog.Info("tools: boot convergence started; session creation is gated until it finishes",
			"job", job.ID,
			"hint", "POST /api/sessions answers 503 \"tools installing\" (Retry-After 5) and /api/health reports tools=syncing until this converges")
		go awaitBootConvergence(eng, job.ID, status.recordBoot, manifestPath)
	}
	// Boot catalog fetch, explicitly AFTER the reconcile enqueue: the
	// engine's schedule deliberately has no fire-on-start (an immediate
	// enqueue inside New would land ahead of the boot-critical reconcile
	// on the single-flight queue and delay the session gate). Failure is
	// routine before the publisher is reachable; keep-last-good absorbs it.
	if _, rerr := eng.RefreshCatalog(); rerr != nil {
		slog.Warn("tools: boot catalog refresh not enqueued", "error", rerr)
	}
	// The convergence watcher is started here rather than beside the reducer, so
	// it exists only for a runtime that actually has an engine to count. It runs
	// for the process's lifetime: there is no shutdown ceremony because the
	// engine outlives every request and Close() cancels its own work.
	go status.watchConvergence(context.Background(), countMissingTools(eng))

	return toolsRuntime{
		engine:  eng,
		syncing: func() bool { return status.get() == toolsStateSyncing },
		state:   status.get,
		missing: status.missingCount,
	}
}

// awaitBootConvergence blocks on the boot reconcile job, records the verdict
// (lifting the session-create gate via finish), then runs the original
// goroutine's post-convergence tail: the freshness pass for unpinned
// entries (off the boot path — version-check network never holds the session
// gate) and the language-server nudge. manifestPath is threaded through purely
// for that nudge's operator-facing `manifest` field.
func awaitBootConvergence(eng *toolbelt.Engine, jobID string, finish func(string), manifestPath string) {
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
	warnIfNoLSPEnabled(eng, manifestPath)
}

// manifestPathFor names toolbelt's manifest inside a tools root, mirroring the
// library's documented <ConfigDir>/tools.json layout (this app passes one
// toolsRoot as both ConfigDir and ToolsDir). ONE derivation site, so an
// operator-facing record cannot name a different file than the engine reads —
// the drift that left the hints pointing at the pre-move /config/tools.json.
func manifestPathFor(toolsRoot string) string {
	return filepath.Join(toolsRoot, "tools.json")
}

// warnIfNoLSPEnabled logs the code-intelligence nudge when no
// language-server entry is enabled: kiro-cli scans PATH for language
// servers at session start, so a box without one silently lacks code
// intelligence. Detection uses the inventory's catalog-derived Lsp
// marker, so any enabled LSP (seeded template or hand-added) silences
// it.
//
// manifestPath is the RESOLVED manifest both records point an operator at, as
// its own `manifest` field rather than a path spelled into the hint prose. The
// hints used to name /config/tools.json literally and silently went stale when
// the manifest moved under /config/tools/ (one toolsRoot is now both toolbelt
// ConfigDir and ToolsDir), telling an operator to edit a file that no longer
// exists. A restated path drifts; a threaded one cannot, and it stays correct
// for an out-of-container run whose root is a temp dir. The hint text itself
// stays FIXED for the reason the WT_TRUSTED_PROXIES hints are fixed: an
// operator-facing hint must not grow an input-derived tail (CWE-532).
func warnIfNoLSPEnabled(e *toolbelt.Engine, manifestPath string) {
	inv, err := e.Inventory()
	if err != nil {
		// Warn, not Debug: Inventory's only failure mode is an unreadable or
		// unparseable manifest, and toolbelt returns that error without logging
		// it (Engine.Inventory), so at the default level this would be the one
		// record of a manifest an operator has just broken.
		// The nudge below is skipped either way — its ABSENCE must not be read
		// as "a language server is enabled" when the answer is really unknown.
		// Deliberately NOT the "no language servers enabled" wording: that is a
		// different event, and TestWarnIfNoLSPEnabled's inventory-failure
		// subtest counts Warns by that message.
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

// canonicalPathRefusal is the message the canonical-path guard writes. A const
// so a test can pin the exact wording without a second copy of the literal
// (goconst) drifting from this one, the same reason wsAttachMsg is one.
//
// It names the remedy and stops there. It deliberately does NOT echo the path
// the caller sent, nor the cleaned one the guard computed from it: net/http
// carries up to MaxHeaderBytes (webhttp.NewServer's default 1 MiB) of request
// line, so reflecting either turns a one-line refusal into a caller-sized
// response body, and the fix does not need the value quoted back — the sender
// has it. Same posture as loopbackOnly's refusal, which names the surface and
// the remedy and never the request.
const canonicalPathRefusal = "request path is not canonical; resend it with no empty, \".\" or \"..\" path segments " +
	"(this route refuses rather than redirecting, because a redirect is a success status to a client without -L)"

// canonicalPathGuardedRoute reports whether p is one of the routes whose caller
// must be REFUSED a non-canonical spelling rather than redirected to the right
// one. p is the CLEANED path — the one http.ServeMux will actually route — which
// is what makes the test work at all: the spellings this guard exists to catch
// are exactly the ones that do not carry a guarded prefix literally
// ("/api//tools" does not begin with "/api/tools"), so asking the question of
// the path as sent would answer "out of scope" for every request in scope.
//
// The set is this app's own control plane and its probe, named by the same
// constants registerRoutes mounts them under so a rename moves both:
//
//   - toolsPath, exact AND subtree — the loopback tools API is mounted twice
//     (mux.Handle(toolsPath) + mux.Handle(toolsPath+"/")), and its documented
//     callers are the README's plain `curl -s` lines that add a tool, enable one,
//     or read the inventory. The subtree arm is the mutating half.
//   - kiroRescanPath — the README's documented repair POST
//     (`curl -X POST localhost:9848/api/kiro-cli/rescan`), the endpoint whose
//     entire purpose is a side effect on a server that is already answering 503.
//   - healthPath — probed by the baked Docker HEALTHCHECK (`curl -sfS
//     --max-time 4`, no -L) and by Gatus. A redirect read as success here reports
//     a container healthy without ever consulting readiness.
//
// Every other surface is deliberately absent, which is the point of a set rather
// than a blanket check; see canonicalPathGuard.
func canonicalPathGuardedRoute(p string) bool {
	switch p {
	case healthPath, kiroRescanPath, toolsPath:
		return true
	}
	return strings.HasPrefix(p, toolsPath+"/")
}

// canonicalPathGuard refuses a request whose path http.ServeMux would REWRITE
// before routing, when the path it would rewrite to is one of
// canonicalPathGuardedRoute's. Everything else passes through untouched.
//
// # What it prevents
//
// net/http cleans the request path before it selects a pattern, and answers 307
// with a Location when the cleaned path differs — see webhttp.CanonicalRequestPath,
// which is that same computation as a pure function. Measured against this app's
// real mux on go1.26.5: "/api//tools", "/api/tools/.", "/api/./tools",
// "/api/x/../tools", "//api/kiro-cli/rescan", "/api/kiro-cli/./rescan" and
// "/api//health" are all 307, and none of them reaches any handler.
//
// A browser follows that redirect and nothing is lost. The senders these routes
// actually have do not: the README documents the repair POST and the mutating
// tool calls as plain `curl` with no -L, and the image's HEALTHCHECK is
// `curl -sfS --max-time 4` with no -L. To all three a 307 is a SUCCESS — the
// process exits 0 — so the mutation never ran, the probe never consulted
// readiness, and nothing anywhere says the URL was malformed. Refusing is the
// only answer that reaches such a caller, which is why this is a refusal and not
// a log line.
//
// # Why it cannot be a route-level wrapper
//
// It is chain middleware, upstream of the mux, because the canonicalization runs
// BEFORE pattern selection: no registered pattern can intercept a request that
// is about to be redirected, so a wrapper installed at the mount — where
// loopbackOnly sits — would never see one. That asymmetry is the whole reason the
// two admission gates live at different layers while making the same kind of
// decision.
//
// # Which value is fed, and why the DECODED one
//
// r.URL.Path, the decoded path, not r.URL.EscapedPath(). EscapedPath is what
// reproduces ServeMux's cleaning decision exactly; the decoded path is a
// deliberately WIDER verdict, and both halves of that width were measured
// against this app's mux rather than assumed:
//
//   - It is what the SENDER believed it was addressing. "%2e%2e" decodes to
//     ".." and "%74ools" to "tools", and Go's ServeMux matches patterns on
//     unescaped segments — "/api/%74ools" is served 200 by the tools handler.
//     So the decoded path is the one that says which route a request reaches.
//   - It also refuses an encoded dot segment ServeMux would NOT redirect:
//     "/api/tools/sub/%2e%2e" is handed to the toolbelt subtree handler today
//     with r.URL.Path == "/api/tools/sub/..", a path its inner router then
//     interprets however it interprets it. On a loopback-only mutating control
//     plane and a health probe there is no legitimate caller spelling a dot
//     segment either way, so the wider refusal costs nothing real and closes that
//     class too.
//
// The width is bounded by the same scope rule as everything else, which is worth
// stating because it is easy to over-claim: an encoded dot segment whose cleaned
// form leaves the guarded set is NOT refused. "/api/tools/%2e%2e" cleans to
// "/api" — no guarded route — so it passes through and keeps exactly the response
// it has today, just as "/static//app.js" does.
//
// # What is NOT guarded, deliberately
//
// The static mount, the /ws upgrade and the SSE stream are all outside the set,
// so their behaviour is byte-for-byte what it was:
//
//   - Static — this app serves a browser UI, where ServeMux's and FileServer's
//     directory/cleanup redirects are legitimate and wanted. A blanket guard
//     would turn a harmless "/vendor//app.js" into a 400 for a real browser.
//   - terminal.WSPath and terminal.SessionEventsPath — the engine's upgrade and
//     stream. A non-canonical spelling of either still gets today's 307; both
//     have browser clients that follow it, the guard's premise (a non-following
//     machine sender) does not hold for them, and neither is a route whose
//     purpose is a one-shot side effect.
//
// # Status, body and ordering
//
// 400 with the standard webhttp.WriteError envelope and an empty code, like
// every other app-owned refusal here (the two 403 gates, the 405, the 503s): the
// route exists and the caller is authorized, so this is neither 404 nor 403 —
// what is wrong is the request target's spelling. A 4xx is also what makes
// `curl -f` and `curl -sfS` fail, which is the behaviour change that matters. No
// Cache-Control is set and none is needed: 400 is not among RFC 9111 §4.2.2's
// heuristically-cacheable statuses, and the body is this constant message with no
// session, tool or volume state in it. Nothing is logged here either — the access
// line already records the method, status, request id and client_ip for these
// routes, and a second record would only duplicate it.
//
// Placed as the innermost chain entry, in front of the mux and INSIDE
// CrossOriginProtection, which is where the app already puts an admission
// decision of this kind (loopbackOnly is a layer further in still, at the
// mount). The consequence is deliberate: a forged cross-origin POST at a
// mis-spelled rescan path keeps its 403, because the security gate outranks a
// spelling complaint.
//
// # What it does not claim
//
// Only the cleaning redirect. ServeMux's OTHER redirect — subtree
// "/tree" -> "/tree/" — depends on the route table rather than the spelling and
// is invisible to a pure function over the path, so it is out of scope here as it
// is in the library. Concretely "/api/kiro-cli/rescan/" is canonical, passes this
// guard, and remains the static mount's 404 it already was.
func canonicalPathGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean, canonical := webhttp.CanonicalRequestPath(r.URL.Path)
		if canonical || !canonicalPathGuardedRoute(clean) {
			next.ServeHTTP(w, r)
			return
		}
		webhttp.WriteError(w, r, http.StatusBadRequest, "", canonicalPathRefusal)
	})
}

// buildHandler wraps the route mux in web-terminal-kiro's middleware stack via
// webhttp.Chain. Chain(h, A, B, C, D) == A(B(C(D(h)))), so the first entry is
// the outermost wrapper; a request flows Logging -> Recoverer -> wsAttachLog ->
// SecurityHeaders -> host allowlist -> CrossOriginProtection -> canonicalPathGuard
// -> mux, and the response unwinds the other way.
//
//   - Logging — webhttp's access logger. Outermost so it observes every final
//     status on logged routes, including a recovered 500 and a cross-origin
//     403. Its four policies are configured, and each justified, at the call
//     sites in the body below: the stream skips (an ADMITTED /ws upgrade or SSE
//     stream emits no access line; one rejected by the Host allowlist still
//     does, since it never becomes a stream), ProbeLogLevel for /api/health, the
//     WithTemplatePathsUnder redaction that keeps a live session id out of
//     the token-bearing /api/sessions/ subtree's lines, and WithClientIP over
//     the WT_TRUSTED_PROXIES set (see parseTrustedProxies for the trust-nothing
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
//   - hostPolicy.Middleware — the WT_ALLOWED_HOSTS exact-host check
//     (webhttp.HostPolicy; see parseAllowedHosts for the DNS-rebinding
//     rationale). Placed before CrossOriginProtection because rebinding makes
//     Origin and Host agree, so the origin check alone cannot reject it; kept
//     inside SecurityHeaders so even a rejected host gets the baseline headers
//     and — on logged routes — an access-log line. An inactive policy (env
//     unset/blank) collapses
//     to a pass-through per the library's off-contract.
//   - CrossOriginProtection — the stdlib cross-origin/CSRF guard, kept
//     directly in front of the routes (its long-standing position) so it
//     rejects a forged cross-origin unsafe request with 403.
//   - canonicalPathGuard — refuses a non-canonical request path aimed at the
//     loopback control plane or the health probe, instead of letting ServeMux
//     answer the 307 a `curl` without -L reads as success (see
//     canonicalPathGuard for the measured redirect set, why the guard cannot
//     live at the mount like loopbackOnly, and what is deliberately left
//     unguarded). Innermost, so the Host and origin gates both outrank it and
//     an admitted request's spelling is the last thing checked before routing —
//     the same order the app already gives loopbackOnly, one layer further in.
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
			// unset WT_ALLOWED_HOSTS keeps today's behavior exactly.
			// The GET conjunct is the same reasoning as the hostPolicy one, one
			// layer further in. A skip predicate is evaluated BEFORE the chain
			// runs, so it deletes the record whatever status the request ends
			// with -- and CrossOriginProtection, which sits inside this skip,
			// rejects an UNSAFE cross-origin request with a 403 that WriteError
			// logs nowhere. Only a GET can become the stream this skip exists to
			// suppress (SSE is a GET, and the safe methods are the ones the
			// origin gate always admits), so restricting the skip to GET keeps the
			// one refusal a GET can never produce: the cross-origin 403, since
			// CrossOriginProtection admits every safe method. It does NOT keep the
			// engine's own refusals, and that is accepted rather than overlooked:
			// the 503 at the subscriber cap and the 500 for an unflushable writer
			// both arrive on a GET with an allowed Host, so this predicate deletes
			// their access record too. The cap rejection is still recorded by the
			// engine ("terminal: status subscriber rejected (at cap)"), carrying the
			// cap but no client_ip and no request_id -- visible, not attributable --
			// and the 500 is unreachable here, because a skipped request is not
			// wrapped at all and webhttp's StatusRecorder implements Unwrap, so
			// supportsFlush always succeeds. Do not close the attribution gap with
			// an app-side subscribe record: anyone who can reach this endpoint
			// already gets an unauthenticated PTY, so there is no privilege the
			// attribution would protect. The trade is that a non-GET request that IS
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
			// WT_LOG_LEVEL=debug) while a FAILING probe — the readiness
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
		hostPolicy.Middleware(),
		http.NewCrossOriginProtection().Handler,
		canonicalPathGuard,
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

// containCgroupRoot is the container's own cgroup v2 root under a private cgroup
// namespace, and containCgroupPrefix namespaces every cgroup this server creates
// beneath it.
//
// Not an env var, deliberately, for the same reason this app removed its operator
// override of the installed kiro-cli path: a knob whose only effect is to silently
// disable a correctness feature does not belong in a config table. The entrypoint
// decides whether containment is possible (it owns the one-time remount), and the
// server discovers the answer by trying.
const (
	containCgroupRoot   = "/sys/fs/cgroup"
	containCgroupPrefix = "wt-"
)

// startContainment prepares per-session process containment, or returns nil after
// one warning when this host cannot support it.
//
// Nil is a fully supported outcome, not a failure: sessions then behave exactly as
// they did before the feature existed. That matters because the reachable reasons
// for nil are ordinary rather than exotic — a `go run` outside the container, a
// kernel older than 5.19, a seccomp profile that refuses clone3, or an entrypoint
// whose `mount -o remount,rw /sys/fs/cgroup` did not run — and this app's failure
// posture is explicit that a dev box must keep serving a terminal rather than
// refuse to boot over disk hygiene.
//
// What nil costs is now ONLY the per-session peak numbers (mem_peak_bytes,
// tasks_peak), because the engine reaps a closed session's surviving tree from an
// inherited environment marker with no host support at all. That is why this
// container no longer asks for CAP_SYS_ADMIN: the leak the capability was granted
// for is closed either way, and containment is a metrics-and-enforcement extra
// rather than the only boundary. Measured on borgcube while containment was
// silently off: 28 stranded session trees holding 16.2 GB.
func startContainment() *terminal.Containment {
	c, err := terminal.NewContainment(containCgroupRoot, containCgroupPrefix, slog.Default())
	if err != nil {
		slog.Info("per-session cgroup containment unavailable; session trees are still reaped, but per-session peak memory and task counts will not be reported",
			"error", err,
			"hint", "containment needs a writable cgroup v2 root, which needs CAP_SYS_ADMIN for a one-time remount. Not granted by default: the engine's marker-based reaping closes the process leak without it.")
		return nil
	}
	return c
}
