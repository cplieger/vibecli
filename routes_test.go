package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/cplieger/toolbelt/v3"
	"github.com/cplieger/web-terminal-engine/v5/terminal"
	"github.com/cplieger/webhttp/v2"
)

// TestDebugRoutesNotExposed pins the route surface of registerRoutes: the
// engine's terminal.MountAPI wires exactly its documented four routes (/ws,
// /api/sessions + subtree, /api/sessions/events), so no diagnostic or
// engine-internal path may ever answer on this unauthenticated surface. The
// /debug/* probes are canaries for that contract: the pinned engine exports no
// such routes today, and if any version ever grows one, MountAPI's
// release-noted route-set contract plus this test keep it from appearing here
// silently.
func TestDebugRoutesNotExposed(t *testing.T) {
	mux, _, _ := mustRegisterRoutes(t, newTestDeps(false))

	// /ws must be registered as its own pattern.
	if _, pat := mux.Handler(httptest.NewRequest(http.MethodGet, "/ws", http.NoBody)); pat != "/ws" {
		t.Errorf("/ws routed to pattern %q, want %q", pat, "/ws")
	}

	// /debug/* must NOT be registered. Assert the POSITIVE observable — both probes
	// resolve to the "/" file-server catch-all — rather than `pat != p`: ServeMux
	// reports a SUBTREE registration by its pattern, so a handler registered at
	// "/debug/" would answer /debug/raw while pat ("/debug/") still differs from the
	// requested path, and the old assertion passed over an exposed debug handler.
	for _, path := range []string{"/debug/raw", "/debug/screen"} {
		if _, pat := mux.Handler(httptest.NewRequest(http.MethodGet, path, http.NoBody)); pat != "/" {
			t.Errorf("%s routed to pattern %q, want the static catch-all %q; /debug routes must not be exposed", path, pat, "/")
		}
	}
}

// TestHealthEndpoint_reflectsReadiness pins the /api/health readiness gate:
// before ready is set the endpoint returns 503 (so a reverse proxy or
// orchestrator holds traffic during startup and shutdown), and once ready it
// returns 200. The atomic flag is the only thing that flips the branch.
func TestHealthEndpoint_reflectsReadiness(t *testing.T) {
	deps := newTestDeps(false)
	mux, _, _ := mustRegisterRoutes(t, deps)

	get := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
		return rec
	}

	if rec := get(); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("before ready: status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	deps.ready.Set(true)
	if rec := get(); rec.Code != http.StatusOK {
		t.Errorf("after ready: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestHealthEndpoint_reflectsKiroCliReadiness pins the kiro-cli readiness gate
// added for the deferred readiness-decoupled-from-kiro-cli finding. When the
// server owns the install (main.go hands it the manager's Ready), /api/health
// returns 503 while no version is active and 200 once one is — reflecting
// web-terminal-kiro's core dependency from in-memory state, never launching
// kiro-cli. Out-of-container runs (tests, a bare `go run` with no pins) get the
// composition root's permissive (true, "") default instead of a nil policy, so
// they keep pure-listener readiness.
func TestHealthEndpoint_reflectsKiroCliReadiness(t *testing.T) {
	newMux := func(verdict func() (bool, string)) *http.ServeMux {
		deps := newTestDeps(true)
		deps.kiroReady = verdict
		mux, _, _ := mustRegisterRoutes(t, deps)
		return mux
	}
	status := func(mux *http.ServeMux) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
		return rec.Code
	}

	// No active version -> kiro-cli unavailable -> 503.
	unready := func() (bool, string) { return false, reasonUnavailable }
	if code := status(newMux(unready)); code != http.StatusServiceUnavailable {
		t.Errorf("no active version: status = %d, want %d", code, http.StatusServiceUnavailable)
	}

	// A version active with its required settings asserted -> ready -> 200. This
	// is also the unmanaged (no-pins) shape: main.go's unmanagedKiroRuntime
	// supplies exactly this permissive (true, "") default, so the route layer has
	// no nil case to disable a gate for.
	if code := status(newMux(func() (bool, string) { return true, "" })); code != http.StatusOK {
		t.Errorf("version active: status = %d, want %d", code, http.StatusOK)
	}
}

// testIndexHTML is the minimal index fixture route tests embed: it carries one
// inline <script> (the importmap stand-in) and one inline <style> so
// buildCSPPolicy — which fails loud on a script-less or style-less index.html —
// accepts it, mirroring the real page.
const testIndexHTML = `<!doctype html><style>body{margin:0}</style><script type="importmap">{}</script>`

// TestKiroCacheControl pins the two-branch cache POLICY handed to
// webhttp.StaticHandler (the ETag/gzip mechanism now lives in webhttp and is
// tested there): assets under vendor/fonts/ are cached for 30 days but stay
// revalidatable (no `immutable`) while
// everything else is no-cache + must-revalidate so deploys take effect at
// once. Paths arrive normalized (no leading slash; "index.html" for "/"), and
// the fonts prefix's trailing slash is load-bearing -- "vendor/fonts-list.json"
// must NOT be treated as a font.
func TestKiroCacheControl(t *testing.T) {
	cases := []struct {
		name      string
		assetPath string
		wantCache string
	}{
		{name: "font is long-lived but revalidatable", assetPath: "vendor/fonts/iosevka.woff2", wantCache: "public, max-age=2592000"},
		{name: "nested font is long-lived but revalidatable", assetPath: "vendor/fonts/sub/x.woff2", wantCache: "public, max-age=2592000"},
		{name: "html is no-cache", assetPath: "index.html", wantCache: "no-cache, must-revalidate"},
		{name: "js bundle is no-cache", assetPath: "app.js", wantCache: "no-cache, must-revalidate"},
		{name: "vendor non-font prefix is no-cache", assetPath: "vendor/fonts-list.json", wantCache: "no-cache, must-revalidate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kiroCacheControl(tc.assetPath); got != tc.wantCache {
				t.Errorf("kiroCacheControl(%q) = %q, want %q", tc.assetPath, got, tc.wantCache)
			}
		})
	}
}

// TestStaticETagRevalidation pins the embedded-bundle revalidation contract:
// embed.FS reports a zero ModTime, so a bare http.FileServer emits no
// validator and every full load would re-download the body.
// webhttp.StaticHandler precomputes a content-hash ETag (served on the
// default, non-font cache branch), so GET / returns a quoted ETag and a
// conditional GET with a matching If-None-Match answers 304 with an
// empty body instead of re-sending the bundle. Mirrors the sibling
// web-terminal-server's TestStaticHandlerETagAndRevalidation.
func TestStaticETagRevalidation(t *testing.T) {
	mux, _, _ := mustRegisterRoutes(t, newTestDeps(false))

	// First load: the response carries a quoted content-hash ETag.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: status = %d, want %d", rec.Code, http.StatusOK)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("GET /: no ETag header; the browser cannot revalidate the embedded bundle and re-downloads it every load")
	}
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Errorf("ETag %q is not a quoted strong validator", etag)
	}

	// Conditional reload: a matching If-None-Match answers 304 with no body.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("If-None-Match", etag)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("conditional GET /: status = %d, want %d", rec.Code, http.StatusNotModified)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("304 response body = %q, want empty", body)
	}
}

// TestSSEStreamsThroughLoggingMiddleware is the regression guard for the tab
// status stream behind web-terminal-kiro's own middleware. webhttp.Logging wraps most
// requests in a webhttp.StatusRecorder; if the SSE path were wrapped by
// something opaque to streaming the engine's flush probe would fail and the
// stream would 500. It is instead in Logging's WithSkipPaths set (like /ws), so
// it flows through the streaming-transparent primitives. This drives
// /api/sessions/events through the full production middleware stack
// (buildHandler: Logging + Recoverer + SecurityHeaders + CrossOriginProtection)
// and asserts the stream opens (200 + text/event-stream) and flushes an event
// -- also proving the SecurityHeaders/Recoverer layers stay transparent to the
// SSE stream.
func TestSSEStreamsThroughLoggingMiddleware(t *testing.T) {
	mux, _, csp, id := mustStartSession(t, newTestDeps(true))

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions/events", http.NoBody)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/sessions/events: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SSE must bypass the status recorder, not 500)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "data:") && strings.Contains(line, string(id)) {
			return // the initial-sync event flushed through the middleware
		}
	}
	t.Fatalf("SSE stream delivered no data through the logging middleware (scan err: %v)", sc.Err())
}

// sessionCreateBurst pins the burst of webhttp.SessionCreateRateLimit as THIS
// app's documented contract (six creates, then 429). A deliberate tuning
// change in the shared preset fails this test loudly so the app's docs and
// expectations are updated consciously rather than drifting silently.
const sessionCreateBurst = 6

// TestCreateRateLimit pins the create throttle as registerRoutes actually
// wires it: a burst of POST /api/sessions through the production routes is
// allowed, then further creates are 429'd. Driving the real mux (cmd
// /bin/true, so sessions exit immediately) means the test fails if
// registerRoutes stops wiring terminal.WithCreateGate(createGate) or moves
// the mounted path — composition drift the previous direct-preset version
// could not detect.
func TestCreateRateLimit(t *testing.T) {
	deps := newTestDeps(false)
	deps.cmd = staticCmd("/bin/true")
	mux, _, _ := mustRegisterRoutes(t, deps)

	for attempt := 1; attempt <= sessionCreateBurst; attempt++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", http.NoBody))
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d status = %d, want %d (body %s)", attempt, rec.Code, http.StatusCreated, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", http.NoBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("create past burst status = %d, want %d (body %s)", rec.Code, http.StatusTooManyRequests, rec.Body.String())
	}

	// Listing sessions remains available after the create burst is spent: the
	// gate throttles only creation, never the whole sessions subtree.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sessions", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Errorf("list after create burst status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestSecurityHeaders_presentOnNormalResponse pins the baseline response
// security headers that buildHandler layers on every response via
// webhttp.SecurityHeaders(). web-terminal-kiro sent NO security headers before the
// webhttp standardization, so this is the regression guard for the fleet
// baseline: X-Content-Type-Options nosniff and X-Frame-Options DENY on a normal
// 200. It also pins the three deliberate choices -- X-Frame-Options is the DENY
// default because web-terminal-kiro is never embedded in a frame; Referrer-Policy
// is TIGHTENED from webhttp's strict-origin-when-cross-origin default to
// same-origin, so a UI bump that drops the vendored `rel="noreferrer"` cannot
// leak this server's hostname to a page an OSC 8 link points at (see
// buildHandler's rationale, and vibekit pins the same value); and the
// Content-Security-Policy is the
// hash-pinned policy buildCSPPolicy assembles from the embedded index.html
// (asserted below: script-src AND style-src each pin a sha256 token, and no
// directive carries 'unsafe-inline').
// Driven through the full production chain (buildHandler) so the assertion
// tracks what the server actually sends.
func TestSecurityHeaders_presentOnNormalResponse(t *testing.T) {
	mux, _, csp := mustRegisterRoutes(t, newTestDeps(true))

	rec := httptest.NewRecorder()
	buildHandler(mux, nil, csp, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/health: status = %d, want %d", rec.Code, http.StatusOK)
	}
	for _, tc := range []struct{ header, want string }{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "same-origin"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
		{"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
	} {
		if got := rec.Header().Get(tc.header); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
		}
	}
	// The CSP is hash-pinned from the embedded index.html (buildCSPPolicy via
	// webhttp.InlineScriptHashes + inlineStyleHash): script-src carries 'self'
	// plus at least one sha256 token and never 'unsafe-inline'; style-src is
	// likewise hash-pinned to the page's single loading-overlay <style>, so an
	// injected style block or style attribute cannot obscure or spoof the
	// terminal UI (the renderer styles via CSSOM property setters, which
	// style-src does not govern). This closed the family-drift gap
	// where web-terminal-kiro served the same embedded-static + inline-importmap
	// pattern as web-terminal-server with no CSP at all.
	servedCSP := rec.Header().Get("Content-Security-Policy")
	if servedCSP == "" {
		t.Fatal("Content-Security-Policy is unset; the hash-pinned policy must be served on every response")
	}
	if !strings.Contains(servedCSP, "script-src 'self' 'sha256-") {
		t.Errorf("CSP script-src = %q, want 'self' plus a pinned sha256 token", servedCSP)
	}
	if !strings.Contains(servedCSP, "style-src 'self' 'sha256-") {
		t.Errorf("CSP style-src = %q, want 'self' plus a pinned sha256 token", servedCSP)
	}
	if strings.Contains(servedCSP, "'unsafe-inline'") {
		t.Errorf("CSP = %q, want no 'unsafe-inline' in any directive", servedCSP)
	}
	for _, want := range []string{
		"default-src 'self'",
		"img-src 'self' data:", "connect-src 'self'", "frame-ancestors 'none'",
		// The four directives no other assertion reaches. Each is a distinct
		// containment the hash pinning does not provide, and dropping any of
		// them from cspTemplate leaves the whole package green: font-src keeps
		// the Monaspace faces same-origin, base-uri stops an injected <base>
		// from re-pointing every relative module URL at an attacker origin,
		// object-src blocks plugin embedding, and form-action blocks POST
		// exfiltration from an injected form.
		"font-src 'self'", "base-uri 'none'", "object-src 'none'", "form-action 'none'",
	} {
		if !strings.Contains(servedCSP, want) {
			t.Errorf("CSP = %q, want it to contain %q", servedCSP, want)
		}
	}
}

// TestAPICachePolicy_EveryAPIPathSetsNoStore is the enumeration of this app's
// entire /api/ surface and the record of WHO sets each response's cache policy.
// It replaced a pair of narrower tests when the app's /api/-wide apiNoStore
// middleware was deleted: the reason that deletion is safe is not an argument,
// it is this table, and a row goes red the moment an owner stops covering its
// own responses.
//
// Why the surface needs covering at all: a session id is the /ws attach + resume
// capability token that LogID truncates before logging and
// WithTemplatePathsUnder keeps out of the access log, and a response carrying no
// freshness information is heuristically cacheable under RFC 9111 §4.2.2, so
// without a directive the browser persists one to its on-disk cache (outliving
// the tab) and an intermediary proxy may serve a list from cache. The tools
// inventory has a milder version of the same problem: an operator reads it to
// decide whether an install finished, and a cached copy answers with stale state.
//
// Everything runs through buildHandler — the REAL chain, in production order —
// rather than against a handler directly, because three of the four owners set
// the header somewhere the handler-level call cannot see: toolbelt's httpapi
// wraps its own mux, the engine's REST handler has an inner mux of its own, and
// the engine's own withNoStore wraps that handler at its mount. Calling a handler
// directly would assert the wrong thing and stay green through a chain edit.
func TestAPICachePolicy_EveryAPIPathSetsNoStore(t *testing.T) {
	deps := newToolsDeps(t)
	deps.kiroRescan = func(context.Context) (bool, error) { return true, nil }
	mux, mgr, csp := mustRegisterRoutes(t, deps)
	quietTeardown(t, deps)
	h := buildHandler(mux, nil, csp, nil)

	// One live session so the REST handler's success paths (204 close, 405 on a
	// method the session path does not serve) are reached with a real id rather
	// than falling through to the unknown-session 404.
	liveID, err := mgr.Create()
	if err != nil {
		t.Fatalf("mgr.Create: %v", err)
	}

	const noStore = "no-store"
	for _, tc := range []struct {
		name      string
		method    string
		path      string
		body      string
		wantCache string
		// owner names the code that sets the header, so a red row says whose
		// contract broke instead of only that a header went missing.
		owner string
	}{
		// The engine's own coverage: terminal's writeJSON (create + list) and
		// the SSE stream. These hold with NO app middleware at all.
		{"sessions list", http.MethodGet, terminal.SessionsPath, "", noStore, "engine writeJSON"},
		{"sessions create", http.MethodPost, terminal.SessionsPath, "", noStore, "engine writeJSON"},
		{"sessions events (SSE)", http.MethodGet, terminal.SessionEventsPath, "", "no-cache, no-store", "engine events handler"},

		// The engine's session surface BEYOND writeJSON. writeJSON is reached
		// only by create and list, so every row below carries no Cache-Control
		// from writeJSON — the header comes from the engine's own withNoStore,
		// applied to the REST handler at BOTH mounts (SessionsPath and
		// SessionsSubtreePath) and outside the create gate, so it reaches the
		// statuses no handler writes. These rows hold with no app middleware at
		// all; they go red if the engine stops covering its own mux.
		{"session close (204)", http.MethodDelete, terminal.SessionsPath + "/" + string(liveID), "", noStore, "engine withNoStore (MountSessionRoutes)"},
		{"session close, unknown id (404)", http.MethodDelete, terminal.SessionsPath + "/deadbeef", "", noStore, "engine withNoStore (MountSessionRoutes)"},
		{"set title, unknown id (404)", http.MethodPut, terminal.SessionsPath + "/deadbeef/title", `{"title":"x"}`, noStore, "engine withNoStore (MountSessionRoutes)"},
		{"set title, undecodable body (400)", http.MethodPut, terminal.SessionsPath + "/deadbeef/title", "not json", noStore, "engine withNoStore (MountSessionRoutes)"},
		{"set pinned title, unknown id (404)", http.MethodPut, terminal.SessionsPath + "/deadbeef/pinned-title", `{"title":"x"}`, noStore, "engine withNoStore (MountSessionRoutes)"},
		{"clear pinned title, unknown id (404)", http.MethodDelete, terminal.SessionsPath + "/deadbeef/pinned-title", "", noStore, "engine withNoStore (MountSessionRoutes)"},
		// The engine's INNER mux generates these itself, which is why no
		// per-handler fix inside the engine would reach them: a 405 for a
		// method the session path does not serve, and a 404 for the bare
		// subtree path (no {id} segment to match).
		{"session path, unserved method (405)", http.MethodGet, terminal.SessionsPath + "/" + string(liveID), "", noStore, "engine withNoStore (MountSessionRoutes)"},
		{"session subtree root (404)", http.MethodGet, terminal.SessionsSubtreePath, "", noStore, "engine withNoStore (MountSessionRoutes)"},

		// The app's own handlers, each setting the header at the top of the
		// function rather than relying on middleware.
		{"health", http.MethodGet, healthPath, "", noStore, "handleHealth"},
		{"kiro-cli rescan", http.MethodPost, kiroRescanPath, "", noStore, "handleKiroRescan"},

		// toolbelt's httpapi, as of v2.3.0: no-store on every response of its
		// own, set upstream of its mux, so its 404s and 405s are covered too.
		// This is the coverage that let the app's /api/-wide wrapper go — it
		// was the last path with no owner.
		{"tools inventory", http.MethodGet, toolsPath, "", noStore, "toolbelt httpapi"},
		{"tools search", http.MethodGet, toolsPath + "/search", "", noStore, "toolbelt httpapi"},
		{"tools add, undecodable body (400)", http.MethodPost, toolsPath, "not json", noStore, "toolbelt httpapi"},
		{"tools subtree root (404)", http.MethodGet, toolsPath + "/", "", noStore, "toolbelt httpapi"},
		{"tools unrouted path (405)", http.MethodGet, toolsPath + "/nope", "", noStore, "toolbelt httpapi"},

		// Non-API paths, proving the session scope does not leak. A static
		// asset must keep kiroCacheControl's revalidation policy, and /ws — a
		// path nothing downstream decorates (GET without an Upgrade header is
		// the engine's 426) — must carry nothing at all. Without this second
		// row the scoping is unobservable: /index.html is a KNOWN asset whose
		// Cache-Control webhttp.StaticHandler overwrites on its way out.
		{"static asset", http.MethodGet, "/index.html", "", "no-cache, must-revalidate", "kiroCacheControl"},
		{"websocket upgrade path", http.MethodGet, terminal.WSPath, "", "", "nobody (deliberately)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			// Loopback peer AND loopback Host: the tools and rescan admission
			// gate (see TestToolsAPI_LoopbackOnly) refuses anything else, and a
			// 403 would not exercise the response this policy applies to.
			req.RemoteAddr = "127.0.0.1:54321"
			req.Host = "localhost:9848"
			// The SSE stream never completes on its own. Bounding the request
			// context ends it; the header map is already populated by then,
			// which is the whole point of setting it before WriteHeader.
			ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
			defer cancel()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.WithContext(ctx))

			if got := rec.Header().Get("Cache-Control"); got != tc.wantCache {
				t.Errorf("%s %s -> %d: Cache-Control = %q, want %q (set by %s)",
					tc.method, tc.path, rec.Code, got, tc.wantCache, tc.owner)
			}
			// A row that silently stopped reaching its handler would assert
			// nothing: a 403 from the loopback gate, or a fallthrough to the
			// static 404, both produce a response whose header a passing row
			// would happily read.
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s %s: status 403 — the loopback gate refused the request, so this row proves nothing", tc.method, tc.path)
			}
		})
	}
}

// TestAPICachePolicy_UnmatchedAPIPathCarriesNoDirective records the ONE thing
// the /api/-wide wrapper used to do that nothing does now, as a decision rather
// than an oversight: an /api/ path no route matches gets no Cache-Control.
//
// It is deliberately harmless, and measurably not even a change. Such a path
// falls through to the catch-all static mount, and net/http's serveError DELETES
// Cache-Control (with ETag and Last-Modified) on its error path, so a 404 body
// carried no directive even WITH the old middleware in the chain — the header
// the wrapper set was stripped again downstream. The body is net/http's constant
// "404 page not found" text and holds no session or tool state, so a cache
// storing it can only ever replay a 404 for a path that has none.
//
// The rows are the three shapes an unmatched-or-method-mismatched /api/ request
// takes: a path with no mount at all, the bare prefix, and — the one worth
// pinning — a GET on kiroRescanPath, which IS mounted but only for POST and so
// answers the explicit 405 the method-agnostic mount beside it produces (the
// catch-all "/" pattern would otherwise silence ServeMux's own 405 synthesis and
// serve a bare static 404). None of them may carry a Cache-Control directive.
func TestAPICachePolicy_UnmatchedAPIPathCarriesNoDirective(t *testing.T) {
	deps := newToolsDeps(t)
	deps.kiroRescan = func(context.Context) (bool, error) { return true, nil }
	mux, _, csp := mustRegisterRoutes(t, deps)
	h := buildHandler(mux, nil, csp, nil)

	for _, tc := range []struct {
		name, method, path string
		wantStatus         int
		wantAllow          string
	}{
		{"no such route", http.MethodGet, apiPrefix + "nope", http.StatusNotFound, ""},
		{"bare api prefix", http.MethodGet, apiPrefix, http.StatusNotFound, ""},
		{"mounted for POST only, reached by GET", http.MethodGet, kiroRescanPath, http.StatusMethodNotAllowed, http.MethodPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, http.NoBody)
			req.RemoteAddr = "127.0.0.1:54321"
			req.Host = "localhost:9848"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s: status = %d, want %d (this test is about the no-directive property of a request no route body answers)",
					tc.method, tc.path, rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Cache-Control"); got != "" {
				t.Errorf("%s %s: Cache-Control = %q, want none — an unmatched /api/ 404 carrying a directive means something re-grew the /api/-wide wrapper; if that was deliberate, this test is the place to say so",
					tc.method, tc.path, got)
			}
			// Allow is the ACTIONABLE half of a 405 (RFC 9110 requires it): dropping
			// the header leaves the status correct and an in-container agent knowing
			// only that its method was wrong, never which method to use — the exact
			// diagnosis the method-agnostic mount was added to provide.
			if got := rec.Header().Get("Allow"); got != tc.wantAllow {
				t.Errorf("%s %s: Allow = %q, want %q", tc.method, tc.path, got, tc.wantAllow)
			}
		})
	}
}

// TestCSPScriptHashesMatchEmbeddedInlineScripts is the anti-drift guard for
// the script-src hardening, ported from web-terminal-server: it independently
// re-extracts every inline <script> in the REAL embedded index.html with a
// regexp (a different implementation from webhttp's byte scanner, so agreement
// is a genuine cross-check) and asserts the sha256 hash of each appears in the
// CSP buildCSPPolicy assembles. Hashes are computed from the embed, never
// hardcoded, so the test tracks index.html automatically.
func TestCSPScriptHashesMatchEmbeddedInlineScripts(t *testing.T) {
	indexHTML, csp := embeddedCSP(t)

	scriptRE := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	srcRE := regexp.MustCompile(`(?i)(^|[\s/])src\s*=`)

	var oracle []string
	for _, m := range scriptRE.FindAllSubmatch(indexHTML, -1) {
		if srcRE.Match(m[1]) {
			continue // external script (/app.js), covered by 'self'
		}
		sum := sha256.Sum256(m[2])
		token := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(csp, token) {
			t.Errorf("CSP is missing the hash for an inline script.\ncontent=%q\nwant token %s\nCSP: %s", m[2], token, csp)
		}
		oracle = append(oracle, token)
	}
	if len(oracle) < 1 {
		t.Fatalf("oracle found %d inline scripts in index.html, want >= 1 (the importmap); the regexp or the file changed", len(oracle))
	}
	// Pin the tokens to the script-src DIRECTIVE and require it to equal 'self'
	// plus the SPACE-SEPARATED token list, the way the style side does. A
	// policy-wide Contains check per token cannot see the separator: index.html
	// carries two inline scripts, so joining their hashes with "" instead of " "
	// leaves both tokens as substrings of the policy and every assertion above
	// stays green, while the browser parses one unknown source expression,
	// blocks the inline importmap, and the page loads no ES modules at all.
	scriptDirective := cspDirective(csp, "script-src")
	if want := "script-src 'self' " + strings.Join(oracle, " "); scriptDirective != want {
		t.Errorf("CSP script directive = %q, want %q\nCSP: %s", scriptDirective, want, csp)
	}
}

// TestBuildCSPPolicyFailsLoud pins the fail-loud contract: buildCSPPolicy
// returns an error (never a silent 'unsafe-inline' degrade) when
// index.html is missing, index.html holds no inline <script>, or its
// inline <style> block is absent, unterminated, or duplicated. A
// production build always embeds index.html with its inline importmap and its
// single critical-CSS <style>, so any of these means a malformed build that must
// abort startup.
func TestBuildCSPPolicyFailsLoud(t *testing.T) {
	cases := []struct {
		name string
		fsys fs.FS
	}{
		{"missing index.html", fstest.MapFS{}},
		{"only external scripts", fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte(`<html><body><script src="/app.js"></script></body></html>`)},
		}},
		{"no style block", fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte(`<html><script type="importmap">{}</script></html>`)},
		}},
		{"unterminated style block", fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte(`<html><script type="importmap">{}</script><style>body{margin:0}`)},
		}},
		{"unterminated style open tag", fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte(`<html><script type="importmap">{}</script><style`)},
		}},
		{"two style blocks", fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte(`<html><script type="importmap">{}</script><style>a{}</style><style>b{}</style>`)},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildCSPPolicy(tc.fsys); err == nil {
				t.Errorf("buildCSPPolicy(%s) = nil error, want a fail-loud error", tc.name)
			}
		})
	}
}

// newWSUpgradeRequest builds the RFC 6455 handshake request the CSWSH test
// pair shares; the two tests differ ONLY in Origin, so a single builder
// guarantees the positive and negative cases exercise the same handshake.
func newWSUpgradeRequest(t *testing.T, srvURL, id, origin string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL+"/ws?session="+id, http.NoBody)
	if err != nil {
		t.Fatalf("new /ws upgrade request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==") // gitleaks:allow (RFC 6455 example key)
	req.Header.Set("Origin", origin)
	return req
}

// TestWSRejectsCrossOrigin pins the WebSocket CSWSH guard. /ws is mounted via
// mgr.WebSocketHandler() with no origin policy, so the engine allows same-origin
// only. http.NewCrossOriginProtection lets the GET upgrade through as a safe
// method, so that check is the ONLY thing standing between a malicious page in
// the victim's browser and a kiro-cli PTY on localhost.
//
// What this guard is DEFENDING against narrowed at engine v3.4.0, and the
// difference is worth stating. The engine used to take a whole
// websocket.AcceptOptions (WithAcceptOptions), so a single
// InsecureSkipVerify:true anywhere in this app's session factory would have
// silently reopened cross-site hijacking, and this test was the only thing
// watching for it. That option is gone: widening now requires building an
// explicit terminal.OriginPolicy from complete origins, there are no wildcards,
// and the check cannot be disabled at all. So the "someone flips a boolean"
// failure mode is structurally unreachable, and what remains testable is the
// posture itself -- that this app configures no policy and therefore stays
// same-origin. This test fails if a future change hands the manager or the
// handler an origin policy without that being a deliberate, reviewed decision.
func TestWSRejectsCrossOrigin(t *testing.T) {
	// Drive the guard on a REAL session: the shape a malicious page in the
	// victim's browser would actually target. The pinned engine runs the
	// same-origin check on EVERY upgrade -- an unknown id is reported after the
	// upgrade via close 4004 and a non-WebSocket GET gets Accept's 426 either
	// way, so the response is no session-existence oracle -- so the 403 below is
	// the engine's same-origin refusal on a session that exists and is
	// attachable, not an artifact of a missing session.
	mux, _, csp, id := mustStartSession(t, newTestDeps(true))

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	req := newWSUpgradeRequest(t, srv.URL, string(id), "http://evil.example")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("cross-origin /ws handshake: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin /ws handshake = %d, want 403 (CSWSH must be blocked; this app configures no terminal.OriginPolicy and must stay same-origin)", resp.StatusCode)
	}
}

// TestWSAcceptsSameOrigin is the positive companion to TestWSRejectsCrossOrigin:
// a same-origin /ws handshake for a valid session must complete the upgrade
// (101 Switching Protocols). The cross-origin 403 test alone cannot distinguish
// "correctly rejects a foreign Origin" from "rejects every upgrade" -- a handler
// that 403'd unconditionally would still pass the negative test. This pins that
// the 403 is specifically the same-origin (CSWSH) check, not a blanket refusal.
func TestWSAcceptsSameOrigin(t *testing.T) {
	mux, _, csp, id := mustStartSession(t, newTestDeps(true))

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	req := newWSUpgradeRequest(t, srv.URL, string(id), srv.URL) // same origin as the test server
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("same-origin /ws handshake: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("same-origin /ws handshake = %d, want 101 (the CSWSH guard must ACCEPT a same-origin upgrade, else the cross-origin 403 test cannot tell the origin check from a blanket rejection)", resp.StatusCode)
	}
}

// TestSessionFactoryRequestsTheTitleEnv pins that the session factory consults
// deps.sessionTitleEnv for the session it is building.
//
// This is a COMPOSITION test, and it exists because the composition is the part
// that breaks. Tab names come from kiro-cli's own session record, and the whole
// chain rests on one thing this app must do per session: inject WT_TITLE_HANDLE
// into the child environment so a kiro-cli hook can report which kiro session the
// tab is running (sessiontitle.go). Nothing else can supply that pairing. Drop the
// option and every tab silently falls back to the engine's automatic cwd rung and
// reads "workspace" forever, which is exactly how the PREVIOUS title mechanism
// broke here: the engine shipped it as an opt-in and this app stopped passing it,
// with no failing test anywhere. Asserting it THROUGH registerRoutes is the only
// place that catches a dropped option.
func TestSessionFactoryRequestsTheTitleEnv(t *testing.T) {
	var ready webhttp.Ready
	ready.Set(true)

	var gotIDs []terminal.SessionID
	staticSrv, _ := testStaticSurface()
	deps := withDefaultPolicies(&routeDeps{
		static:  staticSrv,
		ready:   &ready,
		workDir: "",
		cmd:     staticCmd("/bin/cat"),
		sessionTitleEnv: func(id terminal.SessionID) []string {
			gotIDs = append(gotIDs, id)
			return []string{"WT_TITLE_HANDLE=" + string(id)}
		},
	})
	_, _, _, id := mustStartSession(t, deps)

	if len(gotIDs) != 1 || gotIDs[0] != id {
		t.Fatalf("sessionTitleEnv called with %v, want exactly [%q] -- the session factory no longer asks for the per-session title environment, so no kiro-cli hook can pair this tab with its session and every tab falls back to the cwd name", gotIDs, id)
	}
}

// TestChildEnvComposesBothOverlays pins that the per-session overlay carries the
// PATH lead AND the title variables, and that a nil sessionTitleEnv (the root's
// off-shape constructors, and tests that do not wire a syncer) degrades to the
// PATH overlay alone rather than panicking.
func TestChildEnvComposesBothOverlays(t *testing.T) {
	t.Run("both overlays present", func(t *testing.T) {
		d := &routeDeps{
			sessionEnv:      func() []string { return []string{"PATH=/pinned:/usr/bin"} },
			sessionTitleEnv: func(id terminal.SessionID) []string { return []string{"WT_TITLE_HANDLE=" + string(id)} },
		}
		got := d.childEnv("tab7")
		want := []string{"PATH=/pinned:/usr/bin", "WT_TITLE_HANDLE=tab7"}
		if !slices.Equal(got, want) {
			t.Errorf("childEnv = %v, want %v", got, want)
		}
	})
	t.Run("nil title env is harmless", func(t *testing.T) {
		d := &routeDeps{sessionEnv: func() []string { return []string{"PATH=/pinned"} }}
		if got := d.childEnv("tab7"); !slices.Equal(got, []string{"PATH=/pinned"}) {
			t.Errorf("childEnv = %v, want the PATH overlay alone", got)
		}
	})
	t.Run("one session's overlay cannot alias another's", func(t *testing.T) {
		// sessionEnv returning a slice with spare capacity is the aliasing trap:
		// appending into it would let tab A's overlay overwrite tab B's.
		base := make([]string, 1, 8)
		base[0] = "PATH=/pinned"
		d := &routeDeps{
			sessionEnv:      func() []string { return base },
			sessionTitleEnv: func(id terminal.SessionID) []string { return []string{"WT_TITLE_HANDLE=" + string(id)} },
		}
		a := d.childEnv("tabA")
		b := d.childEnv("tabB")
		if a[1] != "WT_TITLE_HANDLE=tabA" {
			t.Errorf("first overlay = %v, want it unchanged by the second", a)
		}
		if b[1] != "WT_TITLE_HANDLE=tabB" {
			t.Errorf("second overlay = %v", b)
		}
	})
}

// TestClassifyStatus pins the kiro-cli OSC 9 -> latched-status mapping that
// drives the tab activity dots. It was an inline closure with no test, so a
// typo or an upstream wording drift in the magic strings would silently break
// the dots. The switch is case-sensitive, so a case mismatch must NOT latch.
func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		name      string
		msg       string
		want      string
		wantLatch bool
	}{
		{name: "response complete latches done", msg: "Response complete", want: terminal.StatusDone, wantLatch: true},
		{name: "permission required latches input", msg: "Permission required", want: terminal.StatusInput, wantLatch: true},
		{name: "input required latches input", msg: "Input required", want: terminal.StatusInput, wantLatch: true},
		{name: "unknown message is ignored", msg: "Working on it", want: "", wantLatch: false},
		{name: "empty message is ignored", msg: "", want: "", wantLatch: false},
		{name: "case mismatch is ignored", msg: "response complete", want: "", wantLatch: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			classify := newStatusClassifier(false)
			got, latch := classify(tc.msg)
			if got != tc.want || latch != tc.wantLatch {
				t.Errorf("newStatusClassifier()(%q) = (%q, %v), want (%q, %v)", tc.msg, got, latch, tc.want, tc.wantLatch)
			}
		})
	}
}

// TestHealthEndpoint_reasonDistinguishesUnreadyCause pins the reason body of
// every 503 path, which TestHealthEndpoint_reflectsReadiness and
// TestHealthEndpoint_reflectsKiroCliReadiness leave unchecked: both assert only
// the status code, so the startup 503 and the kiro-cli 503s are
// indistinguishable in the suite. The reason is the operator-facing diagnostic
// (documented as surfacing to docker ps / the monitoring probe), so a
// regression that emitted the wrong reason on the wrong branch -- or the same
// reason for every branch -- would lose the "wait for startup" vs "still
// installing" vs "alert: kiro-cli broken" signal with no failing test.
//
// The kiro-cli reasons come from the install manager's own exported constants,
// so this pins the pass-through, not a copy of the wording: a manager that
// reworded a reason changes both sides at once, while a handler that dropped the
// reason and hardcoded one fails here.
func TestHealthEndpoint_reasonDistinguishesUnreadyCause(t *testing.T) {
	newMux := func(ready bool, verdict func() (bool, string)) *http.ServeMux {
		deps := newTestDeps(ready)
		deps.kiroReady = verdict
		mux, _, _ := mustRegisterRoutes(t, deps)
		return mux
	}
	body := func(mux *http.ServeMux) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
		return rec.Code, rec.Body.String()
	}
	unready := func(reason string) func() (bool, string) {
		return func() (bool, string) { return false, reason }
	}

	// Not-ready (startup/shutdown): the ready gate short-circuits before the
	// kiro-cli check, so 503 with the startup reason regardless of the verdict.
	code, b := body(newMux(false, unready(reasonUnavailable)))
	if code != http.StatusServiceUnavailable || !strings.Contains(b, "starting up or shutting down") {
		t.Errorf("not-ready: (status %d, body %q), want 503 with reason %q", code, b, "starting up or shutting down")
	}

	// Ready, but the manager has no usable version. Each state reports a
	// DIFFERENT reason: a first-boot download in flight is not an alert, an
	// exhausted retry budget is, and unenforced required settings point at a
	// third remedy entirely.
	for _, reason := range []string{
		reasonInstalling,
		reasonRetrying,
		reasonUnavailable,
		reasonSettings,
	} {
		code, b = body(newMux(true, unready(reason)))
		if code != http.StatusServiceUnavailable || !strings.Contains(b, reason) {
			t.Errorf("kiro-cli %q: (status %d, body %q), want 503 with that reason", reason, code, b)
		}
		if strings.Contains(b, "starting up or shutting down") {
			t.Errorf("kiro-cli %q: body %q reports the startup reason, which hides the real cause", reason, b)
		}
	}
}

// TestHealthEndpoint_envelopeMatchesTheLibrary pins the two wire properties this
// app shares with webhttp.ReadinessHandler and therefore with every other app in
// the fleet that serves a readiness verdict.
//
// KEY ORDER: this handler cannot use the library's handler (its verdict is
// composite -- a second reason plus the informational tools field -- while
// ReadinessChecker is Ready() bool), so it matches the library's wire shape by
// hand. It used to build a map, and encoding/json sorts map keys, so it emitted
// {"reason":…,"status":…} while the library emitted {"status":…,"reason":…}: one
// envelope, two orders, across three apps that are supposed to agree.
//
// CACHE: a readiness verdict must never be cached. A 200 with no explicit
// freshness is heuristically cacheable under RFC 9111, and a cached "ok"
// outliving the readiness it reported keeps traffic arriving at an instance that
// has begun draining -- the exact failure the gate exists to prevent. The handler
// sets it itself rather than relying on middleware, which is what let the app's
// /api/-wide no-store wrapper be narrowed to the engine's session surface without
// touching this route; the contract holds wherever the route is mounted. That is
// also why this asserts against the bare mux: it is the HANDLER's property being
// pinned. TestAPICachePolicy_EveryAPIPathSetsNoStore asserts the same header
// through the real chain, where the whole /api/ surface is enumerated together.
// STATUS + READY BODY: the byte-exact bodies above are also what pins the ready
// document, so no separate ready-body test is needed -- an exact match fails for
// a renamed status field, an empty tools value, or ANY extra key (the tools
// key's ABSENCE is what marks the subsystem deliberately disabled, as under bare
// `go run` or tests, rather than degraded). The status codes ride along in the
// same table because the Docker HEALTHCHECK's curl reads only the code.
func TestHealthEndpoint_envelopeMatchesTheLibrary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		deps       *routeDeps
		wantStatus int
		wantBody   string
	}{
		{"unready", newTestDeps(false), http.StatusServiceUnavailable, `{"status":"unready","reason":"starting up or shutting down"}`},
		{"ready", newTestDeps(true), http.StatusOK, `{"status":"ok"}`},
		// The informational tools field rides on the 503 bodies too: tool
		// convergence never GATES readiness, but an operator diagnosing an unready
		// instance needs to see whether tools are still syncing -- and that is
		// exactly the moment the field used to disappear, because both unready paths
		// returned before it was attached. Without this row, reverting
		// handleHealth's healthResponse to the pre-fix early-return shape leaves the
		// whole suite green.
		{"unready carries the informational tools state", unreadyDepsWithTools(), http.StatusServiceUnavailable, `{"status":"unready","reason":"starting up or shutting down","tools":"syncing"}`},
		// The whole-tree convergence count is the SECOND tools question, and the
		// disagreement is the point: the last repair succeeded (tools "ok") while
		// one enabled tool is still missing. Before this field existed, "ok" was
		// the only signal and read as whole-tree health.
		{"a partial repair reports ok alongside an outstanding count", depsWithToolsMissing(true, 1), http.StatusOK, `{"status":"ok","tools":"ok","tools_missing":1}`},
		// Zero MUST be emitted rather than dropped: it is the converged answer,
		// and omitempty on a plain int would erase exactly the good news.
		{"a converged tree reports zero rather than omitting it", depsWithToolsMissing(true, 0), http.StatusOK, `{"status":"ok","tools":"ok","tools_missing":0}`},
		// Unknown is absent, so "not counted yet" can never be misread as
		// converged.
		{"an uncounted tree omits the field", depsWithToolsMissing(false, 0), http.StatusOK, `{"status":"ok","tools":"ok"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, _, _ := mustRegisterRoutes(t, tc.deps)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthPath, http.NoBody))

			if rec.Code != tc.wantStatus {
				t.Errorf("health status = %d, want %d", rec.Code, tc.wantStatus)
			}
			got := strings.TrimSpace(rec.Body.String())
			if got != tc.wantBody {
				t.Errorf("raw health body = %q, want %q (byte-exact: the key ORDER is the shared contract)", got, tc.wantBody)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store: a cached readiness verdict defeats the gate", got)
			}
			// The "ready" and "unready" rows ARE the library's envelope; the tools row is
			// this app's composite extension and has no library counterpart.
			switch tc.name {
			case "ready":
				if libBody, libCC := libraryEnvelope(t, true); got != libBody || rec.Header().Get("Cache-Control") != libCC {
					t.Errorf("ready envelope = %q/%q, webhttp.ReadinessHandler emits %q/%q; the two must agree byte-for-byte",
						got, rec.Header().Get("Cache-Control"), libBody, libCC)
				}
			case "unready":
				if libBody, libCC := libraryEnvelope(t, false); got != libBody || rec.Header().Get("Cache-Control") != libCC {
					t.Errorf("unready envelope = %q/%q, webhttp.ReadinessHandler emits %q/%q; the reason string and key order are the shared contract",
						got, rec.Header().Get("Cache-Control"), libBody, libCC)
				}
			}
		})
	}
}

// readyStub adapts a bool to webhttp.ReadinessChecker so the library's own
// handler can be driven here.
type readyStub bool

func (r readyStub) Ready() bool { return bool(r) }

// libraryEnvelope returns webhttp.ReadinessHandler's body and Cache-Control
// for the given readiness, so the assertions above compare this app's
// hand-matched envelope against the REAL library output rather than against a
// literal copied from it. A webhttp bump that reorders the keys, renames a
// field, reworks the unready wording, or drops no-store fails HERE.
func libraryEnvelope(t *testing.T, ready bool) (body, cacheControl string) {
	t.Helper()
	rec := httptest.NewRecorder()
	webhttp.ReadinessHandler(readyStub(ready)).ServeHTTP(
		rec, httptest.NewRequest(http.MethodGet, healthPath, http.NoBody))
	return strings.TrimSpace(rec.Body.String()), rec.Header().Get("Cache-Control")
}

// withDefaultPolicies fills the four routeDeps POLICY functions with the
// permissive off-shape defaults main.go's composition root supplies
// (unmanagedKiroRuntime, degradedRuntime, startTools' absent-config-dir arm), so
// a test literal only names the fields it cares about. registerRoutes' policy
// contract is TOTAL — nil is reserved for the two mounting decisions (tools,
// kiroRescan) — so every literal needs them.
func withDefaultPolicies(d *routeDeps) *routeDeps {
	d.toolsSyncing = func() bool { return false }
	d.toolsState = func() string { return "" }
	d.toolsMissing = func() (int, bool) { return 0, false }
	d.kiroReady = func() (bool, string) { return true, "" }
	d.sessionEnv = func() []string { return nil }
	return d
}

// testStaticFS is the index fixture that satisfies the fail-loud CSP build,
// standing in for the embedded static tree.
func testStaticFS() fs.FS {
	return fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte(testIndexHTML)}}
}

// testStaticSurface builds the two derivatives the composition root builds in
// production — the serving handler routeDeps.static carries, and the hash-pinned
// CSP buildHandler is given — from that fixture. It panics rather than taking a
// *testing.T so the t-free fixture helpers (newTestDeps) can call it: the fixture
// is a constant, so a failure here is a broken harness rather than a test case.
func testStaticSurface() (http.Handler, string) {
	srv, csp, err := buildStaticSurface(testStaticFS())
	if err != nil {
		panic("buildStaticSurface on the test index fixture: " + err.Error())
	}
	return srv, csp
}

// newTestDeps returns the minimal routeDeps the route tests build
// repeatedly: the static handler the composition root builds from the index
// fixture, a ready flag, and a short-lived cat as the session command. Tests
// tweak fields (cmd, kiroReady) before registering.
func newTestDeps(ready bool) *routeDeps {
	var r webhttp.Ready
	r.Set(ready)
	staticSrv, _ := testStaticSurface()
	return withDefaultPolicies(&routeDeps{
		static:  staticSrv,
		ready:   &r,
		workDir: "",
		cmd:     staticCmd("/bin/cat"),
	})
}

// staticCmd is the fixed-argv session command a test wants where production
// resolves the active kiro-cli version per session.
func staticCmd(argv ...string) func() []string {
	return func() []string { return argv }
}

// unreadyDepsWithTools is an UNREADY handler with a tools engine wired: the
// combination that proves the informational tools field survives the 503 path,
// which newTestDeps(false) alone cannot show (its toolsState reports "", the
// deliberately-disabled case that omits the key).
func unreadyDepsWithTools() *routeDeps {
	d := newTestDeps(false)
	d.toolsState = func() string { return "syncing" }
	return d
}

// depsWithToolsMissing builds a ready runtime whose last job succeeded, with the
// whole-tree convergence count either known (ok) or not yet taken.
func depsWithToolsMissing(known bool, n int) *routeDeps {
	d := newTestDeps(true)
	d.toolsState = func() string { return "ok" }
	d.toolsMissing = func() (int, bool) { return n, known }
	return d
}

// shutdownManager tears the manager down at the end of a test and fails it when
// the teardown does not finish. It builds its own context rather than taking the
// test's: a subtest's context is already cancelled by the time cleanups run, so a
// wait against it would report an expiry on every test.
//
// The budget is deliberately generous against the real ceiling (the engine bounds
// a stubborn child's reap at 5s, and the containment and marker ladders each
// spend several grace windows), so a failure here means teardown genuinely hung
// rather than that the runner was loaded.
func shutdownManager(t *testing.T, mgr *terminal.SessionManager) {
	t.Helper()
	const budget = 20 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := mgr.Shutdown(ctx); err != nil {
		t.Errorf("SessionManager.Shutdown(ctx) = %v, want nil (teardown must finish within %v)", err, budget)
	}
}

// shutdownHandler is the single-session sibling of shutdownManager, for a test
// that builds one handler through the factory instead of a whole manager.
func shutdownHandler(t *testing.T, h *terminal.Handler) {
	t.Helper()
	const budget = 20 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Errorf("Handler.Shutdown(ctx) = %v, want nil (teardown must finish within %v)", err, budget)
	}
}

// mustRegisterRoutes wires deps on a fresh mux and schedules manager shutdown.
// It also returns the hash-pinned CSP the composition root derives from the
// same static fixture (buildStaticSurface), which is what production hands
// buildHandler — registerRoutes itself no longer produces it.
func mustRegisterRoutes(t *testing.T, deps *routeDeps) (*http.ServeMux, *terminal.SessionManager, string) {
	t.Helper()
	mux := http.NewServeMux()
	_, csp := testStaticSurface()
	mgr := registerRoutes(mux, deps)
	t.Cleanup(func() { shutdownManager(t, mgr) })
	return mux, mgr, csp
}

// quietTeardown clears readiness before the registered mgr.Shutdown kills the
// session's child: the factory's fast-death hook keys on readiness, so this
// keeps a teardown kill from emitting a stray broken-install Warn into a
// later test's log capture. Every test that leaves a live session running
// must call it.
func quietTeardown(t *testing.T, deps *routeDeps) {
	t.Helper()
	t.Cleanup(func() { deps.ready.Set(false) })
}

// readMarkerWithin polls a marker file the session's child process writes and
// returns its bytes once it holds at least minBytes, failing the test at the
// deadline with what the child never did. The option pins that observe an engine
// option THROUGH the child (working directory, DEC 1004 focus-out) both need this
// wait, and neither should re-implement the deadline bookkeeping around its own
// one-line assertion.
func readMarkerWithin(t *testing.T, path string, minBytes int, what string) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
		if err == nil && len(b) >= minBytes {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatalf("child did not %s (marker %q holds %d bytes, read error %v)", what, path, len(b), err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// mustStartSession wires deps on a fresh mux, creates ONE live session, and
// registers the readiness pre-drain teardown, returning the mux, manager, CSP
// policy and session id. Binding the three steps is deliberate: quietTeardown is
// a contract every test leaving a live session owes the next test's log capture,
// and four tests in this file had silently dropped it (a teardown kill then
// injected a stray fast-death Warn into a later test's exact-count assertion).
// A session started through this helper cannot forget it.
func mustStartSession(t *testing.T, deps *routeDeps) (*http.ServeMux, *terminal.SessionManager, string, terminal.SessionID) {
	t.Helper()
	mux, mgr, csp := mustRegisterRoutes(t, deps)
	id, err := mgr.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	quietTeardown(t, deps)
	return mux, mgr, csp, id
}

// newToolsDeps builds routeDeps with a real toolbelt engine on temp dirs
// (no catalog: search degrades, installs would fail — irrelevant here,
// these tests exercise the HTTP boundary, not installs).
func newToolsDeps(t *testing.T) *routeDeps {
	t.Helper()
	dir := t.TempDir()
	eng, err := toolbelt.New(&toolbelt.Config{
		ConfigDir: dir,
		ToolsDir:  filepath.Join(dir, "tools"),
	})
	if err != nil {
		t.Fatalf("toolbelt.New: %v", err)
	}
	t.Cleanup(eng.Close)
	var ready webhttp.Ready
	ready.Set(true)
	staticSrv, _ := testStaticSurface()
	return withDefaultPolicies(&routeDeps{
		static:  staticSrv,
		ready:   &ready,
		workDir: "",
		cmd:     staticCmd("/bin/cat"),
		tools:   eng,
	})
}

// TestLoopbackHint pins the LISTEN_ADDR -> "localhost[:port]" mapping the loopback
// surfaces' refusals quote. The 403 is the whole of what a refused caller is told, so a
// hint naming a port the deployment moved away from sends the operator to
// connection-refused with nothing else to work from; the fallback arm must degrade to a
// reachable host rather than to a broken URL like "localhost:" or ":9848".
func TestLoopbackHint(t *testing.T) {
	for name, tc := range map[string]struct{ addr, want string }{
		"the default host-less form": {":9848", "localhost:9848"},
		"a moved port":               {":8080", "localhost:8080"},
		"an explicit bind address":   {"0.0.0.0:8080", "localhost:8080"},
		"a loopback bind":            {"127.0.0.1:9848", "localhost:9848"},
		"an IPv6 bind":               {"[::1]:9848", "localhost:9848"},
		"no port at all":             {"localhost", "localhost"},
		// net.SplitHostPort returns NO error for an empty port, so `port != ""` is
		// the only thing standing between these two and the broken "localhost:"
		// URL this test's comment promises to prevent.
		"a host with an empty port": {"localhost:", "localhost"},
		"a bare colon":              {":", "localhost"},
		"empty":                     {"", "localhost"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := loopbackHint(tc.addr); got != tc.want {
				t.Errorf("loopbackHint(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

// TestToolsAPI_LoopbackOnly pins the tools API's only boundary on this
// unauthenticated port: the SOCKET PEER and the Host header must BOTH be
// loopback. A remote peer gets 403 regardless of headers (forwarded headers
// are client-controlled and deliberately ignored), and a loopback peer
// carrying a non-loopback Host — the DNS-rebound-page shape — is refused
// too; the in-container consumer (curl localhost) passes and reads the
// inventory.
func TestToolsAPI_LoopbackOnly(t *testing.T) {
	mux := http.NewServeMux()
	deps := newToolsDeps(t)
	// A non-default port, so the assertion below fails if the refusal goes back to a
	// hardcoded address instead of this deployment's own.
	deps.listenHint = loopbackHint(":8080")
	mgr := registerRoutes(mux, deps)
	t.Cleanup(func() { shutdownManager(t, mgr) })

	// Remote peer: refused, even claiming loopback via forwarded headers.
	req := httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
	req.RemoteAddr = "203.0.113.9:44321"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote peer: status = %d, want 403 (body %s)", rec.Code, rec.Body.String())
	}
	// The refusal speaks the standard webhttp error envelope with an empty
	// code, the dialect CONTRIBUTING requires of every app-owned error
	// response (the tools-installing 503 is asserted the same way). A
	// hand-crafted http.Error body would still be a 403 and pass every other
	// assertion, silently forking the app's error contract for the one gate a
	// remote caller actually reaches.
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("remote peer: Content-Type = %q, want application/json (webhttp.WriteError envelope)", ct)
	}
	var denied webhttp.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &denied); err != nil {
		t.Fatalf("remote peer: body %q is not the standard envelope: %v", rec.Body.String(), err)
	}
	if !strings.Contains(denied.Error, "loopback-only") || denied.Code != "loopback_only" {
		t.Errorf("remote peer: envelope = {error:%q code:%q}, want a loopback-only message and code %q", denied.Error, denied.Code, "loopback_only")
	}
	// The remedy the 403 names must be this deployment's address, not the default
	// port: a refused caller sees nothing else.
	if !strings.Contains(denied.Error, "curl localhost:8080") {
		t.Errorf("remote peer: envelope error = %q, want it to name this deployment's address (curl localhost:8080)", denied.Error)
	}

	// Loopback peer AND loopback Host: served. The fresh engine has an empty
	// manifest, so the inventory decodes with zero tools.
	req = httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Host = "127.0.0.1:9848"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback peer: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var inv struct {
		Tools []struct{} `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil {
		t.Fatalf("inventory decode: %v", err)
	}
	if len(inv.Tools) != 0 {
		t.Fatalf("fresh inventory = %d tools, want 0", len(inv.Tools))
	}

	// IPv6 loopback passes too.
	req = httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
	req.RemoteAddr = "[::1]:55555"
	req.Host = "[::1]:9848"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ipv6 loopback peer: status = %d, want 200", rec.Code)
	}

	// The DOCUMENTED consumer shape: kiro-cli's ! escape running
	// `curl localhost:9848/api/tools` inside the container sends the NAME
	// localhost, not an IP literal, so loopbackHost's canonical-name arm --
	// not its net.ParseIP arm -- is what admits it. Every other served case
	// above uses an IP literal, so deleting that arm keeps the whole suite
	// green while the tools API becomes unreachable from the only client it
	// exists for. Case folding is part of the same arm's contract
	// (webhttp.CanonicalHost lowercases), and a bare Host with no port must
	// pass too.
	for _, host := range []string{"localhost:9848", "localhost", "LocalHost:9848"} {
		req = httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
		req.RemoteAddr = "127.0.0.1:55555"
		req.Host = host
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("loopback peer with Host %q: status = %d, want 200 (body %s); the in-container consumer calls localhost by name", host, rec.Code, rec.Body.String())
		}
	}

	// A loopback SOCKET PEER whose Host names something else is the
	// DNS-rebinding shape: a page on evil.example resolved to 127.0.0.1 reaches
	// this handler with a loopback peer, and after rebinding its Origin and Host
	// agree so CrossOriginProtection admits it. The gate must refuse on the Host
	// half alone; without this case, deleting the loopbackHost conjunct keeps the
	// suite green while the tools API (which executes manual install strings as
	// root) becomes reachable from a browser. The empty and malformed Hosts pin
	// the fail-closed path through webhttp.CanonicalHost.
	for _, host := range []string{
		"evil.example", "evil.example:9848", "kiro.lan", "", "127.0.0.1:garbage",
		// Name-confusion shapes. Admission is exact-name equality, and every
		// other rejected Host here shares no affix with "localhost", so a
		// widening to prefix/suffix/substring matching -- the plausible "let
		// *.localhost through" edit -- is invisible to the whole package.
		// These are attacker-REGISTERABLE names that resolve to 127.0.0.1 as
		// easily as any other, and the API behind this gate runs `manual`
		// install strings as root.
		"localhost.evil.example", "localhost.evil.example:9848",
		"evil.localhost", "evil.localhost:9848", "notlocalhost",
		// The same widening, one arm over: admission of an IP LITERAL is
		// net.ParseIP + IsLoopback, and every Host above decorates the NAME, so
		// a loosening of the literal arm to a prefix or substring test
		// (`strings.HasPrefix(canon, "127.")`, the equally plausible edit) is
		// invisible to the whole package. These are attacker-REGISTERABLE names
		// that a rebinding page resolves to 127.0.0.1 like any other.
		"127.evil.example", "127.evil.example:9848",
		"127.0.0.1.evil.example", "1.2.3.4",
	} {
		req = httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
		req.RemoteAddr = "127.0.0.1:55555"
		req.Host = host
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("loopback peer with Host %q: status = %d, want 403 (the gate requires a loopback Host as well as a loopback peer)", host, rec.Code)
		}
	}

	// The provenance leg (webhttp.ProxiedRequest): a request that passes BOTH
	// loopback legs but carries proxy or browser evidence is refused. The deny
	// lives in the library since the webhttp.LoopbackOnly adoption (the app-local
	// proxiedOrigin / proxyProvenanceHeaders copies are deleted), so these rows
	// pin that loopbackOnly still COMPOSES that middleware: rewiring it around
	// webhttp.LoopbackRequest alone -- the shape it had before the adoption's
	// library existed -- keeps the rest of the suite green while a same-loopback
	// proxy that rewrites Host to its upstream address readmits the API that runs
	// `manual` install strings as root. Refuse-only by design: a header can never
	// ADMIT, which is why the positive cases above carry none.
	for _, hdr := range [][2]string{
		{"Forwarded", "for=192.0.2.1"},
		{"X-Forwarded-For", "192.0.2.1"},
		{"X-Forwarded-Host", "kiro.lan"},
		{"X-Forwarded-Proto", "https"},
		{"X-Real-Ip", "192.0.2.1"},
		{"Sec-Fetch-Site", "none"},
		{"Origin", "http://localhost:9848"},
	} {
		req = httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
		req.RemoteAddr = "127.0.0.1:55555"
		req.Host = "localhost:9848"
		req.Header.Set(hdr[0], hdr[1])
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("loopback peer+Host with %s header: status = %d, want 403 (provenance headers can only refuse, never admit)", hdr[0], rec.Code)
		}
	}
}

// TestToolsAPI_LoopbackOnly_malformedPeerFailsClosed pins the fail-closed
// posture of the loopback gate on a socket peer it cannot prove is loopback:
// a RemoteAddr that fails net.SplitHostPort (no port), an empty RemoteAddr,
// and a host net.ParseIP rejects must all be refused with 403. The existing
// TestToolsAPI_LoopbackOnly exercises only well-formed host:port peers, so a
// fail-open regression on the error disjunct would pass the suite unnoticed.
func TestToolsAPI_LoopbackOnly_malformedPeerFailsClosed(t *testing.T) {
	mux := http.NewServeMux()
	deps := newToolsDeps(t)
	mgr := registerRoutes(mux, deps)
	t.Cleanup(func() { shutdownManager(t, mgr) })

	for _, tc := range []struct{ name, remoteAddr string }{
		{name: "no port fails SplitHostPort", remoteAddr: "127.0.0.1"},
		{name: "empty RemoteAddr", remoteAddr: ""},
		{name: "unparseable host", remoteAddr: "not-an-ip:1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("RemoteAddr %q: status = %d, want %d (a peer that cannot be proven loopback must be refused)", tc.remoteAddr, rec.Code, http.StatusForbidden)
			}
		})
	}
}

// TestToolsAPI_AbsentWithoutEngine pins the no-engine shape (bare `go run`
// / tests outside the container): /api/tools is simply not a registered
// pattern, falling through to the static catch-all.
func TestToolsAPI_AbsentWithoutEngine(t *testing.T) {
	mux, _, _ := mustRegisterRoutes(t, newTestDeps(false))
	if _, pat := mux.Handler(httptest.NewRequest(http.MethodGet, "/api/tools", http.NoBody)); pat == "/api/tools" {
		t.Fatal("/api/tools registered without a tools engine")
	}
}

// TestSessionCreateGate_ToolsSyncing pins the boot-convergence session
// gate: while the tools reconcile runs, POST /api/sessions answers 503
// ("tools installing") so the first kiro-cli never spawns before the
// manifest's tools are on PATH; once the gate lifts, creation flows
// through to the engine (and its rate limit) again. Health and the tools
// API stay reachable throughout — that is the bind-first point.
func TestSessionCreateGate_ToolsSyncing(t *testing.T) {
	mux := http.NewServeMux()
	deps := newToolsDeps(t)
	var syncing atomic.Bool
	syncing.Store(true)
	deps.toolsSyncing = syncing.Load
	deps.toolsState = func() string { return "syncing" }
	mgr := registerRoutes(mux, deps)
	t.Cleanup(func() { shutdownManager(t, mgr) })

	create := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := create()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("create during sync: status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	// The 503 speaks the standard webhttp error envelope with a machine-readable
	// code, the same dialect as the app's 403 gates — not a hand-rolled body.
	var env webhttp.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("create during sync: body %q is not the standard envelope: %v", rec.Body.String(), err)
	}
	if env.Error != "tools installing" || env.Code != "not_ready" {
		t.Fatalf("create during sync: envelope = {error:%q code:%q}, want {error:%q code:%q}", env.Error, env.Code, "tools installing", "not_ready")
	}

	// Health stays reachable and reports the informational tools state.
	hreq := httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody)
	hrec := httptest.NewRecorder()
	mux.ServeHTTP(hrec, hreq)
	if hrec.Code != http.StatusOK || !strings.Contains(hrec.Body.String(), `"tools":"syncing"`) {
		t.Fatalf("health during sync = %d %s, want 200 with tools:syncing", hrec.Code, hrec.Body.String())
	}

	// Gate lifts: the composed gate passes requests through to the inner
	// chain again. Asserted against a stub inner handler rather than the
	// real create endpoint — spawning an actual PTY session here would
	// leak its logging goroutines into later tests that capture
	// slog.Default (the client-ip threading test), which the race
	// detector rightly flags.
	syncing.Store(false)
	inner := 0
	gate := composeGate(func(next http.Handler) http.Handler { return next },
		func() (bool, string) { return syncing.Load(), "tools installing" })
	gated := gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inner++
		w.WriteHeader(http.StatusCreated)
	}))
	rec = httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", http.NoBody))
	if rec.Code != http.StatusCreated || inner != 1 {
		t.Fatalf("create after sync: status %d inner %d, want pass-through", rec.Code, inner)
	}
	syncing.Store(true)
	rec = httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/sessions", http.NoBody))
	if rec.Code != http.StatusServiceUnavailable || inner != 1 {
		t.Fatalf("re-gated create: status %d inner %d, want 503 and no inner call", rec.Code, inner)
	}
}

// TestBuildStaticSurface_failsLoudOnMalformedStatic pins the fail-loud CSP leg
// of buildStaticSurface, which the composition root calls before it wires any
// route: an embedded index.html with no inline <script> (a malformed build) must
// abort startup with an error, never yield a silently-degraded CSP.
func TestBuildStaticSurface_failsLoudOnMalformedStatic(t *testing.T) {
	fsys := fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte(`<script src="/app.js"></script>`)}}
	if _, _, err := buildStaticSurface(fsys); err == nil {
		t.Fatal("buildStaticSurface returned nil error for an index.html with no inline script; the hash-pinned CSP must abort startup, not degrade silently")
	}
}

// TestComposeGate_narrowsToCreateOnly pins the narrowing contract the gate's
// doc comment states but no test asserts: while a dependency is unready, ONLY
// session creation (POST terminal.SessionsPath) is 503'd — list (GET on the
// same path) and requests to other paths pass through to the inner chain,
// matching the engine's WithCreateGate contract (list/close/title flow
// through the same doubly-mounted handler).
func TestComposeGate_narrowsToCreateOnly(t *testing.T) {
	syncing := func() (bool, string) { return true, "tools installing" }
	identity := func(next http.Handler) http.Handler { return next }

	cases := []struct {
		name     string
		method   string
		path     string
		wantCode int
		wantNext bool
	}{
		{name: "POST create is gated", method: http.MethodPost, path: terminal.SessionsPath, wantCode: http.StatusServiceUnavailable, wantNext: false},
		{name: "GET list passes through", method: http.MethodGet, path: terminal.SessionsPath, wantCode: http.StatusCreated, wantNext: true},
		{name: "DELETE close passes through", method: http.MethodDelete, path: terminal.SessionsPath + "/abc", wantCode: http.StatusCreated, wantNext: true},
		{name: "POST to another path passes through", method: http.MethodPost, path: "/api/health", wantCode: http.StatusCreated, wantNext: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextHit := false
			gated := composeGate(identity, syncing)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextHit = true
				w.WriteHeader(http.StatusCreated)
			}))
			rec := httptest.NewRecorder()
			gated.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, http.NoBody))
			if rec.Code != tc.wantCode || nextHit != tc.wantNext {
				t.Errorf("%s %s during sync = (status %d, next %v), want (%d, %v)",
					tc.method, tc.path, rec.Code, nextHit, tc.wantCode, tc.wantNext)
			}
		})
	}
}

// failOpenFS wraps an fs.FS and fails Open for one path, standing in for an
// unreadable file inside the embedded static tree (a malformed build).
type failOpenFS struct {
	fs.FS
	failPath string
}

func (f failOpenFS) Open(name string) (fs.File, error) {
	if name == f.failPath {
		return nil, errors.New("injected open failure")
	}
	return f.FS.Open(name)
}

// TestBuildStaticSurface_failsLoudOnUnreadableStaticTree pins the static-handler
// leg of buildStaticSurface's fail-loud contract, which
// TestBuildStaticSurface_failsLoudOnMalformedStatic (the CSP leg) does not reach:
// webhttp.StaticHandler walks and hashes every file at construction, so a
// static tree with an unreadable file (a malformed build) must abort startup
// with an error rather than serve a partial site. index.html
// itself stays readable so the CSP build succeeds and the failure is
// attributable to the static-handler leg alone.
func TestBuildStaticSurface_failsLoudOnUnreadableStaticTree(t *testing.T) {
	base := fstest.MapFS{
		"static/index.html": &fstest.MapFile{Data: []byte(testIndexHTML)},
		"static/broken.js":  &fstest.MapFile{Data: []byte("x")},
	}
	if _, _, err := buildStaticSurface(failOpenFS{FS: base, failPath: "static/broken.js"}); err == nil {
		t.Fatal("buildStaticSurface returned nil error for a static tree with an unreadable file; an unhashable asset must abort startup, not serve a partial site")
	}
}

// TestComposeGate_syncingResponseIncludesRetryAfter pins the syncing 503's
// Retry-After hint, which TestSessionCreateGate_ToolsSyncing's status and
// body assertions leave unguarded: without the header a client, a proxy, and
// the UI's retry logic poll blind through a tools-convergence window whose
// only bound is toolbelt's 30-minute job timeout.
func TestComposeGate_syncingResponseIncludesRetryAfter(t *testing.T) {
	identity := func(next http.Handler) http.Handler { return next }
	gated := composeGate(identity, func() (bool, string) { return true, "tools installing" })(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("inner handler called while tools are syncing")
	}))
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, terminal.SessionsPath, http.NoBody))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("syncing response status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got := rec.Header().Get("Retry-After"); got != "5" {
		t.Errorf("syncing response Retry-After = %q, want %q", got, "5")
	}
}

// TestNotifyFingerprint pins the log-hygiene substitution the classifier applies
// to arbitrary child output before ANY of it reaches the log: the notification
// text is replaced by a fixed-width, content-free HMAC-SHA-256 prefix, KEYED
// with a per-classifier secret that never appears in the log stream. Four
// properties carry the whole contract, and each has a distinct failure the
// classifier's own tests cannot see:
//
//   - fixed width and hex-only, so no amount of child output can widen or
//     shape the record (a fingerprint that leaked input length or characters
//     would be a partial copy of the secret it exists to withhold);
//   - stable for equal input under one key, which is what lets an operator
//     correlate the Warn with its Debug twin and tell a repeat from a new
//     wording;
//   - distinct for different input, so two wordings are not conflated into
//     "the same unrecognized notification";
//   - KEY-DEPENDENT, which is the property an unkeyed digest lacked: the
//     plaintext here is low-entropy by nature (a device code, a short token),
//     so an unkeyed hash lets a log reader enumerate candidates offline and
//     confirm one by comparing digests. Under a key the log does not carry,
//     that oracle does not exist — and this assertion is what would fail if
//     someone "simplified" the HMAC back to a plain SHA-256.
//
// The keys below are injected by the test rather than drawn: the production key
// is generated per classifier and deliberately unreachable (see
// notifyFingerprinter), so these properties are pinned against keys the test
// owns.
func TestNotifyFingerprint(t *testing.T) {
	const secret = "verify at https://example.com/device?user_code=ABCD-EFGH"
	fp := notifyFingerprinter{key: []byte("test-key-one-0123456789abcdef0123")}
	otherKey := notifyFingerprinter{key: []byte("test-key-two-0123456789abcdef0123")}
	inputs := map[string]string{
		"empty":              "",
		"short wording":      "Response complete",
		"secret-shaped":      secret,
		"multi-byte":         strings.Repeat("\u2192", 300),
		"invalid utf-8":      "\xff\xfe not utf8",
		"one rune different": "Response complet",
	}
	seen := make(map[string]string, len(inputs))
	for name, msg := range inputs {
		t.Run(name, func(t *testing.T) {
			got := fp.fingerprint(msg)
			if len(got) != notifyFingerprintHexDigits {
				t.Errorf("fingerprint(%q) = %q (%d chars), want exactly %d; the record's width must not depend on child output", msg, got, len(got), notifyFingerprintHexDigits)
			}
			// Hex-only is the confidentiality assertion proper: no character of
			// the notification (a token, a device code) can appear in the record.
			if strings.Trim(got, "0123456789abcdef") != "" {
				t.Errorf("fingerprint(%q) = %q, want lowercase hex only; anything else means child output reached the log verbatim", msg, got)
			}
			if again := fp.fingerprint(msg); again != got {
				t.Errorf("fingerprint(%q) is unstable (%q then %q); an operator could not correlate the Warn with its Debug twin", msg, got, again)
			}
			// metadata is the integration point: it supplies the attrs routes.go
			// logs, and only an EQUALITY against the keyed fingerprint pins that
			// the emitted value IS this HMAC. Every shape assertion above (16
			// lowercase hex digits, stable across the Warn/Debug pair) is equally
			// satisfied by another hex-shaped transform of child output --
			// hex.EncodeToString([]byte(msg))[:16] carries the plaintext and
			// would keep this whole test green.
			meta := fp.metadata(msg)
			if len(meta) != 4 || meta[0] != "message_fingerprint" || meta[1] != got ||
				meta[2] != "message_runes" || meta[3] != len([]rune(msg)) {
				t.Errorf("metadata(%q) = %v, want [message_fingerprint %s message_runes %d]; the logged attribute must BE the keyed fingerprint, not another hex-shaped encoding of the notification", msg, meta, got, len([]rune(msg)))
			}
		})
		got := fp.fingerprint(msg)
		if other, dup := seen[got]; dup {
			t.Errorf("fingerprint collides for %q and %q (both %q); two distinct wordings would read as one", msg, other, got)
		}
		seen[got] = msg
	}

	// The property the key exists for, stated on the input class that motivated
	// it: a device code is short and drawn from a small alphabet, so an UNKEYED
	// digest of it is recoverable by offline enumeration. Two keys must not
	// agree on it — a plain hash would.
	const deviceCode = "ABCD-EFGH"
	underOneKey := fp.fingerprint(deviceCode)
	underAnotherKey := otherKey.fingerprint(deviceCode)
	if underOneKey == underAnotherKey {
		t.Errorf("fingerprint(%q) = %q under two different keys; the identifier is unkeyed, so anyone reading the log can enumerate short candidates offline and confirm the notification's text", deviceCode, underOneKey)
	}

	if keyed := fp.metadata(deviceCode); len(keyed) != 4 || keyed[0] != "message_fingerprint" {
		t.Errorf("keyed metadata(%q) = %v, want [message_fingerprint <hex> message_runes <n>]", deviceCode, keyed)
	}
}

// TestComposeGate_syncingRefusalPreservesCreateBudget pins the composition
// ORDER inside composeGate, which no existing test can see: the tools-syncing
// refusal is checked OUTSIDE the create rate limit, so a client retrying
// through a convergence window (bounded only by toolbelt's 30-minute job
// timeout) spends no rate-limit tokens on refused attempts, and a full burst
// succeeds the moment the gate lifts. Swapping the two layers -- a one-line
// change in composeGate -- leaves every other test in this package green while
// a retrying UI gets 429 "session creation rate exceeded" instead of the 503
// "tools installing" that names the real cause, and then reaches convergence
// with an empty bucket, so the terminal stays unusable for a further refill
// window.
func TestComposeGate_syncingRefusalPreservesCreateBudget(t *testing.T) {
	var syncing atomic.Bool
	syncing.Store(true)
	creates := 0
	gated := composeGate(webhttp.SessionCreateRateLimit(terminal.SessionsPath),
		func() (bool, string) { return syncing.Load(), "tools installing" })(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			creates++
			w.WriteHeader(http.StatusCreated)
		}))
	post := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, terminal.SessionsPath, http.NoBody))
		return rec
	}

	// More refused attempts than the burst allows: every one must be the tools
	// 503, never the rate limit's 429.
	for attempt := 1; attempt <= sessionCreateBurst*2; attempt++ {
		if rec := post(); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("refused create %d = %d, want %d (body %s)", attempt, rec.Code, http.StatusServiceUnavailable, rec.Body.String())
		}
	}
	if creates != 0 {
		t.Fatalf("inner handler ran %d times while tools were syncing, want 0", creates)
	}

	// The budget survived the refusals.
	syncing.Store(false)
	for attempt := 1; attempt <= sessionCreateBurst; attempt++ {
		if rec := post(); rec.Code != http.StatusCreated {
			t.Fatalf("create %d after the gate lifted = %d, want %d (body %s); the refused attempts must not have spent the burst", attempt, rec.Code, http.StatusCreated, rec.Body.String())
		}
	}
}

// TestKiroRescan_reportsUnreadyOnlyWhenAVerdictWasReached pins the two non-ok
// outcomes, neither of which any other test reaches, and the property that
// separates them: BOTH answer 503, and only the one that reached a verdict speaks
// about the install. pinstall's ORDINARY refusal is (false, nil) -- no candidate
// selected, and recording that verdict succeeded -- which answers the manager's
// own reason. A context error means the request was ABANDONED before any verdict
// (the caller's own cancellation while queued for pinstall's operation slot, or
// this server's shutdown pre-drain cancelling the BaseContext every request is
// built on; an ADMITTED rescan detaches with context.WithoutCancel, and a probe or
// assertion that times out surfaces as *exec.ExitError, not as a context error),
// so it answers under its own "abandoned" status and does NOT report "no usable
// version" -- that would be a false broken-install verdict on the one endpoint an
// operator uses while the manager is already unready. "unready" is not a safe
// hedge either: it is itself a weak verdict, and an abandoned rescan says nothing
// about readiness (a caller queued behind another rescan can be dropped on a
// manager that is ready), so the status field carries the discrimination rather
// than the reason string alone.
//
// The empty wantBody this case used to carry was a defect, not a contract: writing
// nothing let net/http synthesize an implicit 200, so an operator's
// `curl -sfS -X POST .../api/kiro-cli/rescan` exited 0 -- reporting success for a
// repair that never ran. Both assertions below are load-bearing against a
// regression to that shape.
func TestKiroRescan_reportsUnreadyOnlyWhenAVerdictWasReached(t *testing.T) {
	for name, tc := range map[string]struct {
		rescanErr error
		wantCode  int
		wantBody  string
	}{
		"a refusal that reached a verdict reports unready": {
			rescanErr: nil,
			wantCode:  http.StatusServiceUnavailable,
			wantBody:  `{"status":"unready","reason":"kiro-cli unavailable"}`,
		},
		"an abandoned caller reports the abandonment, never a verdict": {
			rescanErr: context.Canceled,
			wantCode:  http.StatusServiceUnavailable,
			wantBody:  `{"status":"abandoned","reason":"kiro-cli rescan not performed: request abandoned before any verdict"}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			deps := newTestDeps(true)
			deps.kiroReady = func() (bool, string) { return false, "kiro-cli unavailable" }
			deps.kiroRescan = func(context.Context) (bool, error) { return false, tc.rescanErr }
			mux, _, _ := mustRegisterRoutes(t, deps)

			req := httptest.NewRequest(http.MethodPost, kiroRescanPath, http.NoBody)
			req.RemoteAddr = "127.0.0.1:5555"
			req.Host = "localhost:9848"
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantCode, rec.Body.String())
			}
			if got := strings.TrimSpace(rec.Body.String()); got != tc.wantBody {
				t.Errorf("body = %q, want %q", got, tc.wantBody)
			}
		})
	}
}

// The two tests that used to sit here pinned this app's OWN admission gate and
// its context.WithoutCancel wrapper: that an abandoned queued caller never
// entered pinstall, and that an admitted rescan survived a client disconnect.
// Both behaviours are now the LIBRARY's (pinstall >= v1.1.0 makes waiting for its
// operation slot cancellable and runs an admitted rescan detached), and they are
// pinned there by TestRescanQueuedCallerCanAbandon and
// TestAdmittedRescanIgnoresCallerCancellation, which exercise the real manager.
// These app-level versions drove a FAKE kiroRescan, so after the move they could
// only ever assert that the fake had no gate — a test of the stub, not the app.
//
// What is still this app's to get wrong is the one line below, and it is the
// reason this test exists rather than nothing: the handler must hand the REQUEST
// context to the manager unchanged. Re-detaching it here (the shape that was
// correct before the bump) would defeat the library's cancellable wait, silently
// restoring the unbounded-queue hazard the gate was written for.
func TestKiroRescan_PassesTheRequestContextThrough(t *testing.T) {
	seen := make(chan context.Context, 1)
	deps := newTestDeps(true)
	deps.kiroRescan = func(ctx context.Context) (bool, error) {
		seen <- ctx
		return true, nil
	}
	mux, _, _ := mustRegisterRoutes(t, deps)

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequest(http.MethodPost, kiroRescanPath, http.NoBody).WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Host = "localhost:9848"
	mux.ServeHTTP(httptest.NewRecorder(), req)

	var got context.Context
	select {
	case got = <-seen:
	default:
		t.Fatal("the rescan hook was never called")
	}

	// Cancelling the REQUEST must be visible to the manager: that is what lets
	// pinstall drop a caller still queued for its operation slot.
	cancel()
	select {
	case <-got.Done():
	default:
		t.Error("cancelling the request did not reach the context handed to pinstall; the handler is detaching it itself, which defeats the library's cancellable wait and restores the unbounded-queue hazard")
	}
}
