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
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"
	"github.com/cplieger/toolbelt/v2"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
	"github.com/cplieger/webhttp"
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
// server is handed a marker path (as entrypoint.sh does via
// KIRO_CLI_READY_MARKER), /api/health returns 503 while the marker is absent (a
// failed/incomplete kiro-cli install) and 200 once it exists — reflecting
// web-terminal-kiro's core dependency with a cheap Stat, never launching kiro-cli. An
// empty marker path skips the gate, so out-of-container runs (tests, bare
// `go run`) keep pure-listener readiness.
func TestHealthEndpoint_reflectsKiroCliReadiness(t *testing.T) {
	marker := filepath.Join(t.TempDir(), ".kiro-cli-ready")

	newMux := func(markerPath string) *http.ServeMux {
		deps := newTestDeps(true)
		deps.kiroReadyMarker = markerPath
		mux, _, _ := mustRegisterRoutes(t, deps)
		return mux
	}
	status := func(mux *http.ServeMux) int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
		return rec.Code
	}

	// Marker path set but file absent -> kiro-cli unavailable -> 503.
	if code := status(newMux(marker)); code != http.StatusServiceUnavailable {
		t.Errorf("marker absent: status = %d, want %d", code, http.StatusServiceUnavailable)
	}

	// Marker present -> ready -> 200.
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	if code := status(newMux(marker)); code != http.StatusOK {
		t.Errorf("marker present: status = %d, want %d", code, http.StatusOK)
	}

	// Empty marker path -> gate disabled -> 200 even with no file on disk.
	if code := status(newMux("")); code != http.StatusOK {
		t.Errorf("marker gate disabled: status = %d, want %d", code, http.StatusOK)
	}
}

// testIndexHTML is the minimal index fixture route tests embed: it carries one
// inline <script> (the importmap stand-in) and one inline <style> so
// buildCSPPolicy — which fails loud on a script-less or style-less index.html —
// accepts it, mirroring the real page.
const testIndexHTML = `<!doctype html><style>body{margin:0}</style><script type="importmap">{}</script>`

// TestKiroCacheControl pins the two-branch cache POLICY handed to
// webhttp.StaticHandler (the ETag/gzip mechanism now lives in webhttp and is
// tested there): assets under vendor/fonts/ are immutable for 30 days while
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
		{name: "font is immutable", assetPath: "vendor/fonts/iosevka.woff2", wantCache: "public, max-age=2592000, immutable"},
		{name: "nested font is immutable", assetPath: "vendor/fonts/sub/x.woff2", wantCache: "public, max-age=2592000, immutable"},
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
		if line := sc.Text(); strings.HasPrefix(line, "data:") && strings.Contains(line, id) {
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
	deps.cmd = []string{"/bin/true"}
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

// TestAPINoStore pins that the token-bearing JSON surface is uncacheable while
// static assets keep their own policy. GET /api/sessions returns live session
// ids, which are the /ws attach/resume capability tokens the logging layer
// deliberately keeps out of logs; without no-store the browser persists one to
// its on-disk cache and an intermediary proxy may serve the list from cache.
func TestAPINoStore(t *testing.T) {
	mux, _, csp := mustRegisterRoutes(t, newTestDeps(true))
	h := buildHandler(mux, nil, csp, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, terminal.SessionsPath, http.NoBody))
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control on %s = %q, want %q (session ids are capability tokens)", terminal.SessionsPath, got, "no-store")
	}

	srec := httptest.NewRecorder()
	h.ServeHTTP(srec, httptest.NewRequest(http.MethodGet, "/index.html", http.NoBody))
	if got := srec.Header().Get("Cache-Control"); got != "no-cache, must-revalidate" {
		t.Errorf("Cache-Control on a static asset = %q, want kiroCacheControl's policy (the API gate must not leak onto static)", got)
	}

	// A non-API path nothing downstream decorates, so the /api/ scoping is
	// actually observable: GET /ws without an Upgrade header is answered 426 by
	// the engine's WebSocket handler, which sets no Cache-Control. Neither
	// check above can see the guard -- /index.html is a KNOWN asset whose
	// Cache-Control webhttp.StaticHandler overwrites on its way out, and an
	// unknown path 404s through net/http's serveError, which since Go 1.23
	// DELETES Cache-Control (with ETag/Last-Modified) on the error path, so it
	// carries none whether or not apiNoStore is /api/-scoped.
	nrec := httptest.NewRecorder()
	h.ServeHTTP(nrec, httptest.NewRequest(http.MethodGet, terminal.WSPath, http.NoBody))
	if got := nrec.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control on the non-API path %s = %q, want none (the no-store gate is /api/-scoped)", terminal.WSPath, got)
	}
}

// TestAPINoStore_marksToolsInventoryUncacheable pins the surface apiNoStore
// covers ALONE, which TestAPINoStore above cannot see: the engine sets no-store
// on its own /api/sessions responses, so that test stays green with the
// apiNoStore chain entry deleted. toolbelt's httpapi handler sets no
// Cache-Control at all, so without the app's middleware a successful tools
// inventory response is cacheable and a browser or intermediary can keep
// serving stale tool state (an inventory an operator reads to decide whether an
// install finished). Verified red against a build with only the apiNoStore chain
// entry removed.
func TestAPINoStore_marksToolsInventoryUncacheable(t *testing.T) {
	deps := newToolsDeps(t)
	mux, _, csp := mustRegisterRoutes(t, deps)
	// Loopback peer AND loopback Host: the tools API's admission gate (see
	// TestToolsAPI_LoopbackOnly) refuses anything else, and a 403 would not
	// exercise the successful response this header policy applies to.
	req := httptest.NewRequest(http.MethodGet, toolsPath, http.NoBody)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Host = "localhost:9848"
	rec := httptest.NewRecorder()
	buildHandler(mux, nil, csp, nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want %d (body %s)", toolsPath, rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control on %s = %q, want %q; toolbelt's handler does not set this header, so apiNoStore must", toolsPath, got, "no-store")
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
	indexHTML, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded static/index.html: %v", err)
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	csp, err := buildCSPPolicy(sub)
	if err != nil {
		t.Fatalf("buildCSPPolicy: %v", err)
	}

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
	var scriptDirective string
	for directive := range strings.SplitSeq(csp, ";") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "script-src ") {
			scriptDirective = directive
			break
		}
	}
	if want := "script-src 'self' " + strings.Join(oracle, " "); scriptDirective != want {
		t.Errorf("CSP script directive = %q, want %q\nCSP: %s", scriptDirective, want, csp)
	}
}

// TestBuildCSPPolicyFailsLoud pins the fail-loud contract: buildCSPPolicy
// returns an error (never a silent 'unsafe-inline' degrade) when the static FS
// is nil, index.html is missing, index.html holds no inline <script>, or its
// inline <style> block is absent, unterminated, or duplicated. A
// production build always embeds index.html with its inline importmap and its
// single critical-CSS <style>, so any of these means a malformed build that must
// abort startup.
func TestBuildCSPPolicyFailsLoud(t *testing.T) {
	cases := []struct {
		name string
		fsys fs.FS
	}{
		{"nil FS", nil},
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
// mgr.WebSocketHandler() with no WithAcceptOptions, so the engine relies on
// coder/websocket's secure-by-default same-origin check (nil AcceptOptions ->
// authenticateOrigin). http.NewCrossOriginProtection lets the GET upgrade
// through, so this same-origin check is the ONLY thing standing between a
// malicious page in the victim's browser and a kiro-cli PTY on localhost.
// Unlike /debug (TestDebugRoutesNotExposed) this posture had no regression
// guard: a future WithAcceptOptions{InsecureSkipVerify:true} would silently
// re-open cross-site WebSocket hijacking. This test fails if that happens.
func TestWSRejectsCrossOrigin(t *testing.T) {
	// Drive the guard on a REAL session: the shape a malicious page in the
	// victim's browser would actually target. The pinned engine runs the
	// same-origin check on EVERY upgrade -- an unknown id is reported after the
	// upgrade via close 4004 and a non-WebSocket GET gets Accept's 426 either
	// way, so the response is no session-existence oracle -- so the 403 below is
	// websocket.Accept's origin refusal (nil AcceptOptions) on a session that
	// exists and is attachable, not an artifact of a missing session.
	mux, _, csp, id := mustStartSession(t, newTestDeps(true))

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	req := newWSUpgradeRequest(t, srv.URL, id, "http://evil.example")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("cross-origin /ws handshake: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin /ws handshake = %d, want 403 (CSWSH must be blocked; do not set InsecureSkipVerify)", resp.StatusCode)
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

	req := newWSUpgradeRequest(t, srv.URL, id, srv.URL) // same origin as the test server
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("same-origin /ws handshake: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("same-origin /ws handshake = %d, want 101 (the CSWSH guard must ACCEPT a same-origin upgrade, else the cross-origin 403 test cannot tell the origin check from a blanket rejection)", resp.StatusCode)
	}
}

// TestSessionTitleDerivesFromInput pins terminal.WithInputTitle() in the session
// factory's option list: send one submitted line into a session's PTY and the
// manager must report that line as the session's title.
//
// This is a COMPOSITION test, and it exists because the composition is the part
// that broke. The engine ships the deriver as an opt-in mechanism (off by
// default, deliberately: a general-purpose terminal wants the
// foreground-process name instead), so the whole feature reaching a user rests
// on this app passing one option. When the client-side deriver was retired in
// favour of the server-side one, that option was never added here — every tab
// silently fell through to the automatic ladder's cwd rung and read "workspace"
// forever, with no failing test anywhere. Asserting the derived title THROUGH
// registerRoutes is the only place that catches a dropped option; a unit test
// of the engine's deriver passes either way.
func TestSessionTitleDerivesFromInput(t *testing.T) {
	var ready webhttp.Ready
	ready.Set(true)
	deps := &routeDeps{
		staticFS: fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte(testIndexHTML)}},
		ready:    &ready,
		workDir:  "",
		// /bin/cat stands in for kiro-cli: the deriver reads the bytes the
		// client SENDS, so what the program does with them is irrelevant.
		cmd: []string{"/bin/cat"},
	}
	mux, mgr, csp, id := mustStartSession(t, deps)

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?session=" + id
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: srv.Client()})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial /ws: %v", err)
	}
	defer conn.CloseNow()

	// One binary frame is one atomic input event (the chunk boundary the
	// deriver's escape parser relies on). The leading byte must not be 0x00,
	// which the wire protocol reserves for control frames.
	const want = "name this session"
	if err := conn.Write(ctx, websocket.MessageBinary, []byte(want+"\r")); err != nil {
		t.Fatalf("write input frame: %v", err)
	}

	// The title is resolved on read (no status sweep needed), but the frame
	// still has to cross the socket and reach the PTY write.
	deadline := time.Now().Add(5 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		for _, s := range mgr.List() {
			if s.ID == id {
				got = s.Title
			}
		}
		if got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("session title = %q, want %q -- terminal.WithInputTitle() is missing from the session factory, so every tab falls back to the cwd/command name", got, want)
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
// the two 503 paths, which TestHealthEndpoint_reflectsReadiness and
// TestHealthEndpoint_reflectsKiroCliReadiness leave unchecked: both assert only
// the status code, so the startup 503 and the kiro-cli-unavailable 503 are
// indistinguishable in the suite. The reason is the operator-facing diagnostic
// (documented as surfacing to docker ps / the monitoring probe), so a
// regression that emitted the wrong reason on the wrong branch -- or the same
// reason for both -- would lose the "wait for startup" vs "alert: kiro-cli
// broken" signal with no failing test. This pins each 503 branch to its reason.
func TestHealthEndpoint_reasonDistinguishesUnreadyCause(t *testing.T) {
	newMux := func(ready bool, markerPath string) *http.ServeMux {
		deps := newTestDeps(ready)
		deps.kiroReadyMarker = markerPath
		mux, _, _ := mustRegisterRoutes(t, deps)
		return mux
	}
	body := func(mux *http.ServeMux) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", http.NoBody))
		return rec.Code, rec.Body.String()
	}

	// Not-ready (startup/shutdown): the ready gate short-circuits before the
	// marker check, so 503 with the startup reason regardless of the marker.
	code, b := body(newMux(false, filepath.Join(t.TempDir(), ".absent")))
	if code != http.StatusServiceUnavailable || !strings.Contains(b, "starting up or shutting down") {
		t.Errorf("not-ready: (status %d, body %q), want 503 with reason %q", code, b, "starting up or shutting down")
	}

	// Ready but kiro-cli marker absent: 503 with the kiro-cli reason, which must
	// differ from the startup reason so a probe can tell the two causes apart.
	code, b = body(newMux(true, filepath.Join(t.TempDir(), ".absent")))
	if code != http.StatusServiceUnavailable || !strings.Contains(b, "kiro-cli unavailable") {
		t.Errorf("kiro-cli-absent: (status %d, body %q), want 503 with reason %q", code, b, "kiro-cli unavailable")
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
// sets it itself rather than relying on the /api/-wide apiNoStore middleware, so
// the contract holds wherever the route is mounted and a future narrowing of that
// middleware's scope cannot silently drop it. That is also why this asserts
// against the bare mux: it is the HANDLER's property being pinned.
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

// newTestDeps returns the minimal routeDeps the route tests build
// repeatedly: the index fixture that satisfies the fail-loud CSP build,
// a ready flag, and a short-lived cat as the session command. Tests
// tweak fields (cmd, kiroReadyMarker) before registering.
func newTestDeps(ready bool) *routeDeps {
	var r webhttp.Ready
	r.Set(ready)
	return &routeDeps{
		staticFS: fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte(testIndexHTML)}},
		ready:    &r,
		workDir:  "",
		cmd:      []string{"/bin/cat"},
	}
}

// unreadyDepsWithTools is an UNREADY handler with a tools engine wired: the
// combination that proves the informational tools field survives the 503 path,
// which newTestDeps(false) alone cannot show (its toolsState is nil, and a nil
// state is the deliberately-disabled case that omits the key).
func unreadyDepsWithTools() *routeDeps {
	d := newTestDeps(false)
	d.toolsState = func() string { return "syncing" }
	return d
}

// mustRegisterRoutes wires deps on a fresh mux, failing the test on
// error and scheduling manager shutdown.
func mustRegisterRoutes(t *testing.T, deps *routeDeps) (*http.ServeMux, *terminal.SessionManager, string) {
	t.Helper()
	mux := http.NewServeMux()
	mgr, csp, err := registerRoutes(mux, deps)
	if err != nil {
		t.Fatalf("registerRoutes: %v", err)
	}
	t.Cleanup(mgr.Shutdown)
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
func mustStartSession(t *testing.T, deps *routeDeps) (*http.ServeMux, *terminal.SessionManager, string, string) {
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
	return &routeDeps{
		staticFS: fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte(testIndexHTML)}},
		ready:    &ready,
		workDir:  "",
		cmd:      []string{"/bin/cat"},
		tools:    eng,
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
	mgr, _, err := registerRoutes(mux, deps)
	if err != nil {
		t.Fatalf("registerRoutes: %v", err)
	}
	t.Cleanup(mgr.Shutdown)

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
	if !strings.Contains(denied.Error, "loopback-only") || denied.Code != "" {
		t.Errorf("remote peer: envelope = {error:%q code:%q}, want a loopback-only message with an empty code", denied.Error, denied.Code)
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
	mgr, _, err := registerRoutes(mux, deps)
	if err != nil {
		t.Fatalf("registerRoutes: %v", err)
	}
	t.Cleanup(mgr.Shutdown)

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
	mgr, _, err := registerRoutes(mux, deps)
	if err != nil {
		t.Fatalf("registerRoutes: %v", err)
	}
	t.Cleanup(mgr.Shutdown)

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
	// The 503 speaks the standard webhttp error envelope (empty code), the
	// same dialect as the app's 403 gates — not a hand-rolled body.
	var env webhttp.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("create during sync: body %q is not the standard envelope: %v", rec.Body.String(), err)
	}
	if env.Error != "tools installing" || env.Code != "" {
		t.Fatalf("create during sync: envelope = {error:%q code:%q}, want {error:%q code:%q}", env.Error, env.Code, "tools installing", "")
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
	gate := composeGate(func(next http.Handler) http.Handler { return next }, syncing.Load)
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

// TestRegisterRoutes_failsLoudOnMalformedStatic pins the error propagation of
// the fail-loud CSP build through registerRoutes: an embedded index.html with
// no inline <script> (a malformed build) must abort route registration with an
// error, never register routes with a silently-degraded CSP.
func TestRegisterRoutes_failsLoudOnMalformedStatic(t *testing.T) {
	mux := http.NewServeMux()
	var ready webhttp.Ready
	deps := &routeDeps{
		staticFS: fstest.MapFS{"static/index.html": &fstest.MapFile{Data: []byte(`<script src="/app.js"></script>`)}},
		ready:    &ready,
		workDir:  "",
		cmd:      []string{"/bin/cat"},
	}
	if _, _, err := registerRoutes(mux, deps); err == nil {
		t.Fatal("registerRoutes returned nil error for an index.html with no inline script; the hash-pinned CSP must abort startup, not degrade silently")
	}
}

// TestComposeGate_narrowsToCreateOnly pins the narrowing contract the gate's
// doc comment states but no test asserts: while tools are syncing, ONLY
// session creation (POST terminal.SessionsPath) is 503'd — list (GET on the
// same path) and requests to other paths pass through to the inner chain,
// matching the engine's WithCreateGate contract (list/close/title flow
// through the same doubly-mounted handler).
func TestComposeGate_narrowsToCreateOnly(t *testing.T) {
	syncing := func() bool { return true }
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

// TestRegisterRoutes_failsLoudOnUnreadableStaticTree pins the static-handler
// leg of buildStaticSurface's fail-loud contract, which
// TestRegisterRoutes_failsLoudOnMalformedStatic (the CSP leg) does not reach:
// webhttp.StaticHandler walks and hashes every file at construction, so a
// static tree with an unreadable file (a malformed build) must abort route
// registration with an error rather than serve a partial site. index.html
// itself stays readable so the CSP build succeeds and the failure is
// attributable to the static-handler leg alone.
func TestRegisterRoutes_failsLoudOnUnreadableStaticTree(t *testing.T) {
	base := fstest.MapFS{
		"static/index.html": &fstest.MapFile{Data: []byte(testIndexHTML)},
		"static/broken.js":  &fstest.MapFile{Data: []byte("x")},
	}
	mux := http.NewServeMux()
	var ready webhttp.Ready
	deps := &routeDeps{
		staticFS: failOpenFS{FS: base, failPath: "static/broken.js"},
		ready:    &ready,
		workDir:  "",
		cmd:      []string{"/bin/cat"},
	}
	if _, _, err := registerRoutes(mux, deps); err == nil {
		t.Fatal("registerRoutes returned nil error for a static tree with an unreadable file; an unhashable asset must abort startup, not serve a partial site")
	}
}

// TestComposeGate_syncingResponseIncludesRetryAfter pins the syncing 503's
// Retry-After hint, which TestSessionCreateGate_ToolsSyncing's status and
// body assertions leave unguarded: without the header a client, a proxy, and
// the UI's retry logic poll blind through a tools-convergence window whose
// only bound is toolbelt's 30-minute job timeout.
func TestComposeGate_syncingResponseIncludesRetryAfter(t *testing.T) {
	identity := func(next http.Handler) http.Handler { return next }
	gated := composeGate(identity, func() bool { return true })(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
			got, ok := fp.fingerprint(msg)
			if !ok {
				t.Fatalf("fingerprint(%q) reported no key on a keyed fingerprinter; the Warn and Debug records would lose their only identifier", msg)
			}
			if len(got) != notifyFingerprintHexDigits {
				t.Errorf("fingerprint(%q) = %q (%d chars), want exactly %d; the record's width must not depend on child output", msg, got, len(got), notifyFingerprintHexDigits)
			}
			// Hex-only is the confidentiality assertion proper: no character of
			// the notification (a token, a device code) can appear in the record.
			if strings.Trim(got, "0123456789abcdef") != "" {
				t.Errorf("fingerprint(%q) = %q, want lowercase hex only; anything else means child output reached the log verbatim", msg, got)
			}
			if again, _ := fp.fingerprint(msg); again != got {
				t.Errorf("fingerprint(%q) is unstable (%q then %q); an operator could not correlate the Warn with its Debug twin", msg, got, again)
			}
		})
		got, _ := fp.fingerprint(msg)
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
	underOneKey, _ := fp.fingerprint(deviceCode)
	underAnotherKey, _ := otherKey.fingerprint(deviceCode)
	if underOneKey == underAnotherKey {
		t.Errorf("fingerprint(%q) = %q under two different keys; the identifier is unkeyed, so anyone reading the log can enumerate short candidates offline and confirm the notification's text", deviceCode, underOneKey)
	}

	// Fail-closed: a fingerprinter with no key (crypto/rand unavailable at
	// construction) must omit the identifier rather than emit a predictable one,
	// and must still report the rune count so the record stays diagnosable.
	unkeyed := notifyFingerprinter{}
	if got, ok := unkeyed.fingerprint(deviceCode); ok || got != "" {
		t.Errorf("unkeyed fingerprint(%q) = (%q, %v), want (%q, false); a keyless fallback would be a guessable copy of child output", deviceCode, got, ok, "")
	}
	attrs := unkeyed.metadata(deviceCode)
	if len(attrs) != 2 || attrs[0] != "message_runes" || attrs[1] != len([]rune(deviceCode)) {
		t.Errorf("unkeyed metadata(%q) = %v, want exactly [message_runes %d]; the record must drop the fingerprint and keep the length", deviceCode, attrs, len([]rune(deviceCode)))
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
	gated := composeGate(webhttp.SessionCreateRateLimit(terminal.SessionsPath), syncing.Load)(
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
