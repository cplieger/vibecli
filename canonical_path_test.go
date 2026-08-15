package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
	"github.com/cplieger/webhttp"
)

// loopbackRequest returns a request shaped like the ONE sender the guarded
// routes are documented for: an in-container client (kiro-cli's `!` escape
// running `curl localhost:9848`). Loopback socket peer AND loopback Host,
// because loopbackOnly refuses anything else and a 403 would prove nothing
// about the canonical-path guard sitting in front of it.
func loopbackRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:54321"
	req.Host = "localhost:9848"
	return req
}

// TestCanonicalPathGuard_refusesNonCanonicalControlPlanePath is the reason the
// guard exists. Each row is a spelling http.ServeMux CLEANS before it selects a
// pattern, aimed at a route whose caller does not follow redirects: the README's
// documented repair POST and mutating tool calls (plain `curl`, no -L) and the
// image's baked health probe (`curl -sfS --max-time 4`, no -L). Verified against
// the real mux on go1.26.5, every one of these was a 307 before the guard — and a
// 307 makes those callers exit 0 having never reached a handler, so the mutation
// silently did not happen.
//
// The assertion that matters is therefore twofold and both halves are checked:
// the response is a 4xx the caller cannot mistake for success, and it is NOT a
// redirect. Asserting only "not 307" would pass on a 200; asserting only "400"
// would pass if some future layer answered 400 for an unrelated reason.
//
// Driven through buildHandler — the REAL chain in production order — because the
// guard is chain middleware by necessity: ServeMux's canonicalization runs BEFORE
// pattern selection, so no wrapper at the mount (where loopbackOnly sits) can
// ever see one of these requests. A test against the mux alone would assert the
// old 307 and stay green forever.
func TestCanonicalPathGuard_refusesNonCanonicalControlPlanePath(t *testing.T) {
	deps := newToolsDeps(t)
	var rescans atomic.Int64
	deps.kiroRescan = func(context.Context) (bool, error) {
		rescans.Add(1)
		return true, nil
	}
	mux, _, csp := mustRegisterRoutes(t, deps)
	h := buildHandler(mux, nil, csp, nil)

	for _, tc := range []struct {
		name, method, target string
		// why names the redirect the mux would otherwise have answered, so a red
		// row says which caller was being misled rather than only that a status
		// changed.
		why string
	}{
		{"health, empty segment", http.MethodGet, "/api//health", "307 to /api/health; the baked HEALTHCHECK curl exits 0 and reports the container healthy without ever consulting readiness"},
		{"health, dot segment", http.MethodGet, "/api/./health", "307 to /api/health, same probe"},
		{"tools exact, empty segment", http.MethodGet, "/api//tools", "307 to /api/tools; the README's inventory read returns nothing and succeeds"},
		{"tools exact, trailing dot", http.MethodGet, toolsPath + "/.", "307 to /api/tools"},
		{"tools exact, dot-dot segment", http.MethodGet, "/api/x/../tools", "307 to /api/tools"},
		{"tools subtree, empty segment", http.MethodPatch, toolsPath + "//gopls", "307 to /api/tools/gopls; the README's enable-and-install PATCH never runs"},
		{"tools subtree, encoded dot-dot", http.MethodGet, toolsPath + "/sub/%2e%2e", "no redirect at all — ServeMux hands this to the toolbelt subtree handler as /api/tools/sub/.., which is the wider refusal the decoded path buys"},
		{"tools subtree, encoded dot", http.MethodPatch, toolsPath + "/%2e/gopls", "no redirect either — the decoded path cleans to /api/tools/gopls, so this is the same enable-and-install PATCH by another spelling"},
		{"rescan, leading empty segment", http.MethodPost, "//api/kiro-cli/rescan", "307 to /api/kiro-cli/rescan; the README's documented repair POST reports success and repairs nothing"},
		{"rescan, dot segment", http.MethodPost, "/api/kiro-cli/./rescan", "307 to /api/kiro-cli/rescan, same repair POST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, loopbackRequest(tc.method, tc.target, ""))

			if rec.Code == http.StatusTemporaryRedirect || rec.Code == http.StatusMovedPermanently {
				t.Fatalf("%s %s: status = %d with Location %q — the guard did not fire, so this is %s",
					tc.method, tc.target, rec.Code, rec.Header().Get("Location"), tc.why)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s: status = %d, want %d (body %s)",
					tc.method, tc.target, rec.Code, http.StatusBadRequest, rec.Body.String())
			}

			// The refusal speaks this app's OWN envelope: webhttp.ErrorResponse
			// with an empty code, like every other app-owned refusal here (the
			// two 403 gates, the 405, the 503s), and carrying the request id so a
			// refused call correlates with its access-log line.
			var got webhttp.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("%s %s: body %q is not the app's JSON error envelope: %v",
					tc.method, tc.target, rec.Body.String(), err)
			}
			if got.Error != canonicalPathRefusal {
				t.Errorf("%s %s: error = %q, want %q", tc.method, tc.target, got.Error, canonicalPathRefusal)
			}
			if got.Code != "" {
				t.Errorf("%s %s: code = %q, want empty (this app's app-owned refusals carry no code)",
					tc.method, tc.target, got.Code)
			}
			if got.RequestID == "" {
				t.Errorf("%s %s: request_id is empty; a refused control-plane call must correlate with its access-log line",
					tc.method, tc.target)
			}
			// The refusal must not leak the caller's own request target back into
			// the body: net/http carries up to MaxHeaderBytes of request line, so
			// echoing it would make the response caller-sized.
			if strings.Contains(got.Error, tc.target) {
				t.Errorf("%s %s: error body echoes the request path: %q", tc.method, tc.target, got.Error)
			}
		})
	}

	// The whole point, stated as state rather than as a status code: no rescan
	// ran. Every row above that aimed at the repair hook was refused before the
	// mux selected a pattern, so the side effect the caller asked for did not
	// happen — and now it also does not report success.
	if n := rescans.Load(); n != 0 {
		t.Errorf("kiroRescan ran %d time(s) during the refused rows; a refused request must have no side effect", n)
	}
}

// TestCanonicalPathGuard_canonicalPathReachesHandler is the other half of the
// contract: the guard is inert on every spelling a real caller sends. Same
// routes, same senders, canonical paths — each must reach its own handler, which
// is what keeps the guard from being a denial of the surface it protects.
//
// The rows assert the OWNER's response (the toolbelt inventory, the app's rescan
// and health envelopes) rather than merely "not 400", so a guard that started
// refusing something legitimate cannot hide behind a status a fallthrough would
// also produce.
func TestCanonicalPathGuard_canonicalPathReachesHandler(t *testing.T) {
	deps := newToolsDeps(t)
	var rescans atomic.Int64
	deps.kiroRescan = func(context.Context) (bool, error) {
		rescans.Add(1)
		return true, nil
	}
	mux, _, csp := mustRegisterRoutes(t, deps)
	h := buildHandler(mux, nil, csp, nil)

	for _, tc := range []struct {
		name, method, target string
		wantStatus           int
		wantBodyContains     string
		owner                string
	}{
		{"health", http.MethodGet, healthPath, http.StatusOK, `"status"`, "handleHealth"},
		{"tools inventory", http.MethodGet, toolsPath, http.StatusOK, `"tools"`, "toolbelt httpapi"},
		{"tools subtree", http.MethodGet, toolsPath + "/search", http.StatusOK, "", "toolbelt httpapi"},
		{"tools subtree, trailing slash", http.MethodGet, toolsPath + "/", http.StatusNotFound, "", "toolbelt httpapi"},
		{"rescan", http.MethodPost, kiroRescanPath, http.StatusOK, `"ok"`, "handleKiroRescan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, loopbackRequest(tc.method, tc.target, ""))

			if rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), canonicalPathRefusal) {
				t.Fatalf("%s %s: the canonical-path guard refused a CANONICAL path; %s never ran",
					tc.method, tc.target, tc.owner)
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s: status = %d, want %d from %s (body %s)",
					tc.method, tc.target, rec.Code, tc.wantStatus, tc.owner, rec.Body.String())
			}
			if tc.wantBodyContains != "" && !strings.Contains(rec.Body.String(), tc.wantBodyContains) {
				t.Errorf("%s %s: body %q does not contain %q, so it is not %s's response",
					tc.method, tc.target, rec.Body.String(), tc.wantBodyContains, tc.owner)
			}
		})
	}

	// A canonical POST reached the repair hook: the refusal test's zero count
	// above means "refused", not "unreachable".
	if n := rescans.Load(); n != 1 {
		t.Errorf("kiroRescan ran %d time(s), want 1; the canonical repair POST must still reach the handler", n)
	}

	// The guard runs upstream of the mux, therefore upstream of loopbackOnly —
	// forced, since a request about to be rewritten never reaches a mount. So a
	// REMOTE caller's non-canonical spelling is answered 400 by the guard rather
	// than 403 by the loopback gate. Pinned as a deliberate consequence: it
	// discloses only that the cleaned path is one of the routes the public README
	// already documents, and the canonical spelling from the same peer keeps its
	// 403.
	rec := httptest.NewRecorder()
	remote := httptest.NewRequest(http.MethodGet, "/api//tools", http.NoBody)
	remote.RemoteAddr = "203.0.113.9:44321"
	remote.Host = "terminal.example:9848"
	h.ServeHTTP(rec, remote)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("remote peer, non-canonical tools path: status = %d, want %d from the guard", rec.Code, http.StatusBadRequest)
	}

	rec = httptest.NewRecorder()
	remote = httptest.NewRequest(http.MethodGet, toolsPath, http.NoBody)
	remote.RemoteAddr = "203.0.113.9:44321"
	remote.Host = "terminal.example:9848"
	h.ServeHTTP(rec, remote)
	if rec.Code != http.StatusForbidden {
		t.Errorf("remote peer, canonical tools path: status = %d, want %d — the loopback gate must still own this refusal",
			rec.Code, http.StatusForbidden)
	}
}

// TestCanonicalPathGuard_leavesStaticWSAndSSEAlone pins the SCOPE decision, which
// is the half of this change that is about what it deliberately does NOT do.
// These three surfaces keep byte-for-byte the behaviour they had:
//
//   - the static mount, because this app serves a browser UI where ServeMux's and
//     FileServer's cleanup/directory redirects are legitimate and wanted;
//   - the /ws upgrade and the SSE stream, whose clients are browsers that follow
//     a redirect, so the guard's premise (a machine sender that reads 307 as
//     success) does not hold for either.
//
// The engine's two paths come from terminal.WSPath and terminal.SessionEventsPath
// and the routes are the ones mgr.MountAPI really mounted, per this repo's
// convention: a wiring test asserts agreement with the ENGINE, never with a
// literal copied into the test.
func TestCanonicalPathGuard_leavesStaticWSAndSSEAlone(t *testing.T) {
	mux, _, csp, sessionID := mustStartSession(t, newTestDeps(true))
	h := buildHandler(mux, nil, csp, nil)

	// A non-canonical spelling on each unguarded surface must still be the mux's
	// own redirect, NOT the guard's refusal. httptest.NewRecorder is used rather
	// than a client so the redirect is observed instead of followed.
	for _, tc := range []struct{ name, target, wantLocation string }{
		{"static asset", "//index.html", "/index.html"},
		{"websocket upgrade path", "/" + terminal.WSPath, terminal.WSPath},
		{"sse stream", "/api//sessions/events", terminal.SessionEventsPath},
	} {
		t.Run(tc.name+", non-canonical", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, loopbackRequest(http.MethodGet, tc.target, ""))
			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("GET %s: status = %d, want %d (the mux's cleaning redirect); body %s",
					tc.target, rec.Code, http.StatusTemporaryRedirect, rec.Body.String())
			}
			if loc := rec.Header().Get("Location"); loc != tc.wantLocation {
				t.Errorf("GET %s: Location = %q, want %q", tc.target, loc, tc.wantLocation)
			}
		})
	}

	// And the canonical spellings still behave exactly as before, redirects
	// included: FileServer's own /index.html -> ./ 301 is precisely the
	// browser-facing redirect this guard must not touch, the asset itself is
	// served, a bare GET on the upgrade path gets the engine's own refusal (426,
	// not 400), and the SSE stream opens and flushes.
	t.Run("static index redirect, canonical", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/index.html", ""))
		if rec.Code != http.StatusMovedPermanently {
			t.Fatalf("GET /index.html: status = %d, want %d (http.FileServer's own redirect to ./); body %s",
				rec.Code, http.StatusMovedPermanently, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "./" {
			t.Errorf("GET /index.html: Location = %q, want %q", loc, "./")
		}
	})

	t.Run("static asset, canonical", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(http.MethodGet, "/", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "importmap") {
			t.Errorf("GET /: body %q is not the embedded index.html", rec.Body.String())
		}
	})

	t.Run("websocket upgrade path, canonical", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, loopbackRequest(http.MethodGet, terminal.WSPath, ""))
		if rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), canonicalPathRefusal) {
			t.Fatalf("GET %s: the canonical-path guard answered the upgrade path", terminal.WSPath)
		}
		if rec.Code != http.StatusUpgradeRequired {
			t.Errorf("GET %s: status = %d, want %d — the engine's own handshake refusal must still own this response (body %s)",
				terminal.WSPath, rec.Code, http.StatusUpgradeRequired, rec.Body.String())
		}
	})

	t.Run("sse stream, canonical", func(t *testing.T) {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+terminal.SessionEventsPath, http.NoBody)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", terminal.SessionEventsPath, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200; the stream must still open through the chain",
				terminal.SessionEventsPath, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("Content-Type = %q, want text/event-stream", ct)
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data:") && strings.Contains(line, sessionID) {
				return // the initial-sync event still flushes with the guard in the chain
			}
		}
		t.Fatalf("SSE stream delivered no data with the canonical-path guard in the chain (scan err: %v)", sc.Err())
	})
}

// TestCanonicalPathGuardedRoute pins the SCOPE as a set, at the unit the chain
// cannot show cheaply: which cleaned paths are in and which are out. It is the
// companion to the chain tests above — those prove the guard fires and stays out
// of the way, this one states the boundary, including the two shapes a prefix
// test gets wrong if written carelessly (a route whose name merely STARTS with a
// guarded one, and the sessions subtree the engine owns).
func TestCanonicalPathGuardedRoute(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
		why  string
	}{
		{healthPath, true, "the baked HEALTHCHECK's probe"},
		{toolsPath, true, "the tools API's exact mount"},
		{toolsPath + "/", true, "the tools API's subtree mount"},
		{toolsPath + "/gopls", true, "a mutating tool call under the subtree"},
		{kiroRescanPath, true, "the documented repair POST"},
		{"/", false, "the static catch-all: browser redirects there are wanted"},
		{"/index.html", false, "a static asset"},
		{terminal.WSPath, false, "the engine's upgrade, browser client"},
		{terminal.SessionsPath, false, "the engine's session API, browser client"},
		{terminal.SessionEventsPath, false, "the engine's SSE stream, browser client"},
		{apiPrefix, false, "the bare API prefix is not a route"},
		{healthPath + "extra", false, "a longer name that merely starts with a guarded path is not that route"},
		{toolsPath + "extra", false, "same, for the tools mount: the subtree arm must match on the separator"},
	} {
		if got := canonicalPathGuardedRoute(tc.path); got != tc.want {
			t.Errorf("canonicalPathGuardedRoute(%q) = %v, want %v (%s)", tc.path, got, tc.want, tc.why)
		}
	}
}
