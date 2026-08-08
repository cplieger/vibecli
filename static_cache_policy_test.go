package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// TestStaticCachePolicyServedOnResponses pins the WIRING of the app-owned
// cache policy into webhttp.StaticHandler. TestKiroCacheControl covers the
// policy FUNCTION in isolation, so dropping
// webhttp.WithStaticCacheControl(kiroCacheControl) from buildStaticSurface
// leaves the helper's default header on every asset and the whole suite stays
// green (verified by deleting the option: fonts then answer "no-cache" and
// only this test fails). The two branches are what the header must prove:
// the ~9.4 MB Monaspace fonts are cached for 30 days without `immutable`
// (otherwise every visit re-downloads them, and with `immutable` a font whose
// bytes change under the same filename could not be busted by a reload) and
// everything else is no-cache +
// must-revalidate (otherwise a deploy serves a stale bundle against a
// changed server wire protocol).
func TestStaticCachePolicyServedOnResponses(t *testing.T) {
	deps := newTestDeps(true)
	// The font entry is what this test adds to the shared default tree: the
	// two Cache-Control branches are fonts vs everything else. Built through
	// buildStaticSurface, the same call the composition root makes, so the
	// option under test is wired exactly as production wires it.
	staticSrv, _, err := buildStaticSurface(fstest.MapFS{
		"static/index.html":              &fstest.MapFile{Data: []byte(testIndexHTML)},
		"static/vendor/fonts/mono.woff2": &fstest.MapFile{Data: []byte("font-bytes")},
	})
	if err != nil {
		t.Fatalf("buildStaticSurface: %v", err)
	}
	deps.static = staticSrv
	mux, _, _ := mustRegisterRoutes(t, deps)

	for _, tc := range []struct{ path, wantCache string }{
		{path: "/vendor/fonts/mono.woff2", wantCache: "public, max-age=2592000"},
		{path: "/", wantCache: "no-cache, must-revalidate"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status = %d, want %d", tc.path, rec.Code, http.StatusOK)
			}
			if got := rec.Header().Get("Cache-Control"); got != tc.wantCache {
				t.Errorf("GET %s: Cache-Control = %q, want %q (kiroCacheControl must be wired into webhttp.StaticHandler)", tc.path, got, tc.wantCache)
			}
		})
	}
}
