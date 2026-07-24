package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/cplieger/webhttp"
)

// TestStaticCachePolicyServedOnResponses pins the WIRING of the app-owned
// cache policy into webhttp.StaticHandler. TestKiroCacheControl covers the
// policy FUNCTION in isolation, so dropping
// webhttp.WithStaticCacheControl(kiroCacheControl) from buildStaticSurface
// leaves the helper's default header on every asset and the whole suite stays
// green (verified by deleting the option: fonts then answer "no-cache" and
// only this test fails). The two branches are what the header must prove:
// the ~9.4 MB Monaspace fonts are immutable for 30 days (otherwise every
// visit re-downloads them) and everything else is no-cache +
// must-revalidate (otherwise a deploy serves a stale bundle against a
// changed server wire protocol).
func TestStaticCachePolicyServedOnResponses(t *testing.T) {
	var ready webhttp.Ready
	ready.Set(true)
	deps := &routeDeps{
		staticFS: fstest.MapFS{
			"static/index.html":              &fstest.MapFile{Data: []byte(testIndexHTML)},
			"static/vendor/fonts/mono.woff2": &fstest.MapFile{Data: []byte("font-bytes")},
		},
		ready:   &ready,
		workDir: "",
		cmd:     []string{"/bin/cat"},
	}
	mux, _, _ := mustRegisterRoutes(t, deps)

	for _, tc := range []struct{ path, wantCache string }{
		{path: "/vendor/fonts/mono.woff2", wantCache: "public, max-age=2592000, immutable"},
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
