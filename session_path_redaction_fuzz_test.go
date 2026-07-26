package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// FuzzRedactSessionPath_neverEmitsRawToken fuzzes the one untrusted-input
// boundary whose OUTPUT is written into the aggregated log stream: the
// request path reaching redactSessionPath is fully client-controlled, and a
// session id under /api/sessions/ is the /ws attach + resume capability
// token. The invariant is an enumeration, not a reimplementation of the
// branch logic: for any path under the subtree (other than the SSE route)
// the policy may return ONLY one of the three fixed route templates or the
// empty string webhttp records as "(path-redaction-failed)". Any other
// return means client bytes -- and therefore a live token -- reached the log
// (CWE-532). The stability check is the metamorphic half: applying the
// policy to its own output must be a fixed point, so no future arm can
// produce a value that re-classifies into a different route on a second
// pass. The request is built as a struct literal rather than via
// httptest.NewRequest because NewRequest panics on target strings the fuzzer
// generates; redactSessionPath reads only r.URL.Path.
func FuzzRedactSessionPath_neverEmitsRawToken(f *testing.F) {
	sub := terminal.SessionsSubtreePath
	for _, seed := range []string{
		"/", "/api/health", terminal.SessionsPath, terminal.SessionEventsPath,
		sub, sub + "abc", sub + "abc/title", sub + "abc/pinned-title",
		sub + "abc/", sub + "/title", sub + "abc/extra/title", sub + "abc\nx",
		sub + "abc/pinned-title/extra", "/api/sessionsx/abc",
	} {
		f.Add(seed)
	}
	allowed := map[string]bool{
		"":                        true,
		sub + "{id}":              true,
		sub + "{id}/title":        true,
		sub + "{id}/pinned-title": true,
	}
	f.Fuzz(func(t *testing.T, path string) {
		got := redactSessionPath(&http.Request{URL: &url.URL{Path: path}})
		switch {
		case !strings.HasPrefix(path, sub), path == terminal.SessionEventsPath:
			if got != path {
				t.Errorf("redactSessionPath(%q) = %q, want the path unchanged (only the id-bearing subtree is rewritten)", path, got)
			}
		default:
			if !allowed[got] {
				t.Errorf("redactSessionPath(%q) = %q, want one of the fixed route templates or the fail-closed empty string; any other value carries client-supplied bytes into the access log", path, got)
			}
		}
		if again := redactSessionPath(&http.Request{URL: &url.URL{Path: got}}); again != got {
			t.Errorf("redactSessionPath is not stable on its own output: %q -> %q -> %q", path, got, again)
		}
	})
}
