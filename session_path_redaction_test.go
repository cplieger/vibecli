package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// TestRedactSessionPath pins the access log's recorded-path POLICY as a unit,
// which TestBuildHandlerSkipsAccessLogForStreams (the wiring test) cannot
// fully reach: it drives only three subtree shapes through the middleware, so
// the pinned-title template -- the engine's PUT + DELETE
// /api/sessions/{id}/pinned-title rename routes the vendored UI's tab rename
// calls -- has zero coverage, and the SSE self-mapping arm is unreachable
// through buildHandler at all (WithSkipPaths means the path func never runs
// for that route). Two contracts per row: a served shape maps to its
// token-free route template, and anything that is NOT a served shape returns
// the empty string webhttp records as its fail-closed
// "(path-redaction-failed)" placeholder -- never the raw path, so a live
// session id (the /ws attach + resume capability token) cannot reach a
// log-read consumer through a malformed request either.
func TestRedactSessionPath(t *testing.T) {
	sub := terminal.SessionsSubtreePath
	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "unrelated path passes through", path: "/api/health", want: "/api/health"},
		{name: "static root passes through", path: "/", want: "/"},
		{name: "exact create/list path passes through", path: terminal.SessionsPath, want: terminal.SessionsPath},
		{name: "SSE stream maps to itself", path: terminal.SessionEventsPath, want: terminal.SessionEventsPath},
		{name: "id segment maps to the id template", path: sub + "live-token-1234", want: sub + "{id}"},
		{name: "title route maps to the title template", path: sub + "live-token-1234/title", want: sub + "{id}/title"},
		{name: "pinned-title route maps to the pinned-title template", path: sub + "live-token-1234/pinned-title", want: sub + "{id}/pinned-title"},
		{name: "bare subtree with no id fails closed", path: sub, want: ""},
		{name: "trailing slash after an id fails closed", path: sub + "live-token-1234/", want: ""},
		{name: "empty id segment fails closed", path: sub + "/title", want: ""},
		{name: "deeper path under title fails closed", path: sub + "live-token-1234/extra/title", want: ""},
		{name: "deeper path under pinned-title fails closed", path: sub + "live-token-1234/pinned-title/extra", want: ""},
		{name: "case-mismatched suffix fails closed", path: sub + "live-token-1234/Title", want: ""},
		{name: "unknown suffix fails closed", path: sub + "live-token-1234/resize", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSessionPath(httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))
			if got != tc.want {
				t.Errorf("redactSessionPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
			if tc.want == "" && strings.Contains(got, "live-token") {
				t.Errorf("redactSessionPath(%q) = %q, which carries the raw session token; an unserved shape must fail closed, not leak the id", tc.path, got)
			}
		})
	}
}
