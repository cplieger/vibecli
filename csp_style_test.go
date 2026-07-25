package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestCSPStyleHashMatchesEmbeddedInlineStyle is the anti-drift guard for the
// style-src hardening, the mirror of TestCSPScriptHashesMatchEmbeddedInlineScripts:
// it independently re-extracts the REAL embedded index.html's inline <style>
// content with a regexp (a different implementation from inlineStyleHash's byte
// scanner, so agreement is a genuine cross-check) and asserts the sha256 of that
// content appears in the assembled CSP. The hash is computed from the embed,
// never hardcoded, so the test tracks index.html automatically.
func TestCSPStyleHashMatchesEmbeddedInlineStyle(t *testing.T) {
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

	styleRE := regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style\s*>`)
	matches := styleRE.FindAllSubmatch(indexHTML, -1)
	if len(matches) != 1 {
		t.Fatalf("oracle found %d inline <style> blocks in index.html, want exactly 1 (the critical CSS); the page or the regexp changed", len(matches))
	}
	sum := sha256.Sum256(matches[0][1])
	token := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp, token) {
		t.Errorf("CSP is missing the hash for the inline style block.\nwant token %s\nCSP: %s", token, csp)
	}
	// The whole point of pinning the hash: no directive may fall back to
	// 'unsafe-inline', which would let an injected style block or style
	// attribute obscure or spoof the terminal UI.
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("CSP = %q, want no 'unsafe-inline' in any directive", csp)
	}
	if !strings.Contains(csp, "style-src 'self' 'sha256-") {
		t.Errorf("CSP style-src = %q, want 'self' plus the pinned sha256 token", csp)
	}
}

// TestInlineStyleHashIsByteExact pins the scanner's boundary contract: the hash
// covers exactly the bytes between the open tag's '>' and '</style', with no
// attribute text and no tag markup, which is what a browser hashes. Divergence
// here would produce a policy that silently blocks the page's critical CSS.
func TestInlineStyleHashIsByteExact(t *testing.T) {
	const content = "\n  body { margin: 0 }\n"
	sum := sha256.Sum256([]byte(content))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	cases := []struct {
		name string
		html string
	}{
		{"bare tag", "<html><style>" + content + "</style></html>"},
		{"tag with attributes", `<html><style type="text/css" media="all">` + content + "</style></html>"},
		{"uppercase tag", "<HTML><STYLE>" + content + "</STYLE></HTML>"},
		{"spaced close tag", "<html><style>" + content + "</style ></html>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inlineStyleHash([]byte(tc.html))
			if err != nil {
				t.Fatalf("inlineStyleHash: %v", err)
			}
			if got != want {
				t.Errorf("inlineStyleHash = %s, want %s (hash must cover the style content only)", got, want)
			}
		})
	}
}
