package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// embeddedCSP returns the REAL embedded index.html and the CSP assembled from the
// same static tree, the fixture both hash-anti-drift tests start from.
func embeddedCSP(t *testing.T) ([]byte, string) {
	t.Helper()
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
	return indexHTML, csp
}

// cspDirective isolates one directive from the assembled policy, so both hash tests
// assert on the DIRECTIVE rather than on token presence anywhere in the policy (a
// policy-wide Contains stays green when a token lands in the wrong directive). The
// structure it depends on -- semicolon-separated, name then one space -- is defined
// here once.
func cspDirective(csp, name string) string {
	for directive := range strings.SplitSeq(csp, ";") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, name+" ") {
			return directive
		}
	}
	return ""
}

// TestCSPStyleHashMatchesEmbeddedInlineStyle is the anti-drift guard for the
// style-src hardening, the mirror of TestCSPScriptHashesMatchEmbeddedInlineScripts:
// it independently re-extracts the REAL embedded index.html's inline <style>
// content with a regexp (a different implementation from webhttp.InlineStyleHashes'
// byte scanner, so agreement is a genuine cross-check) and asserts the sha256 of that
// content is exactly what style-src pins in the assembled CSP. The hash is
// computed from the embed, never hardcoded, so the test tracks index.html
// automatically.
func TestCSPStyleHashMatchesEmbeddedInlineStyle(t *testing.T) {
	indexHTML, csp := embeddedCSP(t)

	styleRE := regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style\s*>`)
	matches := styleRE.FindAllSubmatch(indexHTML, -1)
	if len(matches) != 1 {
		t.Fatalf("oracle found %d inline <style> blocks in index.html, want exactly 1 (the critical CSS); the page or the regexp changed", len(matches))
	}
	sum := sha256.Sum256(matches[0][1])
	token := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	// Pin the token to style-src BY NAME and assert the directive EXACTLY equals
	// 'self' plus that token. A policy-wide strings.Contains(csp, token) would
	// stay green if the token landed in script-src instead -- swapping
	// cspTemplate's two Sprintf arguments compiles and would satisfy both a
	// "token appears somewhere" and a "style-src has some sha256" check -- so
	// presence anywhere is not enough; the directive itself is the contract.
	if want, got := "style-src 'self' "+token, cspDirective(csp, "style-src"); got != want {
		t.Errorf("CSP style directive = %q, want %q\nCSP: %s", got, want, csp)
	}
	// The whole point of pinning the hash: no directive may fall back to
	// 'unsafe-inline', which would let an injected style block or style
	// attribute obscure or spoof the terminal UI.
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("CSP = %q, want no 'unsafe-inline' in any directive", csp)
	}
}
