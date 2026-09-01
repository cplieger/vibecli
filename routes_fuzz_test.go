package main

import (
	"strings"
	"testing"
)

// FuzzNotifyFingerprint is the coverage-guided half of the log-redaction cover.
// notifyFingerprinter is the only place in this app that shapes arbitrary CHILD
// output for the log stream: the engine's sanitizeNotification guarantees only
// integrity (unsafe runes dropped, 256-rune cap) and redacts nothing, and this
// function's output is written to a store Loki retains far longer than PTY
// scrollback.
//
// The key is injected here (production draws it per classifier and never logs
// it), so the invariants below cover keying too: a hex-only fixed-width output
// (so neither input length nor alphabet shows through), stable per key (the
// correlation the Warn/Debug pair relies on), sensitive to a one-bit change (so
// distinct wordings never collapse), never its own prefix (rules out
// truncate-instead-of-hash), and key-dependent (no offline guessing oracle).
func FuzzNotifyFingerprint(f *testing.F) {
	fp := notifyFingerprinter{key: []byte("fuzz-key-one-0123456789abcdef0123")}
	otherKey := notifyFingerprinter{key: []byte("fuzz-key-two-0123456789abcdef0123")}
	f.Add("")
	f.Add("Response complete")
	f.Add("deadbeefdeadbeef")
	f.Add(strings.Repeat("\u2192", 300))
	f.Add("\u202eevil wording")
	f.Add("verify at https://example.com/device?user_code=ABCD-EFGH and confirm the code shown there")
	f.Add("\xff\xfe invalid bytes")
	f.Fuzz(func(t *testing.T, msg string) {
		got := fp.fingerprint(msg)
		if len(got) != notifyFingerprintHexDigits {
			t.Fatalf("fingerprint(%q) = %q (%d chars), want exactly %d; the record's width must not depend on child output", msg, got, len(got), notifyFingerprintHexDigits)
		}
		if strings.Trim(got, "0123456789abcdef") != "" {
			t.Fatalf("fingerprint(%q) = %q, want lowercase hex only; any other character means child output reached the log verbatim", msg, got)
		}
		if again := fp.fingerprint(msg); again != got {
			t.Fatalf("fingerprint(%q) is unstable (%q then %q); the Warn and its Debug twin would no longer correlate", msg, got, again)
		}
		// Metamorphic: a one-bit change to the notification must change the
		// fingerprint, ruling out a constant or length-derived degenerate.
		if len(msg) > 0 {
			mutated := []byte(msg)
			mutated[0] ^= 0x01
			if other := fp.fingerprint(string(mutated)); other == got {
				t.Fatalf("fingerprint(%q) and its one-bit mutation both = %q; distinct wordings must not collapse into one record", msg, got)
			}
		}
		// Truncation, not hashing, is the regression that would still look
		// hex-ish.
		if strings.Trim(msg, "0123456789abcdef") == "" && len(msg) > notifyFingerprintHexDigits && got == msg[:notifyFingerprintHexDigits] {
			t.Fatalf("fingerprint(%q) = %q, its own prefix; the notification must be hashed, not truncated", msg, got)
		}
		// Keying: an unkeyed digest -- the shape this replaced -- would return
		// the same value under a different key, the offline oracle that makes a
		// short token or device code recoverable from the log.
		if underOther := otherKey.fingerprint(msg); underOther == got {
			t.Fatalf("fingerprint(%q) = %q under two different keys; a log reader could enumerate candidates offline and confirm the text", msg, got)
		}
	})
}
