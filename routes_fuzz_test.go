package main

import (
	"strings"
	"testing"
)

// FuzzNotifyFingerprint is the coverage-guided half of the log-redaction cover.
// notifyFingerprint is the only place in this app where arbitrary CHILD output
// is shaped for the log stream: a program run in the terminal can emit any
// `ESC ] 9 ; <text>`, the engine's sanitizeNotification guarantees only
// integrity (unsafe runes dropped, 256-rune cap) and redacts NOTHING, and
// whatever this function returns is written to a store Loki retains far longer
// than PTY scrollback. Redaction is therefore a security property of untrusted
// input, and the invariants below keep it checked against inputs no table
// enumerates.
//
// The invariants are deliberately stronger than crash-only, and each is the
// redaction property stated a different way: the output is a fixed number of
// lowercase hex digits (so neither the length nor the alphabet of the input can
// show through), it is stable for equal input (the correlation property the Warn
// and Debug records rely on), a one-bit change to the input changes it (so
// distinct wordings never collapse into one record), and a hex-only input is not
// returned as its own prefix (the truncate-instead-of-hash regression that would
// still pass the alphabet check). The seed corpus is the durable coverage here --
// the weekly coverage-guided run starts from these seeds every time and keeps
// nothing -- so the seeds carry the empty, hex-looking, device-code-shaped,
// Bidi-control, multi-byte and invalid-UTF-8 cases directly.
func FuzzNotifyFingerprint(f *testing.F) {
	f.Add("")
	f.Add("Response complete")
	f.Add("deadbeefdeadbeef")
	f.Add(strings.Repeat("\u2192", 300))
	f.Add("\u202eevil wording")
	f.Add("verify at https://example.com/device?user_code=ABCD-EFGH and confirm the code shown there")
	f.Add("\xff\xfe invalid bytes")
	f.Fuzz(func(t *testing.T, msg string) {
		got := notifyFingerprint(msg)
		if len(got) != notifyFingerprintHexDigits {
			t.Fatalf("notifyFingerprint(%q) = %q (%d chars), want exactly %d; the record's width must not depend on child output", msg, got, len(got), notifyFingerprintHexDigits)
		}
		if strings.Trim(got, "0123456789abcdef") != "" {
			t.Fatalf("notifyFingerprint(%q) = %q, want lowercase hex only; any other character means child output reached the log verbatim", msg, got)
		}
		if again := notifyFingerprint(msg); again != got {
			t.Fatalf("notifyFingerprint(%q) is unstable (%q then %q); the Warn and its Debug twin would no longer correlate", msg, got, again)
		}
		// Metamorphic: a one-bit change to the notification must change the
		// fingerprint. This is what rules out the degenerate implementations the
		// width/alphabet checks above accept -- a constant, or a fingerprint
		// derived from the length alone -- which would silently conflate every
		// unrecognized wording into one.
		if len(msg) > 0 {
			mutated := []byte(msg)
			mutated[0] ^= 0x01
			if other := notifyFingerprint(string(mutated)); other == got {
				t.Fatalf("notifyFingerprint(%q) and its one-bit mutation both = %q; distinct wordings must not collapse into one record", msg, got)
			}
		}
		// Truncation, not hashing, is the regression that would still look
		// hex-ish: a hex-only notification longer than the width would come back
		// as its own leading characters.
		if strings.Trim(msg, "0123456789abcdef") == "" && len(msg) > notifyFingerprintHexDigits && got == msg[:notifyFingerprintHexDigits] {
			t.Fatalf("notifyFingerprint(%q) = %q, its own prefix; the notification must be hashed, not truncated", msg, got)
		}
	})
}
