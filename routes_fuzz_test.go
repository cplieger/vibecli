package main

import (
	"strings"
	"testing"
)

// FuzzNotifyFingerprint is the coverage-guided half of the log-redaction cover.
// notifyFingerprinter is the only place in this app where arbitrary CHILD output
// is shaped for the log stream: a program run in the terminal can emit any
// `ESC ] 9 ; <text>`, the engine's sanitizeNotification guarantees only
// integrity (unsafe runes dropped, 256-rune cap) and redacts NOTHING, and
// whatever this function returns is written to a store Loki retains far longer
// than PTY scrollback. Redaction is therefore a security property of untrusted
// input, and the invariants below keep it checked against inputs no table
// enumerates.
//
// The key is injected here (the production key is drawn per classifier and
// never logged), which also makes the KEYING itself fuzzable: the same input
// under a second key must not reproduce the first identifier, the invariant that
// fails if the HMAC is ever "simplified" back to a plain digest of low-entropy
// child output.
//
// The invariants are deliberately stronger than crash-only, and each is the
// redaction property stated a different way: the output is a fixed number of
// lowercase hex digits (so neither the length nor the alphabet of the input can
// show through), it is stable for equal input under one key (the correlation
// property the Warn and Debug records rely on), a one-bit change to the input
// changes it (so distinct wordings never collapse into one record), a hex-only
// input is not returned as its own prefix (the truncate-instead-of-hash
// regression that would still pass the alphabet check), and it depends on the
// key (no offline guessing oracle for a short token or device code). The seed
// corpus is the durable coverage here -- the weekly coverage-guided run starts
// from these seeds every time and keeps nothing -- so the seeds carry the empty,
// hex-looking, device-code-shaped, Bidi-control, multi-byte and invalid-UTF-8
// cases directly.
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
		// fingerprint. This is what rules out the degenerate implementations the
		// width/alphabet checks above accept -- a constant, or a fingerprint
		// derived from the length alone -- which would silently conflate every
		// unrecognized wording into one.
		if len(msg) > 0 {
			mutated := []byte(msg)
			mutated[0] ^= 0x01
			if other := fp.fingerprint(string(mutated)); other == got {
				t.Fatalf("fingerprint(%q) and its one-bit mutation both = %q; distinct wordings must not collapse into one record", msg, got)
			}
		}
		// Truncation, not hashing, is the regression that would still look
		// hex-ish: a hex-only notification longer than the width would come back
		// as its own leading characters.
		if strings.Trim(msg, "0123456789abcdef") == "" && len(msg) > notifyFingerprintHexDigits && got == msg[:notifyFingerprintHexDigits] {
			t.Fatalf("fingerprint(%q) = %q, its own prefix; the notification must be hashed, not truncated", msg, got)
		}
		// Keying: the identifier must not be reproducible from the notification
		// alone. An unkeyed digest -- the shape this replaced -- would return the
		// same value here, which is exactly the offline oracle that makes a short
		// token or device code recoverable from the log.
		if underOther := otherKey.fingerprint(msg); underOther == got {
			t.Fatalf("fingerprint(%q) = %q under two different keys; a log reader could enumerate candidates offline and confirm the text", msg, got)
		}
	})
}
