package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzNotifyExcerpt is the coverage-guided half of the excerpt bound's cover.
// notifyExcerpt is the only place in this app where arbitrary CHILD output is
// shaped for the always-on log stream: a program run in the terminal can emit
// any `ESC ] 9 ; <text>`, the engine's sanitizeNotification guarantees only
// integrity (unsafe runes dropped, 256-rune cap) and redacts nothing, and
// whatever survives is written to a stream Loki retains far longer than PTY
// scrollback. The bound is therefore a security-relevant property of untrusted
// input, and the invariants below are what keep it checked against inputs no
// table enumerates.
//
// The invariants are deliberately stronger than crash-only: pass-through
// identity under the bound, an exact rune budget over it, the marker's presence,
// valid UTF-8 out whenever the input was valid UTF-8 (the byte-slicing defect),
// and the excerpt being a genuine prefix of the input rather than any
// same-length string. The seed corpus is the durable coverage here -- the weekly
// coverage-guided run starts from these seeds every time and keeps nothing -- so
// the seeds carry the boundary, the multi-byte, the Bidi-control, the
// device-code-shaped and the invalid-UTF-8 cases directly.
func FuzzNotifyExcerpt(f *testing.F) {
	f.Add("")
	f.Add("Response complete")
	f.Add(strings.Repeat("a", unrecognizedNotifyExcerptRunes))
	f.Add(strings.Repeat("a", unrecognizedNotifyExcerptRunes+1))
	f.Add(strings.Repeat("\u2192", unrecognizedNotifyExcerptRunes+5))
	f.Add("\u202eevil wording")
	f.Add("verify at https://example.com/device?user_code=ABCD-EFGH and confirm the code shown there")
	f.Add("\xff\xfe invalid bytes")
	f.Fuzz(func(t *testing.T, msg string) {
		got := notifyExcerpt(msg)
		if utf8.ValidString(msg) && !utf8.ValidString(got) {
			t.Fatalf("notifyExcerpt(%q) = %q, which is not valid UTF-8; a byte-sliced excerpt puts a broken rune in the log", msg, got)
		}
		if utf8.RuneCountInString(msg) <= unrecognizedNotifyExcerptRunes {
			if got != msg {
				t.Fatalf("notifyExcerpt(%q) = %q, want it returned unchanged; a wording within the bound must not be marked clipped", msg, got)
			}
			return
		}
		if n := utf8.RuneCountInString(got); n != unrecognizedNotifyExcerptRunes+1 {
			t.Errorf("notifyExcerpt(%q) is %d runes, want exactly %d (the bound plus the marker); the always-on stream must not carry child output in full", msg, n, unrecognizedNotifyExcerptRunes+1)
		}
		if !strings.HasSuffix(got, "\u2026") {
			t.Errorf("notifyExcerpt(%q) = %q, want the truncation marker so a clipped wording stays distinguishable from a short one", msg, got)
		}
		if utf8.ValidString(msg) && !strings.HasPrefix(msg, strings.TrimSuffix(got, "\u2026")) {
			t.Errorf("notifyExcerpt(%q) = %q, whose text is not a prefix of the input; the excerpt must be the leading runes, not rearranged output", msg, got)
		}
	})
}
