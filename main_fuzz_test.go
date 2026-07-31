package main

import (
	"strings"
	"testing"
)

// FuzzSessionCommandNeverSplices generalizes the ONE property that makes the
// per-session PTY argv safe: neither the cli path nor an operator-supplied
// KIRO_CLI_CHAT_ARGS flag is ever interpolated into the guard script. Both ride
// the positional params (`$0` and `"$@"`), so a value carrying spaces, quotes,
// newlines, NULs or command substitution reaches `kiro-cli chat` verbatim and can
// never become shell syntax.
//
// The existing tests pin that with three fixed flags and one hand-picked
// `$(touch ...)` payload; this asserts it for arbitrary bytes at ~60k exec/s, so
// the weekly coverage-guided run explores the metacharacter space the hand-picked
// cases cannot. Three invariants: the script is byte-identical for every input
// (no splicing), each argument survives as its own element (no joining or
// re-quoting), and the element count is exact (nothing dropped or added).
func FuzzSessionCommandNeverSplices(f *testing.F) {
	f.Add("/config/tools/kiro-cli-versions/2.14.2/kiro-cli", "--v3")
	f.Add("/opt/kiro cli/kiro-cli", "$(touch /tmp/pwned)")
	f.Add("", "")
	f.Add("kiro-cli", "'; rm -rf / #")
	f.Add("kiro-cli", "--effort\nhigh")
	f.Add("kiro-cli", "\x00--v3")
	f.Add("$0", "$@")

	// The script the wrapper must return for EVERY input, captured once from a
	// call whose values appear nowhere in it.
	script := sessionCommand("baseline")[2]
	if !strings.Contains(script, `exec "$0" chat "$@"`) {
		f.Fatalf("guard script no longer forwards the positional params to chat only: %q", script)
	}

	f.Fuzz(func(t *testing.T, cliPath, arg string) {
		argv := sessionCommand(cliPath, arg, arg)

		if len(argv) != 6 { // /bin/sh -c <script> <cliPath> + two chat args
			t.Fatalf("len(argv) = %d, want 6; every chat arg must survive as its own element", len(argv))
		}
		if argv[0] != "/bin/sh" || argv[1] != "-c" {
			t.Errorf("argv[:2] = %q, want the /bin/sh -c wrapper", argv[:2])
		}
		if argv[2] != script {
			t.Errorf("the guard script changed with the inputs, so a path or flag was spliced into it instead of riding the positional params:\n got %q\nwant %q", argv[2], script)
		}
		if argv[3] != cliPath {
			t.Errorf("argv[3] = %q, want the cli path verbatim as $0", argv[3])
		}
		if argv[4] != arg || argv[5] != arg {
			t.Errorf("chat args = %q, want %q twice, verbatim", argv[4:], arg)
		}
	})
}
