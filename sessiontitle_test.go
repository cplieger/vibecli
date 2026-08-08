package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// fakeSetter records what the syncer pushed onto the engine's client title rung,
// and can report a session as gone (the manager's false return).
type fakeSetter struct {
	calls   []string // "id=title" in call order, so a repeat push is visible
	missing map[string]bool
	// live is the tab set List reports, i.e. what the engine's session manager
	// still holds. pass() reclaims any mapping whose tab is not in it, so a test
	// that expects a push has to name its tab here.
	live []string
}

func (f *fakeSetter) SetSessionTitle(id, title string) bool {
	f.calls = append(f.calls, id+"="+title)
	return !f.missing[id]
}

func (f *fakeSetter) List() []terminal.SessionInfo {
	out := make([]terminal.SessionInfo, 0, len(f.live))
	for _, id := range f.live {
		out = append(out, terminal.SessionInfo{ID: id})
	}
	return out
}

// titleFixture builds a syncer over temp dirs plus helpers to plant the two inputs
// the real system produces: the hook's mapping file and kiro-cli's session record.
type titleFixture struct {
	t    *testing.T
	sync *sessionTitleSync
	home string
}

func newTitleFixture(t *testing.T) *titleFixture {
	t.Helper()
	root, home := t.TempDir(), t.TempDir()
	s := newSessionTitleSync(root, home)
	if err := s.ensureStateDir(); err != nil {
		t.Fatalf("ensureStateDir: %v", err)
	}
	return &titleFixture{t: t, sync: s, home: home}
}

// mapping plants what the hook writes: a file named for the tab holding kiro's id.
func (f *titleFixture) mapping(tabID, kiroID string) {
	f.t.Helper()
	path := filepath.Join(f.sync.titleStateDir(), tabID)
	if err := os.WriteFile(path, []byte(kiroID+"\n"), 0o600); err != nil {
		f.t.Fatalf("write mapping %s: %v", tabID, err)
	}
}

// session plants a kiro session record under a per-workspace hash directory, which
// is the level the syncer has to scan because the hash is kiro's private business.
func (f *titleFixture) session(hash, kiroID, body string) {
	f.t.Helper()
	dir := filepath.Join(f.home, ".kiro", "sessions", hash, kiroID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		f.t.Fatalf("mkdir session %s: %v", kiroID, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), []byte(body), 0o600); err != nil {
		f.t.Fatalf("write session.json %s: %v", kiroID, err)
	}
}

func titleJSON(title string) string {
	return `{"id":"x","title":` + quote(title) + `,"status":"in_progress"}`
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// TestSessionTitlePushesKiroTitle is the happy path end to end through the two
// files the real system produces.
func TestSessionTitlePushesKiroTitle(t *testing.T) {
	f := newTitleFixture(t)
	f.mapping("tab1", "sess_11111111-2222-3333-4444-555555555555")
	f.session("hash0", "sess_11111111-2222-3333-4444-555555555555",
		titleJSON("Kopia audit: landed, verified, cleaned"))

	set := &fakeSetter{live: []string{"tab1"}}
	f.sync.pass(set)

	want := "tab1=Kopia audit: landed, verified, cleaned"
	if len(set.calls) != 1 || set.calls[0] != want {
		t.Errorf("pushed %v, want exactly [%q]", set.calls, want)
	}
}

// TestSessionTitlePushesOnlyOnChange pins the de-duplication: the poller runs every
// few seconds for the life of a tab, and a title changes a handful of times per
// conversation, so an unchanged title must not call into the manager again.
func TestSessionTitlePushesOnlyOnChange(t *testing.T) {
	f := newTitleFixture(t)
	id := "sess_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	f.mapping("tab1", id)
	f.session("hash0", id, titleJSON("first message verbatim"))

	set := &fakeSetter{live: []string{"tab1"}}
	f.sync.pass(set)
	f.sync.pass(set)
	if len(set.calls) != 1 {
		t.Fatalf("pushed %v, want one push for an unchanged title", set.calls)
	}

	// The agent renames the session mid-conversation: that must reach the tab.
	f.session("hash0", id, titleJSON("Unsticking fleet CI/sync PRs"))
	f.sync.pass(set)
	if len(set.calls) != 2 || set.calls[1] != "tab1=Unsticking fleet CI/sync PRs" {
		t.Errorf("pushed %v, want the updated title as a second push", set.calls)
	}
}

// TestSessionTitleSkipsUnusableTitles pins the cases that must leave the engine's
// automatic name ladder alone rather than overwriting it with something worse.
func TestSessionTitleSkipsUnusableTitles(t *testing.T) {
	cases := map[string]string{
		"kiro placeholder":  titleJSON(placeholderTitle),
		"empty title":       titleJSON(""),
		"whitespace only":   titleJSON("   "),
		"title key absent":  `{"id":"x","status":"in_progress"}`,
		"not json at all":   `this is not json`,
		"json but not JSON": `{`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			f := newTitleFixture(t)
			id := "sess_deadbeef-0000-1111-2222-333333333333"
			f.mapping("tab1", id)
			f.session("hash0", id, body)

			set := &fakeSetter{live: []string{"tab1"}}
			f.sync.pass(set)
			if len(set.calls) != 0 {
				t.Errorf("pushed %v, want nothing pushed", set.calls)
			}
		})
	}
}

// TestSessionTitleNoMappingIsSilent covers the normal pre-first-hook state and the
// state after an operator deletes the hook config: no mapping, no push, no error.
func TestSessionTitleNoMappingIsSilent(t *testing.T) {
	f := newTitleFixture(t)
	// A session record exists but nothing paired it to a tab.
	f.session("hash0", "sess_11111111-2222-3333-4444-555555555555", titleJSON("orphan"))

	set := &fakeSetter{}
	f.sync.pass(set)
	if len(set.calls) != 0 {
		t.Errorf("pushed %v with no mapping present, want nothing", set.calls)
	}
}

// TestSessionTitleForgetsClosedTabs pins the cleanup: a tab closed while the poller
// was reading returns false from the manager, and its mapping file must go so a
// long-lived container does not accumulate dead pairings.
func TestSessionTitleForgetsClosedTabs(t *testing.T) {
	f := newTitleFixture(t)
	id := "sess_11111111-2222-3333-4444-555555555555"
	f.mapping("gonetab", id)
	f.session("hash0", id, titleJSON("a real title"))

	// The tab is still in the manager's list at snapshot time and disappears at the
	// push, which is the within-sweep race this arm exists for -- not the ordinary
	// close, which pass() now reclaims before syncOne is reached at all.
	set := &fakeSetter{missing: map[string]bool{"gonetab": true}, live: []string{"gonetab"}}
	f.sync.pass(set)

	if _, err := os.Stat(filepath.Join(f.sync.titleStateDir(), "gonetab")); !os.IsNotExist(err) {
		t.Errorf("mapping for a closed tab still present (stat err = %v), want it removed", err)
	}
}

// TestSessionTitleReclaimsAMappingWhoseTabIsGone pins pass()'s liveness sweep, which
// is the reclaim path production actually takes: an ordinary close leaves the tab's
// session.json title FROZEN, so syncOne's `s.pushed[tabID] == title` memo returns
// before the SetSessionTitle-false probe and that probe never fires again. The manager
// no longer lists the tab, which is the only signal that does not depend on a title
// still changing. TestSessionTitleForgetsClosedTabs covers the other arm (still listed
// at snapshot time, gone at the push), so without this case deleting the whole
// liveness branch leaves the suite green while the mapping file, its pushed entry and
// its per-tick ReadDir + session.json read survive for the container's life.
func TestSessionTitleReclaimsAMappingWhoseTabIsGone(t *testing.T) {
	f := newTitleFixture(t)
	id := "sess_11111111-2222-3333-4444-555555555555"
	f.mapping("closedtab", id)
	f.session("hash0", id, titleJSON("a real title"))

	// First sweep with the tab live: the title is pushed and memoized, which is the
	// state that used to hide the dead tab from the reclaim.
	set := &fakeSetter{live: []string{"closedtab"}}
	f.sync.pass(set)
	if len(set.calls) != 1 {
		t.Fatalf("first pass pushed %v, want exactly one push before the tab closes", set.calls)
	}

	// The tab closes. The title never changes again, so only the manager's list can
	// report it: the mapping file must go, and no further push may be attempted.
	set.live = nil
	f.sync.pass(set)

	if _, err := os.Stat(filepath.Join(f.sync.titleStateDir(), "closedtab")); !os.IsNotExist(err) {
		t.Errorf("mapping for a tab the manager no longer lists is still present (stat err = %v), want it reclaimed", err)
	}
	if len(set.calls) != 1 {
		t.Errorf("pushed %v after the tab left the manager's list, want no second push: the sweep must reclaim before syncOne runs", set.calls)
	}
	if _, memoized := f.sync.pushed["closedtab"]; memoized {
		t.Error("the pushed memo still holds the reclaimed tab; a recycled id would then be judged unchanged and never pushed")
	}
}

// TestSessionTitleRejectsHostileIdentifiers is the security half for the one
// identifier this package validates: the kiro session id read OUT of a mapping
// file, which a hostile writer chooses freely and which becomes a path component
// under the kiro session store. The tab id needs no predicate — every production
// value is an os.ReadDir basename of the state dir, so it is one path component
// by construction — so only the kiro id is gated at the Go boundary, and that
// gate is checked here independently of the hook's own.
func TestSessionTitleRejectsHostileIdentifiers(t *testing.T) {
	t.Run("kiro id must look like a kiro session id", func(t *testing.T) {
		for _, bad := range []string{
			"../../../etc", "sess_../..", "sess_", "", "notasession",
			"sess_" + strings.Repeat("a", 200), "sess_abc/def",
		} {
			if validKiroSessionID(bad) {
				t.Errorf("validKiroSessionID(%q) = true, want false", bad)
			}
		}
		if !validKiroSessionID("sess_11111111-2222-3333-4444-555555555555") {
			t.Error("a real kiro session id was rejected")
		}
	})
	t.Run("traversal in a mapping file reads nothing", func(t *testing.T) {
		f := newTitleFixture(t)
		f.mapping("tab1", "../../../../etc")
		set := &fakeSetter{live: []string{"tab1"}}
		f.sync.pass(set)
		if len(set.calls) != 0 {
			t.Errorf("pushed %v from a traversal mapping, want nothing", set.calls)
		}
	})
}

// TestSessionTitleBoundsFileReads pins that neither state file can make the server
// allocate without bound: an oversized mapping file is REFUSED at the read
// (atomicfile.ErrFileTooLarge) rather than truncated, and nothing is pushed.
func TestSessionTitleBoundsFileReads(t *testing.T) {
	f := newTitleFixture(t)
	huge := filepath.Join(f.sync.titleStateDir(), "tab1")
	if err := os.WriteFile(huge, []byte(strings.Repeat("a", maxTitleFileBytes*3)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readSmallFile(huge); !errors.Is(err, atomicfile.ErrFileTooLarge) {
		t.Fatalf("readSmallFile(oversized) = %v, want ErrFileTooLarge", err)
	}
	set := &fakeSetter{live: []string{"tab1"}}
	f.sync.pass(set)
	if len(set.calls) != 0 {
		t.Errorf("pushed %v from an oversized mapping, want nothing", set.calls)
	}
}

// TestSessionTitleEnvNamesWhatTheHookReads is the contract between the Go side and
// the shell hook: the hook reads exactly these two variable names, so a rename here
// silently stops every tab from being named. hooks/session-title.sh is the other
// half and this asserts they agree.
func TestSessionTitleEnvNamesWhatTheHookReads(t *testing.T) {
	f := newTitleFixture(t)
	env := f.sync.sessionEnv("tab42")

	want := map[string]string{
		"KWEB_SESSION_ID":      "tab42",
		"KWEB_TITLE_STATE_DIR": f.sync.titleStateDir(),
	}
	got := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("env entry %q is not KEY=VALUE", kv)
		}
		got[k] = v
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("env %s = %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("env has %d entries (%v), want exactly %d", len(got), env, len(want))
	}

	script, err := os.ReadFile("hooks/session-title.sh")
	if err != nil {
		t.Fatalf("read the hook script: %v", err)
	}
	for k := range want {
		if !strings.Contains(string(script), k) {
			t.Errorf("hooks/session-title.sh does not mention %s; the hook and the server disagree on the variable name, so no tab would ever be named", k)
		}
	}
}

// TestSessionTitleHookWriteFormatReachesThePoller is the OTHER half of the
// cross-language contract: TestSessionTitleEnvNamesWhatTheHookReads pins the two
// variable NAMES, this one pins the FILE FORMAT by running the shipped script and
// letting the real poller consume what it wrote. Nothing else executes
// hooks/session-title.sh — every other test fabricates the mapping file itself, so
// without this leg the agreement that the file is named for the tab id and holds a
// bare `sess_...` line is asserted only against the consumer's own idea of it. Both
// sides fail SILENTLY by construction (the hook exits 0 on every failure path
// because a non-zero exit can block the user's prompt, and the poller says nothing
// when the name or location is wrong), so a drift would surface only as tabs
// quietly reverting to the engine's automatic cwd label.
func TestSessionTitleHookWriteFormatReachesThePoller(t *testing.T) {
	sh, err := exec.LookPath("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh on this host: %v", err)
	}
	const kiroID = "sess_0f8fad5b-d9cb-469f-a165-70867728950e"
	const title = "Kopia audit: landed"

	f := newTitleFixture(t)
	// Run the REAL hook the image ships, in the environment the session factory
	// injects, with the payload kiro-cli hands a hook on stdin.
	cmd := exec.Command(sh, "hooks/session-title.sh")
	cmd.Env = append(os.Environ(),
		"KWEB_SESSION_ID=tab42",
		"KWEB_TITLE_STATE_DIR="+f.sync.titleStateDir())
	cmd.Stdin = strings.NewReader(`{"session_id":"` + kiroID + `"}`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook: %v (output %q)", err, out)
	}

	// Seed the kiro session record the poller resolves, then assert the pairing
	// lands: the mapping file the hook chose to write is one the poller finds,
	// reads and believes.
	f.session("hash0", kiroID, titleJSON(title))
	set := &fakeSetter{live: []string{"tab42"}}
	f.sync.pass(set)
	if len(set.calls) != 1 || set.calls[0] != "tab42="+title {
		t.Errorf("the hook's mapping did not reach the poller: got %v, want [%q]", set.calls, "tab42="+title)
	}
}

// TestSessionTitleScansEveryWorkspaceHashDir pins the reason readTitle loops over
// the hash level at all: kiro-cli files each session under a per-workspace hash
// directory, a /config volume accumulates one per workspace path it has ever
// seen, and os.ReadDir returns them sorted -- so a tab's session is routinely NOT
// under the first entry. Every other test in this file plants exactly one hash
// directory holding exactly the session under test, so collapsing the scan to the
// first entry (turning the read-miss continue into a return, or breaking out of
// the loop) keeps the whole suite green while every tab whose session lives under
// a later hash silently keeps the engine's automatic cwd label.
func TestSessionTitleScansEveryWorkspaceHashDir(t *testing.T) {
	f := newTitleFixture(t)
	id := "sess_abcdef01-2345-6789-abcd-ef0123456789"
	f.mapping("tab1", id)
	// Two earlier-sorting hash directories that do not hold this session: one
	// belonging to another workspace, one with no sessions in it at all.
	f.session("hash0", "sess_00000000-0000-0000-0000-000000000000", titleJSON("another workspace"))
	if err := os.MkdirAll(filepath.Join(f.home, ".kiro", "sessions", "hash1"), 0o750); err != nil {
		t.Fatalf("mkdir a hash directory with no sessions in it: %v", err)
	}
	f.session("hash2", id, titleJSON("Kopia audit: landed, verified, cleaned"))

	set := &fakeSetter{live: []string{"tab1"}}
	f.sync.pass(set)

	want := "tab1=Kopia audit: landed, verified, cleaned"
	if len(set.calls) != 1 || set.calls[0] != want {
		t.Errorf("pushed %v, want exactly [%q]: the scan must carry on past a hash directory that does not hold this session", set.calls, want)
	}
}

// TestSessionTitleSanitizesUntrustedTitle pins the rune policy readTitle applies
// before the title reaches either sink it does not own: the slog attribute in
// syncOne and the engine's client title rung, whose own sanitizer drops only C0 +
// DEL. The other title tests cover blank, placeholder, malformed JSON and ordinary
// text, so replacing the sanitizer with a bare strings.TrimSpace keeps them green
// while bidi overrides, C1 controls and line separators from a kiro session record
// reach the browser tab label and the structured log verbatim.
func TestSessionTitleSanitizesUntrustedTitle(t *testing.T) {
	f := newTitleFixture(t)
	id := "sess_11111111-2222-3333-4444-555555555555"
	f.mapping("tab1", id)
	f.session("hash0", id, `{"title":"alpha\u202ebeta\nline\u0085tail"}`)

	set := &fakeSetter{live: []string{"tab1"}}
	f.sync.pass(set)

	const want = "tab1=alpha beta line tail"
	if len(set.calls) != 1 || set.calls[0] != want {
		t.Errorf("pushed %q, want [%q]; browser and log title sinks must not receive bidi, C1, or line-control runes", set.calls, want)
	}
}
