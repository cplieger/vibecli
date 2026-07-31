package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSetter records what the syncer pushed onto the engine's client title rung,
// and can report a session as gone (the manager's false return).
type fakeSetter struct {
	calls   []string // "id=title" in call order, so a repeat push is visible
	missing map[string]bool
}

func (f *fakeSetter) SetSessionTitle(id, title string) bool {
	f.calls = append(f.calls, id+"="+title)
	return !f.missing[id]
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

	set := &fakeSetter{}
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

	set := &fakeSetter{}
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

			set := &fakeSetter{}
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

	set := &fakeSetter{missing: map[string]bool{"gonetab": true}}
	f.sync.pass(set)

	if _, err := os.Stat(filepath.Join(f.sync.titleStateDir(), "gonetab")); !os.IsNotExist(err) {
		t.Errorf("mapping for a closed tab still present (stat err = %v), want it removed", err)
	}
}

// TestSessionTitleRejectsHostileIdentifiers is the security half: both identifiers
// become path components, and the state directory is writable by anything in the
// container, so a traversal attempt must not make the server read outside the
// session tree. Checked at the Go boundary independently of the hook's own guard.
func TestSessionTitleRejectsHostileIdentifiers(t *testing.T) {
	t.Run("tab id with a separator is not read", func(t *testing.T) {
		for _, bad := range []string{"../escape", "a/b", ".", "..", "", strings.Repeat("x", 129)} {
			if validSessionFileName(bad) {
				t.Errorf("validSessionFileName(%q) = true, want false", bad)
			}
		}
		if !validSessionFileName("ok") {
			t.Error("sanity: a plain name must be valid")
		}
	})
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
		set := &fakeSetter{}
		f.sync.pass(set)
		if len(set.calls) != 0 {
			t.Errorf("pushed %v from a traversal mapping, want nothing", set.calls)
		}
	})
}

// TestSessionTitleBoundsFileReads pins that neither state file can make the server
// allocate without bound: a huge mapping file is truncated at the read, and the
// truncated value then fails the session-id shape check.
func TestSessionTitleBoundsFileReads(t *testing.T) {
	f := newTitleFixture(t)
	huge := filepath.Join(f.sync.titleStateDir(), "tab1")
	if err := os.WriteFile(huge, []byte(strings.Repeat("a", maxTitleFileBytes*3)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := readSmallFile(huge)
	if err != nil {
		t.Fatalf("readSmallFile: %v", err)
	}
	if len(raw) > maxTitleFileBytes {
		t.Errorf("read %d bytes, want at most %d", len(raw), maxTitleFileBytes)
	}
	set := &fakeSetter{}
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
