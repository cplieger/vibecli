package main

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/web-terminal-engine/v5/terminal"
)

// fakeSetter records what the syncer pushed onto the engine's client title rung,
// and can report a session as gone (the manager's false return).
type fakeSetter struct {
	calls   []string // "id=title" in call order, so a repeat push is visible
	missing map[terminal.SessionID]bool
	// live is the tab set List reports, i.e. what the engine's session manager
	// still holds. pass() reclaims any mapping whose tab is not in it, so a test
	// that expects a push has to name its tab here.
	live []terminal.SessionID
}

func (f *fakeSetter) SetSessionTitle(id terminal.SessionID, title string) bool {
	f.calls = append(f.calls, string(id)+"="+title)
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
	// The state root is a CHILD of the temp dir, so both levels are created --
	// and mode-tightened -- by ensureStateDir itself: a filesystem whose
	// inheritable ACL widens fresh directories (the ZFS nfs4acl case the
	// production comment measures) then cannot make the fixture's own root read
	// as a pre-existing widened level and refuse every test in this file.
	root, home := filepath.Join(t.TempDir(), "state"), t.TempDir()
	s := newSessionTitleSync(root, home)
	if err := s.ensureStateDir(); err != nil {
		t.Fatalf("ensureStateDir: %v", err)
	}
	return &titleFixture{t: t, sync: s, home: home}
}

// mapping plants what the hook writes: a file named for the tab's TITLE HANDLE,
// holding kiro's id. The handle comes from the real minting path, so a test joins
// the two identities the same way the poller does rather than fabricating a filename
// production would never produce.
func (f *titleFixture) mapping(tabID terminal.SessionID, kiroID string) {
	f.t.Helper()
	path := filepath.Join(f.sync.stateDir, f.handle(tabID))
	if err := os.WriteFile(path, []byte(kiroID+"\n"), 0o600); err != nil {
		f.t.Fatalf("write mapping %s: %v", tabID, err)
	}
}

// handle mints (or returns) one tab's title handle, which is what a test must use to
// name anything in the state directory: the mapping file is named for the handle and
// never for the tab, because a tab id is the /ws capability token.
func (f *titleFixture) handle(tabID terminal.SessionID) string {
	f.t.Helper()
	return titleHandleFor(f.t, f.sync, tabID)
}

// titleHandleFor is the fixture-free form, for the tests that build a syncer directly.
func titleHandleFor(t *testing.T, s *sessionTitleSync, tabID terminal.SessionID) string {
	t.Helper()
	handle, err := s.titleHandle(tabID)
	if err != nil {
		t.Fatalf("mint a title handle for %s: %v", tabID, err)
	}
	return handle
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

// TestEnsureStateDirRefusesOnlyAPreExistingWidenedLevel pins the distinction the
// created flag exists for: a level this process created is tightened to 0700 and
// accepted (a filesystem with an inheritable group-write ACL widens os.Mkdir's
// requested mode, and refusing our own directory would disable tab titles for the
// container's life), while a level that was ALREADY group/other-writable is refused
// -- that refusal is pinned through the gate by
// TestEnableSessionTitlesGatesBothConsumersOnTheVerdict, which plants the same
// widened shape and asserts the verdict withholds both consumers.
func TestEnsureStateDirRefusesOnlyAPreExistingWidenedLevel(t *testing.T) {
	t.Run("a level we created is tightened, not refused", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		s := newSessionTitleSync(root, t.TempDir())
		if err := s.ensureStateDir(); err != nil {
			t.Fatalf("ensureStateDir over a self-created tree: %v", err)
		}
		for _, dir := range []string{root, s.stateDir} {
			fi, err := os.Lstat(dir)
			if err != nil {
				t.Fatalf("lstat %s: %v", dir, err)
			}
			if perm := fi.Mode().Perm(); perm != 0o700 {
				t.Errorf("%s mode = %#o, want 0700: a level we created must be tightened to what was asked for", dir, perm)
			}
		}
	})
	t.Run("a level created off-mode is tightened to 0700", func(t *testing.T) {
		// umask is process-wide: this subtest must NOT call t.Parallel, and it
		// restores the mask before any assertion can fail. A umask of 0o200 makes
		// os.Mkdir(0o700) yield 0o500, which is exactly the shape the created flag
		// exists for -- a level WE created whose mode is not what was asked for --
		// and it is the only seam that reaches the chmod-tighten branch on a
		// filesystem that does not widen modes (the ZFS nfs4acl case the code
		// comment measures). The temp parents are made BEFORE the mask changes, so
		// only the two levels ensureStateDir creates are born off-mode. Without
		// the chmod-tighten branch the levels stay 0500 and this fails.
		parent, home := t.TempDir(), t.TempDir()
		root := filepath.Join(parent, "state")
		s := newSessionTitleSync(root, home)
		old := syscall.Umask(0o200)
		err := s.ensureStateDir()
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("ensureStateDir over a self-created off-mode tree: %v", err)
		}
		for _, dir := range []string{root, s.stateDir} {
			fi, statErr := os.Lstat(dir)
			if statErr != nil {
				t.Fatalf("lstat %s: %v", dir, statErr)
			}
			if perm := fi.Mode().Perm(); perm != 0o700 {
				t.Errorf("%s mode = %#o, want 0700: a level we created off-mode must be tightened", dir, perm)
			}
		}
	})
}

// TestEnsureStateDirRefusesAForeignOwnedLevel pins the ownership arm of the custody
// check, which ensureStateLevel's own comment says nothing else covers: a level at
// mode 0700 that is a real directory passes the type check, the created check and
// the group/other-writable check, so OWNERSHIP is the only thing standing between a
// level another local user controls and pass()/forget() sweeping it with os.ReadDir
// and os.Remove every titlePollInterval. Deleting the two Uid lines compiles and
// leaves the rest of this suite green, because every other level any test builds is
// owned by the test process.
//
// The foreign owner is the point rather than the mode: its holder can rename the
// checked path or replace it with a symlink AFTER the verdict, which is the
// post-check window the mode test cannot see.
//
// Requires the privilege to give a directory away, which this app has by design
// (the image runs as root) and an unprivileged CI runner does not, so the test
// skips there rather than failing for the environment.
func TestEnsureStateDirRefusesAForeignOwnedLevel(t *testing.T) {
	const foreignUID, foreignGID = 65534, 65534 // nobody:nogroup, present on the Debian base

	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("make the level: %v", err)
	}
	// os.Mkdir's mode is a REQUEST -- the same fact ensureStateLevel is built around
	// -- so ASK for the bait mode rather than assuming it: an inheritable group-write
	// ACL widens the created level to 0770 and the fixture stops being bait. Chmod is
	// the call that SETS the mode and it is exact even on the dataset that widens the
	// mkdir (measured: mkdir(0o700) -> 0770, chmod(0o700) -> 0700, and chown leaves
	// the perm bits alone), so this is what keeps the ownership arm RUNNING there
	// instead of skipping past it.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("tighten the level to the bait mode: %v", err)
	}
	if err := os.Chown(root, foreignUID, foreignGID); err != nil {
		t.Skipf("cannot give a directory away here, so a foreign-owned level cannot be built: %v", err)
	}
	// Everything except ownership is exactly what the check wants, so this fixture
	// is only bait if the mode really is 0700 and the path really is a directory.
	fi, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("lstat the level: %v", err)
	}
	if !fi.Mode().IsDir() {
		t.Fatalf("fixture is not a directory (mode %#o): os.Mkdir reported success, so this is a real anomaly rather than an environment limit", fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		// Not a defect in the code under test: the chmod above ASKED for the bait mode
		// and this filesystem still would not store it, and a widened level would be
		// refused for its MODE, so the ownership arm this test exists for would never
		// be the reason it failed. Skip like the Chown guard above rather than
		// reporting the filesystem as a failure of the check. A dataset that merely
		// widens the mkdir does NOT land here -- the chmod covers that one.
		t.Skipf("this filesystem stored mode %#o even after a chmod to 0o700, so a level that passes every check but the ownership one cannot be built here", perm)
	}

	if err := newSessionTitleSync(root, t.TempDir()).ensureStateDir(); err == nil {
		t.Errorf("ensureStateDir accepted a level owned by uid %d; its owner can replace the checked path after the verdict, and pass()/forget() then ReadDir and Remove through whatever is there every tick", foreignUID)
	}
}

// TestEnsureStateDirRefusesAPlantedPath pins the planted-path arm of the custody
// check -- the CWE-59 shape ensureStateDir's comment is mostly about -- and with
// it the load-bearing syscall choice: each level must be inspected with Lstat,
// never Stat. Swapping the two compiles and changes no other test's outcome (the
// widened- and created-level cases never involve a link), while silently
// re-opening the planted-symlink delete loop: Stat follows the link to a
// directory this process owns at mode 0700, every remaining check passes, and
// pass()/forget() then ReadDir and Remove through the link every tick. The
// symlink subtest fails under exactly that swap; the plain-file subtest covers
// the other planted shape at the other level.
func TestEnsureStateDirRefusesAPlantedPath(t *testing.T) {
	t.Run("a symlink planted at the state root is refused, not followed", func(t *testing.T) {
		target := t.TempDir()
		if err := os.Chmod(target, 0o700); err != nil {
			t.Fatalf("chmod target: %v", err)
		}
		root := filepath.Join(t.TempDir(), "state")
		if err := os.Symlink(target, root); err != nil {
			t.Fatalf("plant the symlink: %v", err)
		}
		s := newSessionTitleSync(root, t.TempDir())
		if err := s.ensureStateDir(); err == nil {
			t.Error("ensureStateDir accepted a symlink planted at the state root; pass() and forget() would then ReadDir and Remove through it every tick (the CWE-59 delete loop its own comment describes)")
		}
	})
	t.Run("a plain file planted at the drop directory is refused", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("make the root: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, titleStateDirName), []byte("x"), 0o600); err != nil {
			t.Fatalf("plant the file: %v", err)
		}
		s := newSessionTitleSync(root, t.TempDir())
		if err := s.ensureStateDir(); err == nil {
			t.Error("ensureStateDir accepted a plain file planted at the drop directory")
		}
	})
}

// TestEnforceLevelModeRefusesToRepairThroughAPlantedPath pins the two open flags
// that make repairing a level by NAME safe, neither of which any other test
// reaches: O_NOFOLLOW, so a symlink swapped in after os.Mkdir reported success is
// refused instead of having the mode of its TARGET rewritten to 0700, and
// O_DIRECTORY, so a plain file under the same name is refused rather than
// fchmod'ed. Dropping either flag compiles and changes no other test's outcome --
// every level the suite creates is a real directory this process just made -- while
// handing a local user who wins the boot race a chmod on a path of their choosing,
// the CWE-59 window ensureStateLevel's own comment says the handle-based sequence
// closes.
//
// Each planted case asserts the victim's mode is UNCHANGED, not merely that an
// error came back: an implementation that followed the name and then reported some
// later failure would still have performed the write the refusal exists to prevent,
// and the mode is the only observable that separates the two. The errno is
// deliberately not asserted -- the kernel returns ENOTDIR for a symlink under
// O_DIRECTORY|O_NOFOLLOW but ELOOP without O_DIRECTORY, and both are refusals, so
// pinning one would fail a still-safe implementation.
func TestEnforceLevelModeRefusesToRepairThroughAPlantedPath(t *testing.T) {
	t.Run("a symlink is refused and its target is not chmod'ed", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "victim")
		if err := os.Mkdir(target, 0o750); err != nil {
			t.Fatalf("make the victim directory: %v", err)
		}
		// The mode the filesystem STORED, not the one os.Mkdir asked for: an
		// inheritable group-write ACL widens a created mode (the case
		// ensureStateLevel's own comment measures, 0770 from a 0o700 mkdir on a ZFS
		// nfs4acl dataset), and the property under test is that the victim is
		// UNCHANGED -- a comparison against whatever it started as, never against
		// the literal, or the refusal that WORKED is reported as a repair through
		// the link.
		before, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("lstat the victim before the refusal: %v", err)
		}
		link := filepath.Join(t.TempDir(), "level")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("plant the symlink: %v", err)
		}
		if _, err := enforceLevelMode(link); err == nil {
			t.Error("enforceLevelMode followed a symlink planted at the level; O_NOFOLLOW is what turns that boot race into an error instead of a chmod on a path the attacker chose")
		}
		fi, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("lstat the victim: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != before.Mode().Perm() {
			t.Errorf("the symlink target's mode = %#o, want it untouched at %#o: the repair was applied through the link", perm, before.Mode().Perm())
		}
	})
	t.Run("a plain file is refused and not chmod'ed", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "level")
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatalf("plant the file: %v", err)
		}
		// Same reason as the symlink case: the stored mode is the baseline.
		before, err := os.Lstat(file)
		if err != nil {
			t.Fatalf("lstat the planted file before the refusal: %v", err)
		}
		if _, err := enforceLevelMode(file); err == nil {
			t.Error("enforceLevelMode accepted a plain file as a level; O_DIRECTORY is what refuses it")
		}
		fi, err := os.Lstat(file)
		if err != nil {
			t.Fatalf("lstat the planted file: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != before.Mode().Perm() {
			t.Errorf("the planted file's mode = %#o, want it untouched at %#o", perm, before.Mode().Perm())
		}
	})
	t.Run("a directory this process made is repaired and the stored mode reported", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "level")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("make the level: %v", err)
		}
		stored, err := enforceLevelMode(dir)
		if err != nil {
			t.Fatalf("enforceLevelMode over our own directory: %v", err)
		}
		if stored != 0o700 {
			t.Errorf("reported stored mode = %#o, want 0700: ensureStateLevel's group/other-writable check reads this value, not a fresh stat", stored)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("lstat the level: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("on-disk mode = %#o, want 0700: the repair did not take", perm)
		}
	})
}

// TestEnableSessionTitlesGatesBothConsumersOnTheVerdict pins that ensureStateDir's
// refusal is AUTHORITATIVE rather than merely logged. Both of the subsystem's sinks
// hang off this one call, and a warn-only refusal left both pointed at the rejected
// path: the hook still received WT_TITLE_STATE_DIR (so a directory another local
// user can read discloses tab ids, which are /ws capability tokens) and the poller
// still swept it with os.ReadDir + os.Remove. The nil-env half of the contract is
// pinned downstream by TestChildEnvComposesBothOverlays, which asserts routeDeps
// contributes nothing when sessionTitleEnv is nil.
func TestEnableSessionTitlesGatesBothConsumersOnTheVerdict(t *testing.T) {
	t.Run("a refused level yields no env and no poller", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatalf("plant the root: %v", err)
		}
		// Pre-existing and group-writable: somebody else's shape, which
		// ensureStateDir refuses because its owner can swap the checked path.
		if err := os.Chmod(root, 0o770); err != nil {
			t.Fatalf("widen the planted root: %v", err)
		}
		env := enableSessionTitles(newSessionTitleSync(root, t.TempDir()))
		if env != nil {
			t.Error("a refused state dir still produced a session title environment; the hook would write into the rejected path, and a non-nil verdict is also what starts the poller whose os.ReadDir + os.Remove sweep is the delete loop the verification exists to prevent")
		}
	})
	t.Run("a verified level wires both", func(t *testing.T) {
		s := newSessionTitleSync(filepath.Join(t.TempDir(), "state"), t.TempDir())
		env := enableSessionTitles(s)
		if env == nil {
			t.Fatal("a verified state dir produced no session title environment: no hook could pair a tab with its kiro session, and the poller -- gated on this same value -- would never run")
		}
		got := env("tab1")
		for _, want := range []string{"WT_TITLE_HANDLE=" + titleHandleFor(t, s, "tab1"), "WT_TITLE_STATE_DIR=" + s.stateDir} {
			if !slices.Contains(got, want) {
				t.Errorf("session title env = %v, want it to carry %q", got, want)
			}
		}
	})
}

// TestSessionTitlePushesKiroTitle is the happy path end to end through the two
// files the real system produces.
func TestSessionTitlePushesKiroTitle(t *testing.T) {
	f := newTitleFixture(t)
	f.mapping("tab1", "sess_11111111-2222-3333-4444-555555555555")
	f.session("hash0", "sess_11111111-2222-3333-4444-555555555555",
		titleJSON("Kopia audit: landed, verified, cleaned"))

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)

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

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)
	f.sync.pass(t.Context(), set)
	if len(set.calls) != 1 {
		t.Fatalf("pushed %v, want one push for an unchanged title", set.calls)
	}

	// The agent renames the session mid-conversation: that must reach the tab.
	f.session("hash0", id, titleJSON("Unsticking fleet CI/sync PRs"))
	f.sync.pass(t.Context(), set)
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

			set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
			f.sync.pass(t.Context(), set)
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
	f.sync.pass(t.Context(), set)
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
	// Capture the handle BEFORE the sweep: forget drops it from the index, so
	// asking afterwards would mint a fresh one and stat a name that was never
	// written -- an assertion that passes however broken the reclaim is.
	mappingPath := filepath.Join(f.sync.stateDir, f.handle("gonetab"))

	// The tab is still in the manager's list at snapshot time and disappears at the
	// push, which is the within-sweep race this arm exists for -- not the ordinary
	// close, which pass() now reclaims before syncOne is reached at all.
	set := &fakeSetter{missing: map[terminal.SessionID]bool{"gonetab": true}, live: []terminal.SessionID{"gonetab"}}
	f.sync.pass(t.Context(), set)

	if _, err := os.Stat(mappingPath); !os.IsNotExist(err) {
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
	// Captured before the reclaim: the handle leaves the index with the mapping, so
	// resolving it afterwards would mint a new one and stat a path nothing wrote.
	mappingPath := filepath.Join(f.sync.stateDir, f.handle("closedtab"))

	// First sweep with the tab live: the title is pushed and memoized, which is the
	// state that used to hide the dead tab from the reclaim.
	set := &fakeSetter{live: []terminal.SessionID{"closedtab"}}
	f.sync.pass(t.Context(), set)
	if len(set.calls) != 1 {
		t.Fatalf("first pass pushed %v, want exactly one push before the tab closes", set.calls)
	}

	// The tab closes. The title never changes again, so only the manager's list can
	// report it: the mapping file must go, and no further push may be attempted.
	set.live = nil
	f.sync.pass(t.Context(), set)

	if _, err := os.Stat(mappingPath); !os.IsNotExist(err) {
		t.Errorf("mapping for a tab the manager no longer lists is still present (stat err = %v), want it reclaimed", err)
	}
	if len(set.calls) != 1 {
		t.Errorf("pushed %v after the tab left the manager's list, want no second push: the sweep must reclaim before syncOne runs", set.calls)
	}
	if _, memoized := f.sync.pushed["closedtab"]; memoized {
		t.Error("the pushed memo still holds the reclaimed tab; a recycled id would then be judged unchanged and never pushed")
	}
}

// TestSessionTitleReclaimsAMappingWhoseHandleThisProcessNeverMinted pins the arm the
// handle reshape made necessary: entry names are TITLE HANDLES and handles live only
// in this process's index, so a file left behind by a PREVIOUS server run in the same
// container (/tmp is container-layer and survives a restart) resolves to no tab at all
// -- a state the old tab-id key could not produce, because a stale tab id was simply
// not live. Every other test in this file names its entries through the fixture's
// handle helper, so all of them take the `known` path and this arm reports zero hits
// in the coverage profile; dropping its forget call leaves the whole suite green while
// every previous run's mappings stay on disk for the container's life, growing the
// per-tick ReadDir, and every failure path here is Debug-only so nothing says so.
func TestSessionTitleReclaimsAMappingWhoseHandleThisProcessNeverMinted(t *testing.T) {
	f := newTitleFixture(t)
	// A well-formed handle from a previous run: the right alphabet and length, just
	// not in this process's index.
	const stale = "0123456789abcdef0123456789abcdef"
	stalePath := filepath.Join(f.sync.stateDir, stale)
	if err := os.WriteFile(stalePath, []byte("sess_11111111-2222-3333-4444-555555555555\n"), 0o600); err != nil {
		t.Fatalf("plant a previous run's mapping: %v", err)
	}
	// A live tab whose own handle IS known, so the sweep is not trivially empty and
	// an over-broad reclaim shows up as a missing push.
	kiroID := "sess_22222222-3333-4444-5555-666666666666"
	f.mapping("tab1", kiroID)
	f.session("hash0", kiroID, titleJSON("a real title"))
	own := filepath.Join(f.sync.stateDir, f.handle("tab1"))

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Errorf("a mapping named for a handle this process never minted survives (stat err = %v); every previous run's files would stay on disk for the container's life, growing the per-tick ReadDir", err)
	}
	if _, err := os.Stat(own); err != nil {
		t.Errorf("stat the live tab's own mapping = %v, want the unknown-handle reclaim to leave it alone", err)
	}
	if len(set.calls) != 1 {
		t.Errorf("pushes = %v, want exactly the live tab's title: an unknown handle resolves to no tab, so nothing may be pushed for it", set.calls)
	}
}

// TestSessionTitleKeepsTheHooksInFlightTemps pins the reclaim's POPULATION: the hook
// writes each mapping through a dot-prefixed temp (".<handle>.$$" in
// hooks/session-title.sh) and renames it into place, so a temp caught mid-write by a
// sweep has to survive. Without the dot skip the reclaim deletes it, the hook's mv then
// fails, `|| rm -f` runs, and that prompt's re-point is lost with no record anywhere.
// No other test in this file plants a dot-prefixed entry, so deleting the skip keeps the
// whole suite green.
func TestSessionTitleKeepsTheHooksInFlightTemps(t *testing.T) {
	f := newTitleFixture(t)
	tmp := filepath.Join(f.sync.stateDir, "."+f.handle("tab1")+".4242")
	if err := os.WriteFile(tmp, []byte("sess_11111111-2222-3333-4444-555555555555\n"), 0o600); err != nil {
		t.Fatalf("plant an in-flight hook temp: %v", err)
	}

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)

	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("stat the hook's in-flight temp = %v, want it left in place: the reclaim must not race the hook's rename", err)
	}
	if len(set.calls) != 0 {
		t.Errorf("pushed %v from a temp file, want nothing: a temp is not a tab mapping", set.calls)
	}
}

// TestSessionTitleRejectsHostileIdentifiers is the security half for the one
// identifier this package validates: the kiro session id read OUT of a mapping
// file, which a hostile writer chooses freely and which becomes a path component
// under the kiro session store. The mapping file's NAME needs no predicate — since
// the handle reshape it is a title handle, every production value is an os.ReadDir
// basename of the state dir, and pass() resolves it through tabForHandle before
// anything reads it — so only the kiro id is gated at the Go boundary, and that
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
		set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
		f.sync.pass(t.Context(), set)
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
	huge := filepath.Join(f.sync.stateDir, f.handle("tab1"))
	if err := os.WriteFile(huge, []byte(strings.Repeat("a", maxTitleFileBytes*3)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readSmallFile(t.Context(), huge); !errors.Is(err, atomicfile.ErrFileTooLarge) {
		t.Fatalf("readSmallFile(t.Context(), oversized) = %v, want ErrFileTooLarge", err)
	}
	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)
	if len(set.calls) != 0 {
		t.Errorf("pushed %v from an oversized mapping, want nothing", set.calls)
	}
}

// TestSessionTitleEnvNamesWhatTheHookReads is the contract between the Go side and
// the shell hook: the hook reads exactly these two variable names, so a rename here
// silently stops every tab from being named. hooks/session-title.sh is the other
// half and this asserts they agree. The handle VALUE is the subject of
// TestSessionTitleNeverExposesTheTabIDAsTheJoinKey; this leg pins the names, and
// that the value shipped under the handle name is the one the syncer will join on.
func TestSessionTitleEnvNamesWhatTheHookReads(t *testing.T) {
	f := newTitleFixture(t)
	env := f.sync.sessionEnv("tab42")

	want := map[string]string{
		"WT_TITLE_HANDLE":    f.handle("tab42"),
		"WT_TITLE_STATE_DIR": f.sync.stateDir,
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
	// The retired name must not linger anywhere in the hook: it used to carry the
	// tab id, so a leftover reference would either be dead or -- worse -- a second
	// writer naming files after a /ws capability token again.
	if strings.Contains(string(script), "WT_SESSION_ID") {
		t.Error("hooks/session-title.sh still references WT_SESSION_ID; the tab id is the /ws capability token and no longer travels to the hook")
	}
}

// TestSessionTitleHookWriteFormatReachesThePoller is the OTHER half of the
// cross-language contract: TestSessionTitleEnvNamesWhatTheHookReads pins the two
// variable NAMES, this one pins the FILE FORMAT by running the shipped script and
// letting the real poller consume what it wrote. Nothing else executes
// hooks/session-title.sh — every other test fabricates the mapping file itself, so
// without this leg the agreement that the file is named for the tab's TITLE HANDLE
// and holds a bare `sess_...` line is asserted only against the consumer's own idea
// of it. Both sides fail SILENTLY by construction (the hook exits 0 on every failure
// path because a non-zero exit can block the user's prompt, and the poller says
// nothing when the name or location is wrong), so a drift would surface only as tabs
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
	// injects -- built by the real sessionEnv, so the handle the hook names the file
	// after is the one the poller will look for -- with the payload kiro-cli hands a
	// hook on stdin.
	cmd := exec.Command(sh, "hooks/session-title.sh")
	cmd.Env = append(os.Environ(), f.sync.sessionEnv("tab42")...)
	cmd.Stdin = strings.NewReader(`{"session_id":"` + kiroID + `"}`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook: %v (output %q)", err, out)
	}

	// The hook chose the filename from its environment; assert it chose the handle,
	// because a poller that scans by handle and a hook that writes by anything else
	// agree on nothing and say nothing about it.
	if _, err := os.Stat(filepath.Join(f.sync.stateDir, f.handle("tab42"))); err != nil {
		t.Fatalf("stat the mapping the hook wrote = %v, want it named for the tab's title handle", err)
	}

	// Seed the kiro session record the poller resolves, then assert the pairing
	// lands: the mapping file the hook chose to write is one the poller finds,
	// reads and believes.
	f.session("hash0", kiroID, titleJSON(title))
	set := &fakeSetter{live: []terminal.SessionID{"tab42"}}
	f.sync.pass(t.Context(), set)
	if len(set.calls) != 1 || set.calls[0] != "tab42="+title {
		t.Errorf("the hook's mapping did not reach the poller: got %v, want [%q]", set.calls, "tab42="+title)
	}
}

// TestSessionTitleNeverExposesTheTabIDAsTheJoinKey pins the invariant the whole
// handle mechanism exists for, in all three places this feature writes an
// identifier: the hook's environment, the mapping FILENAME (a directory under
// world-writable /tmp that neither this app nor kiro-cli owns), and every log
// attribute. A tab id is the /ws attach+resume capability token -- the credential
// the engine attaches and resumes with -- so none of the three may carry it, whole
// or truncated.
//
// Every other test in this file names state-directory entries through the fixture's
// handle helper, so re-keying the mapping on the tab id (the shape this replaced)
// leaves the entire suite green while a live credential is written to disk under a
// name any local reader can list, and logged again on every adopted title.
//
// slog.Default is process-global, so this test must not call t.Parallel.
func TestSessionTitleNeverExposesTheTabIDAsTheJoinKey(t *testing.T) {
	// Shaped like the engine's own newSessionID (128-bit crypto-random hex), which
	// is what makes a substring search for it meaningful.
	const tabID terminal.SessionID = "3f7a1c9e5b2d4086af13e7c05d9b2846"
	const kiroID = "sess_11111111-2222-3333-4444-555555555555"

	f := newTitleFixture(t)

	// 1. The child environment. sessionEnv mints on first use, so ask it first and
	// resolve the handle afterwards.
	env := f.sync.sessionEnv(tabID)
	handle := f.handle(tabID)
	for _, kv := range env {
		if strings.Contains(kv, string(tabID)) {
			t.Errorf("child env entry %q carries the tab id; that value is the /ws attach+resume capability token", kv)
		}
	}
	if !slices.Contains(env, "WT_TITLE_HANDLE="+handle) {
		t.Fatalf("child env = %v, want it to carry WT_TITLE_HANDLE=%s", env, handle)
	}
	if handle == string(tabID) {
		t.Fatal("the title handle IS the tab id; minting exists precisely so it is not")
	}
	// 128 bits of hex, the engine's own shape: unguessable on purpose even though
	// the handle authenticates nothing, so forgery resistance is unchanged.
	if raw, err := hex.DecodeString(handle); err != nil || len(raw) != 16 {
		t.Errorf("handle %q decoded to %d bytes (err %v), want 16 bytes of hex", handle, len(raw), err)
	}

	// 2. The mapping filename.
	f.mapping(tabID, kiroID)
	f.session("hash0", kiroID, titleJSON("Kopia audit: landed"))
	entries, err := os.ReadDir(f.sync.stateDir)
	if err != nil {
		t.Fatalf("read the state dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("state dir holds %d entries, want exactly the one mapping", len(entries))
	}
	if name := entries[0].Name(); name != handle {
		t.Errorf("mapping file is named %q, want the title handle %q: a filename in this directory must not be a capability token", name, handle)
	}

	// 3. Every log attribute. The sync path emits TWO records about a mapping -- the
	// adopted title and an unusable mapping -- and the reclaim emits none, because
	// forget logs only when os.Remove fails. The third pass below is therefore here to
	// prove the reclaim adds no record naming the tab id, not to observe one.
	var logged strings.Builder
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	set := &fakeSetter{live: []terminal.SessionID{tabID}}
	f.sync.pass(t.Context(), set)
	f.mapping(tabID, "not-a-session-id")
	f.sync.pass(t.Context(), set)
	set.live = nil
	f.sync.pass(t.Context(), set)

	out := logged.String()
	if strings.Contains(out, string(tabID)) {
		t.Errorf("the tab id reached a log attribute whole; output was:\n%s", out)
	}
	// The truncating form too: `terminal.LogID(tabID)` is what a reviewer re-adding
	// a "session" attribute would reach for, and 8 hex characters of a capability
	// token is still 8 characters of one.
	if truncated := terminal.LogID(tabID); strings.Contains(out, truncated) {
		t.Errorf("the tab id reached a log attribute as %q; the handle is the diagnostic identifier for this feature, output was:\n%s", truncated, out)
	}
	if !strings.Contains(out, handle) {
		t.Errorf("no log record named the title handle, so a mapping is undiagnosable; output was:\n%s", out)
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

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)

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

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)

	const want = "tab1=alpha beta line tail"
	if len(set.calls) != 1 || set.calls[0] != want {
		t.Errorf("pushed %q, want [%q]; browser and log title sinks must not receive bidi, C1, or line-control runes", set.calls, want)
	}
}

// TestSessionTitleClearsTheRungWhenTheTabIsRepointed pins the /chat and /tangent
// switch: the hook re-points a live tab from one kiro session to another and the new
// conversation has no usable title yet. Without the clear the tab keeps displaying the
// PREVIOUS conversation's title -- forever if the new session never gains one --
// because the engine retains clientTitle until something replaces it. This is the only
// input that distinguishes the mapping-identity memo from the title-only memo it
// replaced, so without this case the whole re-point branch can be deleted and every
// other title test stays green.
func TestSessionTitleClearsTheRungWhenTheTabIsRepointed(t *testing.T) {
	f := newTitleFixture(t)
	const first = "sess_11111111-2222-3333-4444-555555555555"
	const second = "sess_99999999-8888-7777-6666-555555555555"
	f.mapping("tab1", first)
	f.session("hash0", first, titleJSON("the first conversation"))

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)
	if want := "tab1=the first conversation"; len(set.calls) != 1 || set.calls[0] != want {
		t.Fatalf("first pass pushed %v, want [%q]", set.calls, want)
	}

	// The hook re-points the tab. The new session's record exists but holds kiro's own
	// placeholder, which readTitle reads as "no title" -- the case that used to strand
	// the first conversation's title on the tab.
	f.mapping("tab1", second)
	f.session("hash0", second, titleJSON(placeholderTitle))
	f.sync.pass(t.Context(), set)

	if want := "tab1="; len(set.calls) != 2 || set.calls[1] != want {
		t.Fatalf("after the re-point pushed %v, want a clearing %q so the tab falls back to the engine's automatic ladder", set.calls, want)
	}
	if _, memoized := f.sync.pushed["tab1"]; memoized {
		t.Error("the memo still holds the cleared tab; the new conversation's first real title would then be judged against the old one's")
	}

	// The new conversation gains a real title: it must still be pushed after the clear
	// dropped the tab's memo entry.
	f.session("hash0", second, titleJSON("the second conversation"))
	f.sync.pass(t.Context(), set)
	if want := "tab1=the second conversation"; len(set.calls) != 3 || set.calls[2] != want {
		t.Errorf("after the new session gained a title pushed %v, want %q", set.calls, want)
	}
}

// TestSessionTitleRepointWithATitleReplacesWithoutClearing pins the OTHER half of the
// re-point branch, the one this cycle reshaped: when the new conversation already has a
// usable title the tab is re-labelled in ONE store and never blanked in between (the
// intermediate clear was removed from this arm), and the memo follows the new kiro
// session even when the two titles are identical strings -- otherwise the memo keeps
// pointing at the previous conversation forever.
func TestSessionTitleRepointWithATitleReplacesWithoutClearing(t *testing.T) {
	f := newTitleFixture(t)
	const first = "sess_11111111-2222-3333-4444-555555555555"
	const second = "sess_99999999-8888-7777-6666-555555555555"
	const third = "sess_44444444-3333-2222-1111-000000000000"
	f.mapping("tab1", first)
	f.session("hash0", first, titleJSON("the first conversation"))

	set := &fakeSetter{live: []terminal.SessionID{"tab1"}}
	f.sync.pass(t.Context(), set)

	// The hook re-points the tab to a conversation that ALREADY has its title.
	f.mapping("tab1", second)
	f.session("hash0", second, titleJSON("the second conversation"))
	f.sync.pass(t.Context(), set)

	if len(set.calls) != 2 || set.calls[0] != "tab1=the first conversation" || set.calls[1] != "tab1=the second conversation" {
		t.Fatalf("pushed %v, want the two titles and no blanking push between them: a usable title replaces the rung in one store", set.calls)
	}
	if got := f.sync.pushed["tab1"]; got.kiroID != second {
		t.Fatalf("memo kiroID = %q, want %q", got.kiroID, second)
	}

	// A re-point whose new title happens to equal the old one still has to be pushed and
	// memoized: the memo is keyed on the PAIR, so a title-only comparison would strand it
	// on the previous session's id.
	f.mapping("tab1", third)
	f.session("hash0", third, titleJSON("the second conversation"))
	f.sync.pass(t.Context(), set)

	if len(set.calls) != 3 || set.calls[2] != "tab1=the second conversation" {
		t.Errorf("pushed %v, want a third push: a re-point is a change even when the title text is unchanged", set.calls)
	}
	if got := f.sync.pushed["tab1"]; got.kiroID != third {
		t.Errorf("memo kiroID = %q, want %q: the memo must follow the re-point", got.kiroID, third)
	}
}
