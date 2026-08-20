package main

// Tab titles come from kiro-cli's OWN session record, not from watching what the
// user typed.
//
// The engine can derive a name from the input byte stream (terminal.WithInputTitle),
// and this app used to ask for it. That deriver has to reconstruct a submitted line
// from raw bytes, which means modelling the agent shell's composer: every key that
// discards text (Escape dismissing the slash-command menu, Ctrl-U, Ctrl-W) is a key
// it must know about, or the abandoned text fuses onto the next prompt and the tab
// is named `/I see a new /title command` for the rest of its life. It is a guess by
// construction.
//
// kiro-cli already knows the answer. Every v3 session has a session.json whose
// `title` starts as the first user message and is REPLACED when the agent calls its
// session-information tool, which yields an outcome label a byte-stream deriver
// could never produce ("Kopia audit: landed, verified, cleaned" rather than the
// opening request). Reading that is exact where the deriver was approximate, and it
// improves as the conversation goes.
//
// The hard part is only ever the MAPPING: which kiro session belongs to which tab.
// kiro-cli does not accept a session id from its environment (KIRO_SESSION_ID is a
// variable it EXPORTS to hook processes, not one it reads), and nothing in the
// process tree or the session file names the tab. So the mapping is established the
// one way kiro offers authoritatively: a hook. This app mints a per-tab TITLE
// HANDLE and injects it as WT_TITLE_HANDLE into each tab's child environment, and
// a kiro-cli hook — which inherits that environment and is handed kiro's own
// session_id on stdin — writes the pair into a state directory this app watches. A
// hook re-affirms it on every prompt, so a session switch inside one tab (/chat,
// /tangent) re-points the mapping instead of stranding it.
//
// The join key is that handle and NOT the tab id, which is the one thing in this
// file worth understanding before changing it: a tab id IS the /ws capability token
// the engine attaches and resumes with, so keying on it wrote a live credential into
// a filename under a directory this app does not own and into every diagnostic about
// the feature. sessionEnv says why the handle keeps the session id's unguessability
// while carrying none of its authority.
//
// Deliberately NOT read from the log or the process tree. The KAS log does name its
// session, but it names every OTHER session the tab ever touched too (a resume, a
// subagent), and choosing among them is a guess with a wrong answer available —
// exactly the class of failure this change exists to remove. The hook is told.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/runesafe/v2"
	"github.com/cplieger/web-terminal-engine/v4/terminal"
)

const (
	// titleStateDirName is the directory under the app's state root where hooks
	// drop one file per tab, named for that tab's TITLE HANDLE (not its id) and
	// containing kiro's session id.
	titleStateDirName = "session-titles"

	// titlePollInterval is how often each mapped tab's session.json is re-read. A
	// title changes at most a few times per conversation, so this is deliberately
	// slow relative to the engine's 250ms status sweep: the sweep drives a live
	// activity dot, this drives a label. The cost is one small JSON read per live
	// tab per tick.
	titlePollInterval = 2 * time.Second

	// maxTitleFileBytes bounds a read of either state file. Both are small and
	// machine-written; anything larger is a corrupt or hostile file, not a title.
	maxTitleFileBytes = 64 * 1024

	// placeholderTitle is kiro's own "no title yet" value. Pushing it would
	// replace the engine's automatic name with something less informative, so it
	// is treated as absent.
	placeholderTitle = "New Session"

	// titleStateRoot is the container-local root for the tab -> kiro-session
	// mapping files. Deliberately NOT under /config: a mapping is meaningful only
	// while its tab is live, and this app persists no session state, so carrying
	// these across a container recreation would only leave stale pairings behind.
	titleStateRoot = "/tmp/web-terminal-kiro"
)

// titleSetter is the engine surface this needs: the session manager's CLIENT title
// rung (below a user's pin, above the automatic cwd/process ladder). An interface
// rather than the concrete manager so the poller is testable without a PTY.
type titleSetter interface {
	SetSessionTitle(id, title string) bool
	// List is the live-tab set, and it is the only reclaim signal that does not
	// depend on a title still CHANGING. A closed tab's kiro-cli is gone, so its
	// session.json title is frozen, so syncOne's memo returns early and the
	// SetSessionTitle-false probe below it is never reached again.
	List() []terminal.SessionInfo
}

// pushedTitle is one tab's last push: which kiro session it came from, and the
// title text itself.
type pushedTitle struct {
	kiroID string
	title  string
}

// sessionTitleSync pushes kiro-cli session titles onto the engine's client rung.
//
// It owns no session list of its own: the set of live tabs is the engine's, and the
// set of MAPPED tabs is whatever the hook has written into stateDir. A tab with no
// mapping yet (the hook has not run, or the user removed the hook config) simply
// has no client title, and the engine's automatic ladder still names it — the
// feature degrades to the old cwd label rather than to a blank one.
type sessionTitleSync struct {
	// Field order is load-bearing for govet fieldalignment: the maps go first so
	// the pointer-bearing prefix ends as early as possible, and the pointer-free
	// mutex goes last. Re-check the linter when adding a field.
	//
	// pushed remembers the kiro session and title last pushed per tab, keyed by
	// TAB ID. Keeping the mapping identity lets syncOne clear the old
	// conversation's title when a hook re-points the tab before the new session
	// has a usable title. Touched only by the poller goroutine, so it needs no
	// lock; the two handle maps below do, because sessionEnv mints from whichever
	// goroutine is creating a session.
	pushed map[string]pushedTitle
	// handleByTab and tabByHandle are the same per-tab title handle indexed both
	// ways: sessionEnv needs tab -> handle to tell the hook what to report under,
	// and the poller needs handle -> tab to turn a mapping FILENAME back into the
	// session it may push a title to. Both entries are dropped together when a
	// mapping is reclaimed, so a long-lived container does not accumulate handles
	// for tabs that closed hours ago. Guarded by mu.
	//
	// One residue is accepted rather than swept: a tab whose hook never ran (the
	// operator removed the hook config, or the tab closed before its first prompt)
	// produces no mapping file, so nothing reclaims its two entries and they are
	// held for the container's life -- tens of bytes per tab ever opened. Do NOT
	// "fix" that by sweeping the index against pass()'s liveness snapshot: the
	// handle is minted while the session factory builds the child environment,
	// which is BEFORE the manager lists the session, so a tick landing in that
	// window would drop a live tab's handle while the hook keeps writing under it
	// -- and since the hook holds the handle in its environment for the tab's whole
	// life, the server could never re-learn it and that tab would never be named
	// again. A permanent per-tab failure is worse than a bounded retention.
	handleByTab map[string]string
	tabByHandle map[string]string
	stateDir    string
	// sessionsRoot is kiro-cli's session store ($HOME/.kiro/sessions). Sessions
	// live one level down under a per-workspace hash directory, so a session id
	// is resolved by scanning that one level rather than by recomputing the hash
	// (which is kiro's private business).
	sessionsRoot string
	// mu guards handleByTab and tabByHandle only. sessionEnv runs on the
	// goroutine creating a session and the poller runs on its own ticker, so the
	// handle index is the one piece of this type's state two goroutines touch.
	mu sync.Mutex
}

// newSessionTitleSync builds the syncer. stateRoot is the app's writable state
// root, home is the HOME whose .kiro/sessions tree kiro-cli writes. The session
// manager is not a constructor argument because the route wiring needs this
// object's sessionEnv before registerRoutes has returned a manager; it is handed
// to Run instead.
func newSessionTitleSync(stateRoot, home string) *sessionTitleSync {
	if home == "" {
		// filepath.Join("", ".kiro", "sessions") is RELATIVE, so every title read
		// would resolve against the server's cwd and fail. The feature degrades to
		// the engine's automatic name ladder either way; the point of the line is
		// that the degradation says why. Named env only, no value, like every other
		// startup warning in main.go.
		slog.Warn("HOME is empty; kiro-cli session titles cannot be resolved and tabs keep the automatic name ladder",
			"hint", "the image sets HOME=/config/home; a compose environment entry that blanks it disables tab titles")
	}
	return &sessionTitleSync{
		stateDir:     filepath.Join(stateRoot, titleStateDirName),
		sessionsRoot: filepath.Join(home, ".kiro", "sessions"),
		pushed:       make(map[string]pushedTitle),
		handleByTab:  make(map[string]string),
		tabByHandle:  make(map[string]string),
	}
}

// sessionEnv returns the two variables one tab's kiro-cli process needs so a hook
// can report its kiro session id. This is the whole mechanism on the child's side:
// the TITLE HANDLE it should report under, and where to write it.
//
// The handle is minted here instead of shipping the tab id, and that substitution is
// the whole point of this shape. A tab id IS a capability: it is the credential /ws
// attaches and resumes a session with, which is why the engine refuses to log one
// whole and why this app already keeps it out of the access log
// (WithTemplatePathsUnder) and out of heuristic caches (the engine's
// terminal.MountSessionRoutes applies its own withNoStore to the session REST
// handler). Shipping it
// to a hook made a live capability token the filename of a file in a directory this
// app does not own, and the identifier in every diagnostic about the feature — the
// one egress that policy never reached.
//
// A handle is 128 bits of crypto-random hex with no relation to the session id and no
// authentication meaning anywhere in this app or the engine: leaking one discloses
// nothing and cannot be replayed against /ws. It is unguessable ON PURPOSE even so,
// and that is not belt-and-braces — it is what keeps forgery resistance exactly where
// it was, because a local writer still cannot name a mapping file for a tab whose
// handle it does not know. So do NOT "simplify" this to a counter or a tab index: that
// keeps the confidentiality win and throws the integrity one away.
//
// A mint failure degrades like every other failure on this path: no variables, so the
// hook no-ops (it needs both) and the tab keeps the engine's automatic name ladder.
func (s *sessionTitleSync) sessionEnv(tabID string) []string {
	handle, err := s.titleHandle(tabID)
	if err != nil {
		slog.Warn("session title: could not mint a title handle; this tab keeps the automatic name ladder",
			"error", err)
		return nil
	}
	return []string{
		"WT_TITLE_HANDLE=" + handle,
		"WT_TITLE_STATE_DIR=" + s.stateDir,
	}
}

// titleHandle returns this tab's title handle, minting one the first time the tab
// needs it. Reusing an existing handle keeps the invariant the poller relies on --
// one live mapping file per tab -- so a second call for the same tab cannot strand a
// file under an abandoned name.
func (s *sessionTitleSync) titleHandle(tabID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if handle, ok := s.handleByTab[tabID]; ok {
		return handle, nil
	}
	handle, err := newTitleHandle()
	if err != nil {
		return "", err
	}
	s.handleByTab[tabID] = handle
	s.tabByHandle[handle] = tabID
	return handle, nil
}

// tabForHandle resolves a mapping FILENAME back to the tab it belongs to. A handle
// this process never minted -- a file left behind by a previous server run, or one a
// local writer invented -- names no tab, and the caller then treats it exactly as an
// unknown tab id was treated when the file was named for the tab: reclaimed.
func (s *sessionTitleSync) tabForHandle(handle string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tabID, ok := s.tabByHandle[handle]
	return tabID, ok
}

// dropHandle forgets one handle and its tab, both directions at once. Called from
// forget, which is the single place a mapping stops being live.
func (s *sessionTitleSync) dropHandle(handle string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tabID, ok := s.tabByHandle[handle]; ok {
		delete(s.handleByTab, tabID)
		delete(s.tabByHandle, handle)
	}
}

// newTitleHandle mints one tab's title handle: 128 bits of crypto-random hex, the
// same shape as the engine's own newSessionID and for the same unguessability
// reason, but carrying none of its meaning -- it authenticates nothing and no
// request ever presents it. See sessionEnv for why the strength is kept anyway.
func newTitleHandle() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ensureStateDir creates the hook's drop directory. Called once at start: the hook
// runs as a child of a tab and should not have to create it (a hook that fails is
// silent by design, so a missing directory would be an invisible failure).
//
// Each level is created and then VERIFIED rather than left to os.MkdirAll, because
// titleStateRoot is a compile-time constant inside a world-writable sticky
// directory. MkdirAll cannot tell "I created this" from "something was already
// here": it stats the path, FOLLOWS a symlink, finds a directory and returns nil.
// Everything downstream follows that link too — os.ReadDir in pass(), os.Remove in
// forget(), and readSmallFile's O_NOFOLLOW, which guards the final component and
// never the directory it sits in — so a symlink planted at either level by a local
// user who wins the boot race turns the stale-mapping reclaim into a delete loop
// over the link's target, every titlePollInterval (CWE-59, CWE-377). Lstat is what
// distinguishes the two cases. A group/other-writable level is refused for the same
// reason: a directory somebody else can write is one they can swap the child into
// at any time, so checking its type alone would be a check with a race under it.
//
// Fail closed, and cheap to fail: main warns and tabs degrade to the engine's
// automatic name ladder, which is what every other failure on this path does.
func (s *sessionTitleSync) ensureStateDir() error {
	// filepath.Dir is titleStateRoot: stateDir is always <root>/titleStateDirName.
	for _, dir := range []string{filepath.Dir(s.stateDir), s.stateDir} {
		if err := ensureStateLevel(dir); err != nil {
			return err
		}
	}
	return nil
}

// ensureStateLevel creates ONE level of the drop directory and verifies it. Split
// out of ensureStateDir so each level's create-then-verify reads as one unit.
func ensureStateLevel(dir string) error {
	created := true
	if err := os.Mkdir(dir, 0o700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		created = false
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.Mode().IsDir() {
		return fmt.Errorf("%s is not a directory: a symlink or a plain file is planted at that path", dir)
	}
	// OWNERSHIP, not just mode. A level somebody else owns is one they can rename
	// or replace AFTER this check returns — including replacing it with a symlink,
	// which pass()'s os.ReadDir and forget()'s os.Remove then follow — so mode
	// 0755 owned by another uid passes every other check here and still leaves the
	// planted-path delete loop reachable. Both levels are checked, not only the
	// leaf: the owner of the root controls the child's name.
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s ownership could not be verified", dir)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, want server uid %d: its owner could replace the checked path", dir, stat.Uid, os.Geteuid())
	}
	perm := fi.Mode().Perm()
	if created && perm != 0o700 {
		// os.Mkdir's mode is a REQUEST. A filesystem carrying an inheritable
		// group-write ACL widens what we just created whatever was asked for
		// (measured on a ZFS nfs4acl dataset: 0770 from a 0o700 mkdir, and a child
		// of an already-0700 parent is 0770 too, so tightening the parent does not
		// cover it), and the check below would then refuse this process's OWN
		// directory with nothing retrying. Chmod is the only call that SETS the
		// mode, and only a re-stat turns "I asked for 0700" into "it is 0700" —
		// the same postcondition entrypoint.sh's secure_tools_dir asserts.
		//
		// atomicfile.EnforceMode owns that sequence now, and owns it on an open
		// HANDLE: fchmod then fstat on one descriptor, which no rename can
		// redirect, where the chmod-path-then-lstat-path this replaces could
		// chmod one directory and certify another. Repairing is safe here and only
		// here: os.Mkdir reported that we created this path, /tmp's sticky bit
		// stops another user removing our root, and the child's parent is our own
		// 0700 directory, so no other writer has ever held a name to swap in. A
		// PRE-EXISTING level is never repaired, so the refusal below still fires
		// on exactly the planted shape the guard is for.
		if perm, err = enforceLevelMode(dir); err != nil {
			return err
		}
	}
	// WRITE bits only, deliberately, and this is the place a future reader will
	// want to tighten to 0o077. Do not: listing this directory yields TITLE
	// HANDLES, and a handle authenticates nothing and cannot be replayed against
	// /ws (sessionEnv), so read access here discloses no secret and a wider mask
	// would protect nothing. It WAS a disclosure while the entry names were
	// session ids, and minting a handle is what removed it rather than a sixth
	// permission check. What survives is the INTEGRITY half, which is exactly what
	// this check is: a directory somebody else can write is one they can swap the
	// child into after the check returns, turning the titlePollInterval reclaim
	// sweep into a delete loop over a planted link's target.
	if perm&0o022 != 0 {
		return fmt.Errorf("%s is group/other-writable (%#o): another user could replace the mapping files under it", dir, perm)
	}
	return nil
}

// enforceLevelMode repairs the mode of a level this process just created and
// proves the repair took, returning the permission bits the filesystem actually
// stored. atomicfile.EnforceMode is the postcondition: fchmod then fstat on ONE
// descriptor, so no rename between the two calls can make it certify a
// directory other than the one it changed. A filesystem that will not store 0700
// exactly is REPORTED rather than refused: ensureStateLevel's write-bits check
// owns that verdict, so a widening that adds only read or execute bits stays
// acceptable exactly as it was before the postcondition moved onto a handle.
//
// O_NOFOLLOW is what makes opening by name safe here. The path was just created
// by os.Mkdir, so a symlink at the final component means someone replaced it in
// the interval; refusing to follow turns that race into an error instead of a
// chmod applied to the link's target. O_DIRECTORY refuses a plain file for the
// same reason, and both together mean the descriptor EnforceMode acts on is a
// directory this process made.
func enforceLevelMode(dir string) (os.FileMode, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	stored, err := atomicfile.EnforceMode(f, 0o700)
	if errors.Is(err, atomicfile.ErrModeNotStored) {
		// The filesystem would not store the mode we asked for, which is a REPORT
		// rather than a reason to refuse: EnforceMode still reports the mode it read
		// back, and ensureStateLevel's WRITE-bits check is the policy that decides
		// whether it is acceptable (see the "WRITE bits only, deliberately" paragraph
		// there). Refusing on exact inequality would tighten this path to 0o077, which
		// that paragraph forbids, and would turn a mount whose chmod cannot store 0700
		// into tab titles silently off at every boot.
		//
		// A CHMOD that cannot store the mode is the case, and it is not the
		// creation-widening one this repair exists for: EnforceMode fchmods before it
		// fstats, and the fchmod is exact even on the dataset that widens the mkdir
		// (measured on the ZFS nfs4acl dataset cited above: mkdir(0o700) -> 0770,
		// chmod(0o700) -> 0700, so EnforceMode returns nil there), and /tmp -- where
		// titleStateRoot lives -- is exact both ways. So no filesystem measured here
		// reaches this branch; it is the fail-open side of a policy the paragraph below
		// states, not a path with a witness.
		return stored.Perm(), nil
	}
	if err != nil {
		return 0, err
	}
	return stored.Perm(), nil
}

// enableSessionTitles verifies the hook's drop directory and returns the wiring
// that verdict authorizes: the per-session environment the session factory injects
// into each tab's kiro-cli, or nil when the directory was refused. Nil IS the
// verdict, and both consumers read that one value -- the session factory skips the
// injection (routes.go childEnv already treats nil as this function's off-shape)
// and the composition root skips the poller. One value rather than a value plus a
// bool, so "inject but do not poll" -- hooks writing mapping files nothing reads or
// reclaims -- cannot be expressed at all.
//
// ensureStateDir's whole job is to REFUSE a planted, foreign-owned or
// group/other-writable state directory, and a refusal that only warned left both
// sinks pointed at the refused path regardless: the hook still received
// WT_TITLE_STATE_DIR and wrote a file per tab into it (under a name whose owner
// can swap the directory out from under the next read), and pass()/forget() still
// followed it with os.ReadDir and os.Remove every titlePollInterval — the delete
// loop over a planted link's target that ensureStateDir's comment describes. The
// verdict is now authoritative, so a refusal degrades exactly as documented: no
// injection, no poller, and every tab keeps the engine's automatic name ladder.
//
// The refusal stands on INTEGRITY alone. It used to carry a confidentiality reason
// too — the entry names were tab ids, i.e. /ws attach+resume capability tokens, so a
// readable directory disclosed live credentials — and that reason is gone because
// the names are title handles now (see sessionEnv). The integrity reason is
// unaffected by that change and is sufficient on its own.
func enableSessionTitles(titles *sessionTitleSync) func(tabID string) []string {
	if err := titles.ensureStateDir(); err != nil {
		slog.Warn("session title state dir refused; tabs keep the automatic name ladder and the title poller stays off",
			"dir", titles.stateDir, "error", err,
			"hint", "kiro-cli session titles need this directory owned by the server uid, not group/other-writable, and writable by the hook it seeds")
		return nil
	}
	return titles.sessionEnv
}

// Run polls until ctx is cancelled. One goroutine for every tab, not one per tab:
// the work is a directory listing plus a small read per mapped tab, so a single
// ticker is both simpler and cheaper than a per-session watcher.
func (s *sessionTitleSync) Run(ctx context.Context, mgr titleSetter) {
	t := time.NewTicker(titlePollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pass(mgr)
		}
	}
}

// pass runs one sweep: reclaim every mapping whose tab is gone, then for the ones
// that remain, read that kiro session's title and push it if it changed.
func (s *sessionTitleSync) pass(mgr titleSetter) {
	entries, err := os.ReadDir(s.stateDir)
	if err != nil {
		// No ErrNotExist carve-out. The poller runs ONLY on enableSessionTitles'
		// true verdict, which ensureStateDir has already satisfied, so the
		// pre-first-hook state the carve-out was written for cannot reach this
		// goroutine. Within its lifetime an absent directory means something
		// REMOVED it -- titleStateRoot is under /tmp, writable by every terminal
		// session in this container -- after which this sweep no-ops forever and
		// nothing here re-creates it. That was the one arm on this path with no
		// record at any level.
		slog.Debug("session title: state dir unreadable; no tab can be mapped until it is back",
			"dir", s.stateDir, "error", err)
		return
	}
	// One liveness snapshot per sweep rather than per entry: the manager takes its
	// own lock, and every mapping is then judged against the same picture.
	live := make(map[string]struct{}, len(entries))
	for _, info := range mgr.List() {
		live[info.ID] = struct{}{}
	}
	// How many live tabs this sweep actually resolved a mapping for. Zero while
	// tabs exist is the whole feature being dead, which is what the record below
	// exists to say.
	mapped := 0
	// How many entries this sweep actually TREATED as mappings: the same population
	// the loop below judges, which is what makes it the discriminator the zero-mapping
	// record claims it is. len(entries) is the raw ReadDir snapshot and counts the two
	// shapes the sweep never considers a mapping -- a subdirectory, and the hook's
	// dot-prefixed write temp, which an interrupted hook leaves behind indefinitely --
	// so reporting it says "names are present, none of them belong to a live tab" for
	// a directory holding nothing but one stale temp.
	mappingEntries := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			// The hook's in-flight write temps (".<handle>.$$", renamed into place by
			// hooks/session-title.sh) share this directory. They are never a live tab's
			// name, so the reclaim below would delete one mid-write and silently drop
			// that prompt's mapping update. A dot prefix is the hook's documented temp
			// shape and no title handle starts with a dot, so skipping costs nothing.
			continue
		}
		mappingEntries++
		// The entry name is a TITLE HANDLE, so the tab it belongs to is resolved in
		// memory before anything is judged against it. An unknown handle names no
		// tab -- a file left by a previous server run (handles live only in this
		// process), or one a local writer invented -- and is reclaimed on the spot,
		// which is what an unknown tab id got when the file was named for the tab.
		tabID, known := s.tabForHandle(e.Name())
		if !known {
			s.forget(e.Name())
			continue
		}
		if _, ok := live[tabID]; !ok {
			// The tab is gone. Reclaim now rather than waiting for a title change
			// that will never come: syncOne's memo short-circuits before the
			// SetSessionTitle-false probe, so an ordinary close (stable title)
			// used to keep its mapping file, its pushed entry and its per-tick
			// I/O for the container's life.
			delete(s.pushed, tabID)
			s.forget(e.Name())
			continue
		}
		mapped++
		s.syncOne(mgr, e.Name(), tabID)
	}
	if mapped == 0 && len(live) > 0 {
		// Tabs exist and not one of them has a kiro session mapping, so every one
		// keeps the engine's automatic cwd ladder. state_entries is the discriminator
		// and it counts what this sweep TREATED as a mapping: 0 means no mapping-shaped
		// name was there at all -- either the hook never wrote (its config was replaced,
		// its fixed session_id extraction no longer matches kiro-cli's payload, or hooks
		// are not firing) or it wrote only the dot-prefixed temps an interrupted hook
		// never renamed -- and non-zero means every name present belongs to no live tab.
		// Debug, not Warn: a tab still at the device-flow sign-in legitimately has no
		// kiro session until the user confirms the code in their own browser, so a
		// default-level record would fire on ordinary first-boot sign-ins.
		slog.Debug("session title: no live tab has a kiro session mapping; every tab keeps the automatic name ladder",
			"live_tabs", len(live), "state_entries", mappingEntries, "dir", s.stateDir,
			"hint", "kiro-cli's SessionStart/UserPromptSubmit hooks write these files; check $HOME/.kiro/hooks/web-terminal-session-title.json and hooks/session-title.sh. A tab still at the device-flow sign-in has no kiro session yet, so this is expected until chat starts.")
	}
}

// syncOne maps one tab to its kiro session and pushes that session's title. handle
// is the mapping file's name; tabID is what pass() resolved it to and the only one
// of the two the engine understands.
func (s *sessionTitleSync) syncOne(mgr titleSetter, handle, tabID string) {
	kiroID, ok := s.readMapping(handle)
	if !ok {
		return
	}
	previous, pushed := s.pushed[tabID]
	repointed := pushed && previous.kiroID != kiroID
	title, ok := s.readTitle(kiroID)
	if !ok {
		if !repointed {
			return
		}
		// The hook re-pointed this tab to a conversation with no usable title yet.
		// Clear the old client rung so the tab falls through to the engine's
		// automatic name ladder instead of displaying the previous conversation's
		// title. Only this arm needs a clear: a usable title REPLACES the rung in
		// one store below, so the old title is never observable in between.
		if !mgr.SetSessionTitle(tabID, "") {
			s.forget(handle)
		}
		delete(s.pushed, tabID)
		return
	}
	if pushed && !repointed && previous.title == title {
		return
	}
	// A false return means the tab closed between this sweep's liveness snapshot
	// and this push. pass() reclaims every mapping whose tab was already gone at
	// snapshot time, so this arm is the within-sweep race backstop only.
	if !mgr.SetSessionTitle(tabID, title) {
		delete(s.pushed, tabID)
		s.forget(handle)
		return
	}
	s.pushed[tabID] = pushedTitle{kiroID: kiroID, title: title}
	// The title is kiro-cli's verbatim copy of the user's first message, so this
	// record carries its LENGTH rather than its text -- the same treatment run's
	// chat_args_count line, newSessionFactory's WithCommandLogValue redaction and
	// newStatusClassifier's fingerprint already give their respective values. The
	// tab id is deliberately ABSENT: it is the
	// /ws attach+resume capability token, and the title handle names this mapping
	// for an operator reading the log without disclosing one (see sessionEnv). Do
	// not add the session id back beside the handle -- truncated or otherwise --
	// or the whole point of keying on a handle is lost. kiro_session is kiro-cli's
	// own internal id, not a network capability, so it stays whole.
	slog.Debug("session title: adopted kiro session title",
		"title_handle", handle, "kiro_session", kiroID,
		"title_runes", utf8.RuneCountInString(title))
}

// readMapping reads the handle -> kiro-session-id file the hook wrote. The value is
// validated as a kiro session id rather than trusted: it is interpolated into a
// filesystem path below, and the file is written by a shell hook this app does not
// execute itself.
func (s *sessionTitleSync) readMapping(handle string) (string, bool) {
	raw, err := readSmallFile(filepath.Join(s.stateDir, handle))
	if err != nil {
		// pass() just enumerated this entry, so any failure here is abnormal --
		// EACCES, a refused symlink/FIFO (OpenRegular), an oversized file -- not
		// absence. Same ErrNotExist carve-out as the directory-level reads.
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Debug("session title: mapping file unreadable",
				"title_handle", handle, "error", err)
		}
		return "", false
	}
	id := strings.TrimSpace(string(raw))
	if !validKiroSessionID(id) {
		if id != "" {
			slog.Debug("session title: mapping file holds no usable session id",
				"title_handle", handle)
		}
		return "", false
	}
	return id, true
}

// readTitle finds a kiro session's record under the per-workspace hash level and
// returns its title. Absent, placeholder, and blank titles all read as "no title".
func (s *sessionTitleSync) readTitle(kiroID string) (string, bool) {
	hashDirs, err := os.ReadDir(s.sessionsRoot)
	if err != nil {
		// A missing tree is the normal state before kiro-cli has written its first
		// session, so it stays silent (same rule as pass()'s state dir). Anything
		// else -- a wrong HOME, EACCES on the volume, ENOTDIR -- kills every tab's
		// title with no record at any level, which is the one failure a log-only
		// diagnosis path cannot have.
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Debug("session title: kiro session store unreadable",
				"dir", s.sessionsRoot, "error", err)
		}
		return "", false
	}
	for _, hd := range hashDirs {
		if !hd.IsDir() {
			continue
		}
		if title, settled := s.titleFromRecord(hd.Name(), kiroID); settled {
			return title, title != ""
		}
	}
	return "", false
}

// titleFromRecord reads one candidate session.json and reports whether it SETTLED
// the lookup. A session id lives under exactly one hash directory, so once the
// record has been reached at all its contents are the answer -- a corrupt or
// title-less record settles the lookup as "no title" rather than sending the scan
// on to the remaining directories. A record that could not be READ at all -- absent,
// or unreadable for the abnormal reasons logged below -- is the miss that keeps
// scanning. An empty returned title means "no usable title", which is why
// readTitle derives its own ok from the string rather than from a third result.
func (s *sessionTitleSync) titleFromRecord(hashDir, kiroID string) (string, bool) {
	raw, err := readSmallFile(filepath.Join(s.sessionsRoot, hashDir, kiroID, "session.json"))
	if err != nil {
		// ENOENT is the normal miss (the session lives under one hash dir);
		// anything else -- EACCES, a refused symlink/FIFO, an oversized
		// record -- silently kills this tab's title, the failure class the
		// ReadDir comment in readTitle says a log-only diagnosis path cannot have.
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Debug("session title: session.json unreadable",
				"kiro_session", kiroID, "error", err)
		}
		return "", false
	}
	var rec struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		slog.Debug("session title: session.json is not decodable",
			"kiro_session", kiroID, "error", err)
		return "", true
	}
	// One rune policy for untrusted upstream text (runesafe). This title is
	// kiro-cli's record of the user's first message verbatim, or a label the
	// agent produced from tool output, and it reaches two sinks this function
	// does not own: the slog attribute in syncOne, and the engine's client
	// title rung, whose sanitizeTitle drops only C0 + DEL -- so C1 controls,
	// Unicode Bidi_Control and U+2028/29 reach the browser tab label. The
	// single-line preset is the right one for a label sink, and sanitizing
	// BEFORE the trim matters: unsafe runes become spaces, so a control-only
	// title collapses to "" and is correctly read as "no title".
	title := strings.TrimSpace(runesafe.SanitizeSingleLine(rec.Title))
	if title == placeholderTitle {
		return "", true
	}
	return title, true
}

// forget removes a mapping whose tab no longer exists and drops that tab's handle
// from the in-memory index, so a long-lived container accumulates neither files nor
// handles for tabs that closed hours ago. handle is one path component by
// construction: every caller takes it from an os.ReadDir entry of stateDir, whose
// Name is a single basename and never "." or "..".
func (s *sessionTitleSync) forget(handle string) {
	s.dropHandle(handle)
	if err := os.Remove(filepath.Join(s.stateDir, handle)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Debug("session title: could not drop a stale mapping",
			"title_handle", handle, "error", err)
	}
}

// readSmallFile reads at most maxTitleFileBytes from one of the two state files.
// atomicfile.OpenRegular is the library's own open-a-file-in-a-directory-others-
// can-write sequence -- O_NOFOLLOW (a symlink under the name is refused, not
// followed), O_NONBLOCK (a planted FIFO is refused instead of blocking this
// goroutine in open(2)) and a stat of the OPEN HANDLE rather than of the pathname
// a second time -- and ReadBoundedFile applies the byte bound to that same
// descriptor, refusing a larger file with ErrFileTooLarge rather than truncating
// it. Both files are small and machine-written, and both callers treat any error
// as "no usable value", so refusing is the same outcome as the old truncation
// with none of the three details to re-derive.
func readSmallFile(path string) ([]byte, error) {
	f, _, err := atomicfile.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	return atomicfile.ReadBoundedFile(context.Background(), f, maxTitleFileBytes)
}

// validKiroSessionID gates the id read out of a mapping file before it becomes a
// path component. kiro-cli's v3 ids are "sess_" followed by a UUID; requiring the
// prefix keeps a malformed or hostile file from pointing the read anywhere else.
func validKiroSessionID(id string) bool {
	const prefix = "sess_"
	if !strings.HasPrefix(id, prefix) || len(id) > 128 {
		return false
	}
	rest := id[len(prefix):]
	if rest == "" {
		return false
	}
	for i := range len(rest) {
		c := rest[i]
		switch {
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}
