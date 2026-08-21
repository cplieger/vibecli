package main

// Tab titles come from kiro-cli's OWN session record, not from watching what the user
// typed. Do NOT re-add terminal.WithInputTitle: reconstructing a submitted line from raw
// bytes means modelling the agent shell's composer, and every discard key it does not know
// about (Escape, Ctrl-U, Ctrl-W) fuses abandoned text onto the next prompt for the tab's
// life. The mapping is established the one way kiro offers authoritatively — a hook, which
// inherits WT_TITLE_HANDLE and is handed kiro's session_id on stdin — and NOT from the KAS
// log or the process tree, which can reach a session id and can reach the WRONG one.

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

	"github.com/cplieger/atomicfile/v3"
	"github.com/cplieger/runesafe/v2"
	"github.com/cplieger/web-terminal-engine/v5/terminal"
)

const (
	// titleStateDirName is the directory under the app's state root where hooks drop one
	// file per tab, named for that tab's TITLE HANDLE (not its id).
	titleStateDirName = "session-titles"

	// titlePollInterval is how often each mapped tab's session.json is re-read. A title
	// changes at most a few times per conversation, so this is deliberately slow relative
	// to the engine's 250ms status sweep: that sweep drives a live activity dot, this
	// drives a label.
	titlePollInterval = 2 * time.Second

	// maxTitleFileBytes bounds a read of either state file. Both are small and
	// machine-written; anything larger is a corrupt or hostile file, not a title.
	maxTitleFileBytes = 64 * 1024

	// placeholderTitle is kiro's own "no title yet" value. Pushing it would replace the
	// engine's automatic name with something less informative, so it is treated as absent.
	placeholderTitle = "New Session"

	// titleStateRoot is container-local, deliberately NOT under /config: a mapping is
	// meaningful only while its tab is live, so carrying these across a container
	// recreation would only leave stale pairings behind.
	titleStateRoot = "/tmp/web-terminal-kiro"
)

// titleSetter is the engine surface this needs: the session manager's CLIENT title rung
// (below a user's pin, above the automatic cwd/process ladder). An interface rather than
// the concrete manager so the poller is testable without a PTY.
type titleSetter interface {
	SetSessionTitle(id terminal.SessionID, title string) bool
	// List is the live-tab set, and the only reclaim signal that does not depend on a
	// title still CHANGING: a closed tab's kiro-cli is gone, so its session.json title is
	// frozen, so syncOne's memo returns early and the SetSessionTitle-false probe below it
	// is never reached again.
	List() []terminal.SessionInfo
}

// pushedTitle is one tab's last push: which kiro session it came from, and the title text.
type pushedTitle struct {
	kiroID string
	title  string
}

// sessionTitleSync pushes kiro-cli session titles onto the engine's client rung.
//
// It owns no session list of its own: the set of live tabs is the engine's, and the set of
// MAPPED tabs is whatever the hook has written into stateDir. A tab with no mapping yet
// simply has no client title, and the engine's automatic ladder still names it — so the
// feature degrades to the old cwd label rather than to a blank one.
type sessionTitleSync struct {
	// Field order is load-bearing for govet fieldalignment: the maps go first so the
	// pointer-bearing prefix ends as early as possible, and the pointer-free mutex goes
	// last. Re-check the linter when adding a field.
	//
	// pushed keeps the kiro session and title last pushed per tab, keyed by TAB ID; the
	// mapping identity lets syncOne clear the old conversation's title when a hook re-points
	// a tab. Touched only by the poller goroutine, so it needs no lock.
	pushed map[terminal.SessionID]pushedTitle
	// handleByTab and tabByHandle are the same per-tab title handle indexed both ways:
	// sessionEnv needs tab -> handle, the poller needs handle -> tab.
	//
	// One residue is accepted rather than swept: a tab whose hook never ran produces no
	// mapping file, so nothing reclaims its two entries. Do NOT "fix" that by sweeping the
	// index against pass()'s liveness snapshot — the handle is minted BEFORE the manager
	// lists the session, so a tick in that window would drop a LIVE tab's handle while the
	// hook keeps writing under it, and the server could never re-learn it.
	handleByTab map[terminal.SessionID]string
	tabByHandle map[string]terminal.SessionID
	stateDir    string
	// sessionsRoot is kiro-cli's session store ($HOME/.kiro/sessions). Sessions live one
	// level down under a per-workspace hash directory, so a session id is resolved by
	// scanning that one level rather than by recomputing the hash (kiro's private business).
	sessionsRoot string
	// mu guards handleByTab and tabByHandle only, the one piece of this type's state two
	// goroutines touch.
	mu sync.Mutex
}

// newSessionTitleSync builds the syncer. stateRoot is the app's writable state root, home
// is the HOME whose .kiro/sessions tree kiro-cli writes. The session manager is not a
// constructor argument because the route wiring needs this object's sessionEnv before
// registerRoutes has returned a manager; it is handed to Run instead.
func newSessionTitleSync(stateRoot, home string) *sessionTitleSync {
	if home == "" {
		// filepath.Join("", ".kiro", "sessions") is RELATIVE, so every title read would
		// resolve against the server's cwd and fail. The feature degrades to the automatic
		// name ladder either way; the point of the line is that the degradation says why.
		slog.Warn("HOME is empty; kiro-cli session titles cannot be resolved and tabs keep the automatic name ladder",
			"hint", "the image sets HOME=/config/home; a compose environment entry that blanks it disables tab titles")
	}
	return &sessionTitleSync{
		stateDir:     filepath.Join(stateRoot, titleStateDirName),
		sessionsRoot: filepath.Join(home, ".kiro", "sessions"),
		pushed:       make(map[terminal.SessionID]pushedTitle),
		handleByTab:  make(map[terminal.SessionID]string),
		tabByHandle:  make(map[string]terminal.SessionID),
	}
}

// sessionEnv returns the two variables one tab's kiro-cli process needs so a hook can
// report its kiro session id: the TITLE HANDLE to report under, and where to write it.
//
// The handle is minted instead of shipping the tab id, and that substitution is the whole
// point of this shape: a tab id IS a capability — the credential /ws attaches and resumes
// with — so shipping it made a live token the filename of a file in a directory this app
// does not own. It carries no authentication meaning but is unguessable even so, because
// that is what keeps forgery resistance where it was.
func (s *sessionTitleSync) sessionEnv(tabID terminal.SessionID) []string {
	handle, err := s.titleHandle(tabID)
	if err != nil {
		slog.Warn("session title: could not mint a title handle; this tab keeps the automatic name ladder",
			"error", err)
		return nil
	}
	return []string{
		// These two KEEP the WT_ prefix while every operator knob lost it (LISTEN_ADDR,
		// LOG_LEVEL, WORK_DIR, …). The knobs are read from the server's own environment,
		// where the prefix only leaked an internal component name at an operator who has
		// no reason to know a library called web-terminal-engine serves their HTTP. These
		// are INJECTED into a PTY child's environment, which the user's shell shares with
		// everything else the system, kiro-cli and the user's own profile set — so the
		// prefix is namespacing that earns its keep, and a bare TITLE_HANDLE would be a
		// collision waiting to happen. Same reasoning as the entrypoint's WT_SESSION_PATH.
		"WT_TITLE_HANDLE=" + handle,
		"WT_TITLE_STATE_DIR=" + s.stateDir,
	}
}

// titleHandle returns this tab's title handle, minting one the first time the tab needs it.
// Reusing an existing handle keeps the invariant the poller relies on — one live mapping
// file per tab — so a second call cannot strand a file under an abandoned name.
func (s *sessionTitleSync) titleHandle(tabID terminal.SessionID) (string, error) {
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

// tabForHandle resolves a mapping FILENAME back to the tab it belongs to. A handle this
// process never minted — a file left behind by a previous server run, or one a local writer
// invented — names no tab, and the caller then reclaims it.
func (s *sessionTitleSync) tabForHandle(handle string) (terminal.SessionID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tabID, ok := s.tabByHandle[handle]
	return tabID, ok
}

// dropHandle forgets one handle and its tab, both directions at once. Called from forget,
// which is the single place a mapping stops being live.
func (s *sessionTitleSync) dropHandle(handle string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tabID, ok := s.tabByHandle[handle]; ok {
		delete(s.handleByTab, tabID)
		delete(s.tabByHandle, handle)
	}
}

// newTitleHandle mints one tab's title handle: 128 bits of crypto-random hex, the same
// shape as the engine's own session id and for the same unguessability reason, but carrying
// none of its meaning — it authenticates nothing and no request ever presents it.
func newTitleHandle() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ensureStateDir creates the hook's drop directory, once at start: the hook runs as a child
// of a tab and should not have to create it, since a hook that fails is silent by design.
//
// Each level is created and then VERIFIED rather than left to os.MkdirAll, because
// titleStateRoot is a compile-time constant inside a world-writable sticky directory.
// MkdirAll cannot tell "I created this" from "something was already here": it FOLLOWS a
// symlink and returns nil, and everything downstream follows that link too, so a planted
// symlink turns the reclaim sweep into a delete loop (CWE-59, CWE-377). Lstat separates them.
func (s *sessionTitleSync) ensureStateDir() error {
	// filepath.Dir is titleStateRoot: stateDir is always <root>/titleStateDirName.
	for _, dir := range []string{filepath.Dir(s.stateDir), s.stateDir} {
		if err := ensureStateLevel(dir); err != nil {
			return err
		}
	}
	return nil
}

// ensureStateLevel creates ONE level of the drop directory and verifies it. Split out of
// ensureStateDir so each level's create-then-verify reads as one unit.
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
	// OWNERSHIP, not just mode. A level somebody else owns is one they can rename or
	// replace AFTER this check returns — including with a symlink, which pass()'s ReadDir
	// and forget()'s Remove then follow — so mode 0755 owned by another uid passes every
	// other check here and still leaves the planted-path delete loop reachable. Both levels
	// are checked, not only the leaf: the owner of the root controls the child's name.
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s ownership could not be verified", dir)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, want server uid %d: its owner could replace the checked path", dir, stat.Uid, os.Geteuid())
	}
	perm := fi.Mode().Perm()
	if created && perm != 0o700 {
		// os.Mkdir's mode is a REQUEST. A filesystem carrying an inheritable group-write ACL
		// widens what we just created whatever was asked for (measured on a ZFS nfs4acl
		// dataset: 0770 from a 0o700 mkdir), and the check below would then refuse this
		// process's OWN directory with nothing retrying.
		//
		// Repairing is safe here and only here: os.Mkdir reported that we created this path,
		// /tmp's sticky bit stops another user removing our root, and the child's parent is
		// our own 0700 directory. A PRE-EXISTING level is never repaired.
		if perm, err = enforceLevelMode(dir); err != nil {
			return err
		}
	}
	// WRITE bits only, deliberately, and this is the place a future reader will want to
	// tighten to 0o077. Do not: listing this directory yields TITLE HANDLES, which
	// authenticate nothing and cannot be replayed against /ws, so read access discloses no
	// secret. What survives is the INTEGRITY half: a directory somebody else can write is
	// one they can swap the child into after the check returns, turning the reclaim sweep
	// into a delete loop over a planted link's target.
	if perm&0o022 != 0 {
		return fmt.Errorf("%s is group/other-writable (%#o): another user could replace the mapping files under it", dir, perm)
	}
	return nil
}

// enforceLevelMode repairs the mode of a level this process just created and proves the
// repair took, returning the permission bits the filesystem actually stored.
// atomicfile.EnforceMode is the postcondition: fchmod then fstat on ONE descriptor, so no
// rename between the two calls can make it certify a directory other than the one it
// changed. A filesystem that will not store 0700 exactly is REPORTED rather than refused;
// ensureStateLevel's write-bits check owns that verdict. O_NOFOLLOW is what makes opening by
// name safe: the path was just created, so a symlink at the final component means someone
// replaced it in the interval.
func enforceLevelMode(dir string) (os.FileMode, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	stored, err := atomicfile.EnforceMode(f, 0o700)
	if errors.Is(err, atomicfile.ErrModeNotStored) {
		// The filesystem would not store the mode we asked for, which is a REPORT rather than
		// a reason to refuse: ensureStateLevel's WRITE-bits check decides whether the stored
		// mode is acceptable. Refusing on exact inequality would tighten this path to 0o077,
		// which that check forbids, and would turn a mount whose chmod cannot store 0700 into
		// tab titles silently off at every boot. No filesystem measured here reaches this
		// branch — the fchmod is exact even on the dataset that widens the mkdir.
		return stored.Perm(), nil
	}
	if err != nil {
		return 0, err
	}
	return stored.Perm(), nil
}

// enableSessionTitles verifies the hook's drop directory and returns the wiring that verdict
// authorizes: the per-session environment injected into each tab's kiro-cli, or nil when the
// directory was refused.
//
// Nil IS the verdict, and both consumers read that one value — one value rather than a value
// plus a bool, so "inject but do not poll" cannot be expressed at all. A refusal that only
// WARNED left both sinks pointed at the refused path: the hook still received
// WT_TITLE_STATE_DIR, and pass()/forget() still followed it with ReadDir and Remove.
func enableSessionTitles(titles *sessionTitleSync) func(tabID terminal.SessionID) []string {
	if err := titles.ensureStateDir(); err != nil {
		slog.Warn("session title state dir refused; tabs keep the automatic name ladder and the title poller stays off",
			"dir", titles.stateDir, "error", err,
			"hint", "kiro-cli session titles need this directory owned by the server uid, not group/other-writable, and writable by the hook it seeds")
		return nil
	}
	return titles.sessionEnv
}

// Run polls until ctx is cancelled. ONE goroutine for every tab, not one per tab: the work
// is a directory listing plus a small read per mapped tab, so a single ticker is both
// simpler and cheaper than a per-session watcher.
func (s *sessionTitleSync) Run(ctx context.Context, mgr titleSetter) {
	t := time.NewTicker(titlePollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.pass(ctx, mgr)
		}
	}
}

// pass runs one sweep: reclaim every mapping whose tab is gone, then for the ones that
// remain, read that kiro session's title and push it if it changed.
func (s *sessionTitleSync) pass(ctx context.Context, mgr titleSetter) {
	entries, err := os.ReadDir(s.stateDir)
	if err != nil {
		// No ErrNotExist carve-out. The poller runs ONLY on enableSessionTitles' true
		// verdict, which ensureStateDir has already satisfied, so the pre-first-hook state
		// such a carve-out was written for cannot reach this goroutine. Within its lifetime
		// an absent directory means something REMOVED it — titleStateRoot is under /tmp,
		// writable by every terminal session in this container — after which this sweep
		// no-ops forever and nothing re-creates it.
		slog.Debug("session title: state dir unreadable; no tab can be mapped until it is back",
			"dir", s.stateDir, "error", err)
		return
	}
	// One liveness snapshot per sweep rather than per entry: the manager takes its own
	// lock, and every mapping is then judged against the same picture.
	live := make(map[terminal.SessionID]struct{}, len(entries))
	for _, info := range mgr.List() {
		live[info.ID] = struct{}{}
	}
	mapped := 0
	// How many entries this sweep actually TREATED as mappings, which is what makes it the
	// discriminator the zero-mapping record claims it is. len(entries) is the raw ReadDir
	// snapshot and counts the two shapes the sweep never considers a mapping — a
	// subdirectory, and the hook's dot-prefixed write temp, which an interrupted hook
	// leaves behind indefinitely.
	mappingEntries := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			// The hook's in-flight write temps share this directory. They are never a live
			// tab's name, so the reclaim below would delete one mid-write and silently drop
			// that prompt's mapping update. A dot prefix is the hook's documented temp shape
			// and no title handle starts with a dot, so skipping costs nothing.
			continue
		}
		mappingEntries++
		// The entry name is a TITLE HANDLE, so the tab it belongs to is resolved in memory
		// before anything is judged against it. An unknown handle names no tab — a file left
		// by a previous server run, since handles live only in this process, or one a local
		// writer invented — and is reclaimed on the spot.
		tabID, known := s.tabForHandle(e.Name())
		if !known {
			s.forget(e.Name())
			continue
		}
		if _, ok := live[tabID]; !ok {
			// The tab is gone. Reclaim now rather than waiting for a title change that will
			// never come: syncOne's memo short-circuits before the SetSessionTitle-false
			// probe, so an ordinary close with a stable title used to keep its mapping file,
			// its pushed entry and its per-tick I/O for the container's life.
			delete(s.pushed, tabID)
			s.forget(e.Name())
			continue
		}
		mapped++
		s.syncOne(ctx, mgr, e.Name(), tabID)
	}
	if mapped == 0 && len(live) > 0 {
		// Tabs exist and not one has a kiro session mapping, so every one keeps the engine's
		// automatic cwd ladder. state_entries is the discriminator: 0 means no mapping-shaped
		// name was there at all, non-zero means every name present belongs to no live tab.
		// Debug, not Warn: a tab still at the device-flow sign-in legitimately has no kiro
		// session yet, so a default-level record would fire on ordinary first-boot sign-ins.
		slog.Debug("session title: no live tab has a kiro session mapping; every tab keeps the automatic name ladder",
			"live_tabs", len(live), "state_entries", mappingEntries, "dir", s.stateDir,
			"hint", "kiro-cli's SessionStart/UserPromptSubmit hooks write these files; check $HOME/.kiro/hooks/web-terminal-session-title.json and hooks/session-title.sh. A tab still at the device-flow sign-in has no kiro session yet, so this is expected until chat starts.")
	}
}

// syncOne maps one tab to its kiro session and pushes that session's title. handle is the
// mapping file's name; tabID is what pass() resolved it to and the only one of the two the
// engine understands.
func (s *sessionTitleSync) syncOne(ctx context.Context, mgr titleSetter, handle string, tabID terminal.SessionID) {
	kiroID, ok := s.readMapping(ctx, handle)
	if !ok {
		return
	}
	previous, pushed := s.pushed[tabID]
	repointed := pushed && previous.kiroID != kiroID
	title, ok := s.readTitle(ctx, kiroID)
	if !ok {
		if !repointed {
			return
		}
		// The hook re-pointed this tab to a conversation with no usable title yet. Clear the
		// old client rung so the tab falls through to the engine's automatic ladder instead
		// of displaying the previous conversation's title. Only this arm needs a clear: a
		// usable title REPLACES the rung in one store below.
		if !mgr.SetSessionTitle(tabID, "") {
			s.forget(handle)
		}
		delete(s.pushed, tabID)
		return
	}
	if pushed && !repointed && previous.title == title {
		return
	}
	// A false return means the tab closed between this sweep's liveness snapshot and this
	// push, so this arm is the within-sweep race backstop only.
	if !mgr.SetSessionTitle(tabID, title) {
		delete(s.pushed, tabID)
		s.forget(handle)
		return
	}
	s.pushed[tabID] = pushedTitle{kiroID: kiroID, title: title}
	// The title is kiro-cli's verbatim copy of the user's first message, so this record
	// carries its LENGTH rather than its text. The tab id is deliberately ABSENT: it is the
	// /ws attach+resume capability token, and the title handle names this mapping for an
	// operator without disclosing one. Do not add the session id back beside the handle,
	// truncated or otherwise, or the whole point of keying on a handle is lost. kiro_session
	// is kiro-cli's own internal id, not a network capability, so it stays whole.
	slog.Debug("session title: adopted kiro session title",
		"title_handle", handle, "kiro_session", kiroID,
		"title_runes", utf8.RuneCountInString(title))
}

// readMapping reads the handle -> kiro-session-id file the hook wrote. The value is
// validated as a kiro session id rather than trusted: it is interpolated into a filesystem
// path below, and the file is written by a shell hook this app does not execute itself.
func (s *sessionTitleSync) readMapping(ctx context.Context, handle string) (string, bool) {
	raw, err := readSmallFile(ctx, filepath.Join(s.stateDir, handle))
	if err != nil {
		// pass() just enumerated this entry, so any failure here is abnormal — EACCES, a
		// refused symlink/FIFO, an oversized file — not absence.
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

// readTitle finds a kiro session's record under the per-workspace hash level and returns
// its title. Absent, placeholder, and blank titles all read as "no title".
func (s *sessionTitleSync) readTitle(ctx context.Context, kiroID string) (string, bool) {
	hashDirs, err := os.ReadDir(s.sessionsRoot)
	if err != nil {
		// A missing tree is the normal state before kiro-cli has written its first session,
		// so it stays silent. Anything else — a wrong HOME, EACCES on the volume, ENOTDIR —
		// kills every tab's title with no record at any level, which is the one failure a
		// log-only diagnosis path cannot have.
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
		if title, settled := s.titleFromRecord(ctx, hd.Name(), kiroID); settled {
			return title, title != ""
		}
	}
	return "", false
}

// titleFromRecord reads one candidate session.json and reports whether it SETTLED the
// lookup. A session id lives under exactly one hash directory, so once the record has been
// reached at all its contents are the answer — a corrupt or title-less record settles the
// lookup as "no title" rather than sending the scan on. A record that could not be READ at
// all is the miss that keeps scanning.
func (s *sessionTitleSync) titleFromRecord(ctx context.Context, hashDir, kiroID string) (string, bool) {
	raw, err := readSmallFile(ctx, filepath.Join(s.sessionsRoot, hashDir, kiroID, "session.json"))
	if err != nil {
		// ENOENT is the normal miss (the session lives under one hash dir); anything else
		// silently kills this tab's title, the failure class readTitle's comment says a
		// log-only diagnosis path cannot have.
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
	// One rune policy for untrusted upstream text. This title reaches two sinks this
	// function does not own: the slog attribute in syncOne, and the engine's client title
	// rung, whose sanitizeTitle drops only C0 + DEL — so C1 controls, Bidi controls and
	// U+2028/29 would reach the browser tab label. Sanitizing BEFORE the trim matters:
	// unsafe runes become spaces, so a control-only title collapses to "" and is correctly
	// read as "no title".
	title := strings.TrimSpace(runesafe.SanitizeSingleLine(rec.Title))
	if title == placeholderTitle {
		return "", true
	}
	return title, true
}

// forget removes a mapping whose tab no longer exists and drops that tab's handle from the
// in-memory index. handle is one path component by construction: every caller takes it from
// an os.ReadDir entry of stateDir, whose Name is a single basename and never "." or "..".
func (s *sessionTitleSync) forget(handle string) {
	s.dropHandle(handle)
	if err := os.Remove(filepath.Join(s.stateDir, handle)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Debug("session title: could not drop a stale mapping",
			"title_handle", handle, "error", err)
	}
}

// readSmallFile reads at most maxTitleFileBytes from one of the two state files.
// atomicfile.OpenRegular is the library's open-a-file-in-a-directory-others-can-write
// sequence — O_NOFOLLOW, O_NONBLOCK so a planted FIFO is refused instead of blocking this
// goroutine in open(2), and a stat of the OPEN HANDLE rather than of the pathname a second
// time — and ReadBoundedFile applies the byte bound to that same descriptor, refusing a
// larger file rather than truncating it.
func readSmallFile(ctx context.Context, path string) ([]byte, error) {
	f, _, err := atomicfile.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	// The sweep's context, not context.Background(): ReadBoundedFile checks
	// ctx.Err() at entry and mid-read, so a Background context would make the
	// poller's file reads unabandonable at shutdown for no gain.
	return atomicfile.ReadBoundedFile(ctx, f, maxTitleFileBytes)
}

// validKiroSessionID gates the id read out of a mapping file before it becomes a path
// component. kiro-cli's v3 ids are "sess_" followed by a UUID; requiring the prefix keeps a
// malformed or hostile file from pointing the read anywhere else.
func validKiroSessionID(id string) bool {
	rest, ok := strings.CutPrefix(id, "sess_")
	if !ok || rest == "" || len(id) > 128 {
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
