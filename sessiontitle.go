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
// one way kiro offers authoritatively: a hook. This app injects KWEB_SESSION_ID
// into each tab's child environment, and a kiro-cli hook — which inherits that
// environment and is handed kiro's own session_id on stdin — writes the pair into a
// state directory this app watches. A hook re-affirms it on every prompt, so a
// session switch inside one tab (/chat, /tangent) re-points the mapping instead of
// stranding it.
//
// Deliberately NOT read from the log or the process tree. The KAS log does name its
// session, but it names every OTHER session the tab ever touched too (a resume, a
// subagent), and choosing among them is a guess with a wrong answer available —
// exactly the class of failure this change exists to remove. The hook is told.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cplieger/atomicfile/v2"
	"github.com/cplieger/runesafe"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

const (
	// titleStateDirName is the directory under the app's state root where hooks
	// drop one file per tab, named for the tab and containing kiro's session id.
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
	// Field order is load-bearing for govet fieldalignment: the map goes first so
	// the pointer-bearing prefix ends as early as possible. Re-check the linter
	// when adding a field.
	//
	// pushed remembers the kiro session and title last pushed per tab. Keeping
	// the mapping identity lets syncOne clear the old conversation's title when a
	// hook re-points the tab before the new session has a usable title.
	pushed   map[string]pushedTitle
	stateDir string
	// sessionsRoot is kiro-cli's session store ($HOME/.kiro/sessions). Sessions
	// live one level down under a per-workspace hash directory, so a session id
	// is resolved by scanning that one level rather than by recomputing the hash
	// (which is kiro's private business).
	sessionsRoot string
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
	}
}

// sessionEnv returns the two variables one tab's kiro-cli process needs so a hook
// can report its kiro session id. This is the whole mechanism on the child's side:
// the tab id it should report under, and where to write it.
func (s *sessionTitleSync) sessionEnv(tabID string) []string {
	return []string{
		"KWEB_SESSION_ID=" + tabID,
		"KWEB_TITLE_STATE_DIR=" + s.stateDir,
	}
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
	if created && fi.Mode().Perm() != 0o700 {
		// os.Mkdir's mode is a REQUEST. A filesystem carrying an inheritable
		// group-write ACL widens what we just created whatever was asked for
		// (measured on a ZFS nfs4acl dataset: 0770 from a 0o700 mkdir, and a child
		// of an already-0700 parent is 0770 too, so tightening the parent does not
		// cover it), and the check below would then refuse this process's OWN
		// directory with nothing retrying. Chmod is the only call that SETS the
		// mode. Safe here and only here: os.Mkdir reported that we created this
		// path, /tmp's sticky bit stops another user removing our root, and the
		// child's parent is our own 0700 directory, so no other writer has ever
		// held a name to swap in. A PRE-EXISTING level is never chmod'ed, so the
		// refusal below still fires on exactly the planted shape the guard is for.
		// Re-stat rather than trusting chmod's status, the same postcondition
		// entrypoint.sh's secure_tools_dir asserts.
		if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil {
			return chmodErr
		}
		if fi, err = os.Lstat(dir); err != nil {
			return err
		}
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is group/other-writable (%#o): another user could replace the mapping files under it", dir, perm)
	}
	return nil
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
		// A missing directory is the normal pre-first-hook state, not an error
		// worth logging every tick.
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Debug("session title: state dir unreadable", "dir", s.stateDir, "error", err)
		}
		return
	}
	// One liveness snapshot per sweep rather than per entry: the manager takes its
	// own lock, and every mapping is then judged against the same picture.
	live := make(map[string]struct{}, len(entries))
	for _, info := range mgr.List() {
		live[info.ID] = struct{}{}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			// The hook's in-flight write temps (".<tabID>.$$", renamed into place by
			// hooks/session-title.sh) share this directory. They are never a live tab's
			// name, so the reclaim below would delete one mid-write and silently drop
			// that prompt's mapping update. A dot prefix is the hook's documented temp
			// shape and no engine session id starts with a dot, so skipping costs nothing.
			continue
		}
		if _, ok := live[e.Name()]; !ok {
			// The tab is gone. Reclaim now rather than waiting for a title change
			// that will never come: syncOne's memo short-circuits before the
			// SetSessionTitle-false probe, so an ordinary close (stable title)
			// used to keep its mapping file, its pushed entry and its per-tick
			// I/O for the container's life.
			delete(s.pushed, e.Name())
			s.forget(e.Name())
			continue
		}
		s.syncOne(mgr, e.Name())
	}
}

// syncOne maps one tab to its kiro session and pushes that session's title.
func (s *sessionTitleSync) syncOne(mgr titleSetter, tabID string) {
	kiroID, ok := s.readMapping(tabID)
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
			s.forget(tabID)
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
		s.forget(tabID)
		return
	}
	s.pushed[tabID] = pushedTitle{kiroID: kiroID, title: title}
	// The tab id is the /ws attach+resume capability token and the title is
	// kiro-cli's verbatim copy of the user's first message, so this record carries
	// the truncated id and the title's LENGTH -- the same treatment main.go:1905,
	// routes.go:360 and newStatusClassifier's fingerprint already give their
	// respective values. kiro_session is kiro-cli's own internal id, not a
	// network capability, so it stays whole.
	slog.Debug("session title: adopted kiro session title",
		"session", terminal.LogID(tabID), "kiro_session", kiroID,
		"title_runes", utf8.RuneCountInString(title))
}

// readMapping reads the tab -> kiro-session-id file the hook wrote. The value is
// validated as a kiro session id rather than trusted: it is interpolated into a
// filesystem path below, and the file is written by a shell hook this app does not
// execute itself.
func (s *sessionTitleSync) readMapping(tabID string) (string, bool) {
	raw, err := readSmallFile(filepath.Join(s.stateDir, tabID))
	if err != nil {
		// pass() just enumerated this entry, so any failure here is abnormal --
		// EACCES, a refused symlink/FIFO (OpenRegular), an oversized file -- not
		// absence. Same ErrNotExist carve-out as the directory-level reads.
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Debug("session title: mapping file unreadable",
				"session", terminal.LogID(tabID), "error", err)
		}
		return "", false
	}
	id := strings.TrimSpace(string(raw))
	if !validKiroSessionID(id) {
		if id != "" {
			slog.Debug("session title: mapping file holds no usable session id",
				"session", terminal.LogID(tabID))
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

// forget removes a mapping whose tab no longer exists. tabID is one path
// component by construction: every caller takes it from an os.ReadDir entry of
// stateDir, whose Name is a single basename and never "." or "..".
func (s *sessionTitleSync) forget(tabID string) {
	if err := os.Remove(filepath.Join(s.stateDir, tabID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Debug("session title: could not drop a stale mapping",
			"session", terminal.LogID(tabID), "error", err)
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
