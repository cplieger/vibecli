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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	// pushed remembers the last title pushed per tab so an unchanged title does
	// not call into the manager every tick. The manager already de-duplicates for
	// the event stream; this keeps the common case free.
	pushed   map[string]string
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
	return &sessionTitleSync{
		stateDir:     filepath.Join(stateRoot, titleStateDirName),
		sessionsRoot: filepath.Join(home, ".kiro", "sessions"),
		pushed:       make(map[string]string),
	}
}

// titleStateDir is the directory the hook writes into. Exported to the session
// factory so the child's environment and the poller cannot disagree on the path.
func (s *sessionTitleSync) titleStateDir() string { return s.stateDir }

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
func (s *sessionTitleSync) ensureStateDir() error {
	return os.MkdirAll(s.stateDir, 0o750)
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

// pass runs one sweep: for every mapping the hook has written, read that kiro
// session's title and push it if it changed.
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
	for _, e := range entries {
		if e.IsDir() {
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
	title, ok := s.readTitle(kiroID)
	if !ok {
		return
	}
	if s.pushed[tabID] == title {
		return
	}
	// A false return means the tab is gone (closed while we were reading). Drop
	// the mapping file so a recycled state dir does not accumulate dead tabs.
	if !mgr.SetSessionTitle(tabID, title) {
		delete(s.pushed, tabID)
		s.forget(tabID)
		return
	}
	s.pushed[tabID] = title
	slog.Debug("session title: adopted kiro session title",
		"session", tabID, "kiro_session", kiroID, "title", title)
}

// readMapping reads the tab -> kiro-session-id file the hook wrote. The value is
// validated as a kiro session id rather than trusted: it is interpolated into a
// filesystem path below, and the file is written by a shell hook this app does not
// execute itself.
func (s *sessionTitleSync) readMapping(tabID string) (string, bool) {
	if !validSessionFileName(tabID) {
		return "", false
	}
	raw, err := readSmallFile(filepath.Join(s.stateDir, tabID))
	if err != nil {
		return "", false
	}
	id := strings.TrimSpace(string(raw))
	if !validKiroSessionID(id) {
		if id != "" {
			slog.Debug("session title: mapping file holds no usable session id",
				"session", tabID)
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
		return "", false
	}
	for _, hd := range hashDirs {
		if !hd.IsDir() {
			continue
		}
		raw, err := readSmallFile(filepath.Join(s.sessionsRoot, hd.Name(), kiroID, "session.json"))
		if err != nil {
			continue
		}
		var rec struct {
			Title string `json:"title"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			slog.Debug("session title: session.json is not decodable",
				"kiro_session", kiroID, "error", err)
			return "", false
		}
		title := strings.TrimSpace(rec.Title)
		if title == "" || title == placeholderTitle {
			return "", false
		}
		return title, true
	}
	return "", false
}

// forget removes a mapping whose tab no longer exists.
func (s *sessionTitleSync) forget(tabID string) {
	if !validSessionFileName(tabID) {
		return
	}
	if err := os.Remove(filepath.Join(s.stateDir, tabID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Debug("session title: could not drop a stale mapping", "session", tabID, "error", err)
	}
}

// readSmallFile reads at most maxTitleFileBytes, so neither state file can be used
// to make this server allocate without bound.
func readSmallFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path components are validated by the callers
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	buf := make([]byte, 0, min(int(st.Size())+1, maxTitleFileBytes))
	tmp := make([]byte, 4096)
	for len(buf) < maxTitleFileBytes {
		n, err := f.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf, nil
}

// validSessionFileName gates a tab id used as a path component. The engine's ids
// are hex, but this is the untrusted direction (a filename in a directory any
// process in the container can write to), so it is checked rather than assumed: no
// separators, no dots, no empty, bounded length.
func validSessionFileName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
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
