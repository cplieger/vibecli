package kirocli

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// legacyArtifacts are the fixed-path remains of the shell installer's
// in-place promotion model: the update journal, the hard-linked backups and
// their absence tombstones, both install-completion markers, and the readiness
// marker.
//
// Deleting them outright is the decisions addendum's ruling 1: there is no
// backwards compatibility to keep, so the inherited-open-journal state is
// resolved by DELETION rather than by a journal decoder, a rollback path or a
// legacy ready-fallback. Nothing in this package reads any of these paths, so
// once they are gone they cannot influence a readiness or integrity decision.
var legacyArtifacts = []string{
	".kiro-cli-update-in-progress",
	".kiro-cli-installed",
	".kiro-cli-installed.prev",
	".kiro-cli-ready",
	"bin/.kiro-cli.prev",
	"bin/.kiro-cli.prev.absent",
	"bin/.kiro-cli-chat.prev",
	"bin/.kiro-cli-chat.prev.absent",
	"bin/.kiro-cli-term.prev",
	"bin/.kiro-cli-term.prev.absent",
}

// legacyStagePrefix prefixed the shell installer's staging trees directly under
// the tools dir; the managed staging trees live under the installation root
// instead, so any of these are orphans.
const legacyStagePrefix = ".kiro-cli-stage."

// purgeLegacyOnce runs the purge at most once per process. The convenience
// symlink this manager publishes lives at one of the purged paths, so a retry
// or a rescan must not delete it again.
func (m *Manager) purgeLegacyOnce() {
	m.mu.Lock()
	already := m.purged
	m.purged = true
	m.mu.Unlock()
	if already {
		return
	}
	m.purgeLegacy()
}

// purgeLegacy deletes the entire legacy kiro-cli layout: every fixed-path
// transaction artifact, every kiro-cli* dispatcher in $TOOLS/bin (including
// retired names), and every orphan staging tree.
//
// It is idempotent and interruption-safe by construction: each step is an
// unconditional RemoveAll of a path that nothing reads afterwards, so a kill
// leaves a prefix done and the next boot repeats the sequence, and on an
// already-purged volume every step is a no-op. Failures warn and continue — an
// undeletable artifact is inert, and bricking boot over disk hygiene is exactly
// what the failure posture forbids.
func (m *Manager) purgeLegacy() {
	root, err := os.OpenRoot(m.cfg.ToolsDir)
	if err != nil {
		// A missing tools dir means there is nothing to purge; anything else
		// is worth a line.
		if !os.IsNotExist(err) {
			slog.Warn("failed to open the tools dir to purge the legacy kiro-cli layout", "error", err)
		}
		return
	}
	defer root.Close()

	targets := make([]string, 0, len(legacyArtifacts)+8)
	targets = append(targets, legacyArtifacts...)
	targets = append(targets, legacyDispatchers(root)...)
	targets = append(targets, legacyStages(root)...)

	removed := 0
	for _, name := range targets {
		// RemoveAll through the root confines the delete to the tools tree: a
		// symlinked artifact cannot redirect it at the credential-bearing home
		// next door.
		if err := root.RemoveAll(name); err != nil {
			slog.Warn("failed to remove a legacy kiro-cli artifact; it is inert, so boot continues",
				"entry", name, "error", err)
			continue
		}
		removed++
	}
	if removed == 0 {
		slog.Debug("no legacy kiro-cli layout to purge")
		return
	}
	slog.Info("purged the legacy kiro-cli layout; the pinned version is installed fresh into its own version directory, so this boot downloads the archive once",
		"removed", removed)
}

// legacyDispatchers lists every kiro-cli* entry in $TOOLS/bin. The prefix sweep
// is what reclaims RETIRED dispatcher names an older version left behind, which
// a fixed list cannot know about.
func legacyDispatchers(root *os.Root) []string {
	entries, err := fs.ReadDir(root.FS(), binSubdir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), mainBinary) {
			out = append(out, binSubdir+"/"+e.Name())
		}
	}
	return out
}

// legacyStages lists orphan shell-era staging trees directly under the tools
// dir.
func legacyStages(root *os.Root) []string {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), legacyStagePrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// publishConvenienceLink republishes $TOOLS/bin/kiro-cli as a symlink at the
// active version's binary, for `docker exec … kiro-cli --version` and the
// documented operator path (finding 8).
//
// It is explicitly NON-AUTHORITATIVE: nothing in this package reads it, no
// integrity or readiness decision consults it, and the product always runs the
// absolute version-directory path from CLIPath. Publication is atomic (write a
// temp name, rename over the old one) with the parent synced and the target
// validated, and every failure is a warning — a missing convenience pointer
// must never withhold readiness from a correctly installed CLI.
func (m *Manager) publishConvenienceLink(target string) {
	if !selfContained(target) {
		slog.Warn("not publishing the kiro-cli convenience symlink: the active binary is not a self-contained executable",
			"target", target)
		return
	}
	binDir := filepath.Join(m.cfg.ToolsDir, binSubdir)
	if err := os.MkdirAll(binDir, dirMode); err != nil {
		slog.Warn("failed to create the tools bin dir for the kiro-cli convenience symlink", "path", binDir, "error", err)
		return
	}
	link := filepath.Join(binDir, mainBinary)
	tmp := filepath.Join(binDir, "."+mainBinary+".newlink")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		slog.Warn("failed to stage the kiro-cli convenience symlink", "path", tmp, "error", err)
		return
	}
	if err := m.rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		slog.Warn("failed to publish the kiro-cli convenience symlink; docker exec kiro-cli will not resolve, the product path is unaffected",
			"path", link, "error", err)
		return
	}
	if err := m.fsync(binDir); err != nil {
		slog.Warn("failed to sync the tools bin dir after publishing the kiro-cli convenience symlink", "error", err)
	}
	slog.Debug("published the kiro-cli convenience symlink", "path", link, "target", target)
}
