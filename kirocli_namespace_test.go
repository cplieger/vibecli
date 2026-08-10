package main

// Two engines write into the same persistent tools tree, so the only thing that
// keeps them from deleting each other's installs is the namespace split: the
// toolbelt engine owns bin/, opt/, npm/ and python/ under the tools dir -- its unit
// is opt/<tool>/<version>/ plus a force-replaced bin/<tool> symlink -- and the
// kiro-cli install manager owns kiro-cli-versions/<version>/ plus one convenience
// symlink.
//
// These tests plant a toolbelt footprint for a tool literally named `kiro-cli`.
// That is the worst case rather than a hypothetical: the engine's name validator
// accepts `kiro-cli`, its manifest is hand-editable and re-read per operation, and
// this app mounts its HTTP projection at /api/tools (loopback, reachable from
// kiro-cli's own `!` shell escape), so one Add reaches this state.
//
// The subject survived the move to the pinstall library, but the level did not: the
// collision is a property of the values this app passes (Root, LinkDir, the purge
// data, and the release name that fixes the install root), so the tests build a
// manager from kiroInstallConfig -- the exact configuration production runs --
// rather than from a copy of it. The library's own suite owns the mechanics these
// assertions ride on (the purge shape gate, the sentinel, the confined deletes);
// what is asserted here is that THIS APP's configuration keeps the two engines
// apart.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/pathinside"
	"github.com/cplieger/pinstall/v2"
)

// The pin these tests install, and the toolbelt tool name that collides with it.
const (
	nsVersion = "9.9.9"
	nsTool    = "kiro-cli"
)

// nsToolbeltBody is the content of every regular file the fake toolbelt footprint
// owns, so a survivor check can tell "still there" from "replaced by our own file
// at the same path" -- which is what a publish over a colliding root actually does.
const nsToolbeltBody = "toolbelt-owned\n"

// nsEnv is one planted volume: the tools dir, and the witness path the foreign
// dispatcher records its own execution in.
type nsEnv struct {
	t       *testing.T
	tools   string
	witness string
}

func newNSEnv(t *testing.T) *nsEnv {
	t.Helper()
	tools := t.TempDir()
	return &nsEnv{t: t, tools: tools, witness: filepath.Join(tools, "foreign-was-run")}
}

// config is this app's real install configuration for this volume.
func (e *nsEnv) config() *pinstall.Config {
	return kiroInstallConfig(&baseKiro{
		version: nsVersion,
		// Any well-formed digest: a volume that already holds the complete pin
		// downloads nothing, so no archive is ever fetched to verify.
		sha256:      strings.Repeat("a", 64),
		sha256ARM64: strings.Repeat("b", 64),
		toolsDir:    e.tools,
	})
}

// manager builds a manager from that configuration, as startKiroCLI does.
func (e *nsEnv) manager() *pinstall.Manager {
	e.t.Helper()
	mgr, err := pinstall.New(e.config())
	if err != nil {
		e.t.Fatalf("pinstall.New from the app's own config: %v", err)
	}
	return mgr
}

// plantToolbeltKiroCLI plants what the toolbelt engine puts on the volume for a
// manifest entry named `kiro-cli`: a version tree at opt/<name>/<version>/ and a
// bin/<name> SYMLINK into it for each linked name (the engine's linkBin
// force-replaces those). No `.complete` sentinel, because the engine writes
// none -- which is exactly what would make this tree a victim: to a manager rooted
// at opt/kiro-cli it reads as an INCOMPLETE install, and the partial sweep deletes
// an incomplete install on every boot before selection.
//
// The tree's primary artifact is a script that records its own execution, so "never
// READ" is observable and not merely inferred: if the manager ever probed this
// binary or asserted a setting against it, the witness file appears.
//
// bin/kiro-cli is deliberately NOT linked here. The convenience symlink
// force-replaces that ONE path by design (it is the documented
// `docker exec … kiro-cli` pointer, an atomic rename over whatever is there), so a
// boot legitimately owns it and its end state cannot distinguish "refused then
// republished" from "deleted then republished"; the library's purge suite pins the
// refusal. The sidecar links below are touched by NO code path, which is what makes
// them the assertable half.
//
// It returns every path that must survive untouched, plus the tree directory.
func (e *nsEnv) plantToolbeltKiroCLI(linked ...string) (survivors []string, tree string) {
	e.t.Helper()
	tree = filepath.Join(e.tools, "opt", nsTool, nsVersion)
	binDir := filepath.Join(e.tools, kiroLinkDir)
	for _, dir := range []string{tree, binDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			e.t.Fatalf("MkdirAll(%s): %v", dir, err)
		}
	}
	// The engine's own PATH entry for an unrelated tool, so a sweep that walks the
	// shared bin dir instead of naming its targets is caught too.
	survivors = append(survivors, e.symlink(filepath.Join(e.tools, "opt", "gopls", "1.0.0", "gopls"), filepath.Join(binDir, "gopls")))
	for _, name := range []string{nsTool, nsTool + "-chat", nsTool + "-term"} {
		target := filepath.Join(tree, name)
		if err := os.WriteFile(target, []byte(nsToolbeltBody), 0o600); err != nil {
			e.t.Fatalf("WriteFile(%s): %v", target, err)
		}
		survivors = append(survivors, target)
	}
	// The primary is executable AND self-reporting, so it is a viable probe
	// candidate rather than one excluded for being non-executable.
	foreign := filepath.Join(tree, nsTool)
	e.writeScript(foreign, "printf 'was-run\\n' >>"+nsShellQuote(e.witness)+"\nprintf 'kiro-cli "+nsVersion+"\\n'\n")
	for _, name := range linked {
		survivors = append(survivors, e.symlink(filepath.Join(tree, name), filepath.Join(binDir, name)))
	}
	return survivors, tree
}

// plantOwnVersion writes a COMPLETE version directory under the app's own install
// root, standing in for an install a previous boot finished: the ordinary restart
// path, and the only way to drive this wiring with no download.
//
// It writes BOTH dispatchers because this app's REQUIRED set is
// {kiro-cli, kiro-cli-chat} -- `kiro-cli chat` over a PTY is the product -- so a
// directory holding only the main binary would not count as complete against the
// production configuration these tests build from.
func (e *nsEnv) plantOwnVersion() string {
	e.t.Helper()
	dir := filepath.Join(e.tools, nsTool+"-versions", nsVersion)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	for _, name := range []string{nsTool, nsTool + "-chat"} {
		// Answers --version with the directory's own name (what selection probes)
		// and exits 0 for every settings assertion.
		e.writeScript(filepath.Join(dir, name), "case \"$1\" in --version) printf 'kiro-cli "+nsVersion+"\\n' ;; esac\n")
	}
	// Written LAST, exactly as the install order requires: it is the sentinel that
	// makes the directory a selection candidate at all.
	if err := os.WriteFile(filepath.Join(dir, ".complete"), []byte(nsVersion+"\n"), 0o600); err != nil {
		e.t.Fatalf("write sentinel: %v", err)
	}
	return dir
}

// plantLegacyResidue plants the genuine shell-era residue THIS APP's own installer
// left, so a sweep assertion cannot pass by doing nothing at all. Unlike vibekit,
// this app's installer promoted in place, so its residue includes the update
// journal, the `.prev` hard-link backups with their `.absent` tombstones and both
// install markers -- every fixed-path artifact kiroLegacyPurge names -- plus an
// orphan staging tree and any dispatcher promoted into the shared bin dir.
func (e *nsEnv) plantLegacyResidue(dispatchers ...string) []string {
	e.t.Helper()
	planted := make([]string, 0, len(e.config().Purge.Artifacts)+len(dispatchers)+1)
	for _, rel := range e.config().Purge.Artifacts {
		planted = append(planted, e.writeFile(filepath.Join(e.tools, rel), "shell-era artifact\n"))
	}
	for _, name := range dispatchers {
		planted = append(planted, e.writeFile(filepath.Join(e.tools, kiroLinkDir, name), "shell-era dispatcher\n"))
	}
	stage := filepath.Join(e.tools, legacyStagePrefix+"abc123")
	if err := os.MkdirAll(stage, 0o750); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", stage, err)
	}
	return append(planted, stage)
}

func (e *nsEnv) writeFile(path, body string) string {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		e.t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

func (e *nsEnv) writeScript(path, body string) {
	e.t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"exit 0\n"), 0o700); err != nil { // #nosec G306 -- a dispatcher fake must be executable
		e.t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func (e *nsEnv) symlink(target, newname string) string {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		e.t.Fatalf("MkdirAll(%s): %v", filepath.Dir(target), err)
	}
	if err := os.Symlink(target, newname); err != nil {
		e.t.Fatalf("Symlink(%s -> %s): %v", newname, target, err)
	}
	return newname
}

// assertIntact checks that every planted path is not merely PRESENT but unchanged:
// a symlink still points where the engine pointed it, and a regular file still
// holds the engine's bytes. Presence alone is not enough -- a publish removes a
// colliding version directory and renames its own tree into the same place, so the
// paths reappear holding our files.
//
// It also asserts the witness is absent, which is the "never READ" half: the
// foreign primary appends to it when executed, so a probe or a settings assertion
// against another owner's binary leaves a trace no outcome check would show.
func (e *nsEnv) assertIntact(survivors []string) {
	e.t.Helper()
	optTree := filepath.Join(e.tools, "opt")
	for _, p := range survivors {
		fi, err := os.Lstat(p)
		if err != nil {
			e.t.Errorf("%s is gone: the install reached into the toolbelt engine's namespace", p)
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				e.t.Errorf("Readlink(%s): %v", p, err)
				continue
			}
			// pathinside.Inside rather than a prefix test on the raw string: the
			// link target is read off disk, so it need not be cleaned, and
			// "<opt>/../elsewhere" carries the prefix while pointing outside the
			// tree. Inside counts the opt dir ITSELF as inside, which no planted
			// link is -- every survivor points at a file two levels down -- so
			// the two rules agree on every value this test can produce.
			if !pathinside.Inside(optTree, target) {
				e.t.Errorf("%s now points at %q, outside the engine's own opt tree: its symlink was republished under it", p, target)
			}
			continue
		}
		raw, err := os.ReadFile(p) // #nosec G304 -- a path this test planted.
		if err != nil {
			e.t.Errorf("read %s: %v", p, err)
			continue
		}
		// The foreign primary is a script, so it is checked for still being one of
		// the two shapes this test wrote rather than for the marker body.
		if body := string(raw); body != nsToolbeltBody && !strings.HasPrefix(body, "#!/bin/sh") {
			e.t.Errorf("%s holds %q, neither of the shapes this test planted: it was removed and rewritten", p, body)
		}
	}
	if _, err := os.Lstat(e.witness); err == nil {
		e.t.Error("the manager EXECUTED the toolbelt-owned kiro-cli; another owner's files must never be a version candidate")
	}
}

// TestToolbeltKiroCLIFootprintSurvivesABoot is the whole-boot half of the
// collision: with a toolbelt-owned `kiro-cli` tool already on the volume, a full
// Ensure against this app's own configuration must neither READ nor DELETE any of
// it, and must activate its own version regardless.
//
// Every one of those properties fails if the two roots ever overlap: the partial
// sweep removes the sentinel-less foreign tree, selection probes the foreign
// binary, and the pin is satisfied (or destroyed) by another owner's files. The
// planted foreign tree carries the PINNED version for that reason -- with
// overlapping roots it would be the pin's own directory.
func TestToolbeltKiroCLIFootprintSurvivesABoot(t *testing.T) {
	env := newNSEnv(t)
	survivors, tree := env.plantToolbeltKiroCLI(nsTool+"-chat", nsTool+"-term")
	own := env.plantOwnVersion()
	mgr := env.manager()

	if err := mgr.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	env.assertIntact(survivors)
	if ready, why := mgr.Ready(); !ready {
		t.Errorf("Ready() = false (%s), want true: the app's own install must activate regardless", why)
	}
	if got := mgr.PathEntry(); got != own {
		t.Errorf("PathEntry() = %q, want the app's own version directory %q", got, own)
	}
	if got := mgr.Path(); got != filepath.Join(own, nsTool) {
		t.Errorf("Path() = %q, want the dispatcher inside the app's own version directory", got)
	}
	if strings.HasPrefix(mgr.Path(), tree+string(filepath.Separator)) {
		t.Fatalf("Path() = %q resolves INSIDE the toolbelt-owned tree", mgr.Path())
	}
	// The convenience symlink is the one path in the shared bin dir a boot owns: it
	// must point into the app's own install, never at the colliding tree.
	link := filepath.Join(env.tools, kiroLinkDir, nsTool)
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("the `docker exec … kiro-cli` convenience symlink was not published: %v", err)
	}
	if target != filepath.Join(own, nsTool) {
		t.Errorf("%s points at %q, want the active version's own dispatcher", link, target)
	}
}

// nsToolsRel names dir relative to the tools dir, refusing anything that is not
// under that tree.
//
// The escape decision is pathinside.RelEscapes and NOT filepath.Rel's error,
// because Rel does not error on escape: handed a target above its base it
// returns "../evil" with a nil error, so reading a nil error as "under the tools
// dir" accepted exactly the case the caller's assertion exists to catch. A Rel
// error is a different failure (the two paths cannot be compared at all -- an
// absolute path against a relative root, two Windows volumes) and is refused
// too, because a path that cannot be named relative to the tools dir is not
// under it.
//
// Depth is NOT this function's business: the caller splits the returned name and
// asserts its own component count, which is a separate property (a root nested
// deeper inside the tools dir is still contained by it).
func nsToolsRel(root, dir string) (string, error) {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return "", fmt.Errorf("%q cannot be named relative to %q: %w", dir, root, err)
	}
	if pathinside.RelEscapes(rel) {
		return rel, fmt.Errorf("%q is outside %q (relative name %q)", dir, root, rel)
	}
	return rel, nil
}

// TestNSToolsRelDetectsEscape pins the predicate the structural test below rides
// on, because that test cannot fail for the case it exists to catch:
// filepath.Rel does NOT error on escape -- handed a target above its base it
// returns "../x" with a nil error -- and "../x" then splits into exactly two
// components, so the depth assertion is satisfied too and "bin/opt/npm/python"
// does not contain "..". An install root OUTSIDE the tools dir therefore passed
// every assertion.
//
// The escaping case asserts both halves: the relative name is refused, AND it
// really does split into two components, which is why the depth check cannot
// stand in for the containment check.
func TestNSToolsRelDetectsEscape(t *testing.T) {
	root := t.TempDir()
	cases := map[string]struct {
		dir     string
		wantRel string
	}{
		"the shape this app's configuration produces": {
			dir:     filepath.Join(root, nsTool+"-versions", nsVersion),
			wantRel: filepath.Join(nsTool+"-versions", nsVersion),
		},
		"a sibling of the tools dir, two components up-and-over": {
			dir:     filepath.Join(filepath.Dir(root), "evil"),
			wantRel: "",
		},
		"a path that cannot be compared with the tools dir at all": {
			dir:     "relative/not/absolute",
			wantRel: "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rel, err := nsToolsRel(root, tc.dir)
			if tc.wantRel == "" {
				if err == nil {
					t.Fatalf("nsToolsRel(%q, %q) = %q, nil: a directory outside the tools dir was accepted as under it", root, tc.dir, rel)
				}
				return
			}
			if err != nil {
				t.Fatalf("nsToolsRel(%q, %q) = %v, want %q", root, tc.dir, err, tc.wantRel)
			}
			if rel != tc.wantRel {
				t.Errorf("nsToolsRel(%q, %q) = %q, want %q", root, tc.dir, rel, tc.wantRel)
			}
		})
	}
	// The depth assertion the structural test makes on top of this predicate
	// cannot substitute for it: the escaping name has the same component count
	// as the legitimate one.
	escaping, err := filepath.Rel(root, filepath.Join(filepath.Dir(root), "evil"))
	if err != nil {
		t.Fatalf("Rel: %v", err)
	}
	if parts := strings.Split(escaping, string(filepath.Separator)); len(parts) != 2 {
		t.Fatalf("the escaping relative name %q has %d components; the case that fooled the depth check had 2", escaping, len(parts))
	}
}

// TestInstallRootIsOutsideTheToolbeltNamespace pins the structural half, which no
// single behavioral case can pin on its own: the install root this app's
// configuration produces is ONE component directly under the tools dir, and it is
// none of the four directories the toolbelt engine creates and enumerates. Any tool
// name the engine accepts therefore resolves to a path that cannot contain, be
// contained by, or alias this install's tree.
//
// It is derived from a live manager rather than from a constant, because the root
// is the library's function of the release name -- a name change is exactly the
// silent way this property could be lost.
func TestInstallRootIsOutsideTheToolbeltNamespace(t *testing.T) {
	env := newNSEnv(t)
	own := env.plantOwnVersion()
	mgr := env.manager()
	if err := mgr.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if mgr.PathEntry() != own {
		t.Fatalf("PathEntry() = %q, want %q", mgr.PathEntry(), own)
	}

	rel, err := nsToolsRel(env.tools, mgr.PathEntry())
	if err != nil {
		t.Fatalf("the active version directory is not under the tools dir: %v", err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 {
		t.Fatalf("the active version directory is %s below the tools dir (%q); a nested root can sit inside a tree the engine enumerates", rel, parts)
	}
	// The engine's binDir/optDir/npmDir/pythonDir, i.e. every directory it creates
	// under the tools dir. It never scans the tools dir itself.
	if owned := []string{"bin", "opt", "npm", "python"}; slices.Contains(owned, parts[0]) {
		t.Fatalf("the install root %q collides with the toolbelt engine's own %v trees", parts[0], owned)
	}
}

// TestLegacySweepSparesToolbeltSymlinks pins the sweep half. The prefix sweep this
// configuration replaced listed $TOOLS/bin and deleted every kiro-cli* entry,
// unconditionally, on every boot -- so an engine-owned symlink was unlinked while
// the engine's state row still claimed it, silently, forever.
//
// This app's purge data names three dispatchers, so a symlink at one of those paths
// is refused: it is a shape the shell installer never left there. The genuine
// residue is present at the same time, so the test cannot pass by sweeping nothing;
// and a refusal must NOT withhold the completion marker, or a volume with a
// toolbelt-owned bin/kiro-cli-chat would re-walk the co-owned bin dir forever.
func TestLegacySweepSparesToolbeltSymlinks(t *testing.T) {
	env := newNSEnv(t)
	survivors, _ := env.plantToolbeltKiroCLI(nsTool+"-chat", nsTool+"-term")
	// No bin dispatchers: the two bin names the shell installer also wrote are the
	// engine's symlinks in this volume, and planting a regular file over a symlink
	// would write through it into the tree under test. The fixed-path artifacts and
	// the orphan staging tree are residue enough.
	residue := env.plantLegacyResidue()
	own := env.plantOwnVersion()

	if err := env.manager().Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	env.assertIntact(survivors)
	for _, p := range residue {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("the sweep left the shell installer's own residue at %s", p)
		}
	}
	if _, err := os.Lstat(filepath.Join(env.tools, legacyPurgeMarker)); err != nil {
		t.Errorf("a refused foreign entry blocked %s, so every later boot re-runs the sweep over the co-owned bin dir: %v", legacyPurgeMarker, err)
	}
	// The two entries this install keeps directly under the tools dir must be
	// unreachable by the orphan-stage pass that shares that directory with them.
	if _, err := os.Lstat(own); err != nil {
		t.Errorf("the orphan-stage sweep removed the installation root %s: %v", own, err)
	}
}

// TestLegacySweepRunsOncePerVolume pins the once-only property the marker exists
// for. The layout the sweep deletes cannot come back -- no code writes it any
// more -- so after the migration a pass over the co-owned bin dir can only find
// another owner's files. A SECOND boot (a fresh manager on the same volume, which
// is what a container restart is) must therefore remove nothing at all.
//
// The sidecar name is the replant target because nothing republishes it: the
// primary's path in the shared bin dir is legitimately overwritten by the
// convenience symlink on every boot, so it could not tell a sweep from a publish.
func TestLegacySweepRunsOncePerVolume(t *testing.T) {
	env := newNSEnv(t)
	env.plantOwnVersion()
	residue := env.plantLegacyResidue(nsTool + "-chat")

	if err := env.manager().Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	for _, p := range residue {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("the first boot left the shell installer's own residue at %s", p)
		}
	}
	marker := filepath.Join(env.tools, legacyPurgeMarker)
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("the first boot did not record %s, so every later boot re-runs the sweep: %v", legacyPurgeMarker, err)
	}

	// Plant the sweep's own targets again, in the shape it removes. Only a second
	// pass could take them.
	replanted := env.plantLegacyResidue(nsTool + "-chat")
	if err := env.manager().Ensure(context.Background()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	for _, p := range replanted {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("the second boot removed %s: the migration sweep still runs on every boot", p)
		}
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Errorf("the completion marker was removed by a later boot: %v", err)
	}
}

// nsShellQuote wraps s in single quotes for the fake dispatcher's script body. The
// only inputs are t.TempDir paths, so escaping an embedded quote would be dead
// code; a path that somehow held one would break the script loudly rather than
// silently misdirect the witness write.
func nsShellQuote(s string) string {
	return "'" + s + "'"
}

// TestKiroInstallConfig_requiresTheChatSidecar pins the half of this app's
// install configuration its own product depends on: kiro-cli-chat is REQUIRED, so
// a version directory holding only the main dispatcher is not a candidate at all.
//
// Nothing else can see it. The main dispatcher answers --version correctly, so the
// selection probe accepts a chat-less directory, the sentinel is present, and every
// assertion passes -- the volume looks healthy and every tab dies the moment `chat`
// runs. Dropping "-chat" from kiroInstallConfig's Require leaves the whole suite
// green (plantOwnVersion writes both dispatchers, so no existing test distinguishes
// the two shapes).
//
// It uses Rescan rather than Ensure deliberately: Ensure would answer a rejected
// directory by fetching the pinned archive over the network, while Rescan re-derives
// the verdict from what the volume already holds, which is the property under test.
func TestKiroInstallConfig_requiresTheChatSidecar(t *testing.T) {
	env := newNSEnv(t)
	dir := filepath.Join(env.tools, nsTool+"-versions", nsVersion)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	env.writeScript(filepath.Join(dir, nsTool), "case \"$1\" in --version) printf 'kiro-cli "+nsVersion+"\\n' ;; esac\n")
	if err := os.WriteFile(filepath.Join(dir, ".complete"), []byte(nsVersion+"\n"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	mgr := env.manager()

	if ok, _ := mgr.Rescan(context.Background()); ok {
		t.Fatalf("a version directory holding only %s was activated: it answers --version correctly and then kills every terminal at chat", nsTool)
	}
	if ready, why := mgr.Ready(); ready || why != pinstall.ReasonUnavailable {
		t.Errorf("Ready() = (%v, %v), want (false, %v)", ready, why, pinstall.ReasonUnavailable)
	}
	if got := mgr.Path(); got != "" {
		t.Errorf("Path() = %q, want empty: no version may be active", got)
	}

	// The positive control, so the refusal above cannot be passing because the
	// fixture is unusable for an unrelated reason: adding the sidecar to the SAME
	// directory, changing nothing else, makes it activatable.
	env.writeScript(filepath.Join(dir, nsTool+"-chat"), "exit 0\n")
	ok, err := mgr.Rescan(context.Background())
	if !ok || err != nil {
		t.Fatalf("Rescan with the sidecar present = (%v, %v), want (true, nil)", ok, err)
	}
	if got, want := mgr.Path(), filepath.Join(dir, nsTool); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}
