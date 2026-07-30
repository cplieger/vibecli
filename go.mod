module github.com/cplieger/web-terminal-kiro

go 1.26.5

require (
	github.com/cplieger/pathinside v1.0.0
	github.com/cplieger/pinstall v1.0.1
	github.com/cplieger/slogx v1.4.0
	github.com/cplieger/toolbelt/v2 v2.3.0
	github.com/cplieger/web-terminal-engine/v3 v3.2.1
	github.com/cplieger/webhttp v1.20.0
)

require (
	github.com/cplieger/atomicfile/v2 v2.4.0 // indirect
	github.com/cplieger/httpx/v4 v4.2.1 // indirect
	github.com/cplieger/runesafe v1.2.1 // indirect
	github.com/cplieger/scheduler/v3 v3.0.0 // indirect
	github.com/cplieger/ssrf/v3 v3.0.0 // indirect
	github.com/expr-lang/expr v1.17.8 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

require (
	github.com/coder/websocket v1.8.15
	github.com/cplieger/envx v1.5.0
	github.com/creack/pty v1.1.24 // indirect
)

// ---------------------------------------------------------------------------
// PRE-RELEASE SCAFFOLDING — DELETE ALL THREE REPLACE DIRECTIVES BEFORE MERGE.
//
// This app adopts three library capabilities that are implemented but NOT YET
// PUBLISHED, so the require lines above name the versions they are EXPECTED to
// ship in and these replaces point at the local checkouts until they do:
//
//   - github.com/cplieger/envx v1.5.0    — envx.BoolStrict (parseLogOSCText)
//   - github.com/cplieger/webhttp v1.20.0 — WithSkipUpgrades (buildHandler)
//   - github.com/cplieger/toolbelt/v2 v2.3.0 — httpapi's own Cache-Control:
//     no-store default, which let this app delete its apiNoStore middleware
//     (the tools API was the last /api/ path that did not set the header
//     itself; see TestAPICachePolicy_EveryAPIPathSetsNoStore in routes_test.go).
//
// All three are additive feature releases. At merge time the ONLY step is
// deleting the three replace lines below and running `go mod tidy` to write the
// real go.sum entries; the require versions are already the ones to resolve. If
// a library publishes under a DIFFERENT version than expected, fix the require
// line to match rather than restoring a replace.
//
// Until then the module resolves all three libraries from the sibling working
// copies, which keeps this tree buildable for everyone else working in it: a
// go.mod that required an unpublished version would break every build in the
// repo, not just this branch.
//
// A FOURTH replace (pathinside) sits below with its own banner: same footing,
// separate reason, so it can be dropped independently of these three.
// ---------------------------------------------------------------------------
replace github.com/cplieger/envx => ../envx

replace github.com/cplieger/webhttp => ../webhttp

replace github.com/cplieger/toolbelt/v2 => ../toolbelt

// LOCAL WIRING ONLY - MUST NOT BE MERGED.
// pathinside is a NEW library (the lexical path-containment predicate this
// repo's namespace test used to hand-roll); it has no release yet, so the
// require above carries a placeholder version. Drop this line and pin the real
// first release before this change goes anywhere near main. Test-only here:
// kirocli_namespace_test.go is the sole importer.
replace github.com/cplieger/pathinside => ../pathinside
