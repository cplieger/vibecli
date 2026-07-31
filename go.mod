module github.com/cplieger/web-terminal-kiro

go 1.26.5

require (
	github.com/cplieger/pathinside v1.0.0
	github.com/cplieger/pinstall v1.0.1
	github.com/cplieger/slogx v1.5.0
	github.com/cplieger/toolbelt/v2 v2.3.1
	github.com/cplieger/web-terminal-engine/v3 v3.2.1
	github.com/cplieger/webhttp v1.20.0
)

// TEMPORARY SCAFFOLDING — DELETE THIS REPLACE. toolbelt's opt-in
// Config.VerifyRootIntegrity (the root-integrity prerequisite startTools sets)
// exists in no published toolbelt version yet, so this build resolves the module
// from the sibling working tree instead. Consequences while it is here: the
// container image CANNOT be built (../toolbelt is not in the build context) and
// nothing verifies against a published module. Remove it in the SAME change that
// bumps the require above to the first toolbelt release carrying the field — and
// bump the Dockerfile's TOOLBELT_TOOLCATALOG_VERSION ARG with it, since its
// pin-parity gate reads the require line.
replace github.com/cplieger/toolbelt/v2 => ../toolbelt

require (
	github.com/cplieger/atomicfile/v2 v2.5.0 // indirect
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
