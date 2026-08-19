// Toolchain fence: excludes the TS subtree from the parent Go module so
// `go list ./...` / vet / lint never cross into node_modules (which can
// vendor third-party Go packages, e.g. flatted's golang port). Same
// mechanism as web-terminal-engine's nested ignore module.
module static-src-ignore

go 1.26.7
