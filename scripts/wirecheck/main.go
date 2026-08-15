// Command wirecheck asserts wire-protocol compatibility between the Go
// server half (the web-terminal-engine module go.mod pins) and the served
// TS client half (the Dockerfile-ARG-pinned npm artifact). The compatibility
// RULE is the engine's (terminal.WirePairIncompatibility — the same verdict
// its runtime handshake reaches, so this gate can never disagree with the
// close-4002 refusal); this program supplies the Go side from the engine's
// public constants and the client side from the engine artifact's own
// wire-compatibility manifest (-manifest, required).
//
// Exit 0: the pairing is declared-compatible. Exit 1: a declared floor is
// violated — the pairing would refuse at first connect with close code 4002,
// so fail the build instead. Exit 2: usage error (a missing, unreadable,
// malformed, unknown-schema or value-less manifest). A MIS-declared floor is
// out of scope here; that is the engine conformance suite's contract.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cplieger/web-terminal-engine/v4/terminal"
)

// usageErrMsg is the exit-2 line: the client-side values are unusable, so the
// extraction is broken. Shared by readManifest's refusals and flag's parse-error path,
// so both exit-2 shapes tell the reader to fix the gate rather than move a pin.
// Deliberately NOT installed as flag.Usage — flag calls Usage for -h as well as for a
// parse error, so doing that would tell a maintainer reading the flag names that the
// gate is broken.
const usageErrMsg = "ERROR wire-floor-gate-usage: the client wire revisions are unusable — pass -manifest <engine-pkg>/wire-compatibility.json (the extraction is broken — fix the gate, do not bump a pin)"

// readManifest resolves the client half of the pairing from the engine artifact's own
// manifest, via the engine's exported decoder — the DECODING is the engine's, because it
// publishes the format.
//
// The POLICY stays here, and is the whole reason this wrapper exists: every failure becomes
// the usage error's exit 2, never a compatibility verdict, because an unreadable or
// unknown-schema manifest says the gate cannot see the client's declaration.
// ErrWireManifestSchema is named because its remedy is the opposite one — bump this gate.
func readManifest(path string, stderr io.Writer) (clientRev, clientMinServer int, ok bool) {
	m, err := terminal.ReadWireManifest(path)
	if err != nil {
		if errors.Is(err, terminal.ErrWireManifestSchema) {
			fmt.Fprintf(stderr, "ERROR wire-floor-gate-usage: %s: the manifest format moved ahead of this gate: %v\n", path, err)
		} else {
			fmt.Fprintf(stderr, "ERROR wire-floor-gate-usage: cannot read the engine's wire-compatibility manifest at %s: %v\n", path, err)
		}
		fmt.Fprintln(stderr, usageErrMsg)
		return 0, 0, false
	}
	return m.ProtocolVersion, m.MinimumServerProtocolVersion, true
}

func main() {
	manifest := flag.String("manifest", "", "path to the vendored engine artifact's wire-compatibility.json (required)")
	// ContinueOnError so a parse error can be told apart from -h, which
	// flag.Usage cannot do: an ExitOnError FlagSet exits 0 for ErrHelp, so a
	// Usage override prints the broken-gate ERROR on a successful help request.
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0) // same as ExitOnError's help exit
		}
		fmt.Fprintln(flag.CommandLine.Output(), usageErrMsg)
		os.Exit(2)
	}
	// An absent -manifest reaches terminal.ReadWireManifest as "", which fails
	// to open and produces the same exit-2 "cannot read the engine's
	// wire-compatibility manifest" line the absent-file case produces, so the
	// requirement needs no separate check.
	rev, minServer, ok := readManifest(*manifest, os.Stderr)
	if !ok {
		os.Exit(2)
	}
	os.Exit(run(rev, minServer, os.Stdout, os.Stderr))
}

// run performs the wire-floor gate against the engine's exported constants and returns the
// process exit code: 0 declared-compatible, 1 floor violated. The third code, 2, is main's.
//
// All three reach the Dockerfile's wire-floor gate, which BUILDS this program and invokes the
// binary for exactly that reason: `go run` reports its OWN exit status 1 for ANY non-zero
// program exit, which collapsed 2 and 1 into one code and left only stderr to tell "the
// gate's extraction is broken" from "genuine wire incompatibility". Do not put the step back
// on `go run`; a test fails if anyone does.
func run(clientRev, clientMinServer int, stdout, stderr io.Writer) int {
	if reason := terminal.WirePairIncompatibility(
		terminal.WireProtocolVersion, terminal.MinSupportedClientWireVersion,
		clientRev, clientMinServer,
	); reason != "" {
		fmt.Fprintf(stderr, "ERROR wire-floor-mismatch: %s\n%s\n", reason, remediation())
		return 1
	}
	fmt.Fprintf(stdout, "wirecheck ok: server wire rev %d (min client %d) <-> client wire rev %d (min server %d)\n",
		terminal.WireProtocolVersion, terminal.MinSupportedClientWireVersion, clientRev, clientMinServer)
	return 0
}

// remediation names this repo's two engine pins. Which pin to move is build-
// layout knowledge the engine deliberately does not carry, so the app supplies
// it alongside the engine's reason.
func remediation() string {
	return "fix: bump go.mod's web-terminal-engine (Go half) or the Dockerfile ARG + static-src/package.json engine pins (TS half) so both halves resolve to a compatible pair"
}
