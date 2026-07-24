// Command wirecheck asserts wire-protocol compatibility between the Go
// server half (the web-terminal-engine module go.mod pins) and the served
// TS client half (the Dockerfile-ARG-pinned npm artifact). The compatibility
// RULE is the engine's (terminal.WirePairIncompatibility — the same verdict
// its runtime handshake reaches, so this gate can never disagree with the
// close-4002 refusal); this program supplies the Go side from the engine's
// public constants and the client side from flags the Dockerfile's wire-floor
// gate extracts from the vendored artifact.
//
// Exit 0: the pairing is declared-compatible. Exit 1: a declared floor is
// violated — the pairing would refuse at first connect with close code 4002,
// so fail the build instead. Exit 2: usage error (a missing, malformed, or
// non-positive -client-rev / -client-min-server flag). A MIS-declared floor
// is out of scope here; that is the engine conformance suite's contract.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

func main() {
	clientRev := flag.Int("client-rev", 0, "client WIRE_PROTOCOL_VERSION from the vendored npm artifact")
	clientMinServer := flag.Int("client-min-server", 0, "client MIN_SUPPORTED_SERVER_WIRE_VERSION from the vendored npm artifact")
	flag.Parse()
	os.Exit(run(*clientRev, *clientMinServer, os.Stdout, os.Stderr))
}

// run performs the wire-floor gate against the engine's exported constants and
// returns the process exit code main hands to os.Exit: 0 declared-compatible,
// 1 floor violated (fail the build), 2 usage error (missing/non-positive flag
// values).
//
// The Dockerfile's gate observes only zero vs non-zero: it invokes this via
// `go run`, which reports its OWN exit status 1 for ANY non-zero program exit
// (it prints "exit status 2" to stderr but does not propagate the 2). So the
// three-way code is the contract for direct invocation and
// TestRun_exitCodeContract; in a build log the two failures are told apart by
// their stderr line, not by the code — never add an `[ $? -eq 2 ]` branch to
// the build step.
//
// The flags are validated here rather than left to the engine's comparator so
// a missing extraction is reported as the usage error it is (exit 2, the
// "required positive integers" line, "fix the gate") instead of a
// compatibility verdict (exit 1, "bump a pin").
func run(clientRev, clientMinServer int, stdout, stderr io.Writer) int {
	if clientRev <= 0 || clientMinServer <= 0 {
		fmt.Fprintln(stderr, "wirecheck: -client-rev and -client-min-server are required positive integers")
		return 2
	}
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
