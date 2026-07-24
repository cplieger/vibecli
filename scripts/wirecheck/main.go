// Command wirecheck asserts wire-protocol compatibility between the Go
// server half (the web-terminal-engine module go.mod pins) and the served
// TS client half (the Dockerfile-ARG-pinned npm artifact), using the
// engine's exported compatibility floors. The Dockerfile's wire-floor gate
// extracts the client's constants from the vendored artifact and passes
// them as flags; this program supplies the Go side from the engine's public
// API — no source scraping on the Go half.
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
// returns the process exit code main hands to os.Exit — the contract the
// Dockerfile consumes: 0 declared-compatible, 1 floor violated (fail the
// build), 2 usage error (missing/non-positive flag values).
func run(clientRev, clientMinServer int, stdout, stderr io.Writer) int {
	if clientRev <= 0 || clientMinServer <= 0 {
		fmt.Fprintln(stderr, "wirecheck: -client-rev and -client-min-server are required positive integers")
		return 2
	}
	if reason := incompatibility(terminal.WireProtocolVersion, terminal.MinSupportedClientWireVersion, clientRev, clientMinServer); reason != "" {
		fmt.Fprintf(stderr, "ERROR wire-floor-mismatch: %s\n", reason)
		return 1
	}
	fmt.Fprintf(stdout, "wirecheck ok: server wire rev %d (min client %d) <-> client wire rev %d (min server %d)\n",
		terminal.WireProtocolVersion, terminal.MinSupportedClientWireVersion, clientRev, clientMinServer)
	return 0
}

// incompatibility returns "" when the declared floors admit the pairing in
// both directions, or a human-readable reason naming the violated floor and
// which pin to move.
func incompatibility(serverRev, serverMinClient, clientRev, clientMinServer int) string {
	if serverRev < clientMinServer {
		return fmt.Sprintf(
			"Go engine wire revision %d is below the npm client's minimum supported server revision %d (bump go.mod's web-terminal-engine)",
			serverRev, clientMinServer)
	}
	if clientRev < serverMinClient {
		return fmt.Sprintf(
			"npm client wire revision %d is below the Go engine's minimum supported client revision %d (bump the Dockerfile ARG + static-src/package.json engine pins)",
			clientRev, serverMinClient)
	}
	return ""
}
