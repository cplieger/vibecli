// Command wirecheck asserts wire-protocol compatibility between the Go
// server half (the web-terminal-engine module go.mod pins) and the served
// TS client half (the Dockerfile-ARG-pinned npm artifact). The compatibility
// RULE is the engine's (terminal.WirePairIncompatibility — the same verdict
// its runtime handshake reaches, so this gate can never disagree with the
// close-4002 refusal); this program supplies the Go side from the engine's
// public constants and the client side from the engine artifact's own
// wire-compatibility manifest (-manifest), or from explicit flags.
//
// Exit 0: the pairing is declared-compatible. Exit 1: a declared floor is
// violated — the pairing would refuse at first connect with close code 4002,
// so fail the build instead. Exit 2: usage error (an unreadable, malformed,
// unknown-schema or value-less manifest, or a missing/non-positive
// -client-rev / -client-min-server flag). A MIS-declared floor is out of
// scope here; that is the engine conformance suite's contract.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// usageErrMsg is the exit-2 line: the client-side values are unusable, so the
// extraction is broken. Shared by run's own validation and flag's parse-error
// path (a non-numeric flag value lands there), so both exit-2 shapes tell the
// reader to fix the gate rather than move a pin. It is deliberately NOT
// installed as flag.Usage: flag calls Usage for -h as well as for a parse
// error, so doing that would tell a maintainer reading the flag names that the
// gate is broken — on the one program whose job is to be trusted about whether
// the gate or the pin is at fault.
const usageErrMsg = "ERROR wire-floor-gate-usage: the client wire revisions are unusable — pass -manifest <engine-pkg>/wire-compatibility.json, or -client-rev and -client-min-server as required positive integers (the extraction is broken — fix the gate, do not bump a pin)"

// manifestSchemaVersion is the only wire-compatibility manifest schema this
// gate knows how to read. The engine's manifest declares its own version
// first precisely so a consumer refuses an unknown one instead of guessing at
// a moved field: an unknown schema means THIS program is behind, which is a
// broken gate (exit 2, do not move a pin), never a wire incompatibility.
const manifestSchemaVersion = 1

// wireManifest mirrors the engine's published wire-compatibility.json (a
// package-root file listed in its npm `files` and exported as the
// ./wire-compatibility.json subpath, so the vendored tarball carries it).
// Only the fields this gate consumes are declared; incompatibleCloseCode and
// generatedBy are the engine's own documentation of the pairing it refuses.
type wireManifest struct {
	SchemaVersion     int `json:"schemaVersion"`
	WireCompatibility struct {
		ProtocolVersion              int `json:"protocolVersion"`
		MinimumServerProtocolVersion int `json:"minimumServerProtocolVersion"`
	} `json:"wireCompatibility"`
}

// readManifest resolves the client half of the pairing from the engine
// artifact's own manifest. Every failure returns the usage error's exit 2
// rather than a compatibility verdict: an unreadable, malformed or
// unknown-schema manifest says the gate cannot see the client's declaration,
// which is a broken extraction and never a reason to move a pin. Reported with
// the underlying cause, because "fix the gate" is only actionable when it names
// what could not be read.
func readManifest(path string, stderr io.Writer) (clientRev, clientMinServer int, ok bool) {
	fail := func(format string, args ...any) (int, int, bool) {
		fmt.Fprintf(stderr, "ERROR wire-floor-gate-usage: "+format+"\n", args...)
		fmt.Fprintln(stderr, usageErrMsg)
		return 0, 0, false
	}
	b, err := os.ReadFile(path) // #nosec G304 -- build-time gate; the path is the build's own argument
	if err != nil {
		return fail("cannot read the engine's wire-compatibility manifest: %v", err)
	}
	var m wireManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return fail("cannot parse %s as the engine's wire-compatibility manifest: %v", path, err)
	}
	if m.SchemaVersion != manifestSchemaVersion {
		return fail("%s declares schemaVersion %d, this gate reads %d (the manifest format moved ahead of the gate)",
			path, m.SchemaVersion, manifestSchemaVersion)
	}
	rev, minServer := m.WireCompatibility.ProtocolVersion, m.WireCompatibility.MinimumServerProtocolVersion
	if rev <= 0 || minServer <= 0 {
		return fail("%s carries no usable wireCompatibility revisions (protocolVersion %d, minimumServerProtocolVersion %d)",
			path, rev, minServer)
	}
	return rev, minServer, true
}

func main() {
	manifest := flag.String("manifest", "", "path to the vendored engine artifact's wire-compatibility.json (preferred over the -client-* flags)")
	clientRev := flag.Int("client-rev", 0, "client WIRE_PROTOCOL_VERSION, when no -manifest is available")
	clientMinServer := flag.Int("client-min-server", 0, "client MIN_SUPPORTED_SERVER_WIRE_VERSION, when no -manifest is available")
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
	rev, minServer := *clientRev, *clientMinServer
	if *manifest != "" {
		var ok bool
		if rev, minServer, ok = readManifest(*manifest, os.Stderr); !ok {
			os.Exit(2)
		}
	}
	os.Exit(run(rev, minServer, os.Stdout, os.Stderr))
}

// run performs the wire-floor gate against the engine's exported constants and
// returns the process exit code main hands to os.Exit: 0 declared-compatible,
// 1 floor violated (fail the build), 2 usage error (missing/non-positive flag
// values).
//
// All three codes reach the Dockerfile's wire-floor gate, which BUILDS this
// program and invokes the binary for exactly that reason: `go run` reports its
// OWN exit status 1 for ANY non-zero program exit (it prints "exit status 2" to
// stderr but does not propagate the 2), which collapsed 2 and 1 into one code
// and left only the stderr line to tell "the gate's extraction is broken, do NOT
// bump a pin" from "genuine wire incompatibility". Do not put the step back on
// `go run`; TestDockerfileBuildsTheGateInsteadOfGoRun fails if anyone does, and
// TestGateProcessPropagatesExitCodes pins main's propagation of these codes.
//
// The client-side values are validated here rather than left to the engine's
// comparator so a missing extraction is reported as the usage error it is (exit
// 2, the "required positive integers" line, "fix the gate") instead of a
// compatibility verdict (exit 1, "bump a pin").
func run(clientRev, clientMinServer int, stdout, stderr io.Writer) int {
	if clientRev <= 0 || clientMinServer <= 0 {
		fmt.Fprintln(stderr, usageErrMsg)
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
