package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/cplieger/web-terminal-engine/v3/terminal"
)

// resumeAck frame offsets (the engine's encodeResumeAck layout):
// [0] msg type, [1:9] ack, [9:17] epoch, [17:25] committed, [25:33] oldestIndex.
//
// FOLLOW-UP (blocked on a web-terminal-engine release, then mechanical): DELETE
// these four constants and readResumeAckBounds' frame parsing. They hard-code the
// engine's PRIVATE encodeResumeAck layout — msg type 2, offsets 17 and 25, min
// length 33 — only because no accessor existed when this test was written; a
// layout change inside the engine turns this test into a silent
// never-sees-a-resumeAck timeout rather than a compile error. The engine now
// exports the bounds directly:
//
//	func (h *terminal.Handler) ScrollbackBounds() (committed, oldest uint64)
//
// read-only, both values under ONE mutex acquisition (so the pair is a state the
// session actually had), half-open range [oldest, committed), both 0 on a fresh
// session. When the pinned engine version carries it, rewrite this test to hold
// the session's Handler and call ScrollbackBounds() instead of dialing /ws and
// decoding a frame — which also drops the websocket dial, the read-limit bump and
// the resume-control JSON from this file.
//
// WHOEVER REWRITES IT MUST KEEP IT ABLE TO FAIL. An earlier version of this test
// was VACUOUS: it emitted 2500 lines and asserted oldest == 0, so ANY capacity
// above ~2500 passed and a raised capacity was invisible. The current shape is
// deliberate and must survive the rewrite: emit PAST the configured capacity
// (5250 > 5000) so eviction is observable, wait until enough lines are committed,
// and assert committed-oldest == 5000 EXACTLY — an equality that fails both when
// terminal.WithScrollbackCapacity(5000) is deleted (the engine default retains
// 1000) and when the number is changed in either direction. Red-check the rewrite
// by editing the capacity in registerRoutes' session factory and confirming it
// fails.
const resumeAckMsgType byte = 2

const (
	resumeAckMinLen        = 33
	resumeAckCommittedAt   = 17
	resumeAckOldestIndexAt = 25
)

// TestSessionScrollbackCapacityWiredIntoSessionFactory pins the exact 5000-line
// retention policy wired into registerRoutes' session factory:
// terminal.WithScrollbackCapacity(5000). The engine's own default is 1000 lines,
// and the browser's own LineStore retains 5000, so a smaller server capacity
// silently truncates a reconnect while a larger one wastes memory the client will
// never retain -- and this app's in-memory-only session model has no on-disk store
// to fall back on. 5000 is therefore the pin because it is the CLIENT's retention
// cap, not because it is merely "more than the engine default".
//
// The observable is the engine's resumeAck frame, which carries the absolute
// bounds of retained history (committed, oldestIndex) -- the same pair the browser
// client uses to detect an eviction gap. The child emits PAST the configured
// capacity, so eviction is observable and committed-oldest reports the capacity
// exactly: deleting the option fails (the 1000-line default retains a fifth), and
// so does REDUCING it, which the older ">= emitted lines" form could not see
// (it emitted 2500 and asserted oldest == 0, so any capacity above ~2500 passed).
//
// haveThrough is set far in the future so the server replays no history: this
// exchange is only asked for the bounds. Polling re-sends the resume until the
// scrollback has committed enough lines, rather than sleeping a guessed
// interval.
func TestSessionScrollbackCapacityWiredIntoSessionFactory(t *testing.T) {
	const (
		emitted       = 5250 // past the app-owned 5000-line capacity, so eviction is observable
		wantCommitted = 5100 // enough evicted lines that committed-oldest IS the capacity
		wantCapacity  = 5000 // the app's policy, matching the client's own retention cap
	)
	deps := newTestDeps(true)
	deps.cmd = staticCmd("/bin/sh", "-c", fmt.Sprintf(
		`i=1; while [ $i -le %d ]; do echo "line $i"; i=$((i+1)); done; exec cat`, emitted))
	mux, _, csp, id := mustStartSession(t, deps)

	srv := httptest.NewServer(buildHandler(mux, nil, csp, nil))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/ws?session="+id,
		&websocket.DialOptions{HTTPClient: srv.Client()})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial /ws: %v", err)
	}
	defer conn.CloseNow()
	// The window frame plus modes/title easily exceeds coder/websocket's 32 KiB
	// default read limit on a 120-column screen; without this the library closes
	// the connection mid-exchange and the assertion never runs.
	conn.SetReadLimit(1 << 22)

	resume := append([]byte{0x00}, fmt.Sprintf(
		`{"type":"resume","sessionId":%q,"haveThrough":1000000000,"protocolVersion":%d}`,
		id, terminal.WireProtocolVersion)...)

	deadline := time.Now().Add(20 * time.Second)
	var committed, oldest uint64
	for {
		if err := conn.Write(ctx, websocket.MessageBinary, resume); err != nil {
			t.Fatalf("write resume control: %v", err)
		}
		if c, o, ok := readResumeAckBounds(ctx, t, conn); ok {
			committed, oldest = c, o
			if committed >= wantCommitted {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("scrollback never committed %d lines (committed=%d oldest=%d); the child must emit %d lines",
				wantCommitted, committed, oldest, emitted)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := committed - oldest; got != wantCapacity {
		t.Errorf("retained scrollback lines = %d (committed=%d oldest=%d), want exactly %d -- terminal.WithScrollbackCapacity must stay wired to the app's 5000-line reconnect policy, which is the client store's own retention cap",
			got, committed, oldest, wantCapacity)
	}
}

// readResumeAckBounds reads frames until the engine's resumeAck arrives and
// returns the absolute bounds of retained history it carries.
func readResumeAckBounds(ctx context.Context, t *testing.T, conn *websocket.Conn) (committed, oldest uint64, ok bool) {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		_, msg, err := conn.Read(readCtx)
		if err != nil {
			return 0, 0, false
		}
		if len(msg) >= resumeAckMinLen && msg[0] == resumeAckMsgType {
			return binary.LittleEndian.Uint64(msg[resumeAckCommittedAt:]),
				binary.LittleEndian.Uint64(msg[resumeAckOldestIndexAt:]), true
		}
	}
}
