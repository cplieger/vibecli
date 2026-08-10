package main

import (
	"fmt"
	"testing"
	"time"
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
// The observable is the engine's exported ScrollbackBounds (engine >= v3.6.0):
// the absolute bounds of retained history (committed, oldest), read as a pair
// under one lock -- the same pair the resumeAck frame carries to the browser for
// eviction-gap detection. This replaced a websocket dial that decoded the
// engine's PRIVATE encodeResumeAck layout (msg type 2, offsets 17/25, min length
// 33), which this file's own follow-up note said to delete as soon as the pinned
// engine exported the bounds.
//
// THE SHAPE OF THE ASSERTION IS LOAD-BEARING. An earlier version of this test was
// VACUOUS: it emitted 2500 lines and asserted oldest == 0, so ANY capacity above
// ~2500 passed and a raised capacity was invisible. So: emit PAST the configured
// capacity (5250 > 5000) so eviction is observable, wait until enough lines are
// committed, and assert committed-oldest == 5000 EXACTLY -- an equality that
// fails both when terminal.WithScrollbackCapacity(5000) is deleted (the engine
// default retains 1000) and when the number changes in either direction. Any
// change to this assertion must be red-checked by editing the capacity in
// registerRoutes' session factory and confirming the failure.
func TestSessionScrollbackCapacityWiredIntoSessionFactory(t *testing.T) {
	const (
		emitted       = 5250 // past the app-owned 5000-line capacity, so eviction is observable
		wantCommitted = 5100 // enough evicted lines that committed-oldest IS the capacity
		wantCapacity  = 5000 // the app's policy, matching the client's own retention cap
	)
	deps := newTestDeps(true)
	deps.cmd = staticCmd("/bin/sh", "-c", fmt.Sprintf(
		`i=1; while [ $i -le %d ]; do echo "line $i"; i=$((i+1)); done; exec cat`, emitted))

	// The production factory, driven directly: the option under test is applied
	// in newSessionFactory, so the manager and the HTTP surface add nothing here.
	h := newSessionFactory(deps)("scrollback-capacity-probe")
	if err := h.StartEager(); err != nil {
		t.Fatalf("StartEager: %v", err)
	}
	t.Cleanup(h.Shutdown)

	deadline := time.Now().Add(20 * time.Second)
	var committed, oldest uint64
	for {
		committed, oldest = h.ScrollbackBounds()
		if committed >= wantCommitted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scrollback never committed %d lines (committed=%d oldest=%d); the child must emit %d lines",
				wantCommitted, committed, oldest, emitted)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := committed - oldest; got != wantCapacity {
		t.Errorf("retained scrollback lines = %d (committed=%d oldest=%d), want exactly %d -- terminal.WithScrollbackCapacity must stay wired to the app's 5000-line reconnect policy, which is the client store's own retention cap",
			got, committed, oldest, wantCapacity)
	}
}
