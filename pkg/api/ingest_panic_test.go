package api

import (
	"strings"
	"testing"
	"time"
)

// TestRunIngest_RecoversFromPanic is the regression guard for B1: an ingest
// function that panics (a malformed third-party feed tripping a nil-deref /
// out-of-range in a parser) must not take the server process down, and must not
// leave the runner wedged at running=true. runIngest runs in its own goroutine,
// so without the recover the panic below would crash this test binary outright —
// which is itself the failure signal.
func TestRunIngest_RecoversFromPanic(t *testing.T) {
	r := NewIngestRunner(func() error { panic("boom from a feed parser") }, time.Hour, "")

	if !r.TriggerIngest() {
		t.Fatal("TriggerIngest returned false on a fresh runner")
	}

	// Wait for the goroutine to finish. With recover in place, running flips back
	// to false and lastError is recorded; without it, we never get here.
	deadline := time.Now().Add(2 * time.Second)
	var st IngestStatus
	for {
		st = r.Status()
		if !st.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ingest still running after 2s — runIngest did not reset running on panic")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if st.LastError == "" {
		t.Fatal("expected LastError to be set after a panicking ingest")
	}
	if !strings.Contains(st.LastError, "panic") {
		t.Errorf("LastError = %q, want it to mention the panic", st.LastError)
	}

	// The runner must accept a new trigger — proving it isn't wedged at running=true.
	if !r.TriggerIngest() {
		t.Fatal("runner wedged: TriggerIngest false after a recovered panic")
	}
}
