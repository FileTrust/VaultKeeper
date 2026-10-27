package main

// Structured observability for fail-closed waits.
//
// WHY THIS EXISTS
//
//	Several convergence defects were expensive to diagnose purely because the blocked state
//	was SILENT. Defect A's plan-invalid branch failed closed with err=nil and logged nothing;
//	Defect F's deadlock produced two [lifecycle] lines and then twelve hours of silence; a
//	deletion waiting on the DO's F.1 redrive looked identical to a deletion nobody owned.
//	Each cost a multi-hour smoke run to identify.
//
//	A fail-closed wait that can outlast one normal scheduling cycle must therefore say, in one
//	line: what class of wait it is, which operation, what is blocking it, how old it is, and
//	what event is expected to release it.
//
// THIS CHANGES NO DECISION. It is logging only — no state is written, no gate is altered.
// Emission is rate-limited per (class, subject) so a 60-second sweep cannot flood the log
// while still making a persistent stall obvious.

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// failClosedWaitLogInterval bounds repeat emission for one (class, subject) pair. It is well
// above the 60 s reconciler cadence, so a steady-state wait produces a periodic heartbeat
// rather than one line per sweep.
var failClosedWaitLogInterval = 5 * time.Minute

var (
	failClosedWaitMu   sync.Mutex
	failClosedWaitSeen = map[string]time.Time{}
)

// logFailClosedWait emits one structured line describing a blocked-but-owned state.
//
// class   short stable identifier for the wait (e.g. "deletion-awaiting-declaration")
// subject the affected operation/batch/epoch identifier
// phase   its current durable phase, so the log is self-contained
// blocker why it cannot proceed right now
// release the exact event expected to unblock it — never "retried later"
// age     how long it has been waiting; zero when the age is not meaningfully tracked
func logFailClosedWait(storage, class, subject, phase, blocker, release string, age time.Duration) {
	key := class + "|" + subject
	now := time.Now()

	failClosedWaitMu.Lock()
	last, seen := failClosedWaitSeen[key]
	if seen && now.Sub(last) < failClosedWaitLogInterval {
		failClosedWaitMu.Unlock()
		return
	}
	failClosedWaitSeen[key] = now
	failClosedWaitMu.Unlock()

	ageField := "unknown"
	if age > 0 {
		ageField = age.Round(time.Second).String()
	}
	log.Printf("[fail-closed] class=%s subject=%s phase=%s blocker=%q age=%s awaiting=%q",
		class, subject, phase, blocker, ageField, release)
}

// deletionAcceptedAge reports how long a deletion has been durably accepted, used as the age
// of an awaiting-declaration wait. It returns 0 when no usable timestamp is journalled rather
// than inventing one.
func deletionAcceptedAge(operation DeletionLifecycleOperation, now time.Time) time.Duration {
	for _, stamp := range []string{operation.CreatedAt, operation.UpdatedAt} {
		if stamp == "" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339, stamp); err == nil {
			if age := now.Sub(parsed); age > 0 {
				return age
			}
		}
	}
	return 0
}

var _ = fmt.Sprintf
