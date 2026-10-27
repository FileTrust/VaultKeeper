package main

// Throttled reporting for prover-lane overload.
//
// The lane admission check runs on every scan -- several times a second -- and
// logged its verdict every time. A single 45-second episode produced ~150
// near-identical lines, differing only in a countdown:
//
//   [proof-lane x] overload: storage proof work alone is infeasible by deadline
//                  ...: requires 2m0s, 1m59s available
//   [proof-lane x] overload: ... requires 2m0s, 1m59s available
//   [proof-lane x] overload: ... requires 2m0s, 1m58s available
//
// That volume buries the lines that matter (the work did complete, two minutes
// later, and nothing in the flood said so). Worse, it reads like a fault when
// it is an ordinary scheduling verdict: the lane is busy, this job cannot fit
// before its deadline, try again next scan.
//
// So: report an episode when it starts, repeat at most every 30s while it
// lasts, and say when it clears -- with how long it ran and how many checks it
// covered, which is the part an operator actually needs.

import (
	"log"
	"strings"
	"sync"
	"time"
)

const proofLaneOverloadRepeat = 30 * time.Second

type proofLaneOverloadReporter struct {
	mu         sync.Mutex
	active     bool
	reason     string
	since      time.Time
	lastLog    time.Time
	checks     int
	suppressed int
}

var proofLaneOverload proofLaneOverloadReporter

// reportProofLaneOverload records one lane verdict and logs only when the
// operator learns something: a new episode, a changed reason, a periodic
// reminder, or the end of an episode.
func reportProofLaneOverload(overloaded bool, reason string, now time.Time) {
	proofLaneOverload.report(overloaded, reason, now)
}

func (s *proofLaneOverloadReporter) report(overloaded bool, reason string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !overloaded {
		if s.active {
			log.Printf(
				"[proof-lane] overload cleared after %s (%d checks); proof work resumes",
				now.Sub(s.since).Round(time.Second), s.checks,
			)
		}
		s.active, s.reason, s.checks, s.suppressed = false, "", 0, 0
		return
	}

	// The reason text carries a live countdown ("1m59s available"), so comparing
	// it whole would defeat the throttle entirely -- every scan differs. Compare
	// the part before the countdown instead.
	key := overloadReasonKey(reason)

	if !s.active {
		s.active, s.reason, s.since = true, key, now
		s.checks, s.suppressed = 1, 0
		s.lastLog = now
		log.Printf("[proof-lane] overload: %s", reason)
		return
	}

	s.checks++
	if key != s.reason {
		s.reason, s.lastLog, s.suppressed = key, now, 0
		log.Printf("[proof-lane] overload changed: %s", reason)
		return
	}
	if now.Sub(s.lastLog) >= proofLaneOverloadRepeat {
		log.Printf(
			"[proof-lane] overload continuing for %s (%d checks): %s",
			now.Sub(s.since).Round(time.Second), s.checks, reason,
		)
		s.lastLog, s.suppressed = now, 0
		return
	}
	s.suppressed++
}

// overloadReasonKey strips the trailing "N available" countdown so that one
// episode is recognised as one episode.
func overloadReasonKey(reason string) string {
	if idx := strings.LastIndex(reason, ", "); idx > 0 {
		return reason[:idx]
	}
	return reason
}
