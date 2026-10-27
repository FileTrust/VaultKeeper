package main

// TEMPORAL LIVENESS for deadline-consuming scheduling decisions.
//
// Correct deadline arithmetic is only half of a convergence guarantee. Smoke 9 fixed the
// arithmetic (`OldestPendingMutationAge`, `RebindLatestSafeStart`, successor own-service
// duration). Smoke 10 then showed the other half is a separate property:
//
//	a decision that returns WAIT / NOT_DUE / DEFER while deadline-bearing work is pending
//	must have (1) a guaranteed reevaluation before the binding deadline, and
//	          (2) an identifiable owner that will make progress on that work.
//
// Smoke 10 VK2 satisfied (1) — the proof-daemon scan re-entered
// `capacityProofEpochStartReadyWithConfig` every ~20 s for 18 minutes — and violated (2): two
// applied store mutations on data:30:0 were already exact-current-certified on chain, so
// selection correctly produced zero proof members, and the terminal reconciler refused them on
// a cardinality guard. The decision was therefore `not_due` with `no_exact_selected_work`
// forever, and that reason was not matched by either of the scheduler's two log predicates, so
// the whole 18-minute wedge produced NOT ONE log line. It looked like the scheduler had stopped
// running.
//
// This file makes both halves explicit and observable. It computes nothing from live state
// itself: it is a pure classification over inputs the scheduler already has every scan, which
// is what lets an independent oracle check it in a property test.

import (
	"fmt"
	"time"
)

// capacityWaitLivenessClass names WHO is expected to make progress on the pending
// deadline-bearing work while the start decision waits.
type capacityWaitLivenessClass string

const (
	// capacityWaitNotWaiting — the decision is ready; this is not a wait state.
	capacityWaitNotWaiting capacityWaitLivenessClass = "not_waiting"
	// capacityWaitNoPendingWork — nothing carries a deadline, so waiting is free.
	capacityWaitNoPendingWork capacityWaitLivenessClass = "no_pending_deadline_work"
	// capacityWaitOwnedBySelectedPlan — a frozen selected plan exists; the batch trigger
	// (including hard_lag_latest_start) opens it. This is ordinary healthy batching.
	capacityWaitOwnedBySelectedPlan capacityWaitLivenessClass = "owned_by_selected_plan"
	// capacityWaitOwnedByRecovery — the decision failed closed with an explicit recovery
	// owner, which the same scan re-drives.
	capacityWaitOwnedByRecovery capacityWaitLivenessClass = "owned_by_recovery"
	// capacityWaitUnownedPendingWork — pending deadline-bearing work exists, the decision
	// waits, and NO selected plan and NO recovery owner exists for it. Nothing inside the
	// scheduler will change this state. It is legitimate briefly (a mutation whose partition
	// registration has not yet landed on chain) and is the exact Smoke-10 wedge when it
	// persists. Always reported.
	capacityWaitUnownedPendingWork capacityWaitLivenessClass = "unowned_pending_deadline_work"
)

// capacityStartWaitLiveness is the typed verdict for one WAIT decision.
type capacityStartWaitLiveness struct {
	Class            capacityWaitLivenessClass
	PendingMutations int
	OldestPendingAge time.Duration
	HardLagLimit     time.Duration
	// RemainingToDeadline is the binding latest-safe-start budget: how long the decision may
	// still wait before the oldest pending mutation can no longer be certified in time. It is
	// negative once the deadline is already unmeetable.
	RemainingToDeadline time.Duration
	// MaxReevaluationDelay is the GUARANTEED upper bound on when this decision runs again with
	// no external workload and no new request. For the capacity start decision this is the
	// proof-daemon scan cadence, which has no next-attempt gate above it.
	MaxReevaluationDelay time.Duration
	// ReevaluationBounded is the temporal-liveness invariant itself:
	//     nextEvaluationTime(W) <= latestSafeStart(W)
	ReevaluationBounded bool
	// DeadlineUnmeetable reports that no reevaluation cadence could have met the deadline. The
	// scheduler must then add no further discretionary wait, and admission must stay truthful.
	DeadlineUnmeetable bool
	// ProgressOwned reports whether an owner exists for the pending work.
	ProgressOwned bool
	Detail        string
}

// Healthy is true only when BOTH halves hold: a bounded reevaluation and an owner.
// A already-unmeetable deadline is not counted as an unbounded-reevaluation defect — no
// cadence could have met it — but it is never counted as healthy either.
func (l capacityStartWaitLiveness) Healthy() bool {
	switch l.Class {
	case capacityWaitNotWaiting, capacityWaitNoPendingWork:
		return true
	}
	return l.ProgressOwned && l.ReevaluationBounded && !l.DeadlineUnmeetable
}

// evaluateCapacityStartWaitLiveness classifies one start decision against the durable lag
// snapshot the scheduler refreshed on the same scan.
//
// maxReevaluationDelay is the guaranteed worst-case interval before this decision is evaluated
// again with NO new external work — for the capacity start decision, the proof-daemon poll
// cadence. Passing zero means "no guaranteed reevaluation", which can never be bounded.
func evaluateCapacityStartWaitLiveness(
	decision CapacityStartDecision,
	lag capacityProofLagSnapshot,
	maxReevaluationDelay time.Duration,
) capacityStartWaitLiveness {
	verdict := capacityStartWaitLiveness{
		PendingMutations:     lag.PendingMutations,
		OldestPendingAge:     time.Duration(lag.OldestMutationAgeNanos),
		HardLagLimit:         time.Duration(lag.MaximumLagNanos),
		MaxReevaluationDelay: maxReevaluationDelay,
	}
	if decision.Ready {
		verdict.Class = capacityWaitNotWaiting
		verdict.ProgressOwned = true
		verdict.ReevaluationBounded = true
		return verdict
	}
	if lag.PendingMutations <= 0 {
		verdict.Class = capacityWaitNoPendingWork
		verdict.ProgressOwned = true
		verdict.ReevaluationBounded = true
		return verdict
	}
	verdict.RemainingToDeadline = verdict.HardLagLimit - verdict.OldestPendingAge
	verdict.DeadlineUnmeetable = verdict.RemainingToDeadline <= 0
	verdict.ReevaluationBounded = maxReevaluationDelay > 0 &&
		maxReevaluationDelay <= verdict.RemainingToDeadline

	switch {
	case decision.RecoveryRequired:
		verdict.Class = capacityWaitOwnedByRecovery
		verdict.ProgressOwned = true
		verdict.Detail = string(decision.FailureClass)
	case decision.Estimate.SelectedPartitionCount > 0 && decision.SelectedPlanValid:
		verdict.Class = capacityWaitOwnedBySelectedPlan
		verdict.ProgressOwned = true
		verdict.Detail = string(decision.BatchTriggerReason)
	default:
		verdict.Class = capacityWaitUnownedPendingWork
		verdict.ProgressOwned = false
		verdict.Detail = decision.Detail
	}
	return verdict
}

// capacityWaitLivenessLogInterval bounds the steady-state reporting rate of a healthy wait.
// It is deliberately much shorter than the 1800 s hard mutation lag, so a wedge is visible
// with well over an order of magnitude of margin rather than after the fact.
const capacityWaitLivenessLogInterval = 60 * time.Second

// logCapacityWaitLiveness reports whether this verdict should be emitted now.
//
// A class change is always reported immediately — entering `unowned_pending_deadline_work` is
// exactly the transition that had no observable signal in smoke 10. An unhealthy verdict is
// reported on every scan, because by then a real deadline is being consumed. Everything else is
// rate-limited to one line per interval.
func logCapacityWaitLiveness(
	verdict capacityStartWaitLiveness,
	lastClass capacityWaitLivenessClass,
	lastLoggedAt time.Time,
) bool {
	switch verdict.Class {
	case capacityWaitNotWaiting, capacityWaitNoPendingWork:
		return false
	}
	if verdict.Class != lastClass || !verdict.Healthy() {
		return true
	}
	return lastLoggedAt.IsZero() || time.Since(lastLoggedAt) >= capacityWaitLivenessLogInterval
}

func (l capacityStartWaitLiveness) String() string {
	return fmt.Sprintf(
		"class=%s pendingMutations=%d oldestPendingAgeSeconds=%d hardLagSeconds=%d "+
			"remainingToDeadlineSeconds=%d maxReevaluationDelaySeconds=%d reevaluationBounded=%v "+
			"deadlineUnmeetable=%v progressOwned=%v detail=%q",
		l.Class, l.PendingMutations, int64(l.OldestPendingAge/time.Second),
		int64(l.HardLagLimit/time.Second), int64(l.RemainingToDeadline/time.Second),
		int64(l.MaxReevaluationDelay/time.Second), l.ReevaluationBounded,
		l.DeadlineUnmeetable, l.ProgressOwned, l.Detail)
}
