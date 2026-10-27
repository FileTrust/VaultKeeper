package main

import (
	"fmt"
	"time"
)

// A.2.5 cross-authority per-partition freeze ownership + bounded fairness (Part 4.3, Option A:
// a single protected on-chain frozen slot per partition).
//
// The frozen slot (frozenSnapshots[pKey]) is one slot per partition, held from a successful
// freeze through submit or abandon. Capacity-epoch proofs and deletion-successor proofs both
// need it, so on a contended partition they must be serialized fairly. This arbiter is the
// PURE decision at the heart of that: given the current slot holder and the durable fairness
// inputs, it decides which authority may claim/hold the slot right now. It performs no I/O —
// all inputs are gathered from durable state (queue, deletion journal, capacity epoch/lag,
// on-chain declaration) by gatherPartitionFreezeInputs, so the decision is deterministic and
// survives restart.
//
// Guarantees:
//   - deletion declaration is independent of the slot (it is never arbitrated here);
//   - a FIFO-owner deletion has default priority for the slot;
//   - capacity self-abandons promptly when its held member is excluded;
//   - capacity may age ahead of a later deletion ONLY when its own deadline or hard
//     mutation-lag bound requires progress, and never past the deletion's applicable safety
//     bound (declaration SLA for accepted_queued, dispute-grace for declared_pending);
//   - an accepted_queued deletion past its declaration SLA overrides capacity aging;
//   - neither authority attempts a freeze while the other holds the slot (no thrash);
//   - starvation is impossible: capacity's own deadline forces its turn, and deletion's
//     default priority + safety bounds force its turn — both bounded by their own deadlines.

type freezeHolder int

const (
	freezeHolderNone freezeHolder = iota
	freezeHolderCapacity
	freezeHolderDeletion
)

func (h freezeHolder) String() string {
	switch h {
	case freezeHolderCapacity:
		return "capacity"
	case freezeHolderDeletion:
		return "deletion"
	default:
		return "none"
	}
}

type deletionLifecycleFreezeState int

const (
	deletionFreezeStateNone deletionLifecycleFreezeState = iota
	deletionFreezeStateAcceptedQueued
	deletionFreezeStateDeclaredPending
)

type freezeDecision int

const (
	freezeDecisionNone freezeDecision = iota
	freezeDecisionGrantCapacity
	freezeDecisionGrantDeletion
	freezeDecisionHolderKeeps
	freezeDecisionCapacityMustAbandon
)

func (d freezeDecision) String() string {
	switch d {
	case freezeDecisionGrantCapacity:
		return "grant-capacity"
	case freezeDecisionGrantDeletion:
		return "grant-deletion"
	case freezeDecisionHolderKeeps:
		return "holder-keeps"
	case freezeDecisionCapacityMustAbandon:
		return "capacity-must-abandon"
	default:
		return "none"
	}
}

// partitionFreezeInputs is the complete, durable-derived state the arbiter reasons over.
type partitionFreezeInputs struct {
	// Current slot holder, derived from the local queue's frozen record authority.
	Holder freezeHolder
	// HolderExcluded is true when the holder is capacity and its member has been excluded
	// on-chain (a deletion declared), so its proof is pointless and it must release the slot.
	HolderExcluded bool

	// A FIFO-owner deletion needs the slot for its successor proof.
	DeletionWantsSlot bool
	DeletionState     deletionLifecycleFreezeState
	// DeletionSLADeadline: latest time an accepted_queued deletion may remain undeclared
	// (durable maximum queue-age / declaration SLA). Zero means unknown/none.
	DeletionSLADeadline time.Time
	// DeletionDisputeDeadline: the DO dispute-grace deadline for a declared_pending deletion.
	DeletionDisputeDeadline time.Time

	// Capacity wants this partition (a member of the pending/active epoch cutoff).
	CapacityWantsSlot bool
	// CapacityQualifiedUrgency means the exact current coordinate is durably owned by a
	// qualified G.4B incremental plan. It wins a still-free slot because that one proof
	// satisfies both the blocked capacity demand and the deletion release dependency.
	CapacityQualifiedUrgency bool
	// CapacityMustStartBy: capacity's own proof deadline (epoch freshness). Zero means none.
	CapacityMustStartBy time.Time
	// CapacityHardLagExceeded: capacity's hard mutation-lag bound is breached.
	CapacityHardLagExceeded bool
	// CapacityFreezeToReleaseEstimate: a CONSERVATIVE upper bound (padded percentile /
	// max-observed, never an average) of the time capacity would hold the single slot if it
	// claimed it now — the full non-preemptible freeze → prove → submit/abandon duration.
	CapacityFreezeToReleaseEstimate time.Duration
	// CapacitySubmissionSafetyMargin: extra chain-submission/finality headroom reserved on top
	// of the hold estimate before the deletion's safety deadline.
	CapacitySubmissionSafetyMargin time.Duration

	// ConsecutiveDeletionGrants is how many times in a row this partition's single slot has
	// gone to a deletion without capacity getting a turn. See capacityIsOwedATurn.
	ConsecutiveDeletionGrants int

	// DeletionQueueDepth is how many unresolved deletions are waiting on this partition's
	// single slot. OBSERVABILITY ONLY -- no arbiter decision may read it, or the decision
	// would stop being a function of the safety bounds alone.
	//
	// It exists to answer a question nobody has measured: how deep do these queues actually
	// get on a real run. A deep queue is the only thing that would justify the contract change
	// needed for several deletions to share one successor proof, since the chain allows just
	// one unresolved deletion per partition today.
	DeletionQueueDepth int
}

// deletionGrantsBeforeCapacityTurn is how many consecutive deletions may take a partition's
// slot before capacity is owed the next one.
//
// WHY A SCHEDULED TURN EXISTS AT ALL
//
// A partition has ONE slot and it is not preemptible, and while a deletion holds it that
// partition's capacity proof cannot run. The chain allows only one unresolved deletion per
// partition (DeletionReleaseSC.unresolvedOperationByPartition) with a strict FIFO counter, so
// deleting many pieces from one partition is necessarily a SERIES of slot holds, roughly two
// minutes each. A partition can hold up to partition-max-sectors x sector-max-pieces pieces,
// so a single honest "delete this whole file" can queue a very long series.
//
// Capacity could already "age ahead" of a deletion (capacityMayAgeAhead), but only once it was
// ALREADY under hard-lag pressure -- that is, only after the damage had started. Meanwhile the
// partition's uncertified bytes keep ageing, and oldest_dirty_hard_lag does not close one
// partition, it closes the WHOLE KEEPER. So a long deletion queue on one partition could shut
// a keeper out of the network entirely, which is what makes this worth bounding rather than
// leaving to the pressure check.
//
// Three is deliberately small. The cost of an extra capacity turn is one proof; the cost of
// being wrong in the other direction is the keeper closing.
const deletionGrantsBeforeCapacityTurn = 3

// deletionSafetyDeadline returns the applicable safety bound for the queued deletion: the
// dispute-grace deadline once declared_pending, otherwise the declaration SLA deadline.
func (in partitionFreezeInputs) deletionSafetyDeadline() time.Time {
	if in.DeletionState == deletionFreezeStateDeclaredPending {
		return in.DeletionDisputeDeadline
	}
	return in.DeletionSLADeadline
}

// capacityMayAgeAhead reports whether capacity may claim the free slot ahead of a queued
// deletion. It requires capacity to be under deadline/hard-lag pressure AND that claiming now
// will not breach the deletion's applicable safety bound; an accepted_queued deletion past
// its declaration SLA always overrides.
func (in partitionFreezeInputs) capacityMayAgeAhead(now time.Time) bool {
	pressed := in.CapacityHardLagExceeded ||
		(!in.CapacityMustStartBy.IsZero() && !now.Before(in.CapacityMustStartBy))
	if !pressed {
		return false
	}
	// An accepted_queued deletion past its declaration SLA overrides capacity aging.
	if in.DeletionState == deletionFreezeStateAcceptedQueued &&
		!in.DeletionSLADeadline.IsZero() && !now.Before(in.DeletionSLADeadline) {
		return false
	}
	return in.capacityFitsBeforeDeletionSafety(now)
}

// capacityFitsBeforeDeletionSafety reports whether capacity could take the slot now and still
// be done before the queued deletion's own safety bound.
//
// Capacity's work is NON-PREEMPTIBLE while it owns the single slot, so it must reserve the
// COMPLETE hold duration plus a submission safety margin and still finish strictly before the
// deletion's applicable safety deadline. An unknown deadline fails safe (deletion wins).
func (in partitionFreezeInputs) capacityFitsBeforeDeletionSafety(now time.Time) bool {
	safety := in.deletionSafetyDeadline()
	if safety.IsZero() {
		return false
	}
	return now.Add(in.CapacityFreezeToReleaseEstimate + in.CapacitySubmissionSafetyMargin).Before(safety)
}

// capacityIsOwedATurn reports whether capacity has waited out enough consecutive deletion
// grants on this partition to be given the next free slot.
//
// It reuses the SAME safety bound as capacityMayAgeAhead: a scheduled turn never lets capacity
// run past a deletion's dispute or declaration deadline, because missing a declared deletion's
// window is a worse failure than a late capacity proof. The only thing this changes is the
// TRIGGER -- capacity no longer has to already be in hard lag to get a turn, which is what let
// a long deletion queue drive the whole keeper into oldest_dirty_hard_lag before capacity was
// ever considered.
//
// An accepted_queued deletion past its own declaration SLA still overrides, exactly as it
// overrides capacity aging ahead.
func (in partitionFreezeInputs) capacityIsOwedATurn(now time.Time) bool {
	if in.ConsecutiveDeletionGrants < deletionGrantsBeforeCapacityTurn {
		return false
	}
	if in.DeletionState == deletionFreezeStateAcceptedQueued &&
		!in.DeletionSLADeadline.IsZero() && !now.Before(in.DeletionSLADeadline) {
		return false
	}
	return in.capacityFitsBeforeDeletionSafety(now)
}

// arbitratePartitionFreeze is the pure decision. It never performs I/O.
func arbitratePartitionFreeze(in partitionFreezeInputs, now time.Time) (freezeDecision, string) {
	switch in.Holder {
	case freezeHolderCapacity:
		if in.HolderExcluded {
			return freezeDecisionCapacityMustAbandon, "capacity member excluded on-chain; release the slot promptly"
		}
		return freezeDecisionHolderKeeps, "capacity holds the slot; other authority must not attempt a freeze"
	case freezeHolderDeletion:
		return freezeDecisionHolderKeeps, "deletion holds the slot; capacity must not attempt a freeze"
	}
	// The slot is free.
	if in.DeletionWantsSlot {
		if in.CapacityWantsSlot && in.CapacityQualifiedUrgency {
			return freezeDecisionGrantCapacity, "qualified lifecycle urgency owns the free successor slot"
		}
		if in.CapacityWantsSlot && in.capacityMayAgeAhead(now) {
			return freezeDecisionGrantCapacity, "capacity aging ahead within the deletion's safety bound"
		}
		// A long deletion queue on ONE partition must not be able to close the whole keeper.
		// Deletion still has priority; it simply cannot hold the slot indefinitely while the
		// partition's uncertified bytes age into oldest_dirty_hard_lag.
		if in.CapacityWantsSlot && in.capacityIsOwedATurn(now) {
			return freezeDecisionGrantCapacity, fmt.Sprintf(
				"capacity's scheduled turn after %d consecutive deletion grants",
				in.ConsecutiveDeletionGrants)
		}
		return freezeDecisionGrantDeletion, "deletion FIFO owner has priority for the free slot"
	}
	if in.CapacityWantsSlot {
		return freezeDecisionGrantCapacity, "capacity may take the free slot; no deletion contends"
	}
	return freezeDecisionNone, "no authority currently needs the slot"
}

// freezeAuthorityMayProceed maps an arbiter decision to whether the CALLER (which knows its
// own authority) may proceed with a freeze right now. It is the anti-thrash gate: while the
// other authority holds the slot the caller is told to defer, so it never repeatedly attempts
// a freeze that would revert "snapshot already frozen".
func freezeAuthorityMayProceed(decision freezeDecision, holder, me freezeHolder) bool {
	switch decision {
	case freezeDecisionNone:
		return true
	case freezeDecisionHolderKeeps:
		return holder == me
	case freezeDecisionCapacityMustAbandon:
		// Capacity proceeds to run its self-abandon; deletion defers until the slot frees.
		return me == freezeHolderCapacity
	case freezeDecisionGrantCapacity:
		return me == freezeHolderCapacity
	case freezeDecisionGrantDeletion:
		return me == freezeHolderDeletion
	default:
		return false
	}
}

// A.2.5 fairness tunables (deterministic → restart-stable). The declaration SLA bounds how
// long an accepted_queued deletion may wait before it overrides capacity aging; the
// freeze-to-release estimate is a CONSERVATIVE upper bound of the non-preemptible slot-hold
// duration; the submission safety margin is the extra chain headroom reserved on top of it.
// The dispute grace is chain-sourced at gather time (proof-period) — no local grace constant.
var (
	deletionDeclarationSLA          = 30 * time.Minute
	capacityFreezeToReleaseEstimate = 10 * time.Minute
	capacitySubmissionSafetyMargin  = 2 * time.Minute
)

// freezeChainOracle exposes the authoritative on-chain facts the arbiter's inputs must be
// reconciled against, so the holder / exclusion / declaration deadline never rely on local
// state alone (which can be stale, lost, corrupted, or absent after a crash). It is an
// interface so tests can inject deterministic chain truth for the mismatch scenarios.
// freezeSlotIdentity is the authoritative on-chain frozen-slot A.0 identity, INCLUDING the
// per-partition frozenSnapshotNonce (a later freeze/reanchor of the same authority+content gets
// a distinct nonce, so the nonce is what distinguishes this exact freeze from any other).
type freezeSlotIdentity struct {
	Exists         bool
	ProofEpochID   uint64
	ContentVersion uint64
	ContentHash    string
	SnapshotNonce  uint64
}

type freezeChainOracle interface {
	// FrozenSlot reports the authoritative on-chain frozen slot A.0 identity for a partition.
	FrozenSlot(partition PartitionMeta) (freezeSlotIdentity, error)
	// DeletionDeclared reports chain-confirmed declaration for a deletion commitment.
	DeletionDeclared(commitment string) (bool, error)
	// ChainClock reports the current chain timestamp and the chain-sourced dispute grace
	// seconds (proof period), so the declared_pending deadline is anchored to chain time.
	ChainClock() (nowUnix int64, graceSeconds int64, err error)
	// ConfirmedSenderNonce reports the VK sender's confirmed transaction count, used to prove
	// whether an in-flight freeze's nonce has been consumed (its tx mined) — the authority for
	// resolving an ambiguous broadcast, never the claim TTL.
	ConfirmedSenderNonce() (uint64, error)
}

// gatherPartitionFreezeInputs assembles the arbiter inputs, reconciling the slot holder,
// member exclusion, and the declared_pending deadline against ON-CHAIN TRUTH via the oracle,
// while taking FIFO ownership and capacity pressure from durable local journals. Local
// timestamps are clamped to chain time (no future/rollback), and unknown deadlines fail safe
// (the deletion is protected). The result is deterministic given the same chain facts, so it
// is restart-stable.
func gatherPartitionFreezeInputs(storage string, oracle freezeChainOracle, partition PartitionMeta, now time.Time) (partitionFreezeInputs, error) {
	var in partitionFreezeInputs
	dl, pt := partition.DeadlineIndex, partition.PartitionIndex

	// Holder from ON-CHAIN frozenSnapshots[pKey] truth (not the possibly-stale local record).
	slot, err := oracle.FrozenSlot(partition)
	if err != nil {
		return in, err
	}
	if slot.Exists {
		if slot.ProofEpochID&standaloneDeletionProofFlag != 0 {
			in.Holder = freezeHolderDeletion
		} else if slot.ProofEpochID != 0 {
			in.Holder = freezeHolderCapacity
		}
	}

	// Deletion FIFO owner (durable) + lifecycle state + chain-anchored safety deadline.
	// The candidate list is read here anyway, so its length is the real queue depth for free:
	// how many unresolved deletions are waiting on this one partition's single slot.
	// Observability only -- no decision reads it.
	if candidates, depthErr := deletionPartitionSuccessorCandidates(storage, dl, pt); depthErr == nil {
		in.DeletionQueueDepth = len(candidates)
	}
	ownerCommit, owned, err := deletionPartitionSuccessorOwner(storage, dl, pt)
	if err != nil {
		return in, err
	}
	if owned {
		op, ok, readErr := readDeletionLifecycleOperation(storage, ownerCommit)
		if readErr != nil {
			return in, readErr
		}
		if ok && !deletionPhaseAtLeast(op.Phase, "confirmed") {
			in.DeletionWantsSlot = true
			// Confirm declaration against chain truth, not just the local phase.
			declaredOnChain, decErr := oracle.DeletionDeclared(ownerCommit)
			if decErr != nil {
				return in, decErr
			}
			if declaredOnChain {
				in.DeletionState = deletionFreezeStateDeclaredPending
				chainNow, graceSeconds, clkErr := oracle.ChainClock()
				if clkErr != nil {
					return in, clkErr
				}
				// Anchor the dispute deadline to CHAIN time: elapsed grace is measured on
				// chain, and the local DeclaredAtUnix is clamped so it can never be in the
				// future relative to chain. The remaining grace is expressed in the host
				// `now` frame the arbiter compares against.
				declaredRef := op.DeclaredAtUnix
				if declaredRef <= 0 || declaredRef > chainNow {
					declaredRef = chainNow
				}
				remaining := time.Duration(graceSeconds-(chainNow-declaredRef)) * time.Second
				if remaining < 0 {
					remaining = 0
				}
				in.DeletionDisputeDeadline = now.Add(remaining)
			} else {
				in.DeletionState = deletionFreezeStateAcceptedQueued
				// Declaration SLA from the durable acceptance time; reject a future
				// CreatedAt (clock rollback) → leave the deadline zero (fail safe).
				if created := parseSnapshotTime(op.CreatedAt); !created.IsZero() && !created.After(now) {
					in.DeletionSLADeadline = created.Add(deletionDeclarationSLA)
				}
			}
		}
	}

	// Starvation count carried in the durable claim record, written under this same
	// per-partition flock on every grant. Absent record means no debt.
	if claim, found, claimErr := readFreezeClaimUnlocked(
		storage, partition.PartitionKind, dl, pt,
	); claimErr != nil {
		return in, claimErr
	} else if found {
		in.ConsecutiveDeletionGrants = claim.ConsecutiveDeletionGrants
	}

	// A capacity holder whose FIFO deletion is CHAIN-CONFIRMED declared is excluded on-chain
	// and must self-abandon. The abandon path re-verifies on-chain before acting.
	urgentOwner, urgencyErr := qualifiedUrgencyPlanOwnsPartition(storage, partition)
	if urgencyErr != nil {
		return in, urgencyErr
	}
	in.CapacityQualifiedUrgency = urgentOwner
	if in.Holder == freezeHolderCapacity && in.DeletionState == deletionFreezeStateDeclaredPending && !urgentOwner {
		in.HolderExcluded = true
	}

	// Capacity pressure from the durable proof-lag snapshot.
	in.CapacityFreezeToReleaseEstimate = capacityFreezeToReleaseEstimate
	in.CapacitySubmissionSafetyMargin = capacitySubmissionSafetyMargin
	if lag, ok, lagErr := readCapacityProofLagSnapshot(storage); lagErr != nil {
		return in, lagErr
	} else if ok {
		in.CapacityWantsSlot = lag.PendingMutations > 0 || in.Holder == freezeHolderCapacity
		in.CapacityHardLagExceeded = lag.Breached
		if lag.MutationDeadlineUnix > 0 {
			in.CapacityMustStartBy = time.Unix(lag.MutationDeadlineUnix, 0)
		}
	} else if in.Holder == freezeHolderCapacity {
		in.CapacityWantsSlot = true
	}
	if urgentOwner {
		in.CapacityWantsSlot = true
	}
	return in, nil
}
