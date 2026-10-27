package main

// G.4B — qualified lifecycle urgency.
//
// This activates the G.3 scheduler input `QualifiedLifecycleUrgency`, which has defaulted false
// since G.3. The frozen conjunction is mandatory in all four parts:
//
//	unresolved exact deletion-release obligation
//	AND normal selected-work completion would miss its lifecycle deadline
//	AND a real pending admission request remains pending
//	AND completing this release would make that request fit
//
// Anything less produces no urgency. In particular: deadline pressure alone does not qualify, a
// pending demand alone does not qualify, and a release that only narrows the shortfall without
// closing it does not qualify.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// TriggerQualifiedLifecycleUrgency is the G.4B batch trigger reason.
const TriggerQualifiedLifecycleUrgency BatchTriggerReason = "qualified_lifecycle_urgency"

// ReleaseObligation is one unresolved G.4 deletion-release obligation, read from bound chain
// state. `AuthoritativeReleaseBytes` is DERIVED on chain as
// predecessorCommittedBytes − successorCommittedBytes for the exact current revision; an
// off-chain claimed freedBytes is never accepted.
type ReleaseObligation struct {
	OperationID string
	Revision    uint64

	// Route: deletionReleaseAwaitingSuccessorProof means an active successor snapshot proof is
	// required. An empty-transition obligation requires no proof and must never open a campaign.
	RequiresActiveSuccessorProof bool
	EmptyTransition              bool

	State            uint8
	RecoveryRequired bool // quarantined

	// SuccessorIdentity is the ONE exact partition identity the obligation needs proved.
	// Its PartitionKey is the LOCAL `kind:deadline:partition` coordinate, matching durable plans
	// and the G.3 selected-work estimate. The chain's bytes32 identity is kept separately below;
	// the two domains must never be compared with each other.
	SuccessorIdentity PartitionIdentity
	// SuccessorChainPartitionKey is the exact DeletionReleaseSC/StorageProofSC bytes32 identity
	// the successor was resolved from, retained for auditing and exact-membership checks.
	SuccessorChainPartitionKey string
	// AuthoritativeReleaseBytes is derived from chain state, never from a caller claim.
	AuthoritativeReleaseBytes uint64

	// LifecycleDeadline is authoritative and finite: declaredAt + graceSeconds from the
	// on-chain DeletionRecord, or another already-authoritative contract-derived deadline.
	LifecycleDeadline time.Time
	// DeadlineAuthoritative is false when no finite contract-derived deadline exists. G.4B
	// never invents one.
	DeadlineAuthoritative bool
}

// eligible applies the frozen obligation rules. Every one is mandatory.
func (o ReleaseObligation) eligible(now time.Time) (bool, string) {
	if strings.TrimSpace(o.OperationID) == "" {
		return false, "obligation has no operation id"
	}
	if o.RecoveryRequired {
		return false, "obligation is quarantined"
	}
	if o.State == deletionReleaseSatisfied || o.State == deletionReleaseConfirmed {
		return false, "obligation is already satisfied or confirmed"
	}
	if o.State == deletionReleaseAwaitingSuccessorIdentity {
		// AwaitingSuccessorIdentity alone is not enough: there is no exact identity to select.
		return false, "obligation is still awaiting its successor identity"
	}
	if o.EmptyTransition || !o.RequiresActiveSuccessorProof {
		// An empty transition needs no snapshot proof, so it must never open a capacity
		// campaign — there is no proof work that would advance it.
		return false, "empty-transition obligation requires no snapshot proof"
	}
	if strings.TrimSpace(o.SuccessorIdentity.PartitionKey) == "" ||
		o.SuccessorIdentity.ContentHash == "" {
		return false, "obligation does not expose one exact successor identity"
	}
	if !o.DeadlineAuthoritative || o.LifecycleDeadline.IsZero() {
		return false, "obligation has no authoritative finite lifecycle deadline"
	}
	if o.AuthoritativeReleaseBytes == 0 {
		return false, "obligation releases no ledger bytes"
	}
	return true, ""
}

// ProjectedAdmission is the block-pinned G.5 observation plus the projection for one obligation.
type ProjectedAdmission struct {
	ObservationBlock uint64
	// ObservationTimestampUnix is the timestamp of ObservationBlock. Lifecycle deadlines are
	// contract timestamps, so production comparisons must remain in this same chain-clock
	// domain instead of silently mixing them with the host wall clock.
	ObservationTimestampUnix int64

	DeclaredCapacity   uint64
	LedgerFree         uint64
	RingFresh          uint64
	ActiveReservations uint64
	AdmissionMargin    uint64

	CurrentSafeAllocatable uint64

	ProjectedLedgerFree         uint64
	ProjectedFreshCertifiedFree uint64
	ProjectedSafeAllocatable    uint64
	// RingLimited is true when the certification ring, not the ledger, caps the projection —
	// in which case the deletion cannot help.
	RingLimited bool
}

// projectAdmissionAfterRelease applies the frozen equations with saturating arithmetic.
//
//	projectedLedgerFree         = min(declaredCapacity, ledgerFree + authoritativeReleaseBytes)
//	projectedFreshCertifiedFree = min(ringFresh, projectedLedgerFree)
//	projectedSafeAllocatable    = projectedFreshCertifiedFree - activeReservations - admissionMargin
func projectAdmissionAfterRelease(
	observation ProjectedAdmission, releaseBytes uint64,
) ProjectedAdmission {
	projected := observation

	ledger := observation.LedgerFree
	if releaseBytes > math.MaxUint64-ledger {
		ledger = math.MaxUint64
	} else {
		ledger += releaseBytes
	}
	if ledger > observation.DeclaredCapacity {
		ledger = observation.DeclaredCapacity
	}
	projected.ProjectedLedgerFree = ledger

	fresh := ledger
	if observation.RingFresh < fresh {
		fresh = observation.RingFresh
		projected.RingLimited = true
	}
	projected.ProjectedFreshCertifiedFree = fresh

	safe := fresh
	if observation.ActiveReservations >= safe {
		safe = 0
	} else {
		safe -= observation.ActiveReservations
	}
	if observation.AdmissionMargin >= safe {
		safe = 0
	} else {
		safe -= observation.AdmissionMargin
	}
	projected.ProjectedSafeAllocatable = safe
	return projected
}

// materiallySatisfies is the frozen exactness test: the deletion must make THIS request
// admissible. A release that only reduces the shortfall does not qualify.
func materiallySatisfies(demand BlockedAdmissionDemand, projection ProjectedAdmission) bool {
	if demand.RequestedBytes <= projection.CurrentSafeAllocatable {
		return false // already admissible; no urgency is created by capacity
	}
	return demand.RequestedBytes <= projection.ProjectedSafeAllocatable
}

// ─── the evaluation ────────────────────────────────────────────────────────────────────

// QualifiedUrgencyInput is everything the evaluation needs. All of it is read, never invented.
type QualifiedUrgencyInput struct {
	Observation ProjectedAdmission
	Obligations []ReleaseObligation
	Demands     []BlockedAdmissionDemand

	// NormalCompletion is the frozen G.3 estimate for the exact selected successor:
	// activeCampaignRemaining + cumulativePendingDurationAhead + selectedBatchEstimatedDuration
	// + selectedQueueDelay. Supplied per obligation identity by the caller.
	NormalCompletion func(identity PartitionIdentity) (time.Duration, bool)

	// ActiveCampaignMembers are the identities already frozen into the active campaign. A
	// member already selected is never duplicated.
	ActiveCampaignMembers map[string]struct{}

	// Now is the VK-local request clock used for the local blocked-demand lifetime.
	Now time.Time
	// LifecycleNow is the timestamp of the block-pinned chain observation used only for
	// contract lifecycle deadlines. It defaults to Now for direct/unit callers.
	LifecycleNow time.Time
}

// QualifiedUrgencyResult is the typed outcome.
type QualifiedUrgencyResult struct {
	Qualified bool

	// SelectedIdentity is the ONE exact successor identity to prove.
	SelectedIdentity PartitionIdentity
	OperationID      string
	// AlreadySelected is true when the identity is already in the active campaign, in which
	// case urgency holds but nothing new is scheduled.
	AlreadySelected bool

	MatchedDemands   int
	MatchedDemandIDs []string

	NormalCompletion  time.Duration
	LifecycleDeadline time.Time
	Projection        ProjectedAdmission

	// Reason explains a negative result. Never surfaced as a launch reason.
	Reason string
}

// EvaluateQualifiedLifecycleUrgency applies the frozen four-part conjunction.
//
// Deterministic ordering: earliest lifecycle deadline → oldest still-pending demand →
// operation id / demand id tie-break. One release proof may satisfy several demands in
// projection, but it is scheduled once.
func EvaluateQualifiedLifecycleUrgency(input QualifiedUrgencyInput) QualifiedUrgencyResult {
	lifecycleNow := input.LifecycleNow
	if lifecycleNow.IsZero() {
		lifecycleNow = input.Now
	}
	// (3) a real pending admission request must remain pending
	pending := make([]BlockedAdmissionDemand, 0, len(input.Demands))
	for _, demand := range input.Demands {
		if DemandStillPending(demand, input.Now) {
			pending = append(pending, demand)
		}
	}
	if len(pending) == 0 {
		return QualifiedUrgencyResult{Reason: "no pending blocked demand"}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].CreatedAtUnix != pending[j].CreatedAtUnix {
			return pending[i].CreatedAtUnix < pending[j].CreatedAtUnix
		}
		return pending[i].DemandID < pending[j].DemandID
	})

	// (1) unresolved exact obligations, earliest lifecycle deadline first
	eligible := make([]ReleaseObligation, 0, len(input.Obligations))
	for _, obligation := range input.Obligations {
		if ok, _ := obligation.eligible(lifecycleNow); ok {
			eligible = append(eligible, obligation)
		}
	}
	if len(eligible) == 0 {
		return QualifiedUrgencyResult{Reason: "no eligible unresolved release obligation"}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if !eligible[i].LifecycleDeadline.Equal(eligible[j].LifecycleDeadline) {
			return eligible[i].LifecycleDeadline.Before(eligible[j].LifecycleDeadline)
		}
		return eligible[i].OperationID < eligible[j].OperationID
	})

	lastReason := "no obligation satisfies the frozen conjunction"
	for _, obligation := range eligible {
		// (4) completing THIS release must make a pending request fit
		projection := projectAdmissionAfterRelease(
			input.Observation, obligation.AuthoritativeReleaseBytes)

		matched := make([]string, 0, len(pending))
		for _, demand := range pending {
			if materiallySatisfies(demand, projection) {
				matched = append(matched, demand.DemandID)
			}
		}
		if len(matched) == 0 {
			if projection.RingLimited &&
				projection.ProjectedFreshCertifiedFree == input.Observation.RingFresh {
				lastReason = "certification ring remains the limiting factor"
			} else {
				lastReason = "release does not make any pending request admissible"
			}
			continue
		}

		// (2) normal completion must MISS the lifecycle deadline
		completion, ok := durationOrConservative(input.NormalCompletion, obligation.SuccessorIdentity)
		if !ok {
			lastReason = "selected-work completion estimate unavailable"
			continue
		}
		completionTime := lifecycleNow.Add(completion)
		if !completionTime.After(obligation.LifecycleDeadline) {
			lastReason = "normal completion already meets the lifecycle deadline"
			continue
		}

		key := strings.ToLower(strings.TrimSpace(obligation.SuccessorIdentity.PartitionKey))
		_, already := input.ActiveCampaignMembers[key]
		return QualifiedUrgencyResult{
			Qualified:         true,
			SelectedIdentity:  obligation.SuccessorIdentity,
			OperationID:       obligation.OperationID,
			AlreadySelected:   already,
			MatchedDemands:    len(matched),
			MatchedDemandIDs:  matched,
			NormalCompletion:  completion,
			LifecycleDeadline: obligation.LifecycleDeadline,
			Projection:        projection,
		}
	}
	return QualifiedUrgencyResult{Reason: lastReason}
}

// durationOrConservative resolves the G.3 completion estimate. A missing or corrupt estimate
// uses the configured conservative fallback rather than failing the whole evaluation, but a
// resolver that reports outright failure yields no urgency.
func durationOrConservative(
	resolver func(PartitionIdentity) (time.Duration, bool), identity PartitionIdentity,
) (time.Duration, bool) {
	if resolver == nil {
		return defaultColdStartMemberDuration, true
	}
	completion, ok := resolver(identity)
	if !ok {
		return 0, false
	}
	if completion <= 0 {
		return defaultColdStartMemberDuration, true
	}
	return completion, true
}

// ─── scheduler integration ─────────────────────────────────────────────────────────────

// qualifiedUrgencyDecision converts a qualified result into the frozen scheduler outcome:
//
//	QualifiedLifecycleUrgency = true
//	BatchTriggerReason = qualified_lifecycle_urgency
//	CampaignMode = incremental
//	SelectedPlanValid = true
//	FullSweepReason = none
func qualifiedUrgencyDecision(
	result QualifiedUrgencyResult, estimate SelectedWorkEstimate,
) CapacityStartDecision {
	decision := readyIncremental(estimate, TriggerQualifiedLifecycleUrgency)
	decision.Detail = fmt.Sprintf(
		"qualified lifecycle urgency: op=%s demands=%d completion=%s deadline=%s",
		result.OperationID, result.MatchedDemands,
		result.NormalCompletion.Round(time.Second),
		result.LifecycleDeadline.UTC().Format(time.RFC3339))
	return decision
}

// LogFields renders the aggregate-only observability surface. No demand identifier, capability
// token, requester reference, file identity or commitment hash is ever included.
func (r QualifiedUrgencyResult) LogFields() map[string]any {
	fields := map[string]any{
		"qualifiedLifecycleUrgency": r.Qualified,
		"qualifiedUrgencyCount":     r.MatchedDemands,
	}
	if r.Qualified {
		fields["batchTriggerReason"] = string(TriggerQualifiedLifecycleUrgency)
		fields["campaignMode"] = string(CampaignModeIncremental)
		fields["selectedPlanValid"] = true
		fields["fullSweepReason"] = string(FullSweepNone)
		fields["alreadySelected"] = r.AlreadySelected
		fields["normalCompletionSeconds"] = int64(r.NormalCompletion / time.Second)
		fields["projectedSafeAllocatable"] = r.Projection.ProjectedSafeAllocatable
		fields["currentSafeAllocatable"] = r.Projection.CurrentSafeAllocatable
	} else {
		fields["notQualifiedReason"] = r.Reason
	}
	return fields
}
