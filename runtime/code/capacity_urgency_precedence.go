package main

// G.4B-LV3 — qualified-urgency precedence over NEW ordinary bulk plan creation.
//
// THE DEFECT THIS CLOSES
//
// LV1 wired the urgency evaluator, but the scheduler consulted it only after
// `ensureCapacityIncrementalPlan` had already frozen the ordinary bulk plan, and only on the
// `!incrementalDue` branch:
//
//	ensureCapacityIncrementalPlan(...)      -> bulk plan freezes
//	liveSelectedWorkDecision(...)           -> haveIncremental = true
//	if incrementalDue { return readyIncremental(...) }        <- returns here
//	qualifiedUrgencyPromotesSelection(...)                    <- only when NOT due
//	qualifiedUrgencyOpensSelection(...)                       <- only when NO plan
//
// A backlog large enough to satisfy G.4B predicate 2 ("normal work would miss the lifecycle
// deadline") is necessarily also `due` — Report D measured `batchTriggerDue = true`,
// `batchTriggerReason = hard_lag_latest_start`. So the very condition that makes urgency correct
// guaranteed the bulk path returned first and urgency was never reached. Both LV1 entry points
// were structurally unreachable at acceptance scale.
//
// THE RULE
//
// Urgency priority applies to exactly one question: WHICH NEW incremental plan should freeze on an
// otherwise ownership-free VK. It is not a general "highest priority" bypass.
//
//	no plan, no campaign, no recovery -> urgency may win and freeze ONE exact member
//	durable plan already frozen        -> membership is immutable; urgency must not touch it
//	active campaign                    -> no rebind, no second campaign, no duplicate ownership
//	recovery / uncertain ownership     -> recovery owns the scheduler; urgency stands down
//
// The G.2 exact-set invariant is untouched: this changes which plan is created, never an existing
// one. Nothing here removes members, replaces a frozen set, rebinds a campaign, or force-unlocks.

import (
	"log"
	"strings"
	"time"
)

// capacityUrgencyPrecedenceResult is the typed outcome of the pre-freeze urgency question.
type capacityUrgencyPrecedenceResult struct {
	// Qualified is true only when an exact one-member urgency plan was frozen.
	Qualified bool
	Decision  CapacityStartDecision
	// Detail explains a negative outcome for observability. Never a launch reason.
	Detail string
}

// capacityUrgencyOwnershipFree reports whether no existing plan, campaign or recovery state owns
// scheduling for this VK. Urgency may only pre-empt NEW bulk plan creation, never existing
// ownership.
func capacityUrgencyOwnershipFree(
	storage string, status CapacityProofEpochStatus,
) (bool, string) {
	if status.Active {
		return false, "an incremental campaign is already active"
	}
	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil {
		// Ambiguous durable plan state is a recovery condition for the normal path to classify.
		return false, "durable plan state unreadable"
	}
	if found && len(plan.Chunks) > 0 {
		return false, "a durable incremental plan already owns the selected set"
	}
	if journal, ok, jerr := readCapacityEpochJournal(storage); jerr == nil && ok {
		switch journal.State {
		case capacityEpochStateOpening, capacityEpochStateActive, capacityEpochStatePrepared:
			return false, "a capacity epoch journal owns recovery for this VK"
		}
	}
	if state, ok, serr := readCapacityIncrementalBatchState(storage); serr == nil && ok &&
		strings.TrimSpace(state.RecoveryState) != "" {
		return false, "capacity batch recovery owns the scheduler"
	}
	return true, ""
}

// evaluateCapacityUrgencyPrecedence answers "should an exact one-member urgency plan freeze
// instead of a new ordinary bulk plan?" and, when the answer is yes, freezes exactly that plan.
//
// It runs BEFORE `ensureCapacityIncrementalPlan`, so the ordinary bulk plan is never persisted
// first. The normal-work estimate it needs is produced from an EPHEMERAL bulk plan costed through
// the same production estimator (`selectedWorkDecisionForPlan`) — never a second arithmetic
// implementation, and never a durable freeze.
func evaluateCapacityUrgencyPrecedence(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	status CapacityProofEpochStatus,
	chainTimestamp int64,
) capacityUrgencyPrecedenceResult {
	if free, reason := capacityUrgencyOwnershipFree(storage, status); !free {
		return capacityUrgencyPrecedenceResult{Detail: reason}
	}
	// The LV2 test barrier suppresses ALL stage-A persistence, urgency included, so a held
	// backlog never freezes either plan.
	if lv2IncrementalPlanCreationHeld() {
		return capacityUrgencyPrecedenceResult{Detail: "test barrier holds all plan creation"}
	}

	// Cost the ordinary bulk work WITHOUT freezing it. A failure here is not an urgency decision:
	// the normal path re-runs the same computation and classifies the error itself.
	normalPlan, _, _, haveNormal, err := computeCapacityIncrementalPlan(storage, cfg, partitions)
	if err != nil {
		return capacityUrgencyPrecedenceResult{Detail: "normal candidate computation unavailable"}
	}
	normalRequired := time.Duration(0)
	if haveNormal {
		_, _, _, estimate, estErr := selectedWorkDecisionForPlan(
			storage, normalPlan, partitions, chainTimestamp,
			uint64(max64(cfg.CapacityBytes, 0)), cfg)
		if estErr != nil {
			return capacityUrgencyPrecedenceResult{Detail: "normal selected-work estimate unavailable"}
		}
		normalRequired = estimate.RequiredDuration
	}

	// normalRequired is retained as a fail-closed health guard on the ordinary path and for
	// observability: urgency must not pre-empt planning when the ordinary plan cannot even be
	// costed. Predicate 2 itself uses the per-successor G.3 estimate inside the evaluator.
	outcome := evaluateProductionQualifiedUrgencyWithNormalCompletion(
		storage, cfg, partitions, map[string]struct{}{})
	if !outcome.Evaluated || !outcome.Result.Qualified {
		logQualifiedUrgency(outcome)
		return capacityUrgencyPrecedenceResult{Detail: outcome.Result.Reason}
	}

	// Qualified: freeze EXACTLY the one eligible successor identity, and nothing else.
	inserted, insertErr := ensureUrgencyPriorityChunk(
		storage, outcome.Result.SelectedIdentity, partitions)
	if insertErr != nil || !inserted {
		return capacityUrgencyPrecedenceResult{
			Detail: "urgent identity is not one exact current registered partition"}
	}
	urgentPlan, found, planErr := readCapacityBatchChunkPlan(storage)
	if planErr != nil || !found {
		return capacityUrgencyPrecedenceResult{Detail: "urgent plan did not persist"}
	}
	_, _, _, estimate, estErr := selectedWorkDecisionForPlan(
		storage, urgentPlan, partitions, chainTimestamp,
		uint64(max64(cfg.CapacityBytes, 0)), cfg)
	if estErr != nil || !estimate.PlanValid {
		return capacityUrgencyPrecedenceResult{Detail: "urgent plan is not costable"}
	}
	if repErr := selectedPlanRepresentable(estimate); repErr != nil {
		return capacityUrgencyPrecedenceResult{Detail: "urgent campaign is not representable"}
	}

	log.Printf("[capacity-urgency] qualified urgency takes precedence over new bulk planning "+
		"selected=%d normalRequiredSeconds=%d op=%s",
		estimate.SelectedPartitionCount, int64(normalRequired.Seconds()), outcome.Result.OperationID)
	logQualifiedUrgency(outcome)
	return capacityUrgencyPrecedenceResult{
		Qualified: true,
		Decision:  qualifiedUrgencyDecision(outcome.Result, estimate),
	}
}
