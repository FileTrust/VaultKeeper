package main

// G.4B-LV2 — test-only incremental plan-creation barrier.
//
// WHY THIS EXISTS
//
// The LV2 Phase-1 acceptance needs a durable incremental plan whose selected set exceeds 32
// members across at least two chunks. Production froze its plan 63 seconds into the previous
// 468-upload workload, when only 8 uploads had landed and 3 data identities existed, and a frozen
// selected set is immutable by G.2 design — so the remaining 97 minutes of real backlog could
// never join it.
//
// The scheduler's batching gates (`D1_CAPACITY_PROOF_DEBOUNCE_SECONDS`,
// `…_MAX_OLDEST_MUTATION_SECONDS`, `…_MAX_BATCH_SECONDS`) do not help: they are consumed by
// `EvaluateBatchTrigger` inside `liveSelectedWorkDecision`, which runs AFTER
// `ensureCapacityIncrementalPlan` has already frozen the plan. Three stages must be distinguished:
//
//	A. candidate discovery / selection / exact-set freeze   <- ungated; this barrier holds ONLY this
//	B. campaign begin                                       <- gated already
//	C. proof generation and submission                      <- gated already
//
// This barrier suppresses stage A, and only the durable persistence at the end of stage A, so the
// LV2 harness can build the whole backlog before production freezes its FIRST plan.
//
// WHAT IT DELIBERATELY DOES NOT DO
//
// It never fabricates a plan, a member, a mutation or a heartbeat. It does not touch admission,
// reservations, proof-subsystem health, chain reads, storage writes, StoreV3, EDF, deletion FIFO
// or any G.5 safety rule. Candidate discovery, the block-pinned selection snapshot, the G.2/G.5
// observation-block agreement check and the selection itself all still execute normally — only
// `freezeCapacityBatchChunkPlanIfAbsent` is withheld. The scheduler simply observes "no plan yet",
// which is the same state it observes when there are no candidates at all.
//
// SAFETY: TWO INDEPENDENT SWITCHES, BOTH REQUIRED
//
// A single environment variable capable of disabling incremental planning would be a production
// hazard. Activation therefore requires BOTH an explicit global test mode AND the specific LV2
// hold flag. If the LV2 flag appears without test mode the barrier refuses to engage and
// production planning proceeds unchanged, with one loud warning — a stray flag in a real
// deployment can never silently stop capacity proving.

import (
	"log"
	"os"
	"strings"
	"sync"
)

const (
	// filetrustTestModeEnv is the explicit global test-mode switch. Production never sets it.
	filetrustTestModeEnv = "FILETRUST_TEST_MODE"
	// lv2HoldIncrementalPlanEnv is the specific LV2 stage-A hold. Inert without test mode.
	lv2HoldIncrementalPlanEnv = "D1_G4B_LV2_HOLD_INCREMENTAL_PLAN_CREATION"
)

var lv2BarrierMisconfigurationWarning sync.Once

// envFlagEnabled treats only explicit affirmative values as set, so an empty or "0" value can
// never enable a test hook by accident.
func envFlagEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// lv2IncrementalPlanCreationHeld reports whether the LV2-only stage-A barrier is engaged.
//
// Both switches are mandatory. The LV2 flag alone is a misconfiguration: the barrier stays
// disengaged (production behaviour unchanged) and the condition is reported once so it is
// observable rather than silent.
func lv2IncrementalPlanCreationHeld() bool {
	hold := envFlagEnabled(lv2HoldIncrementalPlanEnv)
	if !hold {
		return false
	}
	if !envFlagEnabled(filetrustTestModeEnv) {
		lv2BarrierMisconfigurationWarning.Do(func() {
			log.Printf("[capacity-batch] IGNORING %s: %s is not enabled; "+
				"incremental plan creation continues normally",
				lv2HoldIncrementalPlanEnv, filetrustTestModeEnv)
		})
		return false
	}
	return true
}

// logLV2PlanCreationHeld records the held selection. Aggregate-only: candidate and member counts
// and the observation block, never a content hash, requester identity, demand id or file linkage.
func logLV2PlanCreationHeld(selection CapacityBatchSelection, block uint64) {
	log.Printf("[capacity-batch] test barrier holding incremental plan creation "+
		"block=%d candidates=%d wouldSelect=%d bytes=%d (no plan frozen, no campaign)",
		block, selection.CandidateCount, selection.SelectedPartitionCount, selection.SelectedBytes)
}
