package main

// G.3B/G.3C — typed capacity start decision and campaign-mode launch gate.
//
// Campaign scope and launch timing are deliberately different domains:
//   - CapacityCampaignMode says WHAT scope is opened;
//   - BatchTriggerReason says WHEN exact selected work is due;
//   - FullSweepReason says WHY the complete manifest must be proved.
//
// A decision carrying both reason domains is invalid and fails closed.

import (
	"fmt"
	"strings"
)

type CapacityCampaignMode string

const (
	CampaignModeNone        CapacityCampaignMode = "none"
	CampaignModeIncremental CapacityCampaignMode = "incremental"
	CampaignModeFullSweep   CapacityCampaignMode = "full_sweep"
)

// FullSweepReason is independent from BatchTriggerReason. Timing conditions can never be
// converted to this type and therefore cannot silently widen selected work to a full sweep.
type FullSweepReason string

const (
	FullSweepNone                    FullSweepReason = ""
	FullSweepInitial                 FullSweepReason = "initial"
	FullSweepDeclaredCapacityRebuild FullSweepReason = "declared_capacity_rebuild"
	FullSweepExplicitAudit           FullSweepReason = "explicit_audit"
	FullSweepMigration               FullSweepReason = "migration"
	FullSweepRecoveryUncertain       FullSweepReason = "recovery_uncertain"
	FullSweepFreshnessRecovery       FullSweepReason = "freshness_recovery"
)

type CapacityDecisionFailureClass string

const (
	FailureNone                       CapacityDecisionFailureClass = ""
	FailureChainStateUnavailable      CapacityDecisionFailureClass = "chain_state_unavailable"
	FailureDurablePlanCorrupt         CapacityDecisionFailureClass = "durable_plan_corrupt"
	FailureBatchingSignalsUnavailable CapacityDecisionFailureClass = "batching_signals_unavailable"
	FailureCampaignNotRepresentable   CapacityDecisionFailureClass = "campaign_not_representable"
)

// FullPlanProvenance proves that a full reason was selected before complete-manifest work was
// costed or opened. ReasonPredicateSatisfied is the explicit reason-specific gate; a timing
// predicate is never accepted here.
type FullPlanProvenance struct {
	Reason                   FullSweepReason
	CompleteManifestBuilt    bool
	CompleteManifestValid    bool
	RequestedExplicitly      bool
	ReasonPredicateSatisfied bool
}

func (p FullPlanProvenance) valid() bool {
	if _, ok := approvedFullSweepReasons[p.Reason]; !ok || p.Reason == FullSweepNone {
		return false
	}
	if !p.CompleteManifestBuilt || !p.CompleteManifestValid || !p.ReasonPredicateSatisfied {
		return false
	}
	switch p.Reason {
	case FullSweepExplicitAudit, FullSweepMigration:
		return p.RequestedExplicitly
	default:
		return true
	}
}

type CapacityStartDecision struct {
	Ready        bool
	CampaignMode CapacityCampaignMode

	BatchTriggerReason BatchTriggerReason
	FullSweepReason    FullSweepReason
	FullPlanProvenance FullPlanProvenance

	SelectedPlanValid bool
	FullPlanValid     bool

	RecoverableError error
	FailureClass     CapacityDecisionFailureClass
	Retryable        bool
	RecoveryRequired bool

	EstimatorFallbackUsed bool
	DurationSaturated     bool

	Estimate SelectedWorkEstimate
	Detail   string
}

const TriggerRecoveryRequired BatchTriggerReason = "recovery_required"

func (d CapacityStartDecision) MayOpenCampaign() bool {
	return d.Ready && d.validate() == nil
}

func failClosed(
	class CapacityDecisionFailureClass, retryable bool, err error, detail string,
) CapacityStartDecision {
	return CapacityStartDecision{
		CampaignMode: CampaignModeNone, BatchTriggerReason: TriggerRecoveryRequired,
		RecoverableError: err, FailureClass: class, Retryable: retryable,
		RecoveryRequired: true, Detail: detail,
	}
}

// readyFullSweep accepts provenance, not a generic reason string. Callers must construct and
// validate the complete manifest before this helper is reachable.
func readyFullSweep(provenance FullPlanProvenance, detail string) CapacityStartDecision {
	return CapacityStartDecision{
		Ready: true, CampaignMode: CampaignModeFullSweep,
		FullSweepReason: provenance.Reason, FullPlanProvenance: provenance,
		FullPlanValid: provenance.valid(), Detail: detail,
	}
}

func readyIncremental(estimate SelectedWorkEstimate, reason BatchTriggerReason) CapacityStartDecision {
	return CapacityStartDecision{
		Ready: true, CampaignMode: CampaignModeIncremental, BatchTriggerReason: reason,
		SelectedPlanValid: true, Estimate: estimate,
		DurationSaturated: estimate.RequiredDuration == maxDuration, Detail: estimate.String(),
	}
}

func notDue(estimate SelectedWorkEstimate, reason BatchTriggerReason, detail string) CapacityStartDecision {
	return CapacityStartDecision{
		CampaignMode: CampaignModeNone, BatchTriggerReason: reason,
		SelectedPlanValid: estimate.SelectedPartitionCount > 0, Estimate: estimate, Detail: detail,
	}
}

var approvedFullSweepReasons = map[FullSweepReason]struct{}{
	FullSweepInitial: {}, FullSweepDeclaredCapacityRebuild: {}, FullSweepExplicitAudit: {},
	FullSweepMigration: {}, FullSweepRecoveryUncertain: {}, FullSweepFreshnessRecovery: {},
}

var approvedIncrementalReasons = map[BatchTriggerReason]struct{}{
	TriggerRecoveryEmergency: {}, TriggerSelectedFreshness: {},
	TriggerSelectedWorkOverload: {}, TriggerHardLagLatestStart: {},
	TriggerMaxBatchAge: {}, TriggerPendingByteThreshold: {},
	TriggerDirtyPartitionCount: {}, TriggerMutationCount: {},
	TriggerBacklogDuration: {}, TriggerDebounceElapsed: {},
	// G.4B-LV1: qualified lifecycle urgency is an incremental trigger by construction. It was
	// absent from this whitelist while nothing produced it, so the launch gate would have
	// refused the decision even once the evaluator was wired.
	TriggerQualifiedLifecycleUrgency: {},
}

func fullSweepReasonOnChainMode(reason FullSweepReason) (uint8, error) {
	modeByReason := map[FullSweepReason]CapacityBatchMode{
		FullSweepInitial:                 BatchModeInitial,
		FullSweepDeclaredCapacityRebuild: BatchModeDeclaredCapacityRebuild,
		FullSweepExplicitAudit:           BatchModeExplicitAudit,
		FullSweepMigration:               BatchModeMigration,
		FullSweepRecoveryUncertain:       BatchModeRecoveryUncertain,
		FullSweepFreshnessRecovery:       BatchModeFreshnessRecovery,
	}
	mode, ok := modeByReason[reason]
	if !ok {
		return 0, fmt.Errorf("full-sweep reason %q has no on-chain mode", reason)
	}
	return mode.OnChainMode()
}

func (d CapacityStartDecision) validate() error {
	// Reject mixed domains even on a not-ready decision; otherwise a later caller could retain
	// one field and accidentally widen the other.
	if d.BatchTriggerReason != "" && d.FullSweepReason != FullSweepNone {
		return fmt.Errorf("decision carries both batch trigger %q and full-sweep reason %q",
			d.BatchTriggerReason, d.FullSweepReason)
	}
	if !d.Ready {
		return nil
	}
	if d.FailureClass != FailureNone {
		return fmt.Errorf("decision is ready with failure class %q", d.FailureClass)
	}
	if d.RecoverableError != nil {
		return fmt.Errorf("decision is ready while carrying error: %v", d.RecoverableError)
	}
	switch d.CampaignMode {
	case CampaignModeIncremental:
		if !d.SelectedPlanValid || d.FullPlanValid || d.FullSweepReason != FullSweepNone {
			return fmt.Errorf("incremental campaign does not carry one exclusive selected plan")
		}
		if _, ok := approvedIncrementalReasons[d.BatchTriggerReason]; !ok {
			return fmt.Errorf("incremental reason %q is not on the approved whitelist", d.BatchTriggerReason)
		}
	case CampaignModeFullSweep:
		if d.BatchTriggerReason != "" || d.SelectedPlanValid {
			return fmt.Errorf("full sweep carries incremental trigger or selected plan")
		}
		if !d.FullPlanValid || d.FullSweepReason == FullSweepNone {
			return fmt.Errorf("full sweep is ready without a valid full plan and reason")
		}
		if d.FullPlanProvenance.Reason != d.FullSweepReason || !d.FullPlanProvenance.valid() {
			return fmt.Errorf("full-sweep provenance is invalid for reason %q", d.FullSweepReason)
		}
	default:
		return fmt.Errorf("ready decision has no campaign mode")
	}
	return nil
}

func (d CapacityStartDecision) LogFields() map[string]any {
	fields := map[string]any{
		"capacityStartReady":   d.Ready,
		"capacityCampaignMode": string(d.CampaignMode),
		"batchTriggerReason":   string(d.BatchTriggerReason),
		"fullSweepReason":      string(d.FullSweepReason),
		"selectedPlanValid":    d.SelectedPlanValid,
		"fullPlanValid":        d.FullPlanValid,
		"fullPlanComplete":     d.FullPlanProvenance.CompleteManifestBuilt && d.FullPlanProvenance.CompleteManifestValid,
		"fullPlanProvenance": fmt.Sprintf("reason=%s built=%v valid=%v explicit=%v predicate=%v",
			d.FullPlanProvenance.Reason, d.FullPlanProvenance.CompleteManifestBuilt,
			d.FullPlanProvenance.CompleteManifestValid, d.FullPlanProvenance.RequestedExplicitly,
			d.FullPlanProvenance.ReasonPredicateSatisfied),
		"decisionFailureClass":     string(d.FailureClass),
		"decisionFailureRetryable": d.Retryable,
		"estimatorFallbackUsed":    d.EstimatorFallbackUsed,
		"durationSaturated":        d.DurationSaturated,
		"recoveryRequired":         d.RecoveryRequired,
	}
	if d.Ready || d.Estimate.SelectedPartitionCount > 0 {
		for key, value := range d.Estimate.LogFields() {
			if _, clash := fields[key]; !clash {
				fields[key] = value
			}
		}
	}
	return fields
}

func (d CapacityStartDecision) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ready=%v mode=%s batchTrigger=%s fullSweepReason=%s selectedPlanValid=%v fullPlanValid=%v",
		d.Ready, d.CampaignMode, d.BatchTriggerReason, d.FullSweepReason,
		d.SelectedPlanValid, d.FullPlanValid)
	if d.FailureClass != FailureNone {
		fmt.Fprintf(&b, " failure=%s retryable=%v", d.FailureClass, d.Retryable)
	}
	if d.Detail != "" {
		fmt.Fprintf(&b, " (%s)", d.Detail)
	}
	return b.String()
}
