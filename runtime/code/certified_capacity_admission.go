package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const (
	AdmissionClosureCertifiedInsufficient  = "certified_capacity_insufficient"
	AdmissionClosureBacklogUnsafe          = "capacity_backlog_unsafe"
	AdmissionClosureOldestDirtyHardLag     = "oldest_dirty_hard_lag"
	AdmissionClosureStorageOverload        = "storage_deadline_overload"
	AdmissionClosureProofUnavailable       = "proof_subsystem_unavailable"
	AdmissionClosureRecoveryDisagreement   = "recovery_accounting_disagreement"
	AdmissionClosureChainUnavailable       = "chain_state_unavailable"
	AdmissionClosureReservationUnavailable = "reservation_state_unavailable"
)

// Tests install a deterministic reader in TestMain. Production leaves this nil
// and always performs the block-pinned adapter action.
var certifiedCapacityAdmissionReaderForTest func(ServerConfig) (CertifiedCapacityAdmissionStatus, error)

func readCertifiedCapacityForAdmission(cfg ServerConfig) (CertifiedCapacityAdmissionStatus, error) {
	if certifiedCapacityAdmissionReaderForTest != nil {
		return certifiedCapacityAdmissionReaderForTest(cfg)
	}
	if cfg.ChainProofCmd == "" {
		return CertifiedCapacityAdmissionStatus{}, fmt.Errorf("chain proof command is not configured")
	}
	return certifiedCapacityAdmissionStatusOnChain(cfg.ChainProofCmd)
}

func subtractAdmissionCapacity(fresh, reserved, margin int64) (unreserved, safe int64) {
	if fresh <= 0 {
		return 0, 0
	}
	if reserved < 0 || margin < 0 {
		return 0, 0
	}
	if reserved >= fresh {
		return 0, 0
	}
	unreserved = fresh - reserved
	if margin >= unreserved {
		return unreserved, 0
	}
	return unreserved, unreserved - margin
}

type admissionSafetyState struct {
	ClosureReason           string
	Detail                  string
	DirtyUncertifiedBytes   int64
	CapacityBacklogDuration time.Duration
	OldestDirtyAge          time.Duration
	ProofSubsystemAvailable bool
	RecoveryDisagreement    bool
}

func readG5AdmissionSafety(storage string, cfg ServerConfig, chainNow time.Time) admissionSafetyState {
	state := admissionSafetyState{ProofSubsystemAvailable: true}
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		state.ProofSubsystemAvailable = false
		state.ClosureReason = AdmissionClosureProofUnavailable
		state.Detail = gateErr.Error()
		return state
	}
	if recovery, found, err := readSectorSlotRecoveryMetrics(storage); err != nil {
		state.ClosureReason = AdmissionClosureReservationUnavailable
		state.Detail = err.Error()
		return state
	} else if found && !recovery.RecoveryComplete {
		state.ClosureReason = AdmissionClosureReservationUnavailable
		state.Detail = "durable startup reservation recovery is incomplete"
		return state
	} else if found && (recovery.Corrupt > 0 || recovery.RetainedAmbiguous > 0 || recovery.LastError != "") {
		state.ClosureReason = AdmissionClosureRecoveryDisagreement
		state.Detail = fmt.Sprintf("reservation recovery ambiguous=%d corrupt=%d error=%s",
			recovery.RetainedAmbiguous, recovery.Corrupt, recovery.LastError)
		state.RecoveryDisagreement = true
		return state
	} else if !found && !sectorAllocationOpen() {
		// The network server holds a process-local startup barrier until it can
		// publish the first durable recovery record. Other processes (notably the
		// proof daemon) use that shared durable record instead of inheriting a
		// meaningless process-local pending bit.
		state.ClosureReason = AdmissionClosureReservationUnavailable
		state.Detail = "startup reservation recovery is incomplete"
		return state
	}
	if health, failed, err := activeProofHealthFailure(storage); err != nil {
		state.ProofSubsystemAvailable = false
		state.ClosureReason = AdmissionClosureProofUnavailable
		state.Detail = err.Error()
		return state
	} else if failed {
		state.ClosureReason = AdmissionClosureStorageOverload
		state.Detail = fmt.Sprintf("missed storage proof deadline for %s dl%d-pt%d",
			health.PartitionKind, health.DeadlineIndex, health.PartitionIndex)
		return state
	}
	if overload, active := proofLaneOverloadActive(storage); active {
		state.ClosureReason = AdmissionClosureStorageOverload
		state.Detail = overload.Reason
		return state
	}

	payload, err := os.ReadFile(partitionProofSnapshotMetricsPath(storage))
	if os.IsNotExist(err) {
		if cfg.DeterministicChallenge {
			state.ProofSubsystemAvailable = false
			state.ClosureReason = AdmissionClosureProofUnavailable
			state.Detail = "proof scheduler state is not initialized"
		}
		return state
	}
	if err != nil {
		state.ProofSubsystemAvailable = false
		state.ClosureReason = AdmissionClosureProofUnavailable
		state.Detail = err.Error()
		return state
	}
	var metrics proofBacklogMetrics
	if json.Unmarshal(payload, &metrics) != nil || metrics.Version != proofBacklogMetricsVersion {
		state.ProofSubsystemAvailable = false
		state.ClosureReason = AdmissionClosureProofUnavailable
		state.Detail = "proof backlog metrics are invalid"
		return state
	}
	state.DirtyUncertifiedBytes = metrics.CapacityPendingBytes
	state.CapacityBacklogDuration = time.Duration(metrics.EstimatedCatchupNanos)
	state.OldestDirtyAge = time.Duration(metrics.CapacityOldestMutationNanos)
	observed := parseSnapshotTime(metrics.ObservedAt)
	hostNow := time.Now()
	staleAfter := time.Duration(metrics.StaleAfterSeconds) * time.Second
	if staleAfter <= 0 {
		staleAfter = 3 * time.Minute
	}
	// ObservedAt and DeadlineChecks are deliberately host-domain values. The scheduler maps
	// chain deadlines to host due-times when it writes this file. Comparing them to chainNow
	// makes a legitimate timelock jump look like stale local metrics and closes admission.
	if metrics.ProofObligationsPresent && (observed.IsZero() || hostNow.Sub(observed) > staleAfter) {
		state.ProofSubsystemAvailable = false
		state.ClosureReason = AdmissionClosureProofUnavailable
		state.Detail = "proof backlog observation is stale"
		return state
	}
	if (metrics.ProofObligationsPresent || metrics.PendingSnapshots > 0) && !metrics.ChainClockAvailable {
		state.ClosureReason = AdmissionClosureChainUnavailable
		state.Detail = "proof backlog chain clock is unavailable"
		return state
	}
	if metrics.CapacityLagBreached {
		state.ClosureReason = AdmissionClosureOldestDirtyHardLag
		state.Detail = metrics.CapacityLagReason
		return state
	}
	if metrics.CapacityLagAtRisk {
		state.ClosureReason = AdmissionClosureBacklogUnsafe
		state.Detail = metrics.CapacityLagReason
		return state
	}
	for _, check := range metrics.DeadlineChecks {
		required := time.Duration(check.RequiredNanos)
		safety := required / 10
		if safety < 30*time.Second {
			safety = 30 * time.Second
		}
		if !hostNow.Add(required + safety).Before(time.Unix(check.DeadlineUnix, 0)) {
			state.ClosureReason = AdmissionClosureBacklogUnsafe
			state.Detail = "conservative proof drain duration exceeds its safe window"
			return state
		}
	}
	return state
}
