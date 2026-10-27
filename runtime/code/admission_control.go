package main

import (
	"fmt"
	"log"
	"sync"
	"time"
)

const DefaultAdmissionMarginBytes int64 = 100 * 1024 * 1024
const AdmissionRegistryFreeBytesSyncInterval = 60 * time.Second

type AdmissionState struct {
	Closed                        bool
	FreeBytes                     int64
	AllocatableBytes              int64
	MarginBytes                   int64
	PhysicalAvailableBytes        int64
	FilesystemReserveBytes        int64
	PhysicalAllocatableBytes      int64
	Reason                        string
	RegistrySyncNeeded            bool
	FreshCertifiedFreeCapacity    int64
	ActiveReservationBytes        int64
	SafeAllocatable               int64
	RequestedBytes                int64
	AdmissionOpen                 bool
	ClosureReason                 string
	ReasonDetail                  string
	CertificationObservationBlock uint64
	ExpiredCertifiedBytes         int64
	DirtyUncertifiedBytes         int64
	CapacityBacklogDuration       time.Duration
	OldestDirtyAge                time.Duration
	ProofSubsystemAvailable       bool
	RecoveryDisagreement          bool
}

var (
	admissionSyncMu               sync.Mutex
	lastAdmissionClosed           bool
	lastAdmissionFreeBytes        int64
	lastAdmissionReason           string
	lastAdmissionObservationBlock uint64
	lastAdmissionSynced           bool
	lastAdmissionSyncSuccess      time.Time
	lastAdmissionSyncAttempt      time.Time
)

func admissionMarginBytes(cfg ServerConfig) int64 {
	if cfg.AdmissionMarginBytes > 0 {
		return cfg.AdmissionMarginBytes
	}
	return DefaultAdmissionMarginBytes
}

func computeUnreservedFreeBytes(storage string, totalCapacityBytes int64) (int64, error) {
	if totalCapacityBytes <= 0 {
		return 0, nil
	}
	accounting, err := computeCapacityAccounting(storage, totalCapacityBytes)
	if err != nil {
		return 0, err
	}
	transferStateMu.Lock()
	reserved, reservationErr := reservedAdmissionCapacityBytesLocked(storage, "", "", "")
	transferStateMu.Unlock()
	if reservationErr != nil {
		return 0, fmt.Errorf("read durable capacity reservations: %w", reservationErr)
	}
	free := totalCapacityBytes - accounting.UsedBytes - reserved
	if free < 0 {
		free = 0
	}
	return free, nil
}

func computeAdmissionState(storage string, cfg ServerConfig) AdmissionState {
	return computeAdmissionStateForRequest(storage, cfg, 0)
}

func closeAdmissionState(state AdmissionState, reason, detail string) AdmissionState {
	state.Closed = true
	state.AdmissionOpen = false
	state.AllocatableBytes = 0
	state.ClosureReason = reason
	state.Reason = reason
	state.ReasonDetail = detail
	return state
}

func computeAdmissionStateForRequest(storage string, cfg ServerConfig, requestedBytes int64) AdmissionState {
	margin := admissionMarginBytes(cfg)
	state := AdmissionState{
		MarginBytes: margin, RequestedBytes: requestedBytes,
		ProofSubsystemAvailable: true, AdmissionOpen: true,
	}
	if cfg.CapacityBytes <= 0 {
		return state
	}
	certified, err := readCertifiedCapacityForAdmission(cfg)
	if err != nil {
		return closeAdmissionState(state, AdmissionClosureChainUnavailable, err.Error())
	}
	state.FreshCertifiedFreeCapacity = certified.FreshCertifiedFreeCapacity
	state.ExpiredCertifiedBytes = certified.ExpiredCertifiedBytes
	state.CertificationObservationBlock = certified.ObservationBlock
	if certified.FreshCertifiedFreeCapacity > cfg.CapacityBytes {
		state.RecoveryDisagreement = true
		return closeAdmissionState(state, AdmissionClosureRecoveryDisagreement,
			fmt.Sprintf("certified free bytes %d exceed declared capacity %d",
				certified.FreshCertifiedFreeCapacity, cfg.CapacityBytes))
	}
	transferStateMu.Lock()
	reserved, reservationErr := reservedAdmissionCapacityBytesAtLocked(
		storage, "", "", "", certified.ChainTimestamp,
	)
	transferStateMu.Unlock()
	if reservationErr != nil {
		return closeAdmissionState(state, AdmissionClosureReservationUnavailable, reservationErr.Error())
	}
	state.ActiveReservationBytes = reserved
	state.FreeBytes, state.SafeAllocatable = subtractAdmissionCapacity(
		certified.FreshCertifiedFreeCapacity, reserved, margin,
	)
	state.AllocatableBytes = state.SafeAllocatable

	safety := readG5AdmissionSafety(storage, cfg, time.Unix(certified.ChainTimestamp, 0))
	state.DirtyUncertifiedBytes = safety.DirtyUncertifiedBytes
	state.CapacityBacklogDuration = safety.CapacityBacklogDuration
	state.OldestDirtyAge = safety.OldestDirtyAge
	state.ProofSubsystemAvailable = safety.ProofSubsystemAvailable
	state.RecoveryDisagreement = safety.RecoveryDisagreement
	if safety.ClosureReason != "" {
		return closeAdmissionState(state, safety.ClosureReason, safety.Detail)
	}

	physical, physicalErr := filesystemAdmissionState(cfg)
	if physicalErr != nil {
		state.RecoveryDisagreement = true
		return closeAdmissionState(state, AdmissionClosureRecoveryDisagreement, physicalErr.Error())
	}
	state.PhysicalAvailableBytes = physical.AvailableBytes
	state.FilesystemReserveBytes = physical.WorkspaceReserve
	state.PhysicalAllocatableBytes = physical.AllocatableBytes
	if physical.AllocatableBytes <= 0 || (requestedBytes > 0 && requestedBytes > physical.AllocatableBytes) {
		state.RecoveryDisagreement = true
		return closeAdmissionState(state, AdmissionClosureRecoveryDisagreement,
			fmt.Sprintf("physical allocatable bytes %d cannot satisfy request %d",
				physical.AllocatableBytes, requestedBytes))
	}
	// Margin is a last acceptance, not a floor: while admission is open
	// (SafeAllocatable > 0) a request may consume the margin itself, and the store that
	// does so closes admission for everything after it. See the same rule at the quote
	// gate in quote_reservation.go for why refusing against SafeAllocatable instead left
	// keepers refusing while still holding visibly free bytes.
	if state.SafeAllocatable <= 0 || (requestedBytes > 0 && requestedBytes > state.FreeBytes) {
		return closeAdmissionState(state, AdmissionClosureCertifiedInsufficient,
			fmt.Sprintf("freshCertified=%d activeReservations=%d margin=%d requested=%d unreserved=%d",
				state.FreshCertifiedFreeCapacity, state.ActiveReservationBytes, margin,
				requestedBytes, state.FreeBytes))
	}
	return state
}

func enrichStorageInfoAdmission(info StorageInfo, storage string, cfg ServerConfig) StorageInfo {
	state := computeAdmissionState(storage, cfg)
	info.AdmissionClosed = state.Closed
	info.AdmissionFreeBytes = state.FreeBytes
	info.AdmissionAllocatableBytes = state.AllocatableBytes
	info.AdmissionMarginBytes = state.MarginBytes
	info.AdmissionReason = state.Reason
	info.FreshCertifiedFreeCapacity = state.FreshCertifiedFreeCapacity
	info.ActiveReservationBytes = state.ActiveReservationBytes
	info.SafeAllocatable = state.SafeAllocatable
	info.RequestedBytes = state.RequestedBytes
	info.AdmissionOpen = state.AdmissionOpen
	info.AdmissionClosureReason = state.ClosureReason
	info.CertificationObservationBlock = state.CertificationObservationBlock
	info.ExpiredCertifiedBytes = state.ExpiredCertifiedBytes
	info.DirtyUncertifiedBytes = state.DirtyUncertifiedBytes
	info.CapacityBacklogDurationSeconds = int64(state.CapacityBacklogDuration / time.Second)
	info.OldestDirtyAgeSeconds = int64(state.OldestDirtyAge / time.Second)
	info.ProofSubsystemAvailable = state.ProofSubsystemAvailable
	info.RecoveryDisagreement = state.RecoveryDisagreement
	info.PhysicalAvailableBytes = state.PhysicalAvailableBytes
	info.FilesystemReserveBytes = state.FilesystemReserveBytes
	info.PhysicalAllocatableBytes = state.PhysicalAllocatableBytes
	// A.2 readiness: surface the proving gate so an operator/launcher sees the VK as degraded
	// and NOT proof-ready when the artifact startup barrier has not opened.
	proofReady, degradedReason := artifactStartupProofReady()
	info.ProofReady = proofReady
	if !proofReady {
		info.Degraded = true
		info.DegradedReason = degradedReason
	}
	// A.4 readiness: any unresolved recovery work (pending retries or terminal failures) makes
	// the VK degraded and never healthy until it is durably resolved.
	if pending, terminal, err := unresolvedProofRecovery(storage); err != nil {
		info.Degraded = true
		if info.DegradedReason == "" {
			info.DegradedReason = "recovery state unreadable: " + err.Error()
		}
	} else if pending > 0 || terminal > 0 {
		info.Degraded = true
		info.RecoveryPending = pending
		info.RecoveryTerminal = terminal
		if info.DegradedReason == "" {
			info.DegradedReason = fmt.Sprintf("unresolved proof recovery: %d pending, %d terminal", pending, terminal)
		}
	}
	// A.4 orphan-GC observability.
	// Reconcile the cached retained count against physical reality so a stale sweep metric
	// (artifact already removed, no fresh sweep since) does not report phantom retained orphans
	// and hold the drain gate open — the Run-17 accounting lag.
	if gc, ok, err := readReconciledOrphanArtifactGCMetrics(storage); err == nil && ok {
		info.OrphanArtifactsRetained = gc.RetainedOrphans
		info.OrphanArtifactOldestAgeSeconds = gc.OldestRetainedAgeSeconds
		info.OrphanArtifactGCError = gc.LastError
	}
	// B.1: report outstanding sector-cap reservations. They occupy real slots, so admission
	// reporting must never present a capacity picture that ignores them. Unreadable reservation
	// metadata is a degradation, not something to silently treat as "no reservations".
	if reserved, err := activeSectorSlotReservationCount(storage); err != nil {
		info.Degraded = true
		info.SectorSlotReservationError = err.Error()
		if info.DegradedReason == "" {
			info.DegradedReason = "sector slot reservations unreadable: " + err.Error()
		}
	} else {
		info.SectorSlotReservationsActive = reserved
	}
	// C.1: until the proof resource controller has a storage root, overload cannot be persisted
	// and lower-priority proving is closed — readiness must say so rather than look healthy.
	info.ProofLaneConfigured = proofLaneConfigured()
	if !info.ProofLaneConfigured {
		info.Degraded = true
		if info.DegradedReason == "" {
			info.DegradedReason = "proof resource controller is not configured"
		}
	}
	// C.1 overload observability: state, affected deadline, required vs available duration.
	if overload, active := proofLaneOverloadActive(storage); active {
		info.Degraded = true
		info.ProofLaneOverload = true
		info.ProofLaneOverloadReason = overload.Reason
		info.ProofLaneOverloadDeadlineUnix = overload.DeadlineUnix
		info.ProofLaneRequiredSeconds = overload.RequiredSeconds
		info.ProofLaneAvailableSeconds = overload.AvailableSeconds
		info.ProofLaneOverloadSince = overload.EnteredAt
		if info.DegradedReason == "" {
			info.DegradedReason = "proof lane overload: " + overload.Reason
		}
	} else if overload.ClearedAt != "" {
		info.ProofLaneOverloadClearedAt = overload.ClearedAt
	}
	// B.4: unreadable, corrupt or ambiguous reservation state degrades readiness rather than
	// being interpreted as zero reservations, and allocation stays closed until recovery ends.
	info.ReservationRecoveryComplete = sectorAllocationOpen()
	if !info.ReservationRecoveryComplete {
		info.Degraded = true
		if info.DegradedReason == "" {
			info.DegradedReason = "sector slot reservation recovery has not completed"
		}
	}
	if metrics, ok, err := readSectorSlotRecoveryMetrics(storage); err == nil && ok {
		info.ReservationsRecoveredCommitted = metrics.RecoveredCommitted
		info.ReservationsReleasedAbandoned = metrics.ReleasedAbandoned
		info.ReservationsRetainedAmbiguous = metrics.RetainedAmbiguous
		info.ReservationsCorrupt = metrics.Corrupt
		info.ReservationOldestUnresolvedAge = metrics.OldestUnresolvedAgeSeconds
		info.ReservationSweepAt = metrics.LastSweepAt
		info.ReservationSweepError = metrics.LastError
		if metrics.Corrupt > 0 || metrics.RetainedAmbiguous > 0 || metrics.LastError != "" {
			info.Degraded = true
			if info.DegradedReason == "" {
				info.DegradedReason = fmt.Sprintf(
					"unresolved sector slot reservations: %d ambiguous, %d corrupt",
					metrics.RetainedAmbiguous, metrics.Corrupt)
			}
		}
	}
	return info
}

// admissionPublishIsRedundant decides whether this keeper can skip republishing
// its admission state. Callers must hold admissionSyncMu.
//
// registryDiverged is the decisive input and must never be dropped: without it
// the decision rests on what THIS process last published, and a vault keeper has
// two publishers. The server publishes on store traffic, the proof daemon on its
// own cycle, and neither sees the other's writes. So the server can publish
// "closed", fall idle (a closed keeper receives no stores), and the daemon —
// which never recorded that close — concludes nothing changed and stays quiet.
// The keeper reopens locally in seconds while the registry says closed forever:
// set by A, clearable only by B, and A prevents anything reaching B. Observed
// live for over two hours on a keeper with 56 MB free.
func admissionPublishIsRedundant(state AdmissionState, registryDiverged bool) bool {
	if registryDiverged {
		return false // the registry is wrong about us; correct it whatever we remember
	}
	if !lastAdmissionSynced || state.Closed != lastAdmissionClosed ||
		state.ClosureReason != lastAdmissionReason {
		return false
	}
	return state.SafeAllocatable == lastAdmissionFreeBytes ||
		time.Since(lastAdmissionSyncSuccess) < AdmissionRegistryFreeBytesSyncInterval
}

func maybeSyncAdmissionStatus(cfg ServerConfig) {
	if !cfg.SyncAdmissionToRegistry || cfg.VKRegistryContract == "" || cfg.VKRegistryABIPath == "" {
		log.Printf("[vk_adm] registry publication disabled enabled=%v registry=%v abi=%v",
			cfg.SyncAdmissionToRegistry, cfg.VKRegistryContract != "", cfg.VKRegistryABIPath != "")
		return
	}
	state := computeAdmissionState(cfg.Storage, cfg)
	admissionSyncMu.Lock()
	defer admissionSyncMu.Unlock()

	// What this process last published is not what the registry necessarily
	// holds. A vault keeper runs two processes against one registry entry: the
	// server publishes on store traffic, the proof daemon on its own cycle, and
	// each remembers only its own writes. So the server can publish "closed",
	// fall idle because a closed keeper receives no stores, and the daemon —
	// which never recorded that close — sees nothing changed and stays silent.
	// The keeper then reopens locally within seconds while the registry keeps
	// saying closed, indefinitely: set by A, clearable only by B, and A stops
	// anything from reaching B.
	//
	// Reading the registry costs one call a minute and removes the assumption
	// entirely. An open keeper that the registry still calls closed republishes
	// regardless of which process closed it.
	if admissionPublishIsRedundant(state, registryDisagreesWithAdmission(cfg, state.Closed)) {
		return
	}
	stateChanged := lastAdmissionSynced && state.Closed != lastAdmissionClosed
	if !stateChanged && time.Since(lastAdmissionSyncAttempt) < 5*time.Second {
		return
	}
	lastAdmissionSyncAttempt = time.Now()
	if syncAdmissionStatusOnRegistry(cfg, state) {
		lastAdmissionClosed = state.Closed
		lastAdmissionFreeBytes = state.SafeAllocatable
		lastAdmissionReason = state.ClosureReason
		lastAdmissionObservationBlock = state.CertificationObservationBlock
		lastAdmissionSynced = true
		lastAdmissionSyncSuccess = time.Now()
	}
}

func forceAdmissionRegistrySync(cfg ServerConfig) {
	admissionSyncMu.Lock()
	lastAdmissionSynced = false
	lastAdmissionSyncAttempt = time.Time{}
	admissionSyncMu.Unlock()
	maybeSyncAdmissionStatus(cfg)
}
