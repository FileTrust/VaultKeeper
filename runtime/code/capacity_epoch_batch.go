package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const capacityEpochBatchStateVersion = 1

type capacityEpochBatchState struct {
	Version                     int    `json:"version"`
	ManifestFingerprint         string `json:"manifestFingerprint"`
	FirstObservedChainUnix      int64  `json:"firstObservedChainUnix"`
	LastManifestChangeChainUnix int64  `json:"lastManifestChangeChainUnix"`
	UpdatedAt                   string `json:"updatedAt"`
}

type capacityProofBatchPolicy struct {
	Debounce               time.Duration
	MaxBatch               time.Duration
	MaxPendingMutations    int
	MaxPendingBytes        int64
	MaxDivergenceBytes     int64
	MaxTouchedPartitions   int
	MaxOldestMutationAge   time.Duration
	MaxQueueDepth          int
	MaxConsecutiveFailures int
	SubmissionSafety       time.Duration
}

type capacityProofBatchSignals struct {
	PendingMutations    int
	PendingBytes        int64
	CapacityDeltaBytes  int64
	TouchedPartitions   int
	OldestMutationAge   time.Duration
	MutationsPerSecond  float64
	DivergenceBytes     int64
	ProofQueueDepth     int
	AverageProofTime    time.Duration
	ProverAvailable     bool
	UserLoadActive      bool
	ConsecutiveFailures int
}

const capacityProofLagSnapshotVersion = 1

type capacityProofLagSnapshot struct {
	Version                  int    `json:"version"`
	ObservedAt               string `json:"observedAt"`
	ChainTimestamp           int64  `json:"chainTimestamp"`
	PendingMutations         int    `json:"pendingMutations"`
	PendingBytes             int64  `json:"pendingBytes"`
	OldestMutationAgeNanos   int64  `json:"oldestMutationAgeNanos"`
	MaximumLagNanos          int64  `json:"maximumLagNanos"`
	EstimatedCompletionNanos int64  `json:"estimatedCompletionNanos"`
	MutationDeadlineUnix     int64  `json:"mutationDeadlineUnix,omitempty"`
	DivergenceBytes          int64  `json:"divergenceBytes"`
	ProofQueueDepth          int    `json:"proofQueueDepth"`
	ConsecutiveFailedEpochs  int    `json:"consecutiveFailedEpochs"`
	AtRisk                   bool   `json:"atRisk"`
	Breached                 bool   `json:"breached"`
	Reason                   string `json:"reason,omitempty"`
}

func capacityProofLagSnapshotPath(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "capacity-proof-lag.json")
}

type capacityProofFailureState struct {
	Version             int    `json:"version"`
	ObservedEpochID     uint64 `json:"observedEpochId"`
	ObservedInvalidated bool   `json:"observedInvalidated"`
	LastCompletedAt     uint64 `json:"lastCompletedAt"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	UpdatedAt           string `json:"updatedAt"`
}

func capacityProofFailureStatePath(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "capacity-proof-failures.json")
}

// capacityProofLedgerConverged is the chain's own verdict that this keeper has nothing left to
// prove: no epoch running, a certificate still inside its freshness window, and the registered
// totals matching the proved totals on both halves of the ledger.
//
// It deliberately ignores Invalidated. That flag describes the PAST epoch, and an aborted epoch
// keeps it set until some later epoch begins — which is precisely the keeper that can no longer
// reach the timestamp-based success signal. The ledger equality is the stronger statement anyway:
// a keeper whose registered and proved totals agree has proved everything it claims to hold,
// however the last epoch ended.
//
// LastCapacityProofAt == 0 is excluded so a keeper that has never certified anything is not read
// as converged on the trivial 0 == 0 ledger it starts life with.
func capacityProofLedgerConverged(status CapacityProofEpochStatus) bool {
	if status.Active || !status.ProofFresh || status.LastCapacityProofAt == 0 {
		return false
	}
	return status.RegisteredFreeBytes == status.ProvedFreeBytes &&
		status.RegisteredDataBytes == status.ProvedDataBytes
}

func observeCapacityProofFailures(storage string, status CapacityProofEpochStatus) (int, error) {
	state := capacityProofFailureState{Version: 1}
	err := withCapacityEpochBatchStateLock(storage, func() error {
		path := capacityProofFailureStatePath(storage)
		if payload, readErr := os.ReadFile(path); readErr == nil {
			if json.Unmarshal(payload, &state) != nil || state.Version != 1 || state.ConsecutiveFailures < 0 {
				return fmt.Errorf("invalid capacity proof failure state")
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
		if status.ProofEpochID != state.ObservedEpochID {
			state.ObservedEpochID = status.ProofEpochID
			state.ObservedInvalidated = false
		}
		if status.Invalidated && !state.ObservedInvalidated {
			state.ConsecutiveFailures++
			state.ObservedInvalidated = true
		}
		if !status.Active && !status.Invalidated && status.LastCapacityProofAt > state.LastCompletedAt {
			state.ConsecutiveFailures = 0
			state.LastCompletedAt = status.LastCapacityProofAt
		}
		// A SECOND reset, because the one above is unreachable for the keeper that needs it most.
		//
		// An aborted epoch ends Invalidated and advances no proof timestamp, so BOTH clauses of
		// the timestamp reset are false at once, and they stay false: Invalidated holds until a
		// new epoch begins, and a converged keeper begins none, because every epoch opener needs
		// something local to point at. The counter then stays pinned at the limit forever.
		//
		// Live on 2026-09-30: vk_5 sat at consecutiveFailures=3 against a limit of 3 with
		// observedEpochId=2 observedInvalidated=true lastCompletedAt=1790712308, while chain
		// getActiveProofEpoch read epoch 2 active=false invalidated=true (aborted at 9 of 10
		// partitions after its cutoff stayed unresolvable) and lastCapacityProofAt was exactly
		// 1790712308 — equal, not greater. Its ledger read registeredFree == provedFree
		// (209715200) and registeredData == provedData (51384832) with a fresh certificate, so it
		// had genuinely proved everything it held.
		//
		// With the counter pinned, the backlog guard below is the only remaining term, so
		// admission slammed shut on every transient queued proof job and reopened when the queue
		// drained: twelve close/open cycles in forty minutes, leaving the keeper open for roughly
		// one minute in four. The 2026-09-28 backlog guard stopped the fully-idle keeper from
		// wedging shut, but a working keeper flapped instead, because the counter itself was never
		// the thing that got fixed.
		if capacityProofLedgerConverged(status) {
			state.ConsecutiveFailures = 0
			if status.LastCapacityProofAt > state.LastCompletedAt {
				state.LastCompletedAt = status.LastCapacityProofAt
			}
		}
		state.UpdatedAt = nowRFC3339()
		payload, marshalErr := json.MarshalIndent(state, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		return durableAtomicWriteFile(path, payload, 0600)
	})
	return state.ConsecutiveFailures, err
}

func resolvedCapacityProofBatchPolicy(cfg ServerConfig) capacityProofBatchPolicy {
	policy := capacityProofBatchPolicy{
		Debounce:               time.Duration(cfg.CapacityProofDebounceSeconds) * time.Second,
		MaxBatch:               time.Duration(cfg.CapacityProofMaxBatchSeconds) * time.Second,
		MaxPendingMutations:    cfg.CapacityProofMaxPendingMutations,
		MaxPendingBytes:        cfg.CapacityProofMaxPendingBytes,
		MaxDivergenceBytes:     cfg.CapacityProofMaxDivergenceBytes,
		MaxTouchedPartitions:   cfg.CapacityProofMaxTouchedPartitions,
		MaxOldestMutationAge:   time.Duration(cfg.CapacityProofMaxOldestMutationSeconds) * time.Second,
		MaxQueueDepth:          cfg.CapacityProofMaxQueueDepth,
		MaxConsecutiveFailures: cfg.CapacityProofMaxConsecutiveFailedEpochs,
		SubmissionSafety:       time.Duration(cfg.CapacityProofSubmissionSafetySeconds) * time.Second,
	}
	if policy.Debounce <= 0 {
		policy.Debounce = time.Duration(DefaultCapacityProofDebounceSeconds) * time.Second
	}
	if policy.MaxBatch <= 0 {
		policy.MaxBatch = time.Duration(DefaultCapacityProofMaxBatchSeconds) * time.Second
	}
	if policy.MaxPendingMutations <= 0 {
		policy.MaxPendingMutations = DefaultCapacityProofMaxPendingMutations
	}
	if policy.MaxPendingBytes <= 0 {
		policy.MaxPendingBytes = DefaultCapacityProofMaxPendingBytes
	}
	if policy.MaxDivergenceBytes <= 0 {
		policy.MaxDivergenceBytes = DefaultCapacityProofMaxDivergenceBytes
	}
	if policy.MaxTouchedPartitions <= 0 {
		policy.MaxTouchedPartitions = DefaultCapacityProofMaxTouchedPartitions
	}
	if policy.MaxOldestMutationAge <= 0 {
		policy.MaxOldestMutationAge = time.Duration(DefaultCapacityProofMaxOldestMutationSeconds) * time.Second
	}
	if policy.MaxQueueDepth <= 0 {
		policy.MaxQueueDepth = DefaultCapacityProofMaxQueueDepth
	}
	if policy.MaxConsecutiveFailures <= 0 {
		policy.MaxConsecutiveFailures = DefaultCapacityProofMaxConsecutiveFailedEpochs
	}
	if policy.SubmissionSafety <= 0 {
		policy.SubmissionSafety = time.Duration(DefaultCapacityProofSubmissionSafetySeconds) * time.Second
	}
	return policy
}

func validateCapacityProofBatchConfig(cfg ServerConfig) error {
	if cfg.CapacityProofDebounceSeconds < 0 || cfg.CapacityProofMaxBatchSeconds < 0 ||
		cfg.CapacityProofMaxPendingMutations < 0 || cfg.CapacityProofMaxPendingBytes < 0 ||
		cfg.CapacityProofMaxDivergenceBytes < 0 || cfg.CapacityProofMaxTouchedPartitions < 0 ||
		cfg.CapacityProofMaxOldestMutationSeconds < 0 || cfg.CapacityProofMaxQueueDepth < 0 ||
		cfg.CapacityProofMaxConsecutiveFailedEpochs < 0 || cfg.CapacityProofSubmissionSafetySeconds < 0 {
		return fmt.Errorf("capacity proof batch thresholds cannot be negative")
	}
	p := resolvedCapacityProofBatchPolicy(cfg)
	if p.Debounce > p.MaxBatch || p.MaxOldestMutationAge > p.MaxBatch {
		return fmt.Errorf("capacity proof debounce and oldest-mutation objectives must not exceed max batch window")
	}
	if p.MaxPendingMutations < 1 || p.MaxPendingBytes < 1 || p.MaxDivergenceBytes < 1 ||
		p.MaxTouchedPartitions < 1 || p.MaxQueueDepth < 1 || p.MaxConsecutiveFailures < 1 {
		return fmt.Errorf("capacity proof batch thresholds must be positive")
	}
	return nil
}

func signedAbs(value int64) int64 {
	if value >= 0 {
		return value
	}
	if value == math.MinInt64 {
		return math.MaxInt64
	}
	return -value
}

func uint64AbsDiff(a, b uint64) int64 {
	var delta uint64
	if a >= b {
		delta = a - b
	} else {
		delta = b - a
	}
	if delta > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(delta)
}

func collectCapacityProofBatchSignals(storage string, status CapacityProofEpochStatus, chainTimestamp int64, estimate time.Duration) (capacityProofBatchSignals, error) {
	signals := capacityProofBatchSignals{AverageProofTime: estimate, ProverAvailable: !proofWorkActive(), UserLoadActive: hostForegroundActivityActive()}
	// Mutation-journal timestamps are written by the host clock. Hardhat and other test
	// chains may advance their block clock for governance without advancing the host clock,
	// so journal ages must stay in the host domain. Chain deadlines are derived separately
	// below from the resulting duration and the current chain timestamp.
	hostNow := time.Now()
	failures, failureErr := observeCapacityProofFailures(storage, status)
	if failureErr != nil {
		return signals, failureErr
	}
	signals.ConsecutiveFailures = failures
	err := withCapacityCoordinationLock(storage, func() error {
		records, err := listPendingCapacityMutationJournalRecordsUnlocked(storage)
		if err != nil {
			return err
		}
		touched := map[string]struct{}{}
		oldest := time.Time{}
		for _, record := range records {
			if record.Status == capacityMutationStatusAbandoned || record.Status == capacityMutationStatusIncluded {
				continue
			}
			signals.PendingMutations++
			if affected := signedAbs(record.AffectedBytes); affected > math.MaxInt64-signals.PendingBytes {
				signals.PendingBytes = math.MaxInt64
			} else {
				signals.PendingBytes += affected
			}
			if created, parseErr := time.Parse(time.RFC3339Nano, record.CreatedAt); parseErr == nil &&
				(oldest.IsZero() || created.Before(oldest)) {
				oldest = created
			}
			for _, transition := range record.Transitions {
				for _, state := range []capacityMutationSectorState{transition.Old, transition.New} {
					if state.PartitionKind != "" {
						touched[fmt.Sprintf("%s/%d/%d", state.PartitionKind, state.DeadlineIndex, state.PartitionIndex)] = struct{}{}
					}
				}
				delta := transition.New.CommittedBytes - transition.Old.CommittedBytes
				if signedAbs(delta) > math.MaxInt64-signals.CapacityDeltaBytes {
					signals.CapacityDeltaBytes = math.MaxInt64
				} else {
					signals.CapacityDeltaBytes += signedAbs(delta)
				}
			}
		}
		signals.TouchedPartitions = len(touched)
		if !oldest.IsZero() && hostNow.After(oldest) {
			signals.OldestMutationAge = hostNow.Sub(oldest)
			if signals.OldestMutationAge > 0 {
				signals.MutationsPerSecond = float64(signals.PendingMutations) / signals.OldestMutationAge.Seconds()
			}
		}
		return nil
	})
	if err != nil {
		return signals, err
	}
	signals.DivergenceBytes = uint64AbsDiff(status.RegisteredFreeBytes, status.ProvedFreeBytes)
	if data := uint64AbsDiff(status.RegisteredDataBytes, status.ProvedDataBytes); data > math.MaxInt64-signals.DivergenceBytes {
		signals.DivergenceBytes = math.MaxInt64
	} else {
		signals.DivergenceBytes += data
	}
	if lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv)); lockPath != "" {
		metrics, metricsErr := proofSchedulerMetrics(lockPath, time.Now())
		if metricsErr != nil {
			return signals, metricsErr
		}
		for _, count := range metrics.QueuedByClass {
			signals.ProofQueueDepth += count
		}
	}
	return signals, nil
}

func capacityBatchThresholdReached(policy capacityProofBatchPolicy, signals capacityProofBatchSignals) (bool, string) {
	queueDelay := time.Duration(signals.ProofQueueDepth) * signals.AverageProofTime
	required := signals.AverageProofTime + queueDelay + policy.SubmissionSafety
	if signals.PendingMutations > 0 && signals.OldestMutationAge+required >= policy.MaxOldestMutationAge {
		return true, fmt.Sprintf("hard mutation lag budget reached (age=%s required=%s limit=%s)",
			signals.OldestMutationAge.Round(time.Second), required.Round(time.Second), policy.MaxOldestMutationAge.Round(time.Second))
	}
	switch {
	case signals.PendingMutations >= policy.MaxPendingMutations:
		return true, fmt.Sprintf("pending mutation threshold reached (%d/%d)", signals.PendingMutations, policy.MaxPendingMutations)
	case signals.PendingBytes >= policy.MaxPendingBytes:
		return true, fmt.Sprintf("pending byte threshold reached (%d/%d)", signals.PendingBytes, policy.MaxPendingBytes)
	case signals.CapacityDeltaBytes >= policy.MaxDivergenceBytes:
		return true, "total capacity delta threshold reached"
	case signals.DivergenceBytes >= policy.MaxDivergenceBytes:
		return true, "live-versus-proved capacity divergence threshold reached"
	case signals.TouchedPartitions >= policy.MaxTouchedPartitions:
		return true, "touched partition threshold reached"
	case signals.OldestMutationAge >= policy.MaxOldestMutationAge:
		return true, "oldest unproved mutation service objective reached"
	case signals.ProofQueueDepth >= policy.MaxQueueDepth:
		return true, "proof queue depth threshold reached"
	case signals.ConsecutiveFailures >= policy.MaxConsecutiveFailures:
		return true, "consecutive failed epoch service objective reached"
	}
	// Predictive closure prevents sustained input from crossing the operation
	// objective while the measured proof is running.
	projected := float64(signals.PendingMutations) + signals.MutationsPerSecond*signals.AverageProofTime.Seconds()
	if projected >= float64(policy.MaxPendingMutations) {
		return true, "mutation rate predicts operation objective breach during proof"
	}
	// G.3A: an idle prover is not a reason on its own. A single ordinary mutation must wait for
	// debounce, a threshold, or latest-safe-start pressure like any other work, and that
	// decision is made from the SELECTED work in liveSelectedWorkDecision.

	return false, "capacity batch remains within configured service objectives"
}

func refreshCapacityProofLagSnapshot(
	storage string,
	status CapacityProofEpochStatus,
	partitions []PartitionMeta,
	chainTimestamp, proofPeriodSeconds int64,
	cfg ServerConfig,
) (capacityProofLagSnapshot, error) {
	policy := resolvedCapacityProofBatchPolicy(cfg)
	// G.3C: lag refresh is an ordinary scheduling observation, so it must cost the exact
	// selected plan and must never invoke the whole-manifest estimator. With no selected plan
	// there is no proof-duration obligation to invent; submission safety remains explicit.
	_ = proofPeriodSeconds
	estimate := time.Duration(0)
	haveSelected, _, _, selected, selectedErr := liveSelectedWorkDecision(
		storage, partitions, chainTimestamp, status.DeclaredCapacityBytes, cfg)
	if selectedErr != nil {
		return capacityProofLagSnapshot{}, selectedErr
	}
	if haveSelected && selected.PlanValid {
		estimate = selected.SelectedBatchEstimatedDuration
	}
	signals, err := collectCapacityProofBatchSignals(storage, status, chainTimestamp, estimate)
	if err != nil {
		return capacityProofLagSnapshot{}, err
	}
	queueDelay := time.Duration(signals.ProofQueueDepth) * estimate
	required := estimate + queueDelay + policy.SubmissionSafety
	snapshot := capacityProofLagSnapshot{
		Version: capacityProofLagSnapshotVersion, ObservedAt: nowRFC3339(), ChainTimestamp: chainTimestamp,
		PendingMutations: signals.PendingMutations, PendingBytes: signals.PendingBytes,
		OldestMutationAgeNanos: int64(signals.OldestMutationAge), MaximumLagNanos: int64(policy.MaxOldestMutationAge),
		EstimatedCompletionNanos: int64(required), DivergenceBytes: signals.DivergenceBytes,
		ProofQueueDepth: signals.ProofQueueDepth, ConsecutiveFailedEpochs: signals.ConsecutiveFailures,
	}
	if signals.PendingMutations > 0 {
		oldestUnix := chainTimestamp - int64(signals.OldestMutationAge/time.Second)
		snapshot.MutationDeadlineUnix = oldestUnix + int64(policy.MaxOldestMutationAge/time.Second)
		snapshot.AtRisk = signals.OldestMutationAge+required >= policy.MaxOldestMutationAge
		snapshot.Breached = signals.OldestMutationAge >= policy.MaxOldestMutationAge
	}
	// The consecutive-failure breaker describes RISK TO A BACKLOG, so it may only fire while
	// a backlog exists. With no pending mutation, no divergence and an empty proof queue there
	// is nothing outstanding that repeated failures could endanger: the keeper has converged,
	// and holding admission closed protects nothing while guaranteeing it never reopens.
	//
	// It never reopens because the counter's own reset is unreachable from here.
	// observeCapacityProofFailures clears it only when `!status.Invalidated &&
	// LastCapacityProofAt > LastCompletedAt`, and `Invalidated` is the persistent terminal
	// state of the LAST epoch — it stays set until a new epoch begins. A converged keeper
	// starts no new epoch, because every opener needs something local to point at: a pending
	// mutation, a divergence, a stale certificate, or a blocked demand. So the flag stays set,
	// the counter stays frozen above the limit, and admission stays shut.
	//
	// Live on 2026-09-28: vk_9 sat closed on capacity_backlog_unsafe with
	// consecutiveFailedEpochs=4 against a limit of 3, while its own lag snapshot read
	// pendingMutations=0 pendingBytes=0 divergenceBytes=0 proofQueueDepth=0, its ledger read
	// registered == proved on both totals (200 MiB free, 53.67 MiB data), and its certificate
	// was fresh for another twenty-four hours. capacity-proof-failures.json showed
	// observedEpochId=2 observedInvalidated=true lastCompletedAt=1790608400, and chain
	// lastCapacityProofAt was exactly 1790608400 — so both halves of the reset were blocked at
	// once. It had nothing to prove and no way to say so, and it held the load test's startup
	// gate at 9/10 keepers.
	//
	// Same shape as the vk_7 wedge fixed alongside this: the escape route required a signal
	// that the closed state itself prevents. The breaker still fires on every keeper that has
	// real work outstanding, which is the only situation it was defending.
	backlogOutstanding := signals.PendingMutations > 0 ||
		signals.DivergenceBytes > 0 || signals.ProofQueueDepth > 0
	if signals.ConsecutiveFailures >= policy.MaxConsecutiveFailures && backlogOutstanding {
		snapshot.AtRisk = true
		snapshot.Reason = "consecutive failed capacity epochs reached configured limit"
	} else if snapshot.Breached {
		snapshot.Reason = "oldest unproved capacity mutation exceeded configured maximum lag"
	} else if snapshot.AtRisk {
		snapshot.Reason = "remaining mutation lag is smaller than queued proof and submission budget"
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return snapshot, err
	}
	if err := durableAtomicWriteFile(capacityProofLagSnapshotPath(storage), payload, 0600); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func readCapacityProofLagSnapshot(storage string) (capacityProofLagSnapshot, bool, error) {
	var snapshot capacityProofLagSnapshot
	payload, err := os.ReadFile(capacityProofLagSnapshotPath(storage))
	if os.IsNotExist(err) {
		return snapshot, false, nil
	}
	if err != nil {
		return snapshot, false, err
	}
	if json.Unmarshal(payload, &snapshot) != nil || snapshot.Version != capacityProofLagSnapshotVersion ||
		snapshot.PendingMutations < 0 || snapshot.PendingBytes < 0 || snapshot.MaximumLagNanos <= 0 {
		return snapshot, true, fmt.Errorf("invalid capacity proof lag snapshot")
	}
	return snapshot, true, nil
}

func capacityEpochBatchStatePath(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "capacity-epoch-batch.json")
}

func capacityEpochBatchStateLockPath(storage string) string {
	return capacityEpochBatchStatePath(storage) + ".lock"
}

func withCapacityEpochBatchStateLock(storage string, fn func() error) error {
	path := capacityEpochBatchStateLockPath(storage)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

func capacityEpochManifestFingerprint(partitions []PartitionMeta) (string, int, error) {
	relevant := make([]PartitionMeta, 0, len(partitions))
	for _, partition := range partitions {
		if partition.PartitionKind == PartitionKindCapacity ||
			partition.PartitionKind == PartitionKindData {
			relevant = append(relevant, partition)
		}
	}
	if len(relevant) == 0 {
		return "", 0, fmt.Errorf("capacity epoch manifest has no proof partitions")
	}
	sort.Slice(relevant, func(i, j int) bool {
		if relevant[i].PartitionKind != relevant[j].PartitionKind {
			return relevant[i].PartitionKind < relevant[j].PartitionKind
		}
		if relevant[i].DeadlineIndex != relevant[j].DeadlineIndex {
			return relevant[i].DeadlineIndex < relevant[j].DeadlineIndex
		}
		return relevant[i].PartitionIndex < relevant[j].PartitionIndex
	})
	h := sha256.New()
	for _, partition := range relevant {
		if partition.CommittedBytes <= 0 {
			return "", 0, fmt.Errorf(
				"capacity epoch partition %s dl%d-pt%d has no committed bytes",
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
			)
		}
		_, _ = fmt.Fprintf(
			h, "%s\x00%d\x00%d\x00%d\x00%s\n",
			partition.PartitionKind,
			partition.DeadlineIndex,
			partition.PartitionIndex,
			partition.CommittedBytes,
			partitionContentHash(partition),
		)
	}
	return hex.EncodeToString(h.Sum(nil)), len(relevant), nil
}

func validCapacityEpochBatchState(state capacityEpochBatchState) bool {
	if state.Version != capacityEpochBatchStateVersion ||
		len(state.ManifestFingerprint) != 64 ||
		state.ManifestFingerprint != strings.ToLower(state.ManifestFingerprint) ||
		state.FirstObservedChainUnix <= 0 ||
		state.LastManifestChangeChainUnix < state.FirstObservedChainUnix {
		return false
	}
	_, err := hex.DecodeString(state.ManifestFingerprint)
	return err == nil
}

func observeCapacityEpochManifest(
	storage, fingerprint string, chainTimestamp int64,
) (state capacityEpochBatchState, err error) {
	if chainTimestamp <= 0 || len(fingerprint) != 64 {
		return state, fmt.Errorf("invalid capacity epoch batching observation")
	}
	err = withCapacityEpochBatchStateLock(storage, func() error {
		path := capacityEpochBatchStatePath(storage)
		payload, readErr := os.ReadFile(path)
		found := readErr == nil
		if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		if found {
			if json.Unmarshal(payload, &state) != nil || !validCapacityEpochBatchState(state) {
				return fmt.Errorf("invalid durable capacity epoch batching state")
			}
		}
		if !found || state.FirstObservedChainUnix > chainTimestamp ||
			state.LastManifestChangeChainUnix > chainTimestamp {
			state = capacityEpochBatchState{
				Version:                     capacityEpochBatchStateVersion,
				ManifestFingerprint:         fingerprint,
				FirstObservedChainUnix:      chainTimestamp,
				LastManifestChangeChainUnix: chainTimestamp,
			}
		} else if state.ManifestFingerprint != fingerprint {
			state.ManifestFingerprint = fingerprint
			state.LastManifestChangeChainUnix = chainTimestamp
		}
		state.UpdatedAt = nowRFC3339()
		encoded, marshalErr := json.MarshalIndent(state, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		return durableAtomicWriteFile(path, encoded, 0600)
	})
	return state, err
}

func clearCapacityEpochBatchState(storage string) error {
	return withCapacityEpochBatchStateLock(storage, func() error {
		path := capacityEpochBatchStatePath(storage)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		dir, err := os.Open(filepath.Dir(path))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
}

func capacityEpochProofEstimate(
	partitions []PartitionMeta, proofPeriodSeconds int64,
) time.Duration {
	relevant := make([]PartitionMeta, 0, len(partitions))
	for _, partition := range partitions {
		if partition.PartitionKind == PartitionKindCapacity ||
			partition.PartitionKind == PartitionKindData {
			relevant = append(relevant, partition)
		}
	}
	if len(relevant) == 0 {
		return 0
	}
	period := 24 * time.Hour
	if proofPeriodSeconds > 0 && proofPeriodSeconds <= int64(math.MaxInt64/time.Second) {
		period = time.Duration(proofPeriodSeconds) * time.Second
	}
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	estimates := make([]time.Duration, len(relevant))
	maximumKnown := time.Duration(0)
	for i, partition := range relevant {
		class := fmt.Sprintf(
			"%s-final-n%d", partition.PartitionKind, len(partition.Sectors),
		)
		if lockPath != "" {
			estimates[i] = time.Duration(readProofWorkEstimate(lockPath, class))
		}
		if estimates[i] > maximumKnown {
			maximumKnown = estimates[i]
		}
	}
	fallback := maximumKnown
	if fallback <= 0 {
		fallback = period / (3 * time.Duration(len(relevant)))
	}
	if fallback < 30*time.Second {
		fallback = 30 * time.Second
	}
	total := time.Duration(0)
	for _, estimate := range estimates {
		if estimate <= 0 {
			estimate = fallback
		}
		if estimate < 30*time.Second {
			estimate = 30 * time.Second
		}
		if estimate > time.Duration(math.MaxInt64)-total {
			return time.Duration(math.MaxInt64)
		}
		total += estimate
	}
	return total
}

func durationSecondsCeil(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	seconds := value / time.Second
	if value%time.Second != 0 {
		seconds++
	}
	return int64(seconds)
}

// capacityProofEpochStartReady batches a changing manifest only while the last
// complete proof remains safe. The wait is derived from measured prover time:
// quiet traffic starts quickly, continuous traffic starts after roughly one
// epoch of accumulated work, and an initial/stale/freshness refresh never waits.
//
// emptyDeletionPending forces the epoch to be considered due (empty deletes need
// capacityProofSequence to advance). Every new epoch waits only for the narrow
// pre-successor deletion window: a deletion declared before this epoch cannot
// retroactively exclude its member. Already-sealed epochs are never stopped here.
func capacityProofEpochStartReady(
	storage string,
	status CapacityProofEpochStatus,
	partitions []PartitionMeta,
	chainTimestamp, proofPeriodSeconds int64,
	catchupPending bool,
	emptyDeletionPending bool,
) (bool, string, error) {
	// Compatibility wrapper for unit/standalone callers that do not own the
	// runtime configuration. Production always calls the configured variant.
	compatibility := compatibilityCapacityStartConfig(status)
	return capacityProofEpochStartReadyWithConfig(
		storage, status, partitions, chainTimestamp, proofPeriodSeconds,
		catchupPending, emptyDeletionPending, compatibility,
	)
}

func compatibilityCapacityStartConfig(status CapacityProofEpochStatus) ServerConfig {
	return ServerConfig{
		ChainID: 31337, VKAddress: "0x0000000000000000000000000000000000000002",
		CapacityProofContract: "0x0000000000000000000000000000000000000001",
		CapacityBytes:         int64(status.DeclaredCapacityBytes),
		ZKBlockSize:           DefaultZKBlockSize, ZKTreeDepth: DefaultZKTreeDepth,
		CapacityProofDebounceSeconds:            10,
		CapacityProofMaxBatchSeconds:            40,
		CapacityProofMaxOldestMutationSeconds:   40,
		CapacityProofMaxPendingMutations:        math.MaxInt,
		CapacityProofMaxPendingBytes:            math.MaxInt64,
		CapacityProofMaxDivergenceBytes:         math.MaxInt64,
		CapacityProofMaxTouchedPartitions:       math.MaxInt,
		CapacityProofMaxQueueDepth:              math.MaxInt,
		CapacityProofMaxConsecutiveFailedEpochs: math.MaxInt,
		CapacityProofSubmissionSafetySeconds:    30,
	}
}

// liveSelectedWorkDecision is the G.3 decision on the REAL scheduler path.
//
// It costs only the durable frozen selection (G.2) and never the whole manifest. The legacy
// `capacityEpochProofEstimate` is reachable from here only for an explicit FULL sweep.
//
// Returns (haveIncrementalWork, due, reason, estimate). When there is no durable incremental
// plan the caller falls through to the full-sweep path unchanged.
func liveSelectedWorkDecision(
	storage string,
	partitions []PartitionMeta,
	chainTimestamp int64,
	declaredCapacity uint64,
	cfg ServerConfig,
) (bool, bool, BatchTriggerReason, SelectedWorkEstimate, error) {
	plan, planOK, planErr := readCapacityBatchChunkPlan(storage)
	if planErr != nil {
		// Ambiguous durable state fails conservative: no incremental launch, explicit reason.
		return true, false, TriggerNoSelectedWork, SelectedWorkEstimate{}, planErr
	}
	if !planOK || len(plan.Chunks) == 0 {
		return false, false, TriggerNoSelectedWork, SelectedWorkEstimate{}, nil
	}
	return selectedWorkDecisionForPlan(
		storage, plan, partitions, chainTimestamp, declaredCapacity, cfg)
}

// selectedWorkDecisionForPlan is the G.3 costing for ONE plan, whether that plan is the durable
// one or an ephemeral candidate plan that has not been (and may never be) frozen.
//
// G.4B-LV3 needs the normal-work estimate BEFORE deciding whether to freeze the normal plan at
// all, so the estimator had to become independent of durable persistence. Splitting it here keeps
// exactly one estimator implementation: `liveSelectedWorkDecision` reads the durable plan and
// delegates, and the urgency precedence path supplies an ephemeral plan and delegates to the same
// code. No arithmetic is duplicated.
func selectedWorkDecisionForPlan(
	storage string,
	plan capacityBatchChunkPlan,
	partitions []PartitionMeta,
	chainTimestamp int64,
	declaredCapacity uint64,
	cfg ServerConfig,
) (bool, bool, BatchTriggerReason, SelectedWorkEstimate, error) {
	if len(plan.Chunks) == 0 {
		return false, false, TriggerNoSelectedWork, SelectedWorkEstimate{}, nil
	}
	chunk, ok := plan.nextPendingChunk()
	if !ok {
		return true, false, TriggerNoSelectedWork, SelectedWorkEstimate{}, nil
	}

	pending := make([]capacityBatchChunk, 0, len(plan.Chunks)-1)
	for _, other := range plan.Chunks {
		if other.Index != chunk.Index && !other.Done {
			pending = append(pending, other)
		}
	}
	estimate, err := liveSelectedWorkEstimateForChunk(
		storage, partitions, plan, chunk, 0, pending, chainTimestamp, declaredCapacity, cfg)
	if err != nil {
		return true, false, TriggerNoSelectedWork, SelectedWorkEstimate{}, err
	}
	due, reason := EvaluateBatchTrigger(estimate, BatchTriggerInputs{
		RecoveryEmergency: chunk.RecoveryEmergency,
		PendingBytes:      estimate.SelectedBytes,
		PendingMutations:  estimate.CandidateCount,
		TouchedPartitions: estimate.SelectedPartitionCount,
		BatchAge:          estimate.OldestSelectedMutationAge,
	}, resolvedSelectedWorkPolicy(cfg, declaredCapacity))
	estimate.BatchTriggerReason = reason
	return true, due, reason, estimate, nil
}

// liveSelectedWorkEstimateForChunk is the one production G.3 costing path shared by the
// scheduler and G.4B normal-completion projection. It resolves exact registered shapes, durable
// observed durations, active work, every supplied pending chunk, queue delay and saturating sums.
// Callers choose the selected chunk and the durable chunks that are ahead; they do not reproduce
// any duration arithmetic themselves.
func liveSelectedWorkEstimateForChunk(
	storage string,
	partitions []PartitionMeta,
	plan capacityBatchChunkPlan,
	chunk capacityBatchChunk,
	activeCampaignRemaining time.Duration,
	pendingChunks []capacityBatchChunk,
	chainTimestamp int64,
	declaredCapacity uint64,
	cfg ServerConfig,
) (SelectedWorkEstimate, error) {
	// Proof SHAPE per registered partition — kind and sector count only, never content.
	shapeByKey := map[string]ProofShapeKey{}
	bytesByKey := map[string]uint64{}
	for _, partition := range partitions {
		key := strings.ToLower(strings.TrimSpace(epochPartitionKey(partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)))
		if key == "" {
			continue
		}
		shapeByKey[key] = proofShapeKeyFor(partition.PartitionKind, len(partition.Sectors))
		if partition.CommittedBytes > 0 {
			bytesByKey[key] = uint64(partition.CommittedBytes)
		}
	}

	selection := CapacityBatchSelection{Mode: BatchModeIncremental}
	allIdentitiesKnown := true
	var unresolvedChunkKeys []string
	for _, key := range chunk.Keys {
		if _, known := shapeByKey[key]; !known {
			// G.3B: a frozen member that is not in the current registered manifest means chain
			// state and the durable plan disagree. That is a recovery condition, never a
			// licence to launch a partial campaign.
			allIdentitiesKnown = false
			unresolvedChunkKeys = append(unresolvedChunkKeys, key)
		}
		selection.Selected = append(selection.Selected, SelectedPartition{
			Identity: PartitionIdentity{PartitionKey: key, Active: true},
		})
		selection.SelectedBytes += bytesByKey[key]
	}
	selection.SelectedPartitionCount = len(selection.Selected)
	selection.CandidateCount = len(plan.allKeys())

	policy := resolvedSelectedWorkPolicy(cfg, declaredCapacity)
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath != "" {
		metrics, metricsErr := proofSchedulerMetrics(lockPath, time.Now())
		if metricsErr != nil {
			return SelectedWorkEstimate{}, metricsErr
		}
		for _, count := range metrics.QueuedByClass {
			policy.ProofQueueDepth += count
		}
		// Queue entries have not yet produced an identity-specific observation. Cost each one
		// at the conservative per-member fallback instead of treating queued work as free.
		policy.PerQueuedJobDelay = policy.ColdStartMemberDuration
	}
	lookup := func(shape ProofShapeKey) (time.Duration, bool) {
		if lockPath == "" || shape == "" {
			return 0, false
		}
		observed := time.Duration(readProofWorkEstimate(lockPath, string(shape)))
		return observed, observed > 0
	}
	shapes := func(identity PartitionIdentity) (ProofShapeKey, bool) {
		shape, ok := shapeByKey[identity.PartitionKey]
		return shape, ok
	}

	// Cost each durable pending chunk through the SAME selected-batch estimator. This includes
	// its exact member shapes, submission/confirmation margins and queue delay; an unknown member
	// makes the final plan invalid rather than silently disappearing.
	var ahead []PendingChunkCost
	var unresolvedAheadKeys []string
	for _, other := range pendingChunks {
		if other.Done || other.Index == chunk.Index {
			continue
		}
		otherSelection := CapacityBatchSelection{Mode: BatchModeIncremental}
		otherKnown := true
		for _, key := range other.Keys {
			if _, known := shapeByKey[key]; !known {
				otherKnown = false
				unresolvedAheadKeys = append(unresolvedAheadKeys,
					fmt.Sprintf("chunk%d:%s", other.Index, key))
			}
			otherSelection.Selected = append(otherSelection.Selected, SelectedPartition{
				Identity: PartitionIdentity{PartitionKey: key, Active: true},
			})
			otherSelection.SelectedBytes += bytesByKey[key]
		}
		otherSelection.SelectedPartitionCount = len(otherSelection.Selected)
		otherSelection.CandidateCount = len(plan.allKeys())
		otherEstimate := EstimateSelectedWork(otherSelection, shapes, lookup, 0, nil, policy)
		allIdentitiesKnown = allIdentitiesKnown && otherKnown
		ahead = append(ahead, PendingChunkCost{
			Index: other.Index, Reconstructed: otherKnown, MemberCount: len(other.Keys),
			Remaining: otherEstimate.RequiredDuration,
		})
	}

	estimate := EstimateSelectedWork(
		selection, shapes, lookup, activeCampaignRemaining, ahead, policy)
	estimate.PlanValid = allIdentitiesKnown
	// D.3-VK OBSERVABILITY ONLY — no semantic change. An invalid selected plan
	// fail-closes at capacity_epoch_batch.go's PlanValid gate with err=nil, so the
	// caller logs nothing and the VK goes silent while capacity cannot progress.
	// Name the exact unresolved identities so the condition is diagnosable.
	if !allIdentitiesKnown {
		logUnresolvedSelectedIdentities(
			chunk, unresolvedChunkKeys, unresolvedAheadKeys, shapeByKey, plan)
	}
	estimate.BatchPlanID = fmt.Sprintf("chunk-%d", chunk.Index)
	if oldest := oldestPendingMutationAge(storage, chainTimestamp); oldest > 0 {
		estimate.OldestSelectedMutationAge = oldest
		// SMOKE-9: overwriting the age alone left LatestSafeStartIn derived from the
		// stale selected-only age (live: oldestAge=15m49s vs latestSafeStartIn=14m30s).
		// Rebind the derived decision to the authoritative age AND charge the successor
		// its own campaign, which the selected RequiredDuration does not contain.
		estimate = estimate.RebindLatestSafeStart(oldest, policy.HardMutationLagLimit)
	}
	if chunk.FreshnessDeadline {
		estimate.EarliestSelectedCertificateExpiry = time.Nanosecond
	}
	return estimate, nil
}

// resolvedSelectedWorkPolicy maps the existing batching configuration onto the G.3 policy.
func resolvedSelectedWorkPolicy(cfg ServerConfig, declaredCapacity uint64) SelectedWorkPolicy {
	batch := resolvedCapacityProofBatchPolicy(cfg)
	return SelectedWorkPolicy{
		ColdStartMemberDuration: defaultColdStartMemberDuration,
		MinimumMemberDuration:   defaultMinimumMemberDuration,
		SubmissionDuration:      batch.SubmissionSafety,
		ConfirmationMargin:      batch.SubmissionSafety,
		HardMutationLagLimit:    batch.MaxOldestMutationAge,
		Debounce:                batch.Debounce,
		MaxBatchAge:             batch.MaxBatch,
		MaxPendingMutations:     int(batch.MaxPendingMutations),
		MaxTouchedPartitions:    int(batch.MaxTouchedPartitions),
		MaxBacklogDuration:      batch.MaxBatch,
		PendingBytes:            defaultRelativePendingBytesPolicy,
		DeclaredCapacity:        declaredCapacity,
	}
}

// oldestPendingMutationAge reads the durable mutation journal for the oldest unproved age.
func oldestPendingMutationAge(storage string, chainTimestamp int64) time.Duration {
	snapshot, ok, err := readCapacityProofLagSnapshot(storage)
	if err != nil || !ok || snapshot.OldestMutationAgeNanos <= 0 {
		return 0
	}
	_ = chainTimestamp
	return time.Duration(snapshot.OldestMutationAgeNanos)
}

// startDecisionResult is the single exit point of the start-ready evaluation. It validates the
// G.3B invariant, records a recovery condition when the decision failed closed, and converts to
// the caller's existing (ready, reason, error) contract — where `ready` is now
// `MayOpenCampaign()`, so no error path can ever reach the campaign-opening call site.
func startDecisionResult(storage string, decision CapacityStartDecision) (bool, string, error) {
	if err := decision.validate(); err != nil {
		// A decision that violates the invariant is itself a defect: refuse to launch.
		return false, "invalid start decision: " + err.Error(), err
	}
	if decision.RecoveryRequired {
		if err := enterCapacityBatchRecoveryState(
			storage, string(decision.FailureClass)+": "+decision.Detail, time.Now(),
		); err != nil {
			// Even recording the recovery condition failed; still never launch.
			return false, decision.String() + "; recovery state unavailable", err
		}
	}
	lastCapacityStartDecision.Store(&decision)
	return decision.MayOpenCampaign(), decision.String(), decision.RecoverableError
}

// lastCapacityStartDecision exposes the most recent typed decision for observability and tests.
var lastCapacityStartDecision atomic.Pointer[CapacityStartDecision]

// latestCapacityStartDecision returns the last decision produced by the live path.
func latestCapacityStartDecision() (CapacityStartDecision, bool) {
	decision := lastCapacityStartDecision.Load()
	if decision == nil {
		return CapacityStartDecision{}, false
	}
	return *decision, true
}

// declaredCapacityRebuildRequired compares explicit declaration/layout provenance with the
// last valid completed full baseline. Live proof-accounting totals are intentionally excluded:
// ordinary partition mutation, partial incremental completion, expiry and recovery may all make
// those totals diverge while the exact G.2 selected set remains the only correct work scope.
func declaredCapacityRebuildRequired(
	storage string, status CapacityProofEpochStatus, cfg ServerConfig,
) (fullBaselineEvaluation, error) {
	return evaluateFullCapacityBaseline(storage, status, cfg)
}

// constructFullPlanProvenance dominates every full-manifest estimate and every full opener.
// It proves that a complete non-empty manifest was constructed for an already-selected full
// reason. It never accepts a batching-time condition.
func constructFullPlanProvenance(
	partitions []PartitionMeta,
	reason FullSweepReason,
	requestedExplicitly bool,
	reasonPredicateSatisfied bool,
) (FullPlanProvenance, error) {
	if _, ok := approvedFullSweepReasons[reason]; !ok || reason == FullSweepNone {
		return FullPlanProvenance{}, fmt.Errorf("full-sweep reason %q is not approved", reason)
	}
	fingerprint, count, err := capacityEpochManifestFingerprint(partitions)
	if err != nil {
		return FullPlanProvenance{}, err
	}
	valid := count > 0 && strings.TrimSpace(fingerprint) != ""
	provenance := FullPlanProvenance{
		Reason: reason, CompleteManifestBuilt: true, CompleteManifestValid: valid,
		RequestedExplicitly:      requestedExplicitly,
		ReasonPredicateSatisfied: reasonPredicateSatisfied,
	}
	if !provenance.valid() {
		return FullPlanProvenance{}, fmt.Errorf("full plan provenance is invalid for %q", reason)
	}
	return provenance, nil
}

// evaluateFullSweepStart is the sole full-decision constructor on the live start path. The
// provenance check occurs before capacityEpochProofEstimate, making the whole-manifest
// estimator unreachable from ordinary timing branches.
func evaluateFullSweepStart(
	storage string,
	partitions []PartitionMeta,
	proofPeriodSeconds int64,
	provenance FullPlanProvenance,
	detail string,
) (bool, string, error) {
	if !provenance.valid() {
		return startDecisionResult(storage, failClosed(FailureCampaignNotRepresentable, false,
			nil, "full plan provenance is invalid"))
	}
	if observeFullSweepEstimator != nil {
		observeFullSweepEstimator()
	}
	estimate := capacityEpochProofEstimate(partitions, proofPeriodSeconds)
	if estimate <= 0 {
		return startDecisionResult(storage, failClosed(FailureBatchingSignalsUnavailable, true,
			nil, detail+"; full-sweep proof estimate unavailable"))
	}
	return startDecisionResult(storage, readyFullSweep(provenance, fmt.Sprintf(
		"%s; complete-manifest estimate=%s", detail, estimate.Round(time.Second))))
}

// observeFullSweepEstimator is a focused-test hook. Production leaves it nil; it does not
// replace or alter the estimator and exists only to prove ordinary incremental paths cannot
// reach whole-manifest costing.
var observeFullSweepEstimator func()

// selectedPlanRepresentable rejects a selected plan the frozen contracts could not accept.
// It never truncates or implicitly splits: the deterministic G.2 chunk planner is the only
// mechanism permitted to divide work.
func selectedPlanRepresentable(estimate SelectedWorkEstimate) error {
	if estimate.SelectedPartitionCount > MaxIncrementalBatchMembers {
		return fmt.Errorf(
			"selected count %d exceeds the frozen contract maximum of %d; requires selection chunking",
			estimate.SelectedPartitionCount, MaxIncrementalBatchMembers)
	}
	if estimate.SelectedPartitionCount > math.MaxUint32 {
		return fmt.Errorf("selected count %d does not fit the contract field",
			estimate.SelectedPartitionCount)
	}
	if estimate.SelectedBytes > math.MaxUint64/2 {
		return fmt.Errorf("selected bytes %d does not fit the contract field",
			estimate.SelectedBytes)
	}
	return nil
}

func capacityProofEpochStartReadyWithConfig(
	storage string,
	status CapacityProofEpochStatus,
	partitions []PartitionMeta,
	chainTimestamp, proofPeriodSeconds int64,
	catchupPending bool,
	emptyDeletionPending bool,
	cfg ServerConfig,
) (bool, string, error) {
	due, reason := capacityProofEpochDue(
		status, chainTimestamp, proofPeriodSeconds, catchupPending,
	)
	// Stale frozen-member retirement runs FIRST, before every gate below.
	//
	// It is pure durable-plan hygiene: it removes a chunk member that can never
	// become current again from a NOT-YET-OPEN chunk. It opens no campaign, submits
	// no transaction, touches no chain state and never modifies an OPEN on-chain
	// obligation, so it is safe under every gate — including while a deletion owns
	// the partition.
	//
	// It used to be hooked inside ensureCapacityIncrementalPlan, which sits BELOW the
	// deletion-successor gate a few lines down. A single declared_pending deletion
	// therefore short-circuited the whole function and the retirement could never
	// run, leaving the frozen chunk wedged on an unresolvable member forever while
	// the deletion itself waited on the capacity progress that the wedge prevented.
	// Live proof (Smoke 6): VK1 held chunk [data:18:0, data:21:0, data:34:0] with
	// data:34:0 unresolvable and one declared_pending deletion — 0 incremental
	// batches and oldestMutationAge 3079 s against the 1800 s hard lag. VK3, with no
	// deletions blocking, reached the same code path and drained to zero.
	if _, retireErr := retireStaleChunkPlanMembers(storage, partitions, time.Now()); retireErr != nil {
		log.Printf("[capacity-batch] stale member retirement deferred: %v", retireErr)
	}
	// Revalidate the durable full-baseline binding before any gate that can return early. A
	// previous transient/adapter defect may have written an ownership-free fail-closed marker;
	// once the same baseline read succeeds, that exact marker no longer represents ambiguity.
	// Clearing it here also lets deletion/capacity recovery make progress when deletion owns a
	// partition below. Every marker carrying members, successors, an epoch, or another failure
	// detail remains latched.
	baseline, baselineErr := declaredCapacityRebuildRequired(storage, status, cfg)
	if baselineErr == nil {
		if cleared, clearErr := clearRevalidatedEmptyFullBaselineRecovery(storage); clearErr != nil {
			return false, "full-capacity baseline recovery clear failed", clearErr
		} else if cleared {
			log.Printf("[capacity-batch] cleared revalidated empty full-baseline recovery")
		}
	}
	// G.3A: emptyDeletionPending is an OBSERVED input, never an independent launch reason.
	// Its qualification and release dependency belong to G.4.
	_ = emptyDeletionPending
	// G.3B (1/7): an unreadable deletion-activity scan is chain state we could not read. It is
	// not a batching trigger, so it fails closed with a recovery condition instead of opening
	// a campaign with no plan.
	blocking, blockErr := deletionMutationsBlockingCapacityEpoch(storage)
	if blockErr != nil {
		return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
			blockErr, reason+"; deletion activity scan unavailable"))
	}
	if blocking {
		return startDecisionResult(storage, notDue(SelectedWorkEstimate{}, TriggerNotDue,
			"capacity epoch start waiting for deletion successor"))
	}
	// Full reasons are selected BEFORE any full-manifest estimate. G.3D reads the durable,
	// chain-bound full baseline first; current proved totals never participate in this choice.
	if baselineErr != nil {
		return startDecisionResult(storage, failClosed(FailureDurablePlanCorrupt, false,
			baselineErr, "full-capacity baseline provenance unavailable"))
	}
	if baseline.Initial {
		provenance, err := constructFullPlanProvenance(
			partitions, FullSweepInitial, false, true)
		if err != nil {
			return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
				err, "initial complete manifest unavailable"))
		}
		return evaluateFullSweepStart(storage, partitions, proofPeriodSeconds, provenance,
			"initial capacity proof required")
	}
	if baseline.Rebuild {
		provenance, err := constructFullPlanProvenance(
			partitions, FullSweepDeclaredCapacityRebuild, false, true)
		if err != nil {
			return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
				err, "declared-capacity complete manifest unavailable"))
		}
		return evaluateFullSweepStart(storage, partitions, proofPeriodSeconds, provenance,
			baseline.Detail)
	}
	// G.4B-LV3: on an ownership-free VK, a qualified lifecycle urgency decides WHICH new
	// incremental plan freezes. This must run BEFORE the ordinary cutoff below, because a
	// backlog large enough to satisfy the urgency deadline predicate is necessarily also `due`,
	// and the due branch returns before urgency would otherwise be consulted. It never touches
	// an existing frozen plan, active campaign or recovery ownership.
	if precedence := evaluateCapacityUrgencyPrecedence(
		storage, cfg, partitions, status, chainTimestamp); precedence.Qualified {
		return startDecisionResult(storage, precedence.Decision)
	}
	// G.2 production cutoff: discover exact expired/mutated identities from one block-pinned
	// chain snapshot before costing selected work. Failure is a recovery condition and can
	// never fall through into a full sweep.
	if _, err := ensureCapacityIncrementalPlan(storage, cfg, partitions); err != nil {
		if errors.Is(err, errCapacityIncrementalPlanState) {
			return startDecisionResult(storage, failClosed(FailureDurablePlanCorrupt, false,
				err, "incremental selected-plan state unavailable"))
		}
		return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
			err, "incremental selection snapshot unavailable"))
	}
	// ── the INCREMENTAL decision runs first and is fully isolated ─────────────────────
	// An incremental failure must never fall through into the full-sweep estimator or the
	// full-sweep threshold branch below, so both outcomes return here.
	haveIncremental, incrementalDue, incrementalReason, selected, selErr :=
		liveSelectedWorkDecision(storage, partitions, chainTimestamp, status.DeclaredCapacityBytes, cfg)
	if selErr != nil {
		// G.3B (2/7): a corrupt or unreconstructable durable plan is never an empty plan and
		// never permission to rebuild the full manifest.
		return startDecisionResult(storage, failClosed(FailureDurablePlanCorrupt, false,
			selErr, "incremental selected-plan state unavailable"))
	}
	if haveIncremental {
		if !selected.PlanValid {
			return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
				nil, "selected identities are not fully known"))
		}
		if repErr := selectedPlanRepresentable(selected); repErr != nil {
			// G.3B (7/7): representability is a hard stop — never truncate, split implicitly
			// or switch silently to a full sweep.
			return startDecisionResult(storage, failClosed(FailureCampaignNotRepresentable, false,
				repErr, "selected campaign is not representable"))
		}
		// FIX C (Run 15): never OPEN a batch whose member a deletion currently owns on the freeze
		// slot. Capacity could open the on-chain batch but never obtain the freeze, so it would loop
		// open -> "deletion holds the slot" -> 5-minute abandon -> reopen, proving nothing (VK5 burned
		// ~37 min on data:13:0 this way). Defer with a WAIT until the deletion resolves; the member is
		// then either freed or removed by stale-member retirement. This is a targeted, per-member wait
		// on an already-held slot, so capacity aging-ahead onto a FREE slot is unaffected.
		if awaiting, member, awaitErr := capacityChunkAwaitingDeletionFreeze(storage, time.Now()); awaitErr != nil {
			return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
				awaitErr, "deletion freeze-ownership check unavailable"))
		} else if awaiting {
			return startDecisionResult(storage, notDue(selected, incrementalReason,
				"waiting for deletion to release the freeze slot for "+member))
		}
		if incrementalDue {
			return startDecisionResult(storage, readyIncremental(selected, incrementalReason))
		}
		// G.4B-LV1: an otherwise not-yet-due incremental plan is promoted when qualified
		// lifecycle urgency holds for an identity already inside the pending chunk. Urgency
		// only ever promotes an EXISTING exact selection; it never widens membership here.
		if urgency, ok := qualifiedUrgencyPromotesSelection(storage, cfg, partitions, status, selected); ok {
			return startDecisionResult(storage, qualifiedUrgencyDecision(urgency, selected))
		}
		return startDecisionResult(storage,
			notDue(selected, incrementalReason, "adaptively batching incremental work"))
	}

	// G.4B-LV1: with no durable incremental plan, qualified lifecycle urgency may create one
	// containing EXACTLY the eligible current successor identity. This is the only path by
	// which a blocked demand can open work, and it is incremental by construction — it never
	// produces a full-sweep reason.
	if urgency, selectedPlan, ok := qualifiedUrgencyOpensSelection(
		storage, cfg, partitions, status, chainTimestamp, proofPeriodSeconds); ok {
		return startDecisionResult(storage, qualifiedUrgencyDecision(urgency, selectedPlan))
	}

	// QUIESCENT DIVERGENCE RECOVERY.
	//
	// Everything above needs something LOCAL to point at: a durable incremental plan, a
	// pending mutation, or a blocked demand. When the chain still reports proved totals
	// behind registered totals but the local journal has nothing pending, none of them
	// exist, so selection returns zero members and this function returns
	// `no exact selected work` on every scan, forever.
	//
	// That state is reachable and self-sustaining. `capacityBatchThresholdReached` can
	// only fire on pending mutations or on divergence crossing MaxDivergenceBytes
	// (512 MiB by default); a divergence below that threshold with zero pending mutations
	// matches no trigger at all. Meanwhile the uncertified bytes keep admission closed
	// (`certified_capacity_insufficient`), so the new traffic that would create the next
	// mutation — the only thing that could reopen work — is exactly what the divergence
	// prevents. A quiet VK therefore never reconverges.
	//
	// Live evidence (2026-09-15, load test): vk_1 and vk_10 held divergenceBytes
	// 6 990 848 and 2 446 848 with pendingMutations 0, breached=false, atRisk=false.
	// Both sat unchanged for 35+ minutes with traffic fully paused, emitting only
	// `[capacity-urgency] ... no pending blocked demand`. The eight VKs that happened to
	// reach zero divergence before the pause stayed converged; nothing distinguished them
	// but timing.
	//
	// Recovery re-proves the current complete manifest, which is the only evidence that
	// can move chain proved totals when no pending mutation names the gap. It is gated to
	// an ownership-free, quiescent VK whose last capacity proof is already older than the
	// hard mutation-lag budget, so it can never race a campaign, a fresh submission still
	// settling on chain, or an incremental plan that owns the same coordinates.
	if recover, detail, recErr := quiescentDivergenceRecoveryRequired(
		storage, status, chainTimestamp, cfg); recErr != nil {
		return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
			recErr, "quiescent divergence recovery check unavailable"))
	} else if recover {
		provenance, err := constructFullPlanProvenance(
			partitions, FullSweepFreshnessRecovery, false, true)
		if err != nil {
			return startDecisionResult(storage, failClosed(FailureChainStateUnavailable, true,
				err, "freshness-recovery complete manifest unavailable"))
		}
		return evaluateFullSweepStart(storage, partitions, proofPeriodSeconds, provenance, detail)
	}

	// No exact selected identities means no campaign. Legacy due/timing signals, catch-up,
	// empty deletion, idle prover state, ordinary staleness and manifest changes cannot create
	// a full reason.
	if !due && !status.Active {
		if err := clearCapacityEpochBatchState(storage); err != nil {
			return false, reason, err
		}
	}
	return startDecisionResult(storage, notDue(
		SelectedWorkEstimate{}, TriggerNoSelectedWork, reason+"; no exact selected work"))
}

// quiescentDivergenceRecoveryRequired reports whether this VK is wedged with chain proved
// totals behind registered totals and no local work of any kind that could ever close the
// gap.
//
// Every condition is necessary, and each one exists to keep this off the ordinary path:
//
//   - divergence is real and non-zero — otherwise there is nothing to recover;
//   - the epoch is not active and nothing owns coordinates — a campaign or frozen plan
//     already owns the gap and must be allowed to finish;
//   - no pending mutations — a pending mutation is an incremental obligation and the
//     existing thresholds (including the hard lag budget) own it, not this path;
//   - the last capacity proof is older than the hard mutation-lag budget — a proof that
//     just landed may not yet be reflected in the chain totals this scan read, and that
//     lag must never be mistaken for a wedge.
//
// A VK that fails any of these is making progress by some other owner, so recovery stays
// out of its way.
func quiescentDivergenceRecoveryRequired(
	storage string,
	status CapacityProofEpochStatus,
	chainTimestamp int64,
	cfg ServerConfig,
) (bool, string, error) {
	if status.Active {
		// A live epoch owns the work; never race it.
		return false, "", nil
	}
	// `Invalidated` deliberately does NOT block here. It describes a PAST epoch that was
	// abandoned, which says nothing about whether a new sweep is owed — and abandoning an
	// epoch is exactly what recovery does, so treating the flag as a veto meant any keeper
	// that ever recovered could never renew its certificate again.
	//
	// The chain does not agree with that refusal: beginProofEpoch requires only that the
	// previous epoch is not active and the new id is higher (CapacityProofSC.sol:829-830);
	// an invalidated predecessor is explicitly fine.
	//
	// Nor does invalidation disturb the numbers this function reads. _abortProofEpoch
	// (CapacityProofSC.sol:945-954) sets `invalidated` and clears `active`, and nothing
	// else; the ledger totals and LastCapacityProofAt are written only by
	// _tryCompleteProofEpoch on success, so they still describe the last GOOD proof.
	//
	// Live 2026-09-22: vk_6's epoch 2 was aborted to break a wedge, leaving invalidated
	// set. It then sat 106 hours past a 15-hour renewal point with no pending mutation, no
	// plan, no journal and zero divergence, refusing on this line every scan without a word
	// in the log. Every other use of the flag is unchanged: they correctly require a live
	// or completed epoch.
	if status.RegisteredFreeBytes < status.ProvedFreeBytes ||
		status.RegisteredDataBytes < status.ProvedDataBytes {
		// Proved ahead of registered is not a shortfall this path can close.
		return false, "", nil
	}
	divergence := (status.RegisteredFreeBytes - status.ProvedFreeBytes) +
		(status.RegisteredDataBytes - status.ProvedDataBytes)
	// Agreeing totals are not the same as a valid certification. CapacityCertificationSC
	// files a certificate only as a side effect of an ACCEPTED capacity proof, and counts
	// a bucket only while `bucket.expirySlot > currentSlot` — expiry costs no transaction,
	// time alone does it. Proof work in turn only exists while something is changing, so a
	// keeper with no traffic proves nothing, files nothing, and its certified capacity
	// silently reaches zero. Admission then closes a keeper that is entirely healthy.
	//
	// Measured live 2026-09-22: vk_3 reported ringCertifiedFreeCapacity=0 with 169 MiB
	// genuinely free, divergence 0, no pending mutation, and every one of its six data
	// partitions matching the chain byte-for-byte. Being stable was the whole fault.
	//
	// Staleness is therefore a second reason to re-prove the current manifest, on exactly
	// the same terms as divergence — every quiescence guard below still applies.
	stale := capacityCertificationRefreshDue(status, chainTimestamp)
	if divergence == 0 && !stale {
		return false, "", nil
	}
	// An initial baseline has its own opener above and must not be pre-empted here.
	if status.LastCapacityProofAt == 0 {
		return false, "", nil
	}
	// Never race a proof that may still be settling into the chain totals just read.
	policy := resolvedCapacityProofBatchPolicy(cfg)
	quietFor := chainTimestamp - int64(status.LastCapacityProofAt)
	if quietFor < int64(policy.MaxOldestMutationAge/time.Second) {
		return false, "", nil
	}
	// Any local owner at all means this is not a wedge.
	globalHold, holdReason, owned, err := capacityTerminalResolutionOwnership(storage)
	if err != nil {
		return false, "", err
	}
	// Catch-up is not an owner of this work — it is what waits on it. The marker sits in
	// `awaiting_proof` until the keeper converges, and converging needs exactly the
	// re-proof this function authorises, so treating it as a hold made each side wait for
	// the other. Live 2026-09-22: vk_5 held 3,845,120 bytes registered-but-unproved with a
	// catch-up marker created Sep 18 and still refreshed four days later, zero pending
	// mutations, no plan and no journal — nothing could ever close it.
	//
	// This is the same deadlock already fixed in tryResolveFreshCapacityAggregate; this is
	// its second site. A real owner — unresolved batch recovery — still blocks, and the
	// per-coordinate check below still blocks anything a live plan or journal holds, which
	// is now populated even while catch-up is pending.
	if globalHold && holdReason != capacityCatchupOwnershipReason {
		return false, "", nil
	}
	if len(owned) > 0 {
		return false, "", nil
	}
	var pending []capacityMutationJournalRecord
	if err := withCapacityCoordinationLock(storage, func() error {
		var readErr error
		pending, readErr = listPendingCapacityMutationJournalRecordsUnlocked(storage)
		return readErr
	}); err != nil {
		return false, "", err
	}
	// A pending mutation blocks recovery unless it names NO partition coordinate and has
	// outlived the hard mutation-lag budget. A coordinate-less record -- a capacity_rebuild
	// at -1/-1 -- can be closed by nothing but a complete re-proof, which is what recovery
	// does. Anything that names partitions belongs to the incremental path.
	//
	// This gate was briefly widened to admit coordinate-bearing records past the budget, to
	// break vk_7's wedge on 2026-09-28. That was the wrong lever and it is narrowed back
	// here. Recovery re-proves the COMPLETE manifest, so admitting one dirty partition
	// through it turned roughly one proof per keeper into eighteen to twenty-four. Measured
	// on 2026-09-29 with ten keepers sharing one prover and one host proof lock: each proof
	// took about forty seconds and each keeper then waited twenty-five minutes for its next
	// turn, so a round went from minutes to hours and admission stayed closed throughout.
	//
	// The wedge that widening was meant to fix is real and still open: the incremental
	// selector reported "no exact selected work" for dirty partitions that plainly had
	// coordinates. That is the defect to find, and routing around it through a full sweep
	// only hid it behind twenty times the work.
	blocking := 0
	unownable := 0
	for _, record := range pending {
		if capacityMutationIsOwnable(record) || !capacityMutationPastHardLag(record, chainTimestamp, policy) {
			blocking++
			continue
		}
		unownable++
	}
	if blocking > 0 {
		return false, "", nil
	}
	if unownable > 0 {
		return true, fmt.Sprintf(
			"%d pending capacity mutation(s) name no partition and are past the %ds lag budget, "+
				"so only a complete re-proof can close them; no owned work, no capacity proof for %ds",
			unownable, int64(policy.MaxOldestMutationAge/time.Second), quietFor), nil
	}
	if divergence == 0 {
		return true, fmt.Sprintf(
			"certification renewal due with no pending mutation and no owned work: "+
				"no capacity proof for %ds against a %ds certification age",
			quietFor, status.MaxProofAgeSeconds), nil
	}
	return true, fmt.Sprintf(
		"chain proved totals trail registered totals by %d bytes with no pending mutation, "+
			"no owned work and no capacity proof for %ds", divergence, quietFor), nil
}

// capacityMutationIsOwnable reports whether any transition in the record names a real
// partition coordinate, which is what selection needs to turn it into campaign members.
// A record with no such transition can only be closed by re-proving the whole manifest.
//
// NOTE: PartitionIndex is an `int` tagged `omitempty`, so a record that never wrote a
// partition index is indistinguishable here from one that wrote zero. Both read as
// ownable. That ambiguity is why vk_7's five deletes were never selected and never
// recovered, and it is part of what the selector investigation has to settle.
func capacityMutationIsOwnable(record capacityMutationJournalRecord) bool {
	for _, transition := range record.Transitions {
		for _, state := range [2]capacityMutationSectorState{transition.Old, transition.New} {
			if state.DeadlineIndex >= 0 && state.PartitionIndex >= 0 {
				return true
			}
		}
	}
	return false
}

// capacityMutationPastHardLag reports whether a pending record has outlived the hard
// mutation-lag budget. Until it has, ordinary processing still owns it and recovery must
// keep its hands off.
func capacityMutationPastHardLag(
	record capacityMutationJournalRecord, chainTimestamp int64, policy capacityProofBatchPolicy,
) bool {
	created, err := time.Parse(time.RFC3339, strings.TrimSpace(record.CreatedAt))
	if err != nil {
		// An unreadable timestamp is not evidence of age. Treat it as still in budget so
		// recovery never fires on a record it cannot date.
		return false
	}
	return chainTimestamp-created.Unix() >= int64(policy.MaxOldestMutationAge/time.Second)
}

// capacityCertificationRefreshDue reports whether the certification filed by the last
// accepted capacity proof has reached its renewal point.
//
// It uses the same half-of-maximum-age rule as the proof-freshness planner
// (`capacityProofEpochDue`), so the two can never disagree about when a quiet keeper owes
// a re-proof. Renewing at half the age leaves a full half-life of margin for the proof to
// be produced, submitted and accepted before the certificate actually expires.
func capacityCertificationRefreshDue(status CapacityProofEpochStatus, chainTimestamp int64) bool {
	if status.LastCapacityProofAt == 0 || status.MaxProofAgeSeconds == 0 || chainTimestamp <= 0 {
		return false
	}
	refresh := status.MaxProofAgeSeconds / 2
	if refresh == 0 || status.LastCapacityProofAt > math.MaxInt64-refresh {
		return false
	}
	return chainTimestamp >= int64(status.LastCapacityProofAt+refresh)
}
