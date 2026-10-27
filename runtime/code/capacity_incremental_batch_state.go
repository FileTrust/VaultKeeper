package main

// G.2 — durable incremental-batch membership.
//
// A batch's membership is frozen at cutoff and never grows. Mutations that land after the
// cutoff become successor work for a later batch and must not rebind or restart the active
// proof. On restart the selected set is reconstructed from this durable state plus chain
// truth, and every selected identity is revalidated.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const capacityIncrementalBatchStateVersion = 1

// capacityBatchMemberState is the durable record of one frozen member.
type capacityBatchMemberState struct {
	PartitionKey   string `json:"partitionKey"`
	VK             string `json:"vk"`
	Kind           string `json:"kind"`
	ContentVersion uint64 `json:"contentVersion"`
	ContentHash    string `json:"contentHash"`
	CommittedBytes uint64 `json:"committedBytes"`
	Reason         string `json:"reason"`
	// IdentityHash is the canonical hash CapacityCertificationSC computed at cutoff. It is
	// stored so a restart can tell "this exact identity" from "a successor identity" without
	// recomputing any encoding locally.
	IdentityHash string `json:"identityHash"`
	// Certified is set once chain truth confirms this exact identity is certified.
	Certified bool `json:"certified,omitempty"`
	// Superseded is set when a newer registered identity replaced this one after cutoff.
	Superseded bool `json:"superseded,omitempty"`
}

// capacityIncrementalBatchState is the frozen batch: mode, reason, cutoff and membership.
type capacityIncrementalBatchState struct {
	Version         int                        `json:"version"`
	EpochID         uint64                     `json:"epochId"`
	Mode            string                     `json:"mode"`
	FullSweepReason FullSweepReason            `json:"fullSweepReason,omitempty"`
	CutoffUnix      int64                      `json:"cutoffUnix"`
	TargetRound     uint64                     `json:"targetRound"`
	Members         []capacityBatchMemberState `json:"members"`
	// SuccessorKeys are partitions mutated after cutoff. They are NOT members; they are the
	// obligation carried into the next batch.
	SuccessorKeys []string `json:"successorKeys,omitempty"`
	// RecoveryState is non-empty when selection failed closed. It must be resolved explicitly
	// and must never be silently converted into a full sweep.
	RecoveryState string `json:"recoveryState,omitempty"`
}

func capacityIncrementalBatchStatePath(storage string) string {
	return filepath.Join(storage, "capacity-incremental-batch.json")
}

func capacityIncrementalBatchStateLockPath(storage string) string {
	return filepath.Join(storage, "capacity-incremental-batch.lock")
}

// withCapacityIncrementalBatchLock serialises batch-state mutation. Same discipline as the
// existing capacity batch-state lock: brief, no I/O beyond this file, never nested inside a
// partition or coordination lock.
func withCapacityIncrementalBatchLock(storage string, fn func() error) error {
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(capacityIncrementalBatchStateLockPath(storage),
		os.O_CREATE|os.O_RDWR, 0o600)
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

func validCapacityIncrementalBatchState(state capacityIncrementalBatchState) bool {
	if state.Version != capacityIncrementalBatchStateVersion {
		return false
	}
	if !CapacityBatchMode(state.Mode).Valid() {
		return false
	}
	if state.CutoffUnix <= 0 {
		return false
	}
	if CapacityBatchMode(state.Mode).IsFullSweep() && strings.TrimSpace(string(state.FullSweepReason)) == "" {
		return false
	}
	for _, member := range state.Members {
		if strings.TrimSpace(member.PartitionKey) == "" || strings.TrimSpace(member.IdentityHash) == "" {
			return false
		}
	}
	return true
}

func readCapacityIncrementalBatchState(storage string) (capacityIncrementalBatchState, bool, error) {
	raw, err := os.ReadFile(capacityIncrementalBatchStatePath(storage))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return capacityIncrementalBatchState{}, false, nil
		}
		return capacityIncrementalBatchState{}, false, err
	}
	var state capacityIncrementalBatchState
	if err := json.Unmarshal(raw, &state); err != nil {
		// A corrupt batch file is ambiguity, not absence: fail closed rather than pretend
		// there is no active batch and re-select a conflicting membership.
		return capacityIncrementalBatchState{}, false, fmt.Errorf(
			"%w: capacity incremental batch state is unreadable: %v", ErrChainStateUnreadable, err)
	}
	if !validCapacityIncrementalBatchState(state) {
		return capacityIncrementalBatchState{}, false, fmt.Errorf(
			"%w: capacity incremental batch state failed validation", ErrChainStateUnreadable)
	}
	return state, true, nil
}

func writeCapacityIncrementalBatchState(storage string, state capacityIncrementalBatchState) error {
	if !validCapacityIncrementalBatchState(state) {
		return fmt.Errorf("refusing to write invalid capacity incremental batch state")
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(capacityIncrementalBatchStatePath(storage), append(raw, '\n'), 0o600)
}

func clearCapacityIncrementalBatchState(storage string) error {
	if err := os.Remove(capacityIncrementalBatchStatePath(storage)); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// clearRevalidatedEmptyChainReadRecovery consumes only the retryable, ownership-free recovery
// marker produced when the block-pinned incremental selection read was unavailable. The caller
// may invoke it only after that same production read has just completed successfully. A recovery
// record with members, an epoch, successors, a non-chain-read reason, or any other ownership is
// never cleared here.
func clearRevalidatedEmptyChainReadRecovery(storage string) (bool, error) {
	cleared := false
	err := withCapacityIncrementalBatchLock(storage, func() error {
		state, found, err := readCapacityIncrementalBatchState(storage)
		if err != nil || !found {
			return err
		}
		// The safety of this clear comes from the OBLIGATION guards, not from the
		// wording of the detail: mode must still be recovery_uncertain, the epoch id
		// must be 0, and there must be NO durable members and NO successors — i.e.
		// nothing was ever frozen that could be lost. The caller has just completed a
		// successful production read, which is what "revalidated" means here.
		//
		// The detail is matched by FAILURE CLASS, not by one exact sentence. Every
		// FailureChainStateUnavailable detail is the same retryable chain-read class:
		//   "incremental selection snapshot unavailable"
		//   "selected identities are not fully known"     <- capacity_epoch_batch.go:1073
		//   "initial complete manifest unavailable", ...
		// Matching only the first sentence left the others PERMANENTLY latched. A
		// non-empty RecoveryState blocks qualified urgency from freezing any plan
		// (capacity_urgency_precedence.go:74) and blocks aggregate retirement
		// (capacity_aggregate_retirement.go:166), so the VK could never open another
		// capacity campaign and breached the hard mutation lag in silence.
		// Every OTHER failure class (durable plan corrupt, campaign not
		// representable, ...) still fails closed here, unchanged.
		if CapacityBatchMode(state.Mode) != BatchModeRecoveryUncertain || state.EpochID != 0 ||
			len(state.Members) != 0 || len(state.SuccessorKeys) != 0 ||
			!strings.HasPrefix(state.RecoveryState,
				string(FailureChainStateUnavailable)+":") {
			return nil
		}
		if err := clearCapacityIncrementalBatchState(storage); err != nil {
			return err
		}
		cleared = true
		return nil
	})
	return cleared, err
}

// clearRevalidatedEmptyFullBaselineRecovery consumes only the ownership-free marker written
// when full-baseline provenance could not be validated. The caller may invoke it only after
// evaluateFullCapacityBaseline has just succeeded against current chain status. A marker with
// any frozen member, successor, epoch, different mode, or different failure detail remains
// fail-closed.
func clearRevalidatedEmptyFullBaselineRecovery(storage string) (bool, error) {
	cleared := false
	err := withCapacityIncrementalBatchLock(storage, func() error {
		state, found, err := readCapacityIncrementalBatchState(storage)
		if err != nil || !found {
			return err
		}
		const recoveryDetail = "full-capacity baseline provenance unavailable"
		if CapacityBatchMode(state.Mode) != BatchModeRecoveryUncertain || state.EpochID != 0 ||
			len(state.Members) != 0 || len(state.SuccessorKeys) != 0 ||
			strings.TrimSpace(state.RecoveryState) !=
				string(FailureDurablePlanCorrupt)+": "+recoveryDetail {
			return nil
		}
		if err := clearCapacityIncrementalBatchState(storage); err != nil {
			return err
		}
		cleared = true
		return nil
	})
	return cleared, err
}

// freezeCapacityBatchMembership durably records the selection as the active batch. After this
// returns, membership never grows: later mutations become successors.
func freezeCapacityBatchMembership(
	storage string,
	epochID uint64,
	targetRound uint64,
	cutoff time.Time,
	selection CapacityBatchSelection,
	identityHashes map[string]string,
) (capacityIncrementalBatchState, error) {
	state := capacityIncrementalBatchState{
		Version:         capacityIncrementalBatchStateVersion,
		EpochID:         epochID,
		Mode:            string(selection.Mode),
		FullSweepReason: selection.FullSweepReason,
		CutoffUnix:      cutoff.Unix(),
		TargetRound:     targetRound,
	}
	for _, member := range selection.Selected {
		hash := identityHashes[member.Identity.PartitionKey]
		if strings.TrimSpace(hash) == "" {
			return capacityIncrementalBatchState{}, fmt.Errorf(
				"capacity batch member %s has no canonical identity hash",
				member.Identity.PartitionKey)
		}
		state.Members = append(state.Members, capacityBatchMemberState{
			PartitionKey:   member.Identity.PartitionKey,
			VK:             member.Identity.VK,
			Kind:           member.Identity.Kind,
			ContentVersion: member.Identity.ContentVersion,
			ContentHash:    member.Identity.ContentHash,
			CommittedBytes: member.Identity.CommittedBytes,
			Reason:         string(member.Reason),
			IdentityHash:   hash,
		})
	}
	sort.Slice(state.Members, func(i, j int) bool {
		return state.Members[i].PartitionKey < state.Members[j].PartitionKey
	})
	if err := withCapacityIncrementalBatchLock(storage, func() error {
		return writeCapacityIncrementalBatchState(storage, state)
	}); err != nil {
		return capacityIncrementalBatchState{}, err
	}
	return state, nil
}

// recordPostCutoffMutation registers a partition mutated after the cutoff. It never joins the
// active batch. If the partition is already a frozen member, that member is marked superseded:
// the older selected identity may still complete historically, but the newer identity remains
// pending obligation for the next batch.
func recordPostCutoffMutation(storage string, partitionKey string) error {
	key := strings.ToLower(strings.TrimSpace(partitionKey))
	if key == "" {
		return fmt.Errorf("post-cutoff mutation needs a partition key")
	}
	return withCapacityIncrementalBatchLock(storage, func() error {
		state, ok, err := readCapacityIncrementalBatchState(storage)
		if err != nil {
			return err
		}
		if !ok {
			return nil // no active batch: ordinary journal candidate, nothing to record here
		}
		for i := range state.Members {
			if state.Members[i].PartitionKey == key {
				state.Members[i].Superseded = true
			}
		}
		for _, existing := range state.SuccessorKeys {
			if existing == key {
				return writeCapacityIncrementalBatchState(storage, state)
			}
		}
		state.SuccessorKeys = append(state.SuccessorKeys, key)
		sort.Strings(state.SuccessorKeys)
		return writeCapacityIncrementalBatchState(storage, state)
	})
}

// capacityBatchReconciliation is the outcome of revalidating a frozen batch against chain truth.
type capacityBatchReconciliation struct {
	// Certified members whose exact selected identity is certified on chain.
	Certified []string
	// Outstanding members still requiring proof at their selected identity.
	Outstanding []string
	// Superseded members whose selected identity is no longer current. They may complete
	// historically; their successor identity is carried in SuccessorKeys.
	Superseded []string
	// SuccessorKeys is the obligation for the next batch. Never erased by reconciliation.
	SuccessorKeys []string
	// Complete is true when no member is outstanding.
	Complete bool
}

// reconcileCapacityBatchWithChain revalidates every frozen member against chain truth. It is
// the restart path and the drain path: a member may be marked certified only when the exact
// selected identity is certified on chain, or when chain truth shows equivalent certification
// already exists.
//
// It never widens membership and never escalates to a full sweep. Any unreadable chain state
// is returned as an error so the caller can enter an explicit recovery state.
func reconcileCapacityBatchWithChain(
	ctx context.Context,
	chain CapacityChainView,
	state capacityIncrementalBatchState,
) (capacityBatchReconciliation, error) {
	if chain == nil {
		return capacityBatchReconciliation{}, fmt.Errorf(
			"%w: no chain view configured", ErrChainStateUnreadable)
	}
	currentSlot, err := chain.CurrentCertificationSlot(ctx)
	if err != nil {
		return capacityBatchReconciliation{}, fmt.Errorf(
			"%w: reading current certification slot: %v", ErrChainStateUnreadable, err)
	}
	result := capacityBatchReconciliation{SuccessorKeys: append([]string(nil), state.SuccessorKeys...)}

	for _, member := range state.Members {
		record, err := chain.Certification(ctx, member.PartitionKey)
		if err != nil {
			return capacityBatchReconciliation{}, fmt.Errorf(
				"%w: reading certification for %s: %v", ErrChainStateUnreadable, member.PartitionKey, err)
		}
		identity, err := chain.CurrentIdentity(ctx, member.PartitionKey)
		if err != nil {
			return capacityBatchReconciliation{}, fmt.Errorf(
				"%w: resolving identity for %s: %v", ErrChainStateUnreadable, member.PartitionKey, err)
		}
		currentHash, err := chain.CertificationIdentityHash(ctx, identity)
		if err != nil {
			return capacityBatchReconciliation{}, fmt.Errorf(
				"%w: computing canonical identity hash for %s: %v",
				ErrChainStateUnreadable, member.PartitionKey, err)
		}

		// Certification and supersession are independent facts, and both can hold at once:
		// the selected identity may complete historically while a newer identity is already
		// registered. The successor obligation is never erased by the historical completion.
		certifiedAtSelectedIdentity := record.Exists &&
			record.CertifiedExpirySlot > currentSlot &&
			strings.EqualFold(record.CertifiedIdentityHash, member.IdentityHash) &&
			strings.EqualFold(record.VK, member.VK)
		superseded := !strings.EqualFold(currentHash, member.IdentityHash)

		if certifiedAtSelectedIdentity {
			result.Certified = append(result.Certified, member.PartitionKey)
		}
		if superseded {
			result.Superseded = append(result.Superseded, member.PartitionKey)
			result.SuccessorKeys = appendUniqueKey(result.SuccessorKeys, member.PartitionKey)
			continue
		}
		if !certifiedAtSelectedIdentity {
			result.Outstanding = append(result.Outstanding, member.PartitionKey)
		}
	}

	sort.Strings(result.Certified)
	sort.Strings(result.Outstanding)
	sort.Strings(result.Superseded)
	sort.Strings(result.SuccessorKeys)
	result.Complete = len(result.Outstanding) == 0
	return result, nil
}

func appendUniqueKey(keys []string, key string) []string {
	for _, existing := range keys {
		if existing == key {
			return keys
		}
	}
	return append(keys, key)
}

// applyCapacityBatchReconciliation persists the reconciliation outcome onto the frozen batch:
// certified members are flagged, superseded members are flagged, successor obligations are
// retained. Membership itself is never modified.
func applyCapacityBatchReconciliation(
	storage string,
	result capacityBatchReconciliation,
) error {
	return withCapacityIncrementalBatchLock(storage, func() error {
		state, ok, err := readCapacityIncrementalBatchState(storage)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		certified := keySet(result.Certified)
		superseded := keySet(result.Superseded)
		for i := range state.Members {
			if _, isCertified := certified[state.Members[i].PartitionKey]; isCertified {
				state.Members[i].Certified = true
			}
			if _, isSuperseded := superseded[state.Members[i].PartitionKey]; isSuperseded {
				state.Members[i].Superseded = true
			}
		}
		for _, key := range result.SuccessorKeys {
			state.SuccessorKeys = appendUniqueKey(state.SuccessorKeys, key)
		}
		sort.Strings(state.SuccessorKeys)
		return writeCapacityIncrementalBatchState(storage, state)
	})
}

func keySet(keys []string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		set[key] = struct{}{}
	}
	return set
}

// carryCapacityBatchSuccessors closes a finished batch and returns the successor obligation
// for the next selection pass. The obligation is never erased by closing a batch.
func carryCapacityBatchSuccessors(storage string) ([]string, error) {
	var successors []string
	err := withCapacityIncrementalBatchLock(storage, func() error {
		state, ok, err := readCapacityIncrementalBatchState(storage)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		successors = append([]string(nil), state.SuccessorKeys...)
		// a member whose selected identity was superseded also carries forward
		for _, member := range state.Members {
			if member.Superseded {
				successors = appendUniqueKey(successors, member.PartitionKey)
			}
		}
		sort.Strings(successors)
		return clearCapacityIncrementalBatchState(storage)
	})
	if err != nil {
		return nil, err
	}
	return successors, nil
}

// enterCapacityBatchRecoveryState records an explicit, observable fail-closed state. It is the
// only permitted response to unreadable or ambiguous chain state — never a full sweep.
func enterCapacityBatchRecoveryState(storage string, reason string, cutoff time.Time) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("recovery state requires an explicit reason")
	}
	return withCapacityIncrementalBatchLock(storage, func() error {
		state, ok, err := readCapacityIncrementalBatchState(storage)
		if err != nil {
			// Even an unreadable existing state must leave an explicit marker behind.
			state = capacityIncrementalBatchState{}
			ok = false
		}
		if !ok {
			state = capacityIncrementalBatchState{
				Version:         capacityIncrementalBatchStateVersion,
				Mode:            string(BatchModeRecoveryUncertain),
				FullSweepReason: FullSweepReason(reason),
				CutoffUnix:      cutoff.Unix(),
			}
		}
		state.RecoveryState = reason
		return writeCapacityIncrementalBatchState(storage, state)
	})
}
