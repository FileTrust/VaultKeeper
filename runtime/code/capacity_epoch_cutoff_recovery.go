package main

// G.4B — deterministic terminal path for a capacity epoch whose immutable cutoff can never be
// resolved locally.
//
// THE DEFECT THIS CLOSES (reproduced live 2026-08-12, then deterministically in
// capacity_epoch_mid_deletion_recovery_test.go)
//
// A deletion changes a frozen member's bytes before submission. `frozenSnapshotStillSafeToSubmit`
// returns ErrPartitionProofSnapshotInvalidated and the scheduler calls
// `abandonAndAdvancePartitionSnapshot`, which retires the local frozen record. If the chain has
// not ALSO excluded that member, `capacityEpochJournalCandidatesWithLagDeadline` fails closed
// forever with "immutable cutoff is incomplete", the epoch stays Active, and because
// `evaluateCapacityUrgencyPrecedence` (the only caller of `reconcileBlockedDemandLifecycle`) runs
// inside the epoch-START path, blocked-demand promotion is starved behind it.
//
// Safety was never at risk: no stale proof is submitted and no frozen snapshot is rewritten.
// Liveness was: the epoch had no terminal state.
//
// WHICH TERMINATION MECHANISM APPLIES, BY AUTHORITY DOMAIN
//
// There are two distinct authorities and the choice between them is NOT interchangeable:
//   - FULL proof epoch      -> CapacityProofSC.abortProofEpoch            (notes below)
//   - INCREMENTAL batch     -> PartitionSnapshotProofSC.abandonIncrementalBatch
//                              (see recoverUnresolvableIncrementalBatch)
// Using the full-epoch primitive on an incremental batch silently does nothing; that mistake
// cost a live run on 2026-08-13 and is now pinned by capacity_epoch_authority_domain_test.go.
//
// WHY ABORT IS THE CORRECT MECHANISM FOR A FULL PROOF EPOCH
//
//   - Re-anchor is NOT applicable. `reanchorPartitionProofSnapshot` re-pins an existing frozen
//     snapshot whose CONTENT is still intact and whose chain anchor went stale. Here the frozen
//     bytes are gone (a deletion replaced them), so there is nothing to re-anchor to.
//   - The chain owns the other recovery. `_excludeCutoffMemberOnDeletion` already excludes a
//     deleted member (or aborts if exclusion would break declared capacity), and
//     `reconcileCapacityEpochJournalWithExclusions` re-anchors the journal from it. That path is
//     correct and is left untouched — this recovery only runs when the chain will never exclude.
//   - Authorization: `abortProofEpoch(uint64)` is `onlyEligibleVK`, i.e. the VK aborts its OWN
//     epoch. No other authority is involved.
//   - Already-submitted members are preserved. `_abortProofEpoch` only sets
//     `invalidated`/`active` and releases the campaign; `lastComplete*`, `provedBackingBytes` and
//     `capacityProofSequence` are written solely by `_tryCompleteProofEpoch`, so previously
//     COMPLETED epochs keep their durable facts. Per-partition proofs already recorded in this
//     epoch keep their partition accounts; only this epoch's aggregate never commits.
//   - No stale proof can follow. `submitPartitionProof` rejects `epoch.invalidated`
//     (CapacityProofSC.sol:1001), so an in-flight submission for the aborted epoch cannot count.
//   - Crash safety and idempotence are free, because the LOCAL terminal state is derived from
//     chain state rather than written speculatively: once the chain reports the epoch inactive and
//     invalidated, `reconcileCapacityEpochJournalWithExclusions` sets the journal to
//     `capacityEpochStateAborted` on the next scan. A crash between the chain call and any local
//     write therefore self-heals, and `_abortProofEpoch` is a no-op when the epoch is already
//     inactive, so a duplicate call is harmless.
//   - Remaining work returns to pending naturally: with no active epoch, ordinary planning
//     re-selects the still-dirty partitions on the next scan. Unrelated partitions are never
//     touched — nothing is deleted, and no journal is hand-edited.
//
// The grace window below exists so a merely SLOW chain exclusion is never mistaken for an
// unresolvable one: a declared-but-unconfirmed deletion still excludes its member when it
// confirms, and that path must be allowed to win.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// capacityEpochCutoffRecoveryGrace is how long an unresolvable immutable cutoff is tolerated
// before the epoch is terminated. It must comfortably exceed the time for a declared deletion to
// confirm on chain and exclude its member (single-digit minutes in the live runs), while staying
// well inside freezeClaimTTL (15 min) so a wedged epoch cannot outlive a freeze claim.
var capacityEpochCutoffRecoveryGrace = 5 * time.Minute

// noteCapacityEpochCutoffUnresolvable records, durably and idempotently, the first moment the
// active epoch's cutoff could not be resolved. It returns that first moment.
func noteCapacityEpochCutoffUnresolvable(
	storage string, epochID uint64, now time.Time,
) (time.Time, error) {
	var since time.Time
	err := updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
		if journal.CutoffUnresolvableSinceUnix == 0 {
			journal.CutoffUnresolvableSinceUnix = now.Unix()
		}
		since = time.Unix(journal.CutoffUnresolvableSinceUnix, 0)
		return nil
	})
	if err == nil {
		return since, nil
	}
	// Fall back ONLY when the journal is genuinely ABSENT. A journal that exists but does not
	// match this epoch may indicate corruption or a stale record, and that must keep failing
	// closed — an abort is never broadcast on ambiguous local state.
	if _, found, readErr := readCapacityEpochJournal(storage); readErr != nil || found {
		return time.Time{}, err
	}
	// THE JOURNAL IS NOT ALWAYS AVAILABLE, AND THAT IS EXACTLY WHEN THIS MATTERS.
	//
	// An epoch can be active on chain while its local journal cannot be built at all — Run 14
	// VK5: a capacity epoch opened for partition data:1:0, a concurrent deletion then proved
	// and DEACTIVATED that partition, so the epoch's only member no longer existed and neither
	// adoption nor chunk reconstruction could produce a journal. Recording the grace inside the
	// journal made this recovery unable to act in the one state it exists to resolve: it
	// errored on every scan for 95 minutes and the epoch never reached a terminal state.
	//
	// Fall back to a standalone durable marker keyed by epoch id. It is independent of the
	// journal, survives restart the same way, and is removed by the same clear path.
	return noteCapacityEpochCutoffUnresolvableSidecar(storage, epochID, now)
}

// capacityEpochCutoffMarkerPath is the journal-independent grace marker for one epoch.
func capacityEpochCutoffMarkerPath(storage string, epochID uint64) string {
	return filepath.Join(partitionProofSnapshotRoot(storage),
		fmt.Sprintf("capacity-epoch-cutoff-unresolvable-%d.json", epochID))
}

type capacityEpochCutoffMarker struct {
	EpochID    uint64 `json:"epochId"`
	SinceUnix  int64  `json:"sinceUnix"`
	RecordedAt string `json:"recordedAt"`
}

func noteCapacityEpochCutoffUnresolvableSidecar(
	storage string, epochID uint64, now time.Time,
) (time.Time, error) {
	path := capacityEpochCutoffMarkerPath(storage, epochID)
	if payload, readErr := os.ReadFile(path); readErr == nil {
		var existing capacityEpochCutoffMarker
		if json.Unmarshal(payload, &existing) == nil && existing.SinceUnix > 0 &&
			existing.EpochID == epochID {
			return time.Unix(existing.SinceUnix, 0), nil
		}
	} else if !os.IsNotExist(readErr) {
		return time.Time{}, readErr
	}
	marker := capacityEpochCutoffMarker{
		EpochID: epochID, SinceUnix: now.Unix(), RecordedAt: now.UTC().Format(time.RFC3339),
	}
	payload, marshalErr := json.MarshalIndent(marker, "", "  ")
	if marshalErr != nil {
		return time.Time{}, marshalErr
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return time.Time{}, err
	}
	if err := durableAtomicWriteFile(path, payload, 0600); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

// clearCapacityEpochCutoffUnresolvableSidecar removes the journal-independent marker.
func clearCapacityEpochCutoffUnresolvableSidecar(storage string, epochID uint64) error {
	if err := os.Remove(capacityEpochCutoffMarkerPath(storage, epochID)); err != nil &&
		!os.IsNotExist(err) {
		return err
	}
	return nil
}

// clearCapacityEpochCutoffUnresolvable removes the marker once the cutoff resolves again. It is a
// no-op when no journal, no marker, or a different epoch is present.
func clearCapacityEpochCutoffUnresolvable(storage string, epochID uint64) error {
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil || !found || journal.EpochID != epochID || journal.CutoffUnresolvableSinceUnix == 0 {
		if err != nil {
			return err
		}
		// No journal marker to clear, but a journal-independent one may exist.
		return clearCapacityEpochCutoffUnresolvableSidecar(storage, epochID)
	}
	if err := updateCapacityEpochJournal(storage, epochID, func(j *capacityEpochJournal) error {
		j.CutoffUnresolvableSinceUnix = 0
		return nil
	}); err != nil {
		return err
	}
	return clearCapacityEpochCutoffUnresolvableSidecar(storage, epochID)
}

// recoverUnresolvableCapacityEpoch gives an epoch whose immutable cutoff cannot be resolved a
// deterministic terminal path. It waits out the grace window first so a slow chain-side exclusion
// still wins, then aborts the epoch on chain. It deliberately writes no local terminal state: the
// journal transition is derived from chain status by the ordinary reconciliation.
//
// Returns true only when the abort was actually broadcast.
func recoverUnresolvableCapacityEpoch(
	storage, chainCmd string,
	status CapacityProofEpochStatus,
	now time.Time,
) (bool, string, error) {
	if !status.Active || status.ProofEpochID == 0 {
		return false, "", nil
	}
	if chainCmd == "" {
		return false, "chain command unavailable", nil
	}
	since, err := noteCapacityEpochCutoffUnresolvable(storage, status.ProofEpochID, now)
	if err != nil {
		// Fail closed: without a durable marker we must not terminate an epoch.
		return false, "", err
	}
	if waited := now.Sub(since); waited < capacityEpochCutoffRecoveryGrace {
		return false, fmt.Sprintf(
			"cutoff unresolvable for %s; allowing chain exclusion until %s",
			waited.Round(time.Second), capacityEpochCutoffRecoveryGrace,
		), nil
	}
	// AUTHORITY DOMAIN. An incremental batch and the full proof epoch are different objects with
	// different owners. Using the wrong one silently does nothing (live 2026-08-13: the full-epoch
	// abort was skipped by the adapter because that epoch was already inactive, so the batch stayed
	// wedged and the VK retried every scan).
	if status.ProofEpochID&incrementalCapacityAuthorityFlag != 0 {
		return recoverUnresolvableIncrementalBatch(storage, chainCmd, status)
	}
	tx, abortErr := abortCapacityProofEpochOnChain(chainCmd, status.ProofEpochID)
	if abortErr != nil {
		return false, "", fmt.Errorf("abort unresolvable capacity epoch: %w", abortErr)
	}
	return true, fmt.Sprintf(
		"aborted unresolvable capacity epoch %d after %s tx=%s",
		status.ProofEpochID, capacityEpochCutoffRecoveryGrace, tx,
	), nil
}

// capacityBatchAbandonReasonUnresolvableCutoff is the reason code recorded on chain. The contract
// accepts 1..ABANDON_REASON_MAX(4); this recovery is always the same cause.
const capacityBatchAbandonReasonUnresolvableCutoff uint8 = 4

// recoverUnresolvableIncrementalBatch performs the two-step authorised recovery.
//
// `PartitionSnapshotProofSC.abandonIncrementalBatch` is deliberately NOT a force-unlock: it
// reverts with "SnapshotProof: live selected snapshot" while any selected-but-unaccepted member
// still holds a live frozen snapshot under this batch. So the VK must first terminally resolve its
// own frozen artifacts (step A), then abandon the batch (step B). Accepted members are never
// touched — they keep their accounting — and unrelated snapshots are never retired.
//
// No local terminal state is written here: the journal derives `aborted` from authoritative chain
// status on a later scan, which is what makes a crash between the two steps recoverable.
func recoverUnresolvableIncrementalBatch(
	storage, chainCmd string, status CapacityProofEpochStatus,
) (bool, string, error) {
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil {
		return false, "", err
	}
	journalMatches := found && journal.EpochID == status.ProofEpochID
	var members []capacityEpochMemberRef
	switch {
	case journalMatches:
		members = journal.Members
	case !found:
		// NO JOURNAL AT ALL. Run 14 VK5: a batch opened on chain selecting data:1:0; a concurrent
		// deletion then DEACTIVATED that partition, so no journal could ever be built. The chunk
		// plan durably records the selected members, so enumerate from it when it is present.
		plan, planFound, planErr := readCapacityBatchChunkPlan(storage)
		if planErr != nil {
			return false, "", planErr
		}
		if planFound {
			for index := range plan.Chunks {
				chunk := &plan.Chunks[index]
				if !chunk.Opened || chunk.Done || chunk.BatchID != status.ProofEpochID {
					continue
				}
				for _, key := range chunk.Keys {
					kind, deadlineIndex, partitionIndex, parseErr := parseEpochPartitionKey(key)
					if parseErr != nil {
						return false, "", fmt.Errorf(
							"incremental recovery cannot parse chunk member %q for batch %d: %w",
							key, status.ProofEpochID, parseErr)
					}
					members = append(members, capacityEpochMemberRef{
						PartitionKind: kind, DeadlineIndex: deadlineIndex,
						PartitionIndex: partitionIndex,
					})
				}
			}
		}
	default:
		// A journal exists but for a DIFFERENT epoch: ambiguous LOCAL state for THIS batch. Do not
		// trust it — fall through to the chain-authoritative enumeration below, which is correct
		// for status.ProofEpochID regardless of any unrelated local journal.
	}

	// CHAIN IS THE AUTHORITY. When local records cannot enumerate this active batch's members — a
	// restart landed while the members were being deleted, destroying the journal AND the chunk
	// plan (Run-18 VK2: batch active on chain, journal empty, chunk plan empty; the enumeration
	// above yields nothing and this recovery used to FAIL CLOSED and defer forever) — enumerate the
	// selected members straight from chain (selectedMemberKeys). This closes the whole family of
	// restart wedges at once: recovery no longer depends on durable local records surviving a
	// restart. Only members the chain still reports as an unaccepted LIVE frozen snapshot need
	// releasing in Step A; the rest cannot block the abandon and are skipped — so a deleted member
	// whose partition is gone is never queried (which would error) and the batch abandons directly.
	if len(members) == 0 {
		chainMembers, memErr := capacityIncrementalBatchMembersOnChain(chainCmd, status.ProofEpochID)
		if memErr != nil {
			return false, "", fmt.Errorf(
				"incremental recovery cannot enumerate batch %d members from chain: %w",
				status.ProofEpochID, memErr)
		}
		for _, chainMember := range chainMembers {
			if chainMember.Accepted || !chainMember.Frozen {
				// Accepted members keep their accounting; non-frozen members hold no live selected
				// snapshot and cannot block the abandon. Neither needs Step A resolution.
				continue
			}
			kind, deadlineIndex, partitionIndex, parseErr := parseEpochPartitionKey(chainMember.Key)
			if parseErr != nil {
				return false, "", fmt.Errorf(
					"incremental recovery cannot parse chain member %q for batch %d: %w",
					chainMember.Key, status.ProofEpochID, parseErr)
			}
			members = append(members, capacityEpochMemberRef{
				PartitionKind: kind, DeadlineIndex: deadlineIndex, PartitionIndex: partitionIndex,
			})
		}
		// members may still be empty (chain reports only accepted/already-resolved members). That is
		// SAFE and deliberate: Step A is a no-op and Step B abandons the batch directly — the
		// contract precondition (no live unaccepted frozen selected snapshot) is then satisfied.
	}

	// Step A — retire every selected-but-unaccepted member that still holds a live frozen
	// snapshot under THIS batch authority, using the existing authorised path.
	excluded := map[string]bool{}
	if journalMatches {
		excluded = make(map[string]bool, len(journal.ExcludedMembers))
		for _, exclusion := range journal.ExcludedMembers {
			excluded[exclusion.SnapshotID] = true
		}
	}
	retired := 0
	for _, member := range members {
		if excluded[member.SnapshotID] {
			continue
		}
		partition := PartitionMeta{
			DeadlineIndex:  member.DeadlineIndex,
			PartitionIndex: member.PartitionIndex,
			PartitionKind:  member.PartitionKind,
		}
		queue, queueFound, queueErr := readPartitionProofSnapshotQueue(
			storage, member.PartitionKind, member.DeadlineIndex, member.PartitionIndex)
		if queueErr != nil {
			return false, "", queueErr
		}
		if queueFound && queue.Frozen != nil && queue.Frozen.ProofEpochID == status.ProofEpochID {
			if err := abandonAndAdvancePartitionSnapshot(
				storage, chainCmd, *queue.Frozen,
				"incremental batch cutoff unresolvable; releasing selected member",
			); err != nil {
				// Fail closed: if a member cannot be retired the batch must not be abandoned.
				return false, "", fmt.Errorf(
					"retire selected member dl=%d pt=%d before batch abandonment: %w",
					member.DeadlineIndex, member.PartitionIndex, err)
			}
			retired++
			continue
		}

		// DEFECT F/G — LOCAL STATE IS NOT THE AUTHORITY HERE.
		//
		// Step B calls PartitionSnapshotProofSC.abandonIncrementalBatch, whose precondition is
		// evaluated over CHAIN state: it loops batch.selectedMemberKeys(batchId) and rejects any
		// unaccepted member whose ON-CHAIN frozenSnapshots[key] is still live under this batch
		// ("SnapshotProof: live selected snapshot", PartitionSnapshotProofSC.sol:333-341).
		//
		// Skipping here because the LOCAL queue has no frozen record made this recovery
		// unsatisfiable by construction whenever the two diverged. Proven live on smoke8 VK3
		// (2026-08-16): "immutable cutoff is incomplete: local unresolved=0 chain unresolved=3"
		// followed by 205+ consecutive abandon reverts, every ~16 s, with no terminal state —
		// the local queue was already clean, so this loop retired nothing and Step B could never
		// satisfy a guard that only chain state can clear.
		//
		// The contract is correct and is not weakened. The fix is to ask the chain what it
		// actually holds, and clear it through the same authorised abandon entry point, using
		// CHAIN-SOURCED identity (contentVersion/contentHash/snapshotNonce) rather than a local
		// record that by definition does not exist in this branch.
		slot, slotErr := frozenPartitionSnapshotStatusOnChain(chainCmd, partition)
		if slotErr != nil {
			return false, "", fmt.Errorf(
				"read chain frozen slot dl=%d pt=%d before batch abandonment: %w",
				member.DeadlineIndex, member.PartitionIndex, slotErr)
		}
		if !slot.Exists || slot.ProofEpochID != status.ProofEpochID {
			continue // genuinely resolved on chain, or owned by a different authority
		}
		if _, err := abandonFrozenPartitionSnapshotOnChain(chainCmd, partitionProofSnapshot{
			Partition:        partition,
			ProofEpochID:     slot.ProofEpochID,
			ContentVersion:   slot.ContentVersion,
			ChainContentHash: slot.ContentHash,
			SnapshotNonce:    slot.SnapshotNonce,
		}); err != nil {
			return false, "", fmt.Errorf(
				"release chain-only frozen slot dl=%d pt=%d before batch abandonment: %w",
				member.DeadlineIndex, member.PartitionIndex, err)
		}
		retired++
	}

	// Step B — abandon the batch through the authorised entry point.
	tx, abandonErr := abandonIncrementalBatchOnChain(
		chainCmd, status.ProofEpochID, capacityBatchAbandonReasonUnresolvableCutoff)
	if abandonErr != nil {
		return false, "", fmt.Errorf("abandon unresolvable incremental batch: %w", abandonErr)
	}
	// The batch is now terminal on chain, so its LOCAL chunk ownership must be released or the
	// next batch is refused with "chunk N already opened as batch <old>". The chunk returns to
	// pending with its identities intact; Done chunks and other batches are never touched.
	releasedChunk, releaseErr := releaseTerminalCapacityBatchChunkBinding(storage, status.ProofEpochID)
	if releaseErr != nil {
		return true, "", fmt.Errorf(
			"batch %d abandoned but its chunk binding could not be released: %w",
			status.ProofEpochID, releaseErr)
	}
	return true, fmt.Sprintf(
		"abandoned unresolvable incremental batch %d after %s (retired %d selected member(s), "+
			"chunk binding released=%t) tx=%s",
		status.ProofEpochID, capacityEpochCutoffRecoveryGrace, retired, releasedChunk, tx,
	), nil
}

// parseEpochPartitionKey is the inverse of epochPartitionKey ("kind:deadline:partition").
func parseEpochPartitionKey(key string) (string, int, int, error) {
	parts := strings.Split(strings.TrimSpace(key), ":")
	if len(parts) != 3 || parts[0] == "" {
		return "", 0, 0, fmt.Errorf("malformed partition key %q", key)
	}
	deadlineIndex, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("malformed deadline in %q: %w", key, err)
	}
	partitionIndex, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", 0, 0, fmt.Errorf("malformed partition in %q: %w", key, err)
	}
	return parts[0], deadlineIndex, partitionIndex, nil
}
