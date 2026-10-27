package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
)

// A.1 durable monotonic local generation.
//
// The on-chain frozenSnapshotNonce (A.0) is the chain's authority counter. This is its
// VK-LOCAL companion: a per-partition, strictly-monotonic generation that the VK owns
// and that disambiguates otherwise-identical snapshot records. Two frozen records for the
// same partition can share a content-addressed ID (identical bytes re-frozen, or a
// reanchor of the same content), so ID alone cannot tell a stale worker's record from the
// live one. The local generation closes that ABA hole: every freeze attempt, reanchor,
// and successor replacement allocates a generation strictly greater than every generation
// ever handed out for that partition, and a worker's durable write is honoured only while
// the generation it holds still matches the live frozen slot.
//
// The counter is persisted in a ledger file that is SEPARATE from the snapshot queue and
// is NEVER deleted when the active snapshot record is removed. Deleting and recreating a
// partition's snapshot therefore continues the sequence (…, N) → (N+1, …); it never
// restarts at 1. The ledger high-water only ever increases.

const partitionGenerationLedgerVersion = 1

// requirePartitionGenerationIdentity selects the A.1 protocol (default): every active
// frozen record MUST carry a positive local generation, and a worker-held generation must
// match the live frozen generation before its durable write is honoured. Legacy records
// with a missing/zero generation never satisfy the identity check — they are refused
// (fail-closed) rather than silently participating. The pre-A.1 behaviour is only entered
// via the explicit -legacy-snapshot-protocol flag / FILETRUST_LEGACY_SNAPSHOT_PROTOCOL.
var requirePartitionGenerationIdentity = true

// partitionGenerationIdentityOK reports whether a worker-held generation still matches the
// durable frozen generation. Under the A.1 protocol a zero generation on either side never
// matches: a legacy (generation 0) record cannot be mistaken for a live A.1 record, and
// two zero generations are never treated as the same identity.
func partitionGenerationIdentityOK(stored, held uint64) bool {
	if requirePartitionGenerationIdentity && (stored == 0 || held == 0) {
		return false
	}
	return stored == held
}

// partitionGenerationLedger is the durable per-partition high-water generation. It lives
// beside the queues but outlives any single snapshot record.
type partitionGenerationLedger struct {
	Version             int    `json:"version"`
	PartitionKind       string `json:"partitionKind"`
	DeadlineIndex       int    `json:"deadlineIndex"`
	PartitionIndex      int    `json:"partitionIndex"`
	HighWaterGeneration uint64 `json:"highWaterGeneration"`
	UpdatedAt           string `json:"updatedAt"`
}

func partitionGenerationLedgerDir(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "generations")
}

func partitionGenerationLedgerPath(storage, kind string, deadlineIndex, partitionIndex int) string {
	return filepath.Join(
		partitionGenerationLedgerDir(storage),
		partitionProofSnapshotQueueName(kind, deadlineIndex, partitionIndex)+".gen",
	)
}

// maxExistingSnapshotGenerationUnlocked returns the highest generation stamped on any
// durable snapshot record (frozen or successor) for the partition, and whether any record
// exists. The caller MUST hold the partition's snapshot lock. It is the tripwire the ledger
// read cross-checks against: a durable record can never carry a generation the ledger has
// not persisted, so a ledger below it — or missing while a record exists — is corruption.
func maxExistingSnapshotGenerationUnlocked(storage, kind string, deadlineIndex, partitionIndex int) (uint64, bool, error) {
	queue, found, err := readPartitionProofSnapshotQueueUnlocked(storage, kind, deadlineIndex, partitionIndex)
	if err != nil {
		return 0, false, err
	}
	if !found {
		return 0, false, nil
	}
	var maxGen uint64
	for _, snap := range []*partitionProofSnapshot{queue.Frozen, queue.Successor} {
		if snap != nil && snap.Generation > maxGen {
			maxGen = snap.Generation
		}
	}
	return maxGen, queue.Frozen != nil || queue.Successor != nil, nil
}

// readPartitionGenerationLedgerUnlocked returns the durable ledger for a partition. The
// caller MUST hold the partition's snapshot lock (withPartitionProofSnapshotLock). It fails
// CLOSED rather than ever inferring a lower high-water and reusing a generation:
//   - a truncated/malformed ledger → decode error;
//   - a ledger identity mismatch → error;
//   - the ledger missing while a durable snapshot record already carries a generation
//     ("missing-after-prior-use") → error, never a silent reset to zero;
//   - a ledger high-water below an existing snapshot generation ("rollback") → error.
// A genuinely first-ever use (no ledger AND no record with a generation) reports high-water
// zero so the first allocation is 1.
func readPartitionGenerationLedgerUnlocked(storage, kind string, deadlineIndex, partitionIndex int) (partitionGenerationLedger, error) {
	maxGen, _, err := maxExistingSnapshotGenerationUnlocked(storage, kind, deadlineIndex, partitionIndex)
	if err != nil {
		return partitionGenerationLedger{}, fmt.Errorf("generation ledger cross-check (unreadable queue): %w", err)
	}
	path := partitionGenerationLedgerPath(storage, kind, deadlineIndex, partitionIndex)
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if maxGen > 0 {
			return partitionGenerationLedger{}, fmt.Errorf(
				"generation ledger missing after prior use for %s dl%d pt%d (snapshot generation %d exists); fail closed",
				kind, deadlineIndex, partitionIndex, maxGen,
			)
		}
		return partitionGenerationLedger{
			Version: partitionGenerationLedgerVersion, PartitionKind: kind,
			DeadlineIndex: deadlineIndex, PartitionIndex: partitionIndex,
		}, nil
	}
	if err != nil {
		return partitionGenerationLedger{}, err
	}
	var ledger partitionGenerationLedger
	if err := json.Unmarshal(payload, &ledger); err != nil {
		return partitionGenerationLedger{}, fmt.Errorf("decode generation ledger (truncated/corrupt?): %w", err)
	}
	if ledger.PartitionKind != kind || ledger.DeadlineIndex != deadlineIndex || ledger.PartitionIndex != partitionIndex {
		return partitionGenerationLedger{}, fmt.Errorf("generation ledger identity mismatch for %s dl%d pt%d", kind, deadlineIndex, partitionIndex)
	}
	if ledger.HighWaterGeneration < maxGen {
		return partitionGenerationLedger{}, fmt.Errorf(
			"generation ledger high-water %d below existing snapshot generation %d for %s dl%d pt%d (rollback/truncation); fail closed",
			ledger.HighWaterGeneration, maxGen, kind, deadlineIndex, partitionIndex,
		)
	}
	return ledger, nil
}

// allocatePartitionGenerationUnlocked advances the durable high-water by one and returns
// the new value. The caller MUST hold the partition's snapshot lock. The high-water is
// written durably (temp → fsync → atomic rename → parent-dir fsync, via
// durableAtomicWriteFile) BEFORE the value is returned, so a crash can never re-hand-out a
// generation; a crash AFTER the ledger advances but BEFORE the snapshot record is written
// merely skips a generation, which is acceptable. The returned value is strictly greater
// than every generation previously allocated for the partition, never resets, and fails
// closed on uint64 overflow rather than wrapping to zero.
func allocatePartitionGenerationUnlocked(storage, kind string, deadlineIndex, partitionIndex int) (uint64, error) {
	ledger, err := readPartitionGenerationLedgerUnlocked(storage, kind, deadlineIndex, partitionIndex)
	if err != nil {
		return 0, err
	}
	if ledger.HighWaterGeneration == math.MaxUint64 {
		return 0, fmt.Errorf("generation counter exhausted for %s dl%d pt%d (overflow); fail closed", kind, deadlineIndex, partitionIndex)
	}
	ledger.Version = partitionGenerationLedgerVersion
	ledger.PartitionKind = kind
	ledger.DeadlineIndex = deadlineIndex
	ledger.PartitionIndex = partitionIndex
	ledger.HighWaterGeneration++
	ledger.UpdatedAt = nowRFC3339()
	payload, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := durableAtomicWriteFile(
		partitionGenerationLedgerPath(storage, kind, deadlineIndex, partitionIndex), payload, 0600,
	); err != nil {
		return 0, err
	}
	return ledger.HighWaterGeneration, nil
}

// allocatePartitionGeneration is the lock-taking form used by callers that do not already
// hold the partition snapshot lock (e.g. the reanchor bump wraps its own lock and uses the
// Unlocked form; tests use this to exercise concurrent allocation).
func allocatePartitionGeneration(storage, kind string, deadlineIndex, partitionIndex int) (gen uint64, err error) {
	lockErr := withPartitionProofSnapshotLock(storage, kind, deadlineIndex, partitionIndex, func() error {
		gen, err = allocatePartitionGenerationUnlocked(storage, kind, deadlineIndex, partitionIndex)
		return err
	})
	if lockErr != nil {
		return 0, lockErr
	}
	return gen, err
}

// currentPartitionGeneration reports the durable high-water without advancing it.
func currentPartitionGeneration(storage, kind string, deadlineIndex, partitionIndex int) (gen uint64, err error) {
	lockErr := withPartitionProofSnapshotLock(storage, kind, deadlineIndex, partitionIndex, func() error {
		ledger, readErr := readPartitionGenerationLedgerUnlocked(storage, kind, deadlineIndex, partitionIndex)
		if readErr != nil {
			return readErr
		}
		gen = ledger.HighWaterGeneration
		return nil
	})
	return gen, lockErr
}
