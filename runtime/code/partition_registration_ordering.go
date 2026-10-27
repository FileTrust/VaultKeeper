package main

// Store-path partition registration must not pre-empt an unresolved deletion that
// owns the same partition.
//
// THE DEFECT THIS FIXES (proven live, D.3-VK smoke3, VK2 2026-08-14)
//
//	register partition dl17-pt0: chain proof command returned error:
//	  real-on-chain adapter: execution reverted: "DR: deleted piece still present"
//
//	DeletionReleaseSC.sol:400-401 requires that the successor manifest presented for
//	a partition NO LONGER CONTAIN the deleted piece commitment. StorageProofSC calls
//	resolveSuccessor (onlyStorageProof) on every data-partition registration for a
//	partition that has an unresolved deletion operation
//	(DeletionReleaseSC.sol:159/337 unresolvedOperationByPartition — the deletion OWNS
//	that partition until it resolves).
//
//	The DELETE path is correctly ordered (lifecycle_reconcile.go:1449-1462):
//	    removePieceFromSectorWithMutation -> mutation.Complete -> syncDataPartitionAfterDelete
//	so by the time it registers, the piece is physically gone and the require passes.
//
//	The STORE path was not. server.go registers the partition's CURRENT local state
//	as soon as a store commits. If a deletion on that partition is declared but has
//	not yet reached partition_synced, the piece is still physically present, so the
//	store registers a successor that still contains a piece the VK has already
//	declared deleted. The contract correctly refuses. Worse, the store treated that
//	refusal as fatal, so the upload was rolled back, the coordinate never entered the
//	registered manifest, and the deletion stayed declared_pending — which in turn
//	blocks capacity epoch start (lifecycle_reconcile.go:640). Nothing broke the cycle.
//
// THE ORDERING RULE
//
//	While an unresolved deletion owns a partition, that deletion owns the partition's
//	next registration. A concurrent store defers; it does not register, and it does
//	not fail. Its bytes are already durable (phase=sector_committed) and the
//	deletion's own syncDataPartitionAfterDelete registers CURRENT local state, which
//	includes the newly stored sector. One registration, correctly ordered, instead of
//	two racing ones.
//
// WHAT THIS DOES NOT DO
//
//	No timer or grace. No weakening of DeletionReleaseSC validation — the require is
//	untouched and still authoritative. No faked registration and no faked release:
//	the deletion still must physically remove the piece and register its own
//	successor, and capacity release still requires the real proof. G.4/G.4B ownership
//	semantics are preserved exactly; this defers to them rather than around them.

import (
	"errors"
	"fmt"
	"strings"
)

// errPartitionRegistrationDeferred signals that registration was intentionally not
// attempted because an unresolved deletion owns the partition. It is NOT a failure:
// the caller keeps the store durably committed and leaves registration to the
// deletion path.
var errPartitionRegistrationDeferred = errors.New("partition registration deferred to the unresolved deletion that owns this partition")

// pendingDeletionOwnsPartition reports whether a local deletion operation targets
// this exact data-partition coordinate and has not yet reached partition_synced —
// i.e. it has not yet removed its piece and registered its successor.
//
// Coordinates are read from the deletion's own durable record, falling back to the
// sector it targets, so a record written before coordinates were journalled is
// still matched rather than silently ignored.
func pendingDeletionOwnsPartition(
	storage string, deadlineIndex, partitionIndex int,
) (bool, string, error) {
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return false, "", err
	}
	for _, operation := range operations {
		phase := strings.ToLower(strings.TrimSpace(operation.Phase))
		switch phase {
		case "", "confirmed", "settled", "terminal", "failed":
			continue
		}
		// Once the successor is registered the deletion no longer blocks a
		// concurrent store: the piece is gone from the manifest.
		if deletionPhaseAtLeast(phase, "partition_synced") {
			continue
		}
		dl, pt := operation.DeadlineIndex, operation.PartitionIndex
		if dl == 0 && pt == 0 {
			sector, found, sectorErr := sectorForDeletionOperation(storage, operation)
			if sectorErr != nil {
				// An unreadable sector index must never be read as "no deletion owns
				// this partition"; that is the exact race this guard exists to stop.
				return false, "", sectorErr
			}
			if !found {
				continue
			}
			dl, pt = sector.DeadlineIndex, sector.PartitionIndex
		}
		if dl == deadlineIndex && pt == partitionIndex {
			return true, fmt.Sprintf("deletion %s phase=%s", truncate(operation.PieceRoot, 18), phase), nil
		}
	}
	return false, "", nil
}

// ── the TOCTOU race (Defect B residual) ──────────────────────────────────────
//
// pendingDeletionOwnsPartition is a LOCAL read. Between it returning false and the
// registration transaction actually executing on chain, a deletion can declare and
// become the partition's unresolved owner. StorageProofSC then calls
// DeletionReleaseSC.resolveSuccessor and the contract CORRECTLY reverts with
// "DR: deleted piece still present", because the manifest we are presenting still
// contains the piece that deletion has now declared.
//
// Observed live 3 times in Smoke 6 (and twice in Smoke 4). The contract is right;
// the store simply lost a race it cannot prevent with a local pre-check alone.
//
// RECOVERY, and only for this proven case:
//   - the revert must name the DR deleted-piece condition, AND
//   - an authoritative re-read must CONFIRM a deletion now owns this partition.
// Both together mean the deletion legitimately owns the next registration, so the
// store yields exactly as it would have if the pre-check had seen it — its bytes are
// already durable and the deletion's own syncDataPartitionAfterDelete will register
// current local state, including this sector.
//
// If the re-check does NOT confirm ownership, the revert stays FATAL. A DR revert is
// never swallowed on its text alone, and no other contract error is affected.

// deletionReleasePieceStillPresent identifies the exact contract condition.
// DeletionReleaseSC.sol:400 require(!_contains(successorPieces, deletedPieceCommitment)).
func deletionReleasePieceStillPresent(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "DR: deleted piece still present")
}

// registrationLostOwnershipRace reports whether a failed registration should be
// reclassified as a deferral to the deletion that now owns the partition.
//
// It requires BOTH the exact contract revert AND a confirming authoritative re-read.
// Anything else keeps its original error.
func registrationLostOwnershipRace(
	storage string, deadlineIndex, partitionIndex int, err error,
) (bool, string) {
	if !deletionReleasePieceStillPresent(err) {
		return false, ""
	}
	owned, why, ownErr := pendingDeletionOwnsPartition(storage, deadlineIndex, partitionIndex)
	if ownErr != nil {
		// An unreadable journal is not confirmation. Keep the original failure.
		return false, ""
	}
	if !owned {
		// The contract refused but no local deletion owns the partition. That is NOT
		// the known race and must not be swallowed.
		return false, ""
	}
	return true, why
}
