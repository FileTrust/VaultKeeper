package main

import (
	"fmt"
	"strings"
)

// B.2 defensive new-sector validation under the selected partition lock.
//
// B.1 makes target selection and reservation atomic, but the reservation is taken BEFORE the
// physical partition lock. Between the two, another process holding that partition lock can
// commit a sector there, freeze/prove the coordinate, or begin a deletion. B.2 therefore
// revalidates the already-reserved target immediately before any new-sector write begins, while
// holding the partition lock, against freshly reloaded authoritative local state.
//
// Lock-order rule: this revalidation NEVER acquires the allocator lock. It reads the durable
// reservation records directly — each record is written atomically (temp → fsync → rename), so a
// lock-free read observes a whole record. On invalidation the caller must release the partition
// lock FIRST and only then return to the B.1 allocator path to reconcile or re-select. This
// keeps the single lock order `allocator (brief) → partition` and makes inversion impossible.
//
// The revalidation performs no writes of any kind, so a failed recheck cannot leave a sector
// write or an on-chain action behind.

// newSectorTargetRequest is the exact placement a caller is about to write.
type newSectorTargetRequest struct {
	OperationID      string
	SectorID         string
	PartitionKind    string
	DeadlineIndex    int
	PartitionIndex   int
	ExpirationBucket int
}

func (r newSectorTargetRequest) bucketKey() partitionBucketKey {
	kind := r.PartitionKind
	if strings.TrimSpace(kind) == "" {
		kind = PartitionKindData
	}
	return partitionBucketKey{
		deadlineIndex: r.DeadlineIndex, partitionIndex: r.PartitionIndex, kind: kind,
	}
}

// newSectorTargetVerdict is the outcome of the under-lock recheck. Invalid is not an error: it
// means the caller must drop the partition lock and reconcile through the allocator path.
type newSectorTargetVerdict struct {
	Valid  bool
	Reason string
}

func invalidTarget(format string, args ...any) newSectorTargetVerdict {
	return newSectorTargetVerdict{Valid: false, Reason: fmt.Sprintf(format, args...)}
}

// revalidateReservedNewSectorTarget re-verifies a reserved new-sector target against freshly
// reloaded authoritative local state. The caller MUST already hold the partition lifecycle lock
// for req's coordinates, and MUST NOT hold the allocator lock.
//
// It is a pure read: repeating it for the same valid operation and target is idempotent and
// yields the same verdict.
func revalidateReservedNewSectorTarget(
	storage string, cfg ServerConfig, req newSectorTargetRequest,
) (newSectorTargetVerdict, error) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return invalidTarget("partitioning is not configured"), nil
	}
	if strings.TrimSpace(req.OperationID) == "" {
		return invalidTarget("no upload-operation identity"), nil
	}
	if strings.TrimSpace(req.SectorID) == "" {
		return invalidTarget("no sector target"), nil
	}
	kind := req.PartitionKind
	if strings.TrimSpace(kind) == "" {
		kind = PartitionKindData
	}
	if kind != PartitionKindData {
		return invalidTarget("new-sector reservation applies to data partitions only, got %q", kind), nil
	}
	if req.DeadlineIndex < 0 || req.DeadlineIndex >= cfg.DeadlineCount ||
		req.PartitionIndex < partitionBaseIndex(kind) || req.PartitionIndex > partitionMaxIndex(kind) {
		return invalidTarget("target dl%d-pt%d is out of range", req.DeadlineIndex, req.PartitionIndex), nil
	}

	// ── The reservation must still exist, belong to this operation, and be live ───────────────
	record, found, err := readSectorSlotReservationUnlocked(storage, req.OperationID)
	if err != nil {
		return newSectorTargetVerdict{}, err
	}
	if !found {
		return invalidTarget("reservation for operation %s no longer exists", req.OperationID), nil
	}
	if record.OperationID != req.OperationID {
		return invalidTarget("reservation belongs to operation %s, not %s", record.OperationID, req.OperationID), nil
	}
	if !record.active() {
		return invalidTarget("reservation for operation %s is %s, not active", req.OperationID, record.State), nil
	}

	// ── Its COMPLETE physical target must match the placement about to be written ─────────────
	if !strings.EqualFold(record.SectorID, req.SectorID) {
		return invalidTarget("reservation targets sector %s, not %s", record.SectorID, req.SectorID), nil
	}
	if record.bucketKey() != req.bucketKey() {
		return invalidTarget("reservation targets %s dl%d-pt%d, not dl%d-pt%d",
			record.PartitionKind, record.DeadlineIndex, record.PartitionIndex,
			req.DeadlineIndex, req.PartitionIndex), nil
	}
	if record.ExpirationBucket != req.ExpirationBucket {
		return invalidTarget("reservation targets expiration bucket %d, not %d",
			record.ExpirationBucket, req.ExpirationBucket), nil
	}

	// ── Reload authoritative local occupancy under the held partition lock ────────────────────
	// Both sources are read through the sanctioned protocol (reservations FIRST, committed
	// sectors SECOND) so a lock-free commit landing between them can never produce a torn view
	// that omits a slot in transition. The operation's own sector is excluded from committed
	// counts so that a sector already written by a crashed earlier attempt is not counted
	// alongside this same operation's reservation (its slot must be counted exactly once).
	snapshot, err := loadSectorSlotOccupancySnapshot(storage, cfg, req.SectorID)
	if err != nil {
		return newSectorTargetVerdict{}, err
	}
	state := snapshot.state
	key := req.bucketKey()
	// Sealed covers every state incompatible with new-sector creation that may have appeared
	// since allocation: a frozen proof snapshot, an exact-content proved coordinate, a pending
	// deletion journal, or a deleted-but-still-assigned sector holding the coordinate.
	if state.sealed[key] {
		return invalidTarget("target dl%d-pt%d became ineligible for new sectors (sealed/frozen/proved/pending-deletion)",
			req.DeadlineIndex, req.PartitionIndex), nil
	}
	if !state.sameBucketOnly(key, req.ExpirationBucket) {
		return invalidTarget("target dl%d-pt%d now holds sectors of another expiration bucket",
			req.DeadlineIndex, req.PartitionIndex), nil
	}

	// ── Committed occupancy + active reservations must not exceed the sector cap ──────────────
	// Reservations come from the snapshot taken above; this never takes the allocator lock (see
	// the lock-order rule) and never re-reads either source out of order.
	if snapshot.bucketConflict(key, req.ExpirationBucket, req.OperationID) {
		return invalidTarget("target dl%d-pt%d is held for another expiration bucket",
			req.DeadlineIndex, req.PartitionIndex), nil
	}
	// This operation's own reservation must be counted exactly once — never zero (it would not
	// be holding the slot) and never twice (it would over-count its own claim).
	if own := snapshot.reservationsOnSlot(key, req.OperationID); own != 1 {
		return invalidTarget("this operation holds %d reservations on dl%d-pt%d, want exactly 1",
			own, req.DeadlineIndex, req.PartitionIndex), nil
	}
	// occupied() counts every active reservation on the slot — including this operation's own,
	// exactly once — plus committed sectors, deduplicating a reservation already committed.
	if occupied := snapshot.occupied(key, ""); occupied > cfg.PartitionMaxSectors {
		return invalidTarget("dl%d-pt%d would exceed the sector cap: %d occupied (committed + reserved) > %d",
			req.DeadlineIndex, req.PartitionIndex, occupied, cfg.PartitionMaxSectors), nil
	}
	return newSectorTargetVerdict{Valid: true}, nil
}
