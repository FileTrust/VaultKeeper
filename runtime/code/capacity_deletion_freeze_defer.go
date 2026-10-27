package main

import (
	"time"
)

// FIX C (Run 15, VK5 data:13:0) — never OPEN a capacity batch for a member a deletion currently
// owns on the freeze slot.
//
// THE DEFECT (proven live, D.3-VK Run 15, VK5 2026-08-18)
//
//	The epoch-start gate deletionMutationsBlockingCapacityEpoch deliberately does NOT block a
//	capacity epoch on an accepted_queued deletion (the DO may be offline; a blanket block could
//	stall capacity indefinitely). But the partition freeze arbiter DOES grant an accepted_queued
//	deletion FIFO priority for the slot. The two subsystems disagree: capacity opens the on-chain
//	batch, then cannot obtain the freeze ("deletion holds the slot"), so the batch is unsatisfiable
//	and is abandoned after 5 minutes — then reopened, and the loop repeats. VK5 spent ~37 minutes
//	reopening a batch for data:13:0 while a deletion held its freeze, proving nothing, until the
//	deletion completed and stale-member retirement finally cleared the coordinate.
//
// THE FIX
//
//	Before an incremental batch is opened, inspect the members of the chunk that would be frozen.
//	If a deletion currently OWNS the freeze slot for any of them, return a notDue decision — a
//	first-class WAIT — instead of opening a batch that cannot be satisfied. The wait is bounded:
//	the deletion either completes (the coordinate is then deactivated and stale-member retirement
//	clears it) or releases its freeze claim, after which capacity opens normally.
//
// WHY THIS IS SAFE, AND NOT A BLANKET accepted_queued BLOCK
//
//   - "Owns" requires BOTH that the deletion is still an active lifecycle operation for the
//     coordinate AND that it currently HOLDS the durable freeze claim (an in-flight broadcast, or
//     an unexpired reservation). A deletion only holds the slot when the slot is NOT free, so
//     capacity aging-ahead under hard-lag pressure — which claims a FREE slot ahead of a deletion
//     that merely WANTS it — is never affected.
//   - Requiring the lifecycle journal to still list the operation excludes a stale claim left by a
//     terminated deletion (a plain, never-broadcast claim inside its TTL — see
//     acquirePartitionFreezeClaim), exactly as the arbiter's in.DeletionWantsSlot input does.
//   - It opens no campaign, writes no chain state and creates no journal; it only withholds an open
//     that could not have succeeded. The existing stale-member retirement remains the escape for
//     the post-deletion unresolvable case; this fix removes the wasteful loop that precedes it.

// capacityChunkAwaitingDeletionFreeze reports whether the next incremental chunk that is about to
// be opened contains a member a deletion currently owns on the freeze slot, and if so which
// coordinate. It examines only a chunk that is NOT yet opened; an already-open chunk is left to the
// existing abandon/recovery path. It is a pure local read and never contacts the chain.
func capacityChunkAwaitingDeletionFreeze(storage string, now time.Time) (bool, string, error) {
	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil {
		return false, "", err
	}
	if !found {
		return false, "", nil
	}
	chunk, ok := plan.nextPendingChunk()
	if !ok || chunk.Opened || len(chunk.Keys) == 0 {
		// No chunk, or the next chunk is already an on-chain obligation: nothing to withhold here.
		return false, "", nil
	}
	deletionPending, err := pendingDeletionPartitionKeys(storage)
	if err != nil {
		return false, "", err
	}
	if len(deletionPending) == 0 {
		return false, "", nil
	}
	for _, key := range chunk.Keys {
		kind, dl, pt, parseErr := parseEpochPartitionKey(key)
		if parseErr != nil {
			// An unparseable coordinate is not a deletion-freeze case; leave it to the existing
			// PlanValid / stale-member-retirement paths.
			continue
		}
		owns, ownErr := deletionOwnsFreezeSlot(storage, kind, dl, pt, deletionPending, now)
		if ownErr != nil {
			return false, "", ownErr
		}
		if owns {
			return true, key, nil
		}
	}
	return false, "", nil
}

// deletionOwnsFreezeSlot reports whether an ACTIVE deletion currently owns the durable freeze slot
// for this coordinate: it both (a) still appears as a pending operation in the deletion lifecycle
// journal and (b) holds the durable freeze claim — an in-flight (broadcast_pending) deletion
// freeze, or an unexpired deletion reservation. It is a pure local read and never contacts the
// chain. See the file header for why both conditions are required and why capacity aging-ahead is
// unaffected.
func deletionOwnsFreezeSlot(
	storage, kind string, dl, pt int,
	deletionPending map[partitionBucketKey]bool, now time.Time,
) (bool, error) {
	if !deletionPending[partitionBucketKey{deadlineIndex: dl, partitionIndex: pt, kind: kind}] {
		return false, nil
	}
	var owns bool
	err := withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
		claim, found, rErr := readFreezeClaimUnlocked(storage, kind, dl, pt)
		if rErr != nil {
			return rErr
		}
		if !found || claim.Authority != "deletion" {
			return nil
		}
		// An in-flight deletion freeze never TTL-expires (only chain reconciliation retires it); an
		// unexpired reservation likewise owns the slot.
		if claim.AttemptState == freezeAttemptBroadcastPending || now.Unix() < claim.ExpiresAtUnix {
			owns = true
		}
		return nil
	})
	return owns, err
}
