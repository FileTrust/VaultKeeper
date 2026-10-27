package main

// Finish sealed deletion successors without waiting for traffic.
//
// A deletion successor is frozen and proved on its own authority
// (standaloneDeletionProofFlag), deliberately outside the capacity-epoch
// reconciler -- retiring one there could strand a declared deletion between
// proof and confirmation. But nothing else ever picked an orphaned one up: the
// ordinary candidate lists are built from partitions that are DUE for a
// periodic proof, and a frozen deletion successor is not on that list.
//
// So the snapshot only progressed while delete traffic kept driving its
// lifecycle. Live on 2026-09-17: vk_4 held data-dl39-pt1 in state "queued"
// with its proof already generated, untouched from 03:49, its deadline nine
// hours past. It holds the partition's single frozen slot, so the keeper could
// not certify that partition, and admission stayed closed on a deadline that
// can never come back -- permanently, with no traffic able to reach it.
//
// A keeper must finish its own obligations whether or not anyone is talking to
// it. This sweep is that guarantee: every scan, any frozen standalone deletion
// successor still queued is proved and submitted on the daemon's own
// initiative. Expiry is not special-cased here -- provePartitionSnapshotCandidate
// already re-anchors a snapshot whose challenge window has passed and proves
// the same bytes again.

import (
	"errors"
	"log"
	"time"
)

// sweepPendingDeletionSuccessors proves every sealed deletion successor that is
// still waiting, and reports how many it attempted.
//
// Errors are logged, never returned upward: this is background catch-up, and a
// single unprovable partition must not stop the others or the caller's scan.
func sweepPendingDeletionSuccessors(
	storage string,
	deadlineCount, partitionMaxSectors int,
	partitionProverCmd, chainCmd string,
	chainTimestamp int64,
) int {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		log.Printf("[deletion-sweep] queue scan deferred: %v", err)
		return 0
	}

	attempted := 0
	for _, queue := range queues {
		frozen := queue.Frozen
		if frozen == nil {
			continue
		}
		if frozen.ProofEpochID&standaloneDeletionProofFlag == 0 {
			continue // capacity members are owned by the capacity reconciler
		}
		// Deliberately NOT restricted to "queued". A keeper restarted between
		// sending a submission and recording its result leaves the record in
		// "submitting" for ever, and the earlier version of this sweep skipped
		// exactly that state -- so the stranded record was never recovered.
		//
		// Live on 2026-09-17: vk_7 held data-dl44-pt1 in "submitting", untouched
		// for over six hours across a restart, while the chain showed that very
		// submission had SUCCEEDED (frozen exists=false, current proven=true at
		// the same version 5 and round 20713). Only the local record lagged, and
		// it kept the keeper closed on a deadline already in the past.
		//
		// The chain decides below what each state means; nothing is assumed from
		// the local label alone.
		if frozen.State != proofSnapshotStateQueued &&
			frozen.State != proofSnapshotStateSubmitting {
			continue // proving, sealed or frozen: an owner is actively on it
		}

		// Is there still anything to prove? The chain is the authority. A
		// successor whose frozen slot no longer exists there has already been
		// accepted and consumed -- its deletion authorization went with it, which
		// is why re-proving it returns "deletion successor not authorized" for
		// ever. Verified on vk_4's data-dl39-pt1 (2026-09-17): chain reported
		// frozen exists=false while current showed proven=true at the SAME
		// version 3 and round 20713 the local entry described. The work was done;
		// only the local record was left behind, holding the partition's single
		// frozen slot and keeping admission shut.
		//
		// Retiring it therefore loses nothing, and it is checked against the chain
		// every time rather than assumed.
		status, statusErr := frozenPartitionSnapshotStatusOnChain(chainCmd, frozen.Partition)
		if statusErr != nil {
			log.Printf("[deletion-sweep] dl=%d pt=%d chain status unavailable, retrying later: %v",
				frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex, statusErr)
			continue
		}
		// exists=false is the authoritative "already accepted" verdict, and it is
		// the same verdict whichever local state the record is in: there is no
		// frozen slot left to prove or submit against.
		if !status.Exists {
			log.Printf(
				"[deletion-sweep] retiring completed deletion successor dl=%d pt=%d "+
					"(round %d) -- chain holds no frozen snapshot, work already accepted",
				frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex, frozen.Round,
			)
			if err := advancePartitionProofSnapshot(storage, *frozen); err != nil {
				log.Printf("[deletion-sweep] dl=%d pt=%d retire deferred: %v",
					frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex, err)
			}
			continue
		}

		if frozen.State == proofSnapshotStateSubmitting {
			// The chain still holds this frozen slot, so a submission really is
			// outstanding. Its owner may be mid-flight right now; re-driving it
			// could submit the same proof twice.
			continue
		}

		attempted++
		log.Printf(
			"[deletion-sweep] finishing sealed deletion successor dl=%d pt=%d version=%d "+
				"(queued since %s) -- no delete traffic is required",
			frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex,
			frozen.ContentVersion, frozen.UpdatedAt,
		)

		err := provePartitionSnapshotCandidate(
			storage, frozen.Partition, frozen.ProofEpochID, frozen.Round,
			deadlineCount, partitionMaxSectors,
			partitionProverCmd, chainCmd,
			"data-urgent",
			time.Unix(frozen.DeadlineUnix, 0),
			chainTimestamp,
			true,  // allowPendingDeletion: this IS the deletion's own successor
			false, // requireCurrentContent: the sealed bytes are the subject, not live content
			"",
		)
		switch {
		case err == nil:
			log.Printf("[deletion-sweep] deletion successor dl=%d pt=%d proved",
				frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex)
		case errors.Is(err, ErrPartitionProofSnapshotReanchored):
			// Its challenge window had passed; it was re-anchored and will be
			// proved on the next scan. Ordinary, not a failure.
			log.Printf("[deletion-sweep] deletion successor dl=%d pt=%d re-anchored after an expired window",
				frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex)
		default:
			log.Printf("[deletion-sweep] deletion successor dl=%d pt=%d deferred: %v",
				frozen.Partition.DeadlineIndex, frozen.Partition.PartitionIndex, err)
		}
	}
	return attempted
}
