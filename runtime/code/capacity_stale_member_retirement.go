package main

// Bounded retirement of frozen incremental chunk members that have become
// permanently non-current.
//
// THE DEFECT THIS FIXES (proven live, D.3-VK 3-VK smoke, VK2 2026-08-14)
//
//	pendingCapacityBatchCandidates only admits a candidate whose coordinate is
//	present in the block-pinned registered manifest (capacity_incremental_production.go:230).
//	So every frozen chunk member WAS current at freeze time. But a data partition
//	coordinate legitimately ceases to be current when its last sector leaves it —
//	the same transition that file documents. The frozen chunk is then bound to a
//	coordinate that can never resolve again, liveSelectedWorkEstimateForChunk sets
//	PlanValid=false, capacity_epoch_batch.go's PlanValid gate fail-closes with
//	err=nil (so nothing is logged), and ensureCapacityIncrementalPlan never
//	recomputes an existing plan. Result: capacity work stops permanently and the
//	hard mutation lag is breached in silence. VK2 reached 1855 s against an 1800 s
//	limit with 53 pending mutations and zero incremental batches.
//
// THE INVARIANT
//
//	A frozen incremental chunk must never remain permanently bound to an identity
//	that can no longer become current.
//
// WHY THIS IS SAFE, AND NOT "IGNORING UNKNOWN IDENTITIES"
//
//   - A member is retired ONLY when it is absent from the SAME authoritative
//     registered-partition snapshot that candidate eligibility already uses. It is
//     not guessed and not skipped: absence there is the definition of non-current.
//   - Retirement requires the member to be observed unresolvable CONTINUOUSLY for
//     capacityStaleMemberGrace. A coordinate that becomes resolvable again — the
//     ordinary transient registration race — clears its observation and is never
//     retired. This preserves legitimately pending work.
//   - A chunk that is OPEN on chain (Opened && !Done) is NEVER modified. An opened
//     chunk has a real on-chain obligation, so it keeps failing closed exactly as
//     before. PlanValid fail-closed safety is untouched for that case.
//   - Retirement is durable, logged and auditable; it never invents, substitutes or
//     proves an identity, and never clears a recovery state.
//
// The grace is far below the hard mutation lag, so a wedge is escaped long before
// the lag can be breached.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// capacityStaleMemberGrace is how long a frozen member must be CONTINUOUSLY absent
// from the registered manifest before it is retired. It must stay well below
// DefaultCapacityProofMaxOldestMutationSeconds (1800 s) so bounded progress is
// guaranteed before the hard lag, while leaving ample room for a transient
// registration race to resolve.
const capacityStaleMemberGrace = 5 * time.Minute

const capacityStaleMemberStateVersion = 1

type capacityStaleMemberState struct {
	Version int `json:"version"`
	// FirstUnresolvedUnix maps a chunk member coordinate to the first time it was
	// observed absent from the registered manifest.
	FirstUnresolvedUnix map[string]int64 `json:"firstUnresolvedUnix,omitempty"`
}

func capacityStaleMemberStatePath(storage string) string {
	return filepath.Join(storage, "capacity-stale-members.json")
}

func readCapacityStaleMemberState(storage string) (capacityStaleMemberState, error) {
	state := capacityStaleMemberState{
		Version:             capacityStaleMemberStateVersion,
		FirstUnresolvedUnix: map[string]int64{},
	}
	raw, err := os.ReadFile(capacityStaleMemberStatePath(storage))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, err
	}
	var stored capacityStaleMemberState
	if err := json.Unmarshal(raw, &stored); err != nil {
		// Unreadable observation bookkeeping is not chain state and must never
		// widen or narrow an obligation. Start the observation window again.
		return state, nil
	}
	if stored.FirstUnresolvedUnix != nil {
		state.FirstUnresolvedUnix = stored.FirstUnresolvedUnix
	}
	return state, nil
}

func writeCapacityStaleMemberState(storage string, state capacityStaleMemberState) error {
	state.Version = capacityStaleMemberStateVersion
	if len(state.FirstUnresolvedUnix) == 0 {
		if err := os.Remove(capacityStaleMemberStatePath(storage)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(capacityStaleMemberStatePath(storage), append(raw, '\n'), 0o600)
}

// currentPartitionKeySet builds the authoritative current-coordinate set from the
// same registered partition metadata candidate eligibility uses.
func currentPartitionKeySet(partitions []PartitionMeta) map[string]struct{} {
	current := make(map[string]struct{}, len(partitions))
	for _, partition := range partitions {
		key := strings.ToLower(strings.TrimSpace(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)))
		if key != "" {
			current[key] = struct{}{}
		}
	}
	return current
}

// retireStaleChunkPlanMembers gives a wedged plan a bounded escape.
//
// It returns the coordinates retired by this call. A nil/empty result means the
// plan was left exactly as it was, which is the overwhelmingly common case.
func retireStaleChunkPlanMembers(
	storage string, partitions []PartitionMeta, now time.Time,
) ([]string, error) {
	var retired []string
	err := withCapacityBatchChunkLock(storage, func() error {
		plan, found, err := readCapacityBatchChunkPlan(storage)
		if err != nil {
			// An unreadable plan is chain-state-unreadable and already fails closed
			// on the normal path. Never retire on the strength of a bad read.
			return nil
		}
		if !found {
			// No plan: drop any stale bookkeeping so a future plan starts clean.
			return writeCapacityStaleMemberState(storage, capacityStaleMemberState{})
		}
		current := currentPartitionKeySet(partitions)
		if len(current) == 0 {
			// An empty manifest is an unreadable/blank observation, not evidence
			// that every member retired. Never retire against it.
			return nil
		}

		state, err := readCapacityStaleMemberState(storage)
		if err != nil {
			return err
		}

		// Observe: which members of a NOT-open chunk are currently unresolvable?
		unresolvedNow := map[string]struct{}{}
		for _, chunk := range plan.Chunks {
			if chunk.Done {
				continue
			}
			if chunk.Opened {
				// Real on-chain obligation. Never retire, never observe: this chunk
				// keeps failing closed exactly as it does today.
				continue
			}
			for _, key := range chunk.Keys {
				if _, ok := current[strings.ToLower(strings.TrimSpace(key))]; !ok {
					unresolvedNow[key] = struct{}{}
				}
			}
		}

		// A coordinate that resolved again clears its window: the transient
		// registration race must never cost legitimately pending work.
		for key := range state.FirstUnresolvedUnix {
			if _, still := unresolvedNow[key]; !still {
				delete(state.FirstUnresolvedUnix, key)
			}
		}
		for key := range unresolvedNow {
			if _, seen := state.FirstUnresolvedUnix[key]; !seen {
				state.FirstUnresolvedUnix[key] = now.Unix()
				log.Printf("[capacity-batch] frozen member %q is not in the registered "+
					"manifest; starting %s retirement observation", key,
					capacityStaleMemberGrace)
			}
		}

		// Retire only what has been continuously unresolvable for the whole grace.
		retiring := map[string]struct{}{}
		for key, firstUnix := range state.FirstUnresolvedUnix {
			if now.Sub(time.Unix(firstUnix, 0)) >= capacityStaleMemberGrace {
				retiring[key] = struct{}{}
			}
		}
		if len(retiring) == 0 {
			return writeCapacityStaleMemberState(storage, state)
		}

		updated, removed := planWithoutMembers(plan, retiring)
		if len(removed) == 0 {
			return writeCapacityStaleMemberState(storage, state)
		}
		sort.Strings(removed)
		for _, key := range removed {
			delete(state.FirstUnresolvedUnix, key)
		}

		if len(updated.Chunks) == 0 {
			// Every remaining obligation retired. Clearing the plan is the bounded
			// escape: the next pass recomputes membership from current candidates.
			if err := clearCapacityBatchChunkPlan(storage); err != nil {
				return err
			}
			log.Printf("[capacity-batch] retired %d permanently non-current frozen "+
				"member(s) [%s]; no obligations remained, plan cleared for reselection",
				len(removed), strings.Join(removed, ","))
		} else {
			if !validCapacityBatchChunkPlan(updated) {
				return fmt.Errorf(
					"refusing to write an invalid plan after retiring %v", removed)
			}
			if err := writeCapacityBatchChunkPlan(storage, updated); err != nil {
				return err
			}
			log.Printf("[capacity-batch] retired %d permanently non-current frozen "+
				"member(s) [%s]; %d chunk(s) remain",
				len(removed), strings.Join(removed, ","), len(updated.Chunks))
		}
		retired = removed
		return writeCapacityStaleMemberState(storage, state)
	})
	return retired, err
}

// planWithoutMembers removes the given coordinates from every chunk that is not an
// open on-chain obligation, drops chunks left with no members, re-indexes the
// survivors and prunes urgency provenance for removed coordinates.
func planWithoutMembers(
	plan capacityBatchChunkPlan, remove map[string]struct{},
) (capacityBatchChunkPlan, []string) {
	var removed []string
	updated := plan
	updated.Chunks = nil
	for _, chunk := range plan.Chunks {
		if chunk.Done || chunk.Opened {
			// Preserve completed history and open obligations untouched.
			chunk.Index = len(updated.Chunks)
			updated.Chunks = append(updated.Chunks, chunk)
			continue
		}
		kept := chunk.Keys[:0:0]
		for _, key := range chunk.Keys {
			if _, drop := remove[key]; drop {
				removed = append(removed, key)
				continue
			}
			kept = append(kept, key)
		}
		if len(kept) == 0 {
			// The whole chunk retired. It was never opened, so there is no on-chain
			// obligation to close: it simply ceases to exist.
			continue
		}
		chunk.Keys = kept
		chunk.Index = len(updated.Chunks)
		updated.Chunks = append(updated.Chunks, chunk)
	}
	if len(removed) == 0 {
		return plan, nil
	}
	survivors := map[string]struct{}{}
	for _, chunk := range updated.Chunks {
		for _, key := range chunk.Keys {
			survivors[key] = struct{}{}
		}
	}
	var urgency []string
	for _, key := range plan.UrgencyKeys {
		if _, alive := survivors[strings.ToLower(strings.TrimSpace(key))]; alive {
			urgency = append(urgency, key)
		}
	}
	updated.UrgencyKeys = urgency
	return updated, removed
}
