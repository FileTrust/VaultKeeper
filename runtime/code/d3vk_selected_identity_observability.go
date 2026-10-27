package main

// D.3-VK OBSERVABILITY ONLY.
//
// When a durable incremental chunk holds a member key that is not present in the
// currently registered partition manifest, capacity_epoch_batch.go sets
// PlanValid=false and fail-closes with err=nil. The caller
// (proof_scheduler.go:2783) only logs when readinessErr != nil, so the VK goes
// completely silent while no incremental capacity batch can ever open.
//
// This file adds NO semantic change whatsoever: it neither alters the decision,
// the plan, the manifest, nor any durable state. It only names the exact
// unresolved identities so the condition is diagnosable from the daemon log.

import (
	"log"
	"sort"
	"strings"
)

// logUnresolvedSelectedIdentities emits the exact keys that could not be resolved,
// the size of the resolvable manifest, and the chunk membership that produced them.
func logUnresolvedSelectedIdentities(
	chunk capacityBatchChunk,
	unresolvedChunkKeys []string,
	unresolvedAheadKeys []string,
	shapeByKey map[string]ProofShapeKey,
	plan capacityBatchChunkPlan,
) {
	known := make([]string, 0, len(shapeByKey))
	for key := range shapeByKey {
		known = append(known, key)
	}
	sort.Strings(known)
	sort.Strings(unresolvedChunkKeys)
	sort.Strings(unresolvedAheadKeys)

	members := make([]string, 0, len(chunk.Keys))
	for _, key := range chunk.Keys {
		members = append(members, key)
	}

	log.Printf("[capacity-selection] PLAN INVALID: selected identities are not fully "+
		"known chunkIndex=%d chunkMembers=%d unresolvedInChunk=%d unresolvedAhead=%d "+
		"manifestKnownKeys=%d planCandidateKeys=%d",
		chunk.Index, len(chunk.Keys), len(unresolvedChunkKeys),
		len(unresolvedAheadKeys), len(shapeByKey), len(plan.allKeys()))
	log.Printf("[capacity-selection] unresolvedChunkKeys=[%s]",
		strings.Join(unresolvedChunkKeys, ","))
	if len(unresolvedAheadKeys) > 0 {
		log.Printf("[capacity-selection] unresolvedAheadKeys=[%s]",
			strings.Join(unresolvedAheadKeys, ","))
	}
	log.Printf("[capacity-selection] chunkMemberKeys=[%s]", strings.Join(members, ","))
	log.Printf("[capacity-selection] manifestKnownKeys=[%s]", strings.Join(known, ","))
}
