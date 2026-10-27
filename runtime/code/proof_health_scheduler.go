package main

import "fmt"

// reconcilePartitionProofHealthSnapshot refreshes every local proof obligation
// from one pinned blockchain block. Existing failure evidence is never erased
// merely because local files changed: until the corresponding on-chain
// partition is updated/deactivated, that old obligation is still enforceable.
// Successful deletion/cleanup and exact-content proof paths clear their records
// explicitly. This ordering prevents an RPC outage after a local mutation from
// briefly reopening admission against stale chain state.
func reconcilePartitionProofHealthSnapshot(
	storage, chainCmd string,
	partitions []PartitionMeta,
	blockNumber uint64,
) error {
	if len(partitions) == 0 {
		return nil
	}
	snapshot, err := partitionProofHealthSnapshotOnChain(chainCmd, partitions, blockNumber)
	if err != nil {
		return fmt.Errorf("read pinned proof-health snapshot: %w", err)
	}
	policy := ProofHealthPolicy{RecurringProofStalenessRounds: snapshot.StalenessThreshold}
	for i, partition := range partitions {
		if err := updatePartitionProofHealthWithPolicy(storage, partition, snapshot.Statuses[i], policy); err != nil {
			return fmt.Errorf(
				"update proof health %s dl%d-pt%d: %w",
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex, err,
			)
		}
	}
	return nil
}
