package main

// G.3C — the single production campaign router. The scheduler passes the complete typed
// decision; it never reduces campaign scope to a Boolean.

import (
	"fmt"
	"log"
	"strings"
	"time"
)

func queueAndBeginCapacityCampaign(
	storage string,
	storageCfg ServerConfig,
	clock ProofClockStatus,
	previous CapacityProofEpochStatus,
	currentPartitions []PartitionMeta,
	decision CapacityStartDecision,
) (CapacityProofEpochStatus, error) {
	if !decision.MayOpenCampaign() {
		return previous, fmt.Errorf("capacity campaign launch gate rejected decision: %s", decision.String())
	}
	switch decision.CampaignMode {
	case CampaignModeFullSweep:
		return queueAndBeginCapacityProofEpoch(
			storage, storageCfg, clock, previous, decision.FullSweepReason)
	case CampaignModeIncremental:
		return queueAndBeginCapacityIncrementalBatch(
			storage, storageCfg, clock, previous, currentPartitions, decision)
	default:
		return previous, fmt.Errorf("capacity campaign has no routable mode")
	}
}

// resolveIncrementalChunkPartitions maps the frozen plan identity to both the local immutable
// input and the contract's bytes32 partition key. During the G.2 transition, durable plans may
// contain either the canonical chain key or the stable kind/deadline/partition coordinate; both
// resolve to exactly one current registered identity and neither widens membership.
func resolveIncrementalChunkPartitions(
	chainCmd string,
	local []PartitionMeta,
	selectedKeys []string,
) ([]PartitionMeta, []string, error) {
	capacity, err := listActiveCapacityPartitionsOnChain(chainCmd)
	if err != nil {
		return nil, nil, err
	}
	data, err := listActiveDataPartitionsOnChain(chainCmd)
	if err != nil {
		return nil, nil, err
	}
	localByCoordinate := make(map[string]PartitionMeta, len(local))
	for _, partition := range local {
		coordinate := strings.ToLower(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex))
		localByCoordinate[coordinate] = partition
	}
	type resolved struct {
		partition PartitionMeta
		chainKey  string
	}
	byIdentity := map[string]resolved{}
	for _, registered := range append(capacity, data...) {
		kind := PartitionKindData
		if registered.PartitionKind == 2 {
			kind = PartitionKindCapacity
		}
		coordinate := strings.ToLower(epochPartitionKey(
			kind, registered.DeadlineIndex, registered.PartitionIndex))
		partition, ok := localByCoordinate[coordinate]
		if !ok || !registered.Active || strings.TrimSpace(registered.PartitionKey) == "" {
			continue
		}
		item := resolved{partition: partition, chainKey: registered.PartitionKey}
		byIdentity[coordinate] = item
		byIdentity[strings.ToLower(registered.PartitionKey)] = item
	}

	resolvedPartitions := make([]PartitionMeta, 0, len(selectedKeys))
	chainKeys := make([]string, 0, len(selectedKeys))
	seen := map[string]struct{}{}
	for _, selected := range selectedKeys {
		item, ok := byIdentity[strings.ToLower(strings.TrimSpace(selected))]
		if !ok {
			return nil, nil, fmt.Errorf("selected identity %q is not one exact current registered partition", selected)
		}
		key := strings.ToLower(item.chainKey)
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, fmt.Errorf("selected identity %q resolves to a duplicate partition", selected)
		}
		seen[key] = struct{}{}
		resolvedPartitions = append(resolvedPartitions, item.partition)
		chainKeys = append(chainKeys, item.chainKey)
	}
	if len(resolvedPartitions) == 0 {
		return nil, nil, fmt.Errorf("incremental selected set is empty")
	}
	return resolvedPartitions, chainKeys, nil
}

// reconcileOpenedCapacityBatchChunk repairs the narrow crash/partial-persist window after the
// contract accepted an incremental batch but before its durable chunk was marked opened. The
// immutable epoch journal and current chain identities must match exactly; count alone is never
// sufficient to bind an on-chain authority id to a local plan.
func reconcileOpenedCapacityBatchChunk(storage, chainCmd string, batchID uint64) error {
	if batchID&incrementalCapacityAuthorityFlag == 0 {
		return nil
	}
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil || !found {
		return err
	}
	if journal.EpochID != batchID {
		// This repair binds ONE opened chain batch to its own durable chunk. A
		// journal for a different epoch is simply not this batch's business, so
		// there is nothing here to repair.
		//
		// An OLDER journal is the superseded case: the chain has moved on, and
		// retireSupersededTerminalCapacityEpochJournal owns retiring it. Erroring
		// here instead blocked the whole status read, which deferred all proof
		// scheduling -- and that scheduling is what would have retired the stale
		// journal. Live on 2026-09-17: vk_3 logged
		//   "incremental batch ...388035 does not match durable epoch journal ...388017"
		// on every scan, proved nothing for hours, and stayed closed on
		// certified_capacity_insufficient with 3.5 MB unproven.
		//
		// A NEWER local journal is different: the local side believes in an epoch
		// the chain has not reached, which is a real inconsistency and still fails
		// closed.
		if journal.EpochID > batchID {
			return fmt.Errorf(
				"incremental batch %d is older than durable epoch journal %d",
				batchID, journal.EpochID)
		}
		return nil
	}
	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil || !found {
		return err
	}
	for _, chunk := range plan.Chunks {
		if chunk.BatchID == batchID {
			if !chunk.Opened || chunk.Done {
				return fmt.Errorf("incremental batch %d has an invalid durable chunk binding", batchID)
			}
			return nil
		}
	}

	registered := map[string]string{}
	capacity, err := listActiveCapacityPartitionsOnChain(chainCmd)
	if err != nil {
		return err
	}
	data, err := listActiveDataPartitionsOnChain(chainCmd)
	if err != nil {
		return err
	}
	for _, item := range append(capacity, data...) {
		kind := PartitionKindData
		if item.PartitionKind == 2 {
			kind = PartitionKindCapacity
		}
		coordinate := strings.ToLower(epochPartitionKey(kind, item.DeadlineIndex, item.PartitionIndex))
		registered[strings.ToLower(strings.TrimSpace(item.PartitionKey))] = coordinate
	}
	want := make(map[string]struct{}, len(journal.Members))
	for _, member := range journal.Members {
		want[strings.ToLower(epochPartitionKey(
			member.PartitionKind, member.DeadlineIndex, member.PartitionIndex))] = struct{}{}
	}
	matchedIndex := -1
	for _, chunk := range plan.Chunks {
		if chunk.Opened || chunk.Done || len(chunk.Keys) != len(want) {
			continue
		}
		seen := map[string]struct{}{}
		matches := true
		for _, raw := range chunk.Keys {
			key := strings.ToLower(strings.TrimSpace(raw))
			coordinate := key
			if mapped, ok := registered[key]; ok {
				coordinate = mapped
			}
			if _, ok := want[coordinate]; !ok {
				matches = false
				break
			}
			seen[coordinate] = struct{}{}
		}
		if matches && len(seen) == len(want) {
			if matchedIndex >= 0 {
				return fmt.Errorf("incremental batch %d matches more than one pending chunk", batchID)
			}
			matchedIndex = chunk.Index
		}
	}
	if matchedIndex < 0 {
		return fmt.Errorf("incremental batch %d has no exact durable chunk match", batchID)
	}
	return markCapacityBatchChunkOpened(storage, matchedIndex, batchID)
}

// recoverOpenedIncrementalBatchJournal closes the transaction-first persistence window for an
// incremental campaign. openBatch must run before the chain-assigned batch id is known, so a
// competing standalone-deletion freeze can win between the on-chain open and local snapshot
// persistence. The opened chunk is the durable exact-set intent for that window. Once the other
// authority releases the slot, reconstruct the batch's frozen local inputs from that exact chunk;
// ordinary journal adoption then binds them to the already-open chain campaign.
//
// This is deliberately narrower than legacy adoption: no accepted member may exist, exactly one
// unfinished chunk must already be bound to this batch, and its exact keys must still resolve to
// the chain's active registrations. A cross-authority conflict is returned unchanged and retried;
// no snapshot is rebound and no chain transaction runs while the coordination lock is held.
func recoverOpenedIncrementalBatchJournal(
	storage, chainCmd string,
	status CapacityProofEpochStatus,
	currentPartitions []PartitionMeta,
) (bool, error) {
	if !status.Active || status.ProofEpochID&incrementalCapacityAuthorityFlag == 0 {
		return false, nil
	}
	if _, found, err := readCapacityEpochJournal(storage); err != nil || found {
		return false, err
	}
	if status.ProvenPartitions != 0 || status.ExpectedPartitions == 0 {
		return false, fmt.Errorf(
			"incremental batch %d missing its journal after accepting %d/%d members",
			status.ProofEpochID, status.ProvenPartitions, status.ExpectedPartitions)
	}
	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil || !found {
		return false, err
	}
	var bound *capacityBatchChunk
	for index := range plan.Chunks {
		chunk := &plan.Chunks[index]
		if chunk.Opened && !chunk.Done && chunk.BatchID == status.ProofEpochID {
			if bound != nil {
				return false, fmt.Errorf(
					"incremental batch %d owns more than one unfinished chunk", status.ProofEpochID)
			}
			bound = chunk
		}
	}
	if bound == nil || len(bound.Keys) != int(status.ExpectedPartitions) {
		return false, fmt.Errorf(
			"incremental batch %d has no exact opened chunk of %d members",
			status.ProofEpochID, status.ExpectedPartitions)
	}
	selected, _, err := resolveIncrementalChunkPartitions(chainCmd, currentPartitions, bound.Keys)
	if err != nil {
		return false, err
	}
	if len(selected) != int(status.ExpectedPartitions) {
		return false, fmt.Errorf(
			"incremental batch %d recovery resolved %d/%d members",
			status.ProofEpochID, len(selected), status.ExpectedPartitions)
	}
	err = withCapacityCoordinationLock(storage, func() error {
		for _, partition := range selected {
			if _, destructive, queueErr := queuePartitionProofSnapshot(
				storage, partition, status.ProofEpochID, status.TargetRound, time.Time{},
			); queueErr != nil {
				return queueErr
			} else if destructive {
				return fmt.Errorf("incremental recovery encountered an unretained generation")
			}
		}
		journal, journalErr := newCapacityEpochJournal(
			storage, status.ProofEpochID, status.TargetRound, status, selected)
		if journalErr != nil {
			return journalErr
		}
		journal.State = capacityEpochStateActive
		applyCapacityEpochChainStatus(&journal, status)
		if createErr := createCapacityEpochJournal(storage, journal); createErr != nil {
			return createErr
		}
		return reconcileCapacityMutationEpochUnlocked(storage, journal, journal.State)
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func queueAndBeginCapacityIncrementalBatch(
	storage string,
	storageCfg ServerConfig,
	clock ProofClockStatus,
	previous CapacityProofEpochStatus,
	currentPartitions []PartitionMeta,
	decision CapacityStartDecision,
) (CapacityProofEpochStatus, error) {
	if decision.CampaignMode != CampaignModeIncremental || !decision.MayOpenCampaign() {
		return previous, fmt.Errorf("incremental opener rejected non-incremental decision")
	}
	if err := ensureProofArtifactWritesEnabled(); err != nil {
		return previous, err
	}
	plan, ok, err := readCapacityBatchChunkPlan(storage)
	if err != nil || !ok {
		return previous, fmt.Errorf("read exact incremental chunk: %w", err)
	}
	chunk, ok := plan.nextPendingChunk()
	if !ok || len(chunk.Keys) == 0 {
		return previous, fmt.Errorf("incremental decision has no pending exact chunk")
	}
	selected, chainKeys, err := resolveIncrementalChunkPartitions(
		storageCfg.ChainProofCmd, currentPartitions, chunk.Keys)
	if err != nil {
		return previous, err
	}
	if len(selected) != decision.Estimate.SelectedPartitionCount {
		return previous, fmt.Errorf("incremental selected count changed before open: plan=%d decision=%d",
			len(selected), decision.Estimate.SelectedPartitionCount)
	}

	batch, tx, err := openCapacityIncrementalBatchOnChain(
		storageCfg.ChainProofCmd, clock.CurrentRound, chainKeys)
	if err != nil {
		return previous, err
	}
	// The chain authority now exists. Bind it before any later local persistence can fail, so
	// restart recovery never mistakes this exact chunk for unopened work.
	if err := markCapacityBatchChunkOpened(storage, chunk.Index, batch.BatchID); err != nil {
		return previous, fmt.Errorf("persist opened incremental chunk %d: %w", batch.BatchID, err)
	}
	status := previous
	status.ProofEpochID = batch.BatchID
	status.TargetRound = batch.TargetRound
	status.CutoffNonce = batch.CutoffNonce
	status.ExpectedPartitions = batch.SelectedPartitions
	status.ProvenPartitions = batch.AcceptedPartitions
	status.ExpectedBytes = batch.SelectedBytes
	status.Active = batch.Active
	status.Invalidated = false

	// The chain campaign exists now. Freeze exactly its selected local inputs and persist the
	// authority journal; no whole-manifest enumeration is used here.
	err = withCapacityCoordinationLock(storage, func() error {
		for _, partition := range selected {
			if _, destructive, queueErr := queuePartitionProofSnapshot(
				storage, partition, batch.BatchID, clock.CurrentRound, time.Time{},
			); queueErr != nil {
				return queueErr
			} else if destructive {
				return fmt.Errorf("incremental cutoff encountered an unretained generation")
			}
		}
		journal, journalErr := newCapacityEpochJournal(
			storage, batch.BatchID, clock.CurrentRound, previous, selected)
		if journalErr != nil {
			return journalErr
		}
		journal.State = capacityEpochStateActive
		journal.BeginTx = tx
		applyCapacityEpochChainStatus(&journal, status)
		if createErr := createCapacityEpochJournal(storage, journal); createErr != nil {
			return createErr
		}
		return reconcileCapacityMutationEpochUnlocked(storage, journal, journal.State)
	})
	if err != nil {
		return previous, fmt.Errorf("persist opened incremental campaign %d: %w", batch.BatchID, err)
	}
	log.Printf("[capacity-batch] opened incremental batch=%d round=%d selected=%d bytes=%d trigger=%s tx=%s",
		batch.BatchID, clock.CurrentRound, len(selected), batch.SelectedBytes,
		decision.BatchTriggerReason, tx)
	// A campaign opening is what an operator needs to see while admission is
	// closed: it is the work that will reopen it.
	logCapacityMilestone("proving %d partition(s), %s -- admission stays closed while this runs",
		len(selected), humanBytes(int64(batch.SelectedBytes)))
	return status, nil
}
