package main

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

const expiredGCJournalVersion = 1

const (
	expiredGCPhasePlanned      = "planned"
	expiredGCPhaseLocalRemoved = "local_removed"
)

// expiredGCRecord is deliberately durable.  Removing an expired sector and
// changing/deactivating its on-chain partition are separate operations; a VK
// crash between them must not make the chain reconciliation disappear.
type expiredGCRecord struct {
	Version                  int      `json:"version"`
	SectorID                 string   `json:"sectorId"`
	SectorRoot               string   `json:"sectorRoot,omitempty"`
	PieceRoots               []string `json:"pieceRoots,omitempty"`
	DeadlineIndex            int      `json:"deadlineIndex"`
	PartitionIndex           int      `json:"partitionIndex"`
	PartitionKind            string   `json:"partitionKind"`
	Expiration               int64    `json:"expiration"`
	Phase                    string   `json:"phase"`
	CapacityMutationSequence uint64   `json:"capacityMutationSequence,omitempty"`
	CreatedAt                string   `json:"createdAt"`
	UpdatedAt                string   `json:"updatedAt"`
}

type expiredGCPartition struct {
	DeadlineIndex  int
	PartitionIndex int
	PartitionKind  string
}

type expiredGCResult struct {
	SectorsRemoved int
	PiecesRemoved  int
	Affected       []expiredGCPartition
	Failures       int
}

func expiredGCJournalDir(storage string) string {
	return filepath.Join(storage, "lifecycle", "expired-gc")
}

func expiredGCJournalPath(storage, sectorID string) string {
	return filepath.Join(expiredGCJournalDir(storage), lifecycleOperationID(sectorID)+".json")
}

func writeExpiredGCRecord(storage string, record expiredGCRecord) error {
	if strings.TrimSpace(record.SectorID) == "" {
		return fmt.Errorf("expired gc journal: empty sector id")
	}
	record.Version = expiredGCJournalVersion
	now := nowRFC3339()
	if record.CreatedAt == "" {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(expiredGCJournalPath(storage, record.SectorID), payload, 0600)
}

func removeExpiredGCRecord(storage, sectorID string) error {
	err := os.Remove(expiredGCJournalPath(storage, sectorID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func listExpiredGCRecords(storage string) ([]expiredGCRecord, error) {
	entries, err := os.ReadDir(expiredGCJournalDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]expiredGCRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(expiredGCJournalDir(storage), entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		var record expiredGCRecord
		if err := json.Unmarshal(payload, &record); err != nil {
			return nil, fmt.Errorf("read expired gc journal %s: %w", entry.Name(), err)
		}
		if record.Version != expiredGCJournalVersion || strings.TrimSpace(record.SectorID) == "" {
			return nil, fmt.Errorf("read expired gc journal %s: unsupported or incomplete record", entry.Name())
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].SectorID < records[j].SectorID })
	return records, nil
}

func expiredGCRecordForSector(sector SectorMeta) expiredGCRecord {
	return expiredGCRecord{
		Version:        expiredGCJournalVersion,
		SectorID:       sector.SectorID,
		SectorRoot:     sector.SectorRoot,
		PieceRoots:     append([]string(nil), sector.PieceRoots...),
		DeadlineIndex:  sector.DeadlineIndex,
		PartitionIndex: sector.PartitionIndex,
		PartitionKind:  partitionKindForSector(sector),
		Expiration:     sector.Expiration,
		Phase:          expiredGCPhasePlanned,
	}
}

func sameRootSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Slice(aa, func(i, j int) bool { return normalizeRoot(aa[i]) < normalizeRoot(aa[j]) })
	sort.Slice(bb, func(i, j int) bool { return normalizeRoot(bb[i]) < normalizeRoot(bb[j]) })
	for i := range aa {
		if !sameRoot(aa[i], bb[i]) {
			return false
		}
	}
	return true
}

func sortedUniqueRoots(roots []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		root = normalizeRoot(root)
		if root == "0x" || seen[root] {
			continue
		}
		seen[root] = true
		out = append(out, root)
	}
	sort.Strings(out)
	return out
}

func relevantDeletionCommitments(storage, sectorID string, roots []string) ([]string, error) {
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return nil, err
	}
	wantedRoots := map[string]bool{}
	for _, root := range roots {
		wantedRoots[normalizeRoot(root)] = true
	}
	seen := map[string]bool{}
	var commitments []string
	for _, operation := range operations {
		if operation.CommitmentHash == "" {
			continue
		}
		if operation.SectorID != sectorID && !wantedRoots[normalizeRoot(operation.PieceRoot)] {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(operation.CommitmentHash))
		if seen[key] {
			continue
		}
		seen[key] = true
		commitments = append(commitments, operation.CommitmentHash)
	}
	sort.Slice(commitments, func(i, j int) bool {
		return strings.ToLower(commitments[i]) < strings.ToLower(commitments[j])
	})
	return commitments, nil
}

func acquireLifecycleLockSet(storage, sectorID string, roots []string) ([]*lifecycleOperationLock, error) {
	locks := make([]*lifecycleOperationLock, 0, len(roots)+2)
	release := func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Release()
		}
	}

	// Store operations use the piece root as their durable lock key. Holding
	// these locks stops a retry from moving/reusing bytes while GC checks all
	// current sector references.
	for _, root := range sortedUniqueRoots(roots) {
		lock, err := acquireLifecycleOperationLock(storage, "store", root)
		if err != nil {
			release()
			return nil, err
		}
		locks = append(locks, lock)
	}
	commitments, err := relevantDeletionCommitments(storage, sectorID, roots)
	if err != nil {
		release()
		return nil, err
	}
	for _, commitment := range commitments {
		lock, err := acquireLifecycleOperationLock(storage, "delete", commitment)
		if err != nil {
			release()
			return nil, err
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

func releaseLifecycleLockSet(locks []*lifecycleOperationLock) {
	for i := len(locks) - 1; i >= 0; i-- {
		locks[i].Release()
	}
}

func readSectorIfPresent(storage, sectorID string) (SectorMeta, bool, error) {
	sector, err := readSector(storage, sectorID)
	if os.IsNotExist(err) {
		return SectorMeta{}, false, nil
	}
	if err != nil {
		return SectorMeta{}, false, err
	}
	return sector, true, nil
}

func pieceReferencedByLiveSector(storage, pieceRoot, excludingSectorID string, chainTimestamp int64) (bool, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return false, err
	}
	for _, sector := range sectors {
		if sector.SectorID == excludingSectorID || sector.Status == "deleted" ||
			sector.SectorBlockCount <= 0 || sector.Expiration <= chainTimestamp {
			continue
		}
		for _, root := range sector.PieceRoots {
			if sameRoot(root, pieceRoot) {
				return true, nil
			}
		}
	}
	return false, nil
}

func removeSectorAliasIfOwned(path, sectorID string) error {
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var indexed SectorMeta
	if json.Unmarshal(payload, &indexed) != nil || indexed.SectorID != sectorID {
		return nil
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// expireSectorLocally performs only filesystem state changes. No RPC is made
// while its lifecycle/capacity/partition locks are held. The caller later
// reconciles the durable journal with the chain.
func expireSectorLocally(storage string, candidate expiredGCRecord, chainTimestamp int64, logger *log.Logger) (expiredGCRecord, bool, int, error) {
	gcLock, err := acquireLifecycleOperationLock(storage, "expired-gc", candidate.SectorID)
	if err != nil {
		return candidate, false, 0, err
	}
	defer gcLock.Release()

	sector, found, err := readSectorIfPresent(storage, candidate.SectorID)
	if err != nil {
		return candidate, false, 0, err
	}
	if found {
		// Recreate the candidate from current durable state. A host-time scan may
		// be stale; only the supplied chain timestamp is authoritative.
		if sector.Expiration > chainTimestamp {
			_ = removeExpiredGCRecord(storage, candidate.SectorID)
			return candidate, false, 0, nil
		}
		candidate = expiredGCRecordForSector(sector)
	}
	if candidate.Expiration <= 0 || candidate.Expiration > chainTimestamp {
		return candidate, false, 0, nil
	}
	if candidate.PartitionKind == "" {
		candidate.PartitionKind = PartitionKindData
	}
	if candidate.Phase == "" {
		candidate.Phase = expiredGCPhasePlanned
	}
	if err := writeExpiredGCRecord(storage, candidate); err != nil {
		return candidate, false, 0, fmt.Errorf("persist gc plan: %w", err)
	}

	// A capacity rebuild changes capacity-sector files directly. Its build lock
	// is local-only and is always released before chain reconciliation.
	var capacityBuildLock *os.File
	if candidate.PartitionKind == PartitionKindCapacity {
		capacityBuildLock, err = acquireCapacityBuildLock(storage)
		if err != nil {
			return candidate, false, 0, err
		}
		defer releaseCapacityBuildLock(capacityBuildLock)
	}

	lifecycleLocks, err := acquireLifecycleLockSet(storage, candidate.SectorID, candidate.PieceRoots)
	if err != nil {
		return candidate, false, 0, err
	}
	defer releaseLifecycleLockSet(lifecycleLocks)

	mutationOperationID := fmt.Sprintf(
		"expired-sector-gc:%s:%s:%d", candidate.SectorID, candidate.SectorRoot, candidate.Expiration,
	)
	mutation, err := beginCapacityMutationOperation(storage, mutationOperationID, "expired_sector_gc")
	if err != nil {
		return candidate, false, 0, err
	}
	defer mutation.Release()
	candidate.CapacityMutationSequence = mutation.JournalSequence()
	if err := writeExpiredGCRecord(storage, candidate); err != nil {
		_ = mutation.Abandon()
		return candidate, false, 0, err
	}

	storeCapacityMu.Lock()
	defer storeCapacityMu.Unlock()
	partitionLock, err := acquirePartitionLifecycleLock(storage, candidate.DeadlineIndex, candidate.PartitionIndex)
	if err != nil {
		return candidate, false, 0, err
	}
	defer partitionLock.Release()
	if candidate.PartitionKind == PartitionKindData {
		pendingDeletion, pendingErr := partitionHasPendingDeletion(
			storage, candidate.DeadlineIndex, candidate.PartitionIndex,
		)
		if pendingErr != nil {
			_ = mutation.Abandon()
			return candidate, false, 0, fmt.Errorf("inspect deletion owner before gc: %w", pendingErr)
		}
		if pendingDeletion {
			// The deletion journal owns one exact post-delete successor until its
			// proof and confirmation complete. Expiring any sector in the same
			// partition would create a different successor, even when it is not the
			// sector named by the deletion.
			_ = mutation.Abandon()
			return candidate, false, 0, nil
		}
	}

	// Re-read after every lock is held. Store/delete/proof work may have won the
	// race while the GC worker waited.
	sector, found, err = readSectorIfPresent(storage, candidate.SectorID)
	if err != nil {
		return candidate, false, 0, err
	}
	if found {
		if sector.Expiration > chainTimestamp {
			_ = mutation.Abandon()
			_ = removeExpiredGCRecord(storage, candidate.SectorID)
			return candidate, false, 0, nil
		}
		if !sameRootSet(sector.PieceRoots, candidate.PieceRoots) {
			// A store completed before the partition lock. Do not touch an unlocked
			// piece; the next pass will acquire the new complete lock set.
			return candidate, false, 0, fmt.Errorf("sector %s changed while gc locks were acquired; retrying safely", candidate.SectorID)
		}
		candidate = expiredGCRecordForSector(sector)
		candidate.Phase = expiredGCPhasePlanned
		candidate.CapacityMutationSequence = mutation.JournalSequence()
		if err := writeExpiredGCRecord(storage, candidate); err != nil {
			return candidate, false, 0, err
		}

		if sector.Status != "deleted" {
			priorSector := sector
			sector.Status = "deleted"
			sector.UpdatedAt = nowRFC3339()
			if err := mutation.PrepareSectorTransition(
				capacityMutationStateForSector(priorSector, true),
				capacityMutationStateForSector(sector, false),
			); err != nil {
				return candidate, false, 0, err
			}
			if err := writeSector(storage, sector); err != nil {
				return candidate, false, 0, fmt.Errorf("mark expired sector deleted: %w", err)
			}
		}
	}

	piecesRemoved := 0
	for _, pieceRoot := range candidate.PieceRoots {
		live, err := pieceReferencedByLiveSector(storage, pieceRoot, candidate.SectorID, chainTimestamp)
		if err != nil {
			return candidate, false, piecesRemoved, err
		}
		meta, metaErr := readMeta(storage, pieceRoot)
		if metaErr != nil && !os.IsNotExist(metaErr) {
			return candidate, false, piecesRemoved, metaErr
		}
		if !live && metaErr == nil && meta.SectorID != "" && meta.SectorID != candidate.SectorID {
			owner, ownerFound, ownerErr := readSectorIfPresent(storage, meta.SectorID)
			if ownerErr != nil {
				return candidate, false, piecesRemoved, ownerErr
			}
			live = ownerFound && owner.Status != "deleted" && owner.SectorBlockCount > 0 && owner.Expiration > chainTimestamp
		}
		if live {
			logger.Printf("[gc] preserving shared piece referenced by a live sector pieceRoot=%s expiredSector=%s",
				truncate(pieceRoot, 18), truncate(candidate.SectorID, 18))
			continue
		}
		removed := false
		if err := os.Remove(piecePath(storage, pieceRoot)); err == nil {
			removed = true
		} else if !os.IsNotExist(err) {
			return candidate, false, piecesRemoved, err
		}
		if metaErr == nil {
			if err := os.Remove(metaPath(storage, pieceRoot)); err == nil {
				removed = true
			} else if !os.IsNotExist(err) {
				return candidate, false, piecesRemoved, err
			}
		} else if os.IsNotExist(metaErr) {
			// already removed: idempotent success
		} else {
			return candidate, false, piecesRemoved, metaErr
		}
		if removed {
			piecesRemoved++
		}
	}

	if candidate.SectorRoot != "" {
		if err := removeSectorAliasIfOwned(sectorByRootPath(storage, candidate.SectorRoot), candidate.SectorID); err != nil {
			return candidate, false, piecesRemoved, err
		}
	}
	if err := removeSectorAliasIfOwned(openSectorPath(storage), candidate.SectorID); err != nil {
		return candidate, false, piecesRemoved, err
	}
	if err := mutation.Complete(); err != nil {
		return candidate, false, piecesRemoved, err
	}
	candidate.Phase = expiredGCPhaseLocalRemoved
	if err := writeExpiredGCRecord(storage, candidate); err != nil {
		return candidate, false, piecesRemoved, err
	}
	return candidate, true, piecesRemoved, nil
}

func appendAffectedPartition(result *expiredGCResult, record expiredGCRecord) {
	want := expiredGCPartition{
		DeadlineIndex: record.DeadlineIndex, PartitionIndex: record.PartitionIndex,
		PartitionKind: record.PartitionKind,
	}
	for _, existing := range result.Affected {
		if existing == want {
			return
		}
	}
	result.Affected = append(result.Affected, want)
}

func runExpiredGCDetailedAt(storage string, logger *log.Logger, chainTimestamp int64) expiredGCResult {
	if logger == nil {
		logger = log.Default()
	}
	var result expiredGCResult
	if chainTimestamp <= 0 {
		logger.Printf("[gc] expired-sector cleanup deferred: invalid chain timestamp %d", chainTimestamp)
		return result
	}

	pending, err := listExpiredGCRecords(storage)
	if err != nil {
		logger.Printf("[gc] ERROR listing durable gc work: %v", err)
		result.Failures++
		return result
	}
	pendingBySector := map[string]expiredGCRecord{}
	for _, record := range pending {
		pendingBySector[record.SectorID] = record
		if record.Phase == expiredGCPhaseLocalRemoved {
			appendAffectedPartition(&result, record)
		}
	}

	sectors, err := listSectors(storage)
	if err != nil {
		logger.Printf("[gc] ERROR listing sectors: %v", err)
		result.Failures++
		return result
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || sector.Expiration > chainTimestamp {
			continue
		}
		if _, exists := pendingBySector[sector.SectorID]; !exists {
			pendingBySector[sector.SectorID] = expiredGCRecordForSector(sector)
		}
	}

	sectorIDs := make([]string, 0, len(pendingBySector))
	for sectorID := range pendingBySector {
		sectorIDs = append(sectorIDs, sectorID)
	}
	sort.Strings(sectorIDs)
	for _, sectorID := range sectorIDs {
		record := pendingBySector[sectorID]
		if record.Phase == expiredGCPhaseLocalRemoved {
			continue
		}
		updated, removed, pieces, err := expireSectorLocally(storage, record, chainTimestamp, logger)
		if err != nil {
			logger.Printf("[gc] expired sector deferred sectorId=%s: %v", truncate(sectorID, 18), err)
			result.Failures++
			continue
		}
		if !removed {
			continue
		}
		result.SectorsRemoved++
		result.PiecesRemoved += pieces
		appendAffectedPartition(&result, updated)
		logger.Printf("[gc] expired sector removed locally sectorId=%s expiredAt=%s pieces=%d; chain reconciliation pending",
			truncate(updated.SectorID, 18), time.Unix(updated.Expiration, 0).UTC().Format(time.RFC3339), pieces)
	}
	return result
}

func activePartitionListed(partitions []CapacityPartitionInfo, deadlineIndex, partitionIndex int) bool {
	for _, partition := range partitions {
		if partition.DeadlineIndex == deadlineIndex && partition.PartitionIndex == partitionIndex && partition.Active {
			return true
		}
	}
	return false
}

// reconcileExpiredGCDataPartitions updates or deactivates each affected data
// partition. It intentionally holds only that partition's lock across RPC; no
// capacity/global lock is held while waiting on the chain.
func reconcileExpiredGCDataPartitions(cfg ServerConfig, chainTimestamp int64, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	records, err := listExpiredGCRecords(cfg.Storage)
	if err != nil {
		logger.Printf("[gc] chain reconciliation deferred: %v", err)
		return
	}
	groups := map[expiredGCPartition][]expiredGCRecord{}
	for _, record := range records {
		if record.Phase != expiredGCPhaseLocalRemoved || record.PartitionKind != PartitionKindData {
			continue
		}
		key := expiredGCPartition{record.DeadlineIndex, record.PartitionIndex, record.PartitionKind}
		groups[key] = append(groups[key], record)
	}
	keys := make([]expiredGCPartition, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].DeadlineIndex != keys[j].DeadlineIndex {
			return keys[i].DeadlineIndex < keys[j].DeadlineIndex
		}
		return keys[i].PartitionIndex < keys[j].PartitionIndex
	})

	for _, key := range keys {
		// ── B.3.1 phase 1: under the partition lock, revalidate identity and claim ────────
		deferReason := ""
		var claim gcPartitionTransition
		var identity gcPartitionLifecycleIdentity
		var claimed bool
		func() {
			lock, lockErr := acquirePartitionLifecycleLock(cfg.Storage, key.DeadlineIndex, key.PartitionIndex)
			if lockErr != nil {
				deferReason = "lock: " + lockErr.Error()
				return
			}
			defer lock.Release()
			pendingDeletion, pendingErr := partitionHasPendingDeletion(
				cfg.Storage, key.DeadlineIndex, key.PartitionIndex,
			)
			if pendingErr != nil {
				deferReason = "deletion ownership check: " + pendingErr.Error()
				return
			}
			if pendingDeletion {
				deferReason = "deferred for deletion successor"
				return
			}
		}()
		if deferReason != "" {
			logger.Printf("[gc] data partition reconciliation dl=%d pt=%d: %s", key.DeadlineIndex, key.PartitionIndex, deferReason)
			continue
		}
		var claimErr error
		claim, identity, claimed, claimErr = claimGCPartitionTransition(
			cfg, key.DeadlineIndex, key.PartitionIndex, chainTimestamp,
		)
		if claimErr != nil {
			logger.Printf("[gc] partition transition claim failed dl=%d pt=%d: %v", key.DeadlineIndex, key.PartitionIndex, claimErr)
			continue
		}
		if !claimed && claim.AttemptID == "" {
			continue
		}

		// ── B.3.1 phase 2: NO lock held while the chain RPC runs ──────────────────────────
		var txHash string
		var rpcErr error
		if claim.Intent == gcTransitionIntentRegister {
			txHash, rpcErr = registerConfiguredPartitionOnChain(cfg, identity.Partition)
		} else {
			var onChain []CapacityPartitionInfo
			onChain, rpcErr = listActiveDataPartitionsOnChain(cfg.ChainProofCmd)
			if rpcErr == nil && activePartitionListed(onChain, key.DeadlineIndex, key.PartitionIndex) {
				txHash, rpcErr = deactivatePartitionOnChain(cfg.ChainProofCmd, key.DeadlineIndex, key.PartitionIndex)
			}
		}
		// On failure the outcome is ambiguous: consult CHAIN TRUTH to tell "already done" from
		// "conclusively failed" from "unknown". A successful call needs no extra read.
		chainTruthKnown, chainConfirmed := true, true
		if rpcErr != nil {
			chainTruthKnown, chainConfirmed = false, false
			if onChain, listErr := listActiveDataPartitionsOnChain(cfg.ChainProofCmd); listErr == nil {
				chainTruthKnown = true
				chainConfirmed = gcTransitionChainConfirms(claim, onChain)
			}
		}

		// ── B.3.1 phase 3: reacquire the lock, verify identity, reconcile chain truth ─────
		completed, reconcileErr := reconcileGCPartitionTransition(
			cfg, claim, chainTimestamp, txHash, rpcErr, chainTruthKnown, chainConfirmed,
		)
		if reconcileErr != nil {
			logger.Printf("[gc] data partition reconciliation deferred dl=%d pt=%d: %v", key.DeadlineIndex, key.PartitionIndex, reconcileErr)
			continue
		}
		if !completed {
			logger.Printf("[gc] data partition transition unresolved dl=%d pt=%d (identity moved or chain outcome unconfirmed)",
				key.DeadlineIndex, key.PartitionIndex)
			continue
		}
		for _, record := range groups[key] {
			if removeErr := finalizeExpiredGCRecord(cfg.Storage, record); removeErr != nil {
				logger.Printf("[gc] finalize warning sector=%s: %v", truncate(record.SectorID, 18), removeErr)
			}
		}
		logger.Printf("[gc] data partition reconciled dl=%d pt=%d intent=%s active=%v",
			key.DeadlineIndex, key.PartitionIndex, claim.Intent, identity.Active)
	}
}

func finalizeExpiredGCRecord(storage string, record expiredGCRecord) error {
	gcLock, err := acquireLifecycleOperationLock(storage, "expired-gc", record.SectorID)
	if err != nil {
		return err
	}
	defer gcLock.Release()
	sector, found, err := readSectorIfPresent(storage, record.SectorID)
	if err != nil {
		return err
	}
	if found && sector.Status != "deleted" {
		// Capacity slots intentionally reuse stable sector IDs after an expired
		// snapshot is rebuilt. Never remove that replacement; only retire the old
		// journal once its newer lifetime/content is visible locally.
		if sector.Expiration > record.Expiration || !sameRoot(sector.SectorRoot, record.SectorRoot) {
			return removeExpiredGCRecord(storage, record.SectorID)
		}
		return fmt.Errorf("sector became active again without a newer snapshot; refusing to finalize gc")
	}
	if found {
		if err := os.Remove(sectorPath(storage, record.SectorID)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return removeExpiredGCRecord(storage, record.SectorID)
}

// settleExpiredGCCapacityRecords only verifies work performed by the normal
// exact-capacity publication pipeline. GC never publishes a partial free-space
// snapshot itself. Until the exact rebuilt content is active (or the obsolete
// partition is inactive), the durable journal remains pending.
func settleExpiredGCCapacityRecords(cfg ServerConfig, chainTimestamp int64, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	records, err := listExpiredGCRecords(cfg.Storage)
	if err != nil {
		return
	}
	groups := map[expiredGCPartition][]expiredGCRecord{}
	for _, record := range records {
		if record.Phase != expiredGCPhaseLocalRemoved || record.PartitionKind != PartitionKindCapacity {
			continue
		}
		key := expiredGCPartition{record.DeadlineIndex, record.PartitionIndex, record.PartitionKind}
		groups[key] = append(groups[key], record)
	}
	if len(groups) == 0 {
		return
	}
	if needs, _, err := capacityNeedsRebalance(cfg.Storage, cfg); err != nil || needs {
		return
	}
	onChain, err := listActiveCapacityPartitionsOnChain(cfg.ChainProofCmd)
	if err != nil {
		return
	}
	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return
	}
	for key, pending := range groups {
		partition, active := currentPartitionMetaByCoordinatesAt(
			sectors, cfg, key.DeadlineIndex, key.PartitionIndex, PartitionKindCapacity, chainTimestamp,
		)
		settled := false
		if active {
			status, statusErr := partitionVersionStatusOnChain(cfg.ChainProofCmd, partition)
			settled = statusErr == nil && status.Active && partitionMatchesChainContent(status, partition)
		} else {
			settled = !activePartitionListed(onChain, key.DeadlineIndex, key.PartitionIndex)
		}
		if !settled {
			continue
		}
		for _, record := range pending {
			if err := finalizeExpiredGCRecord(cfg.Storage, record); err != nil && !errors.Is(err, os.ErrNotExist) {
				logger.Printf("[gc] capacity finalize warning sector=%s: %v", truncate(record.SectorID, 18), err)
			}
		}
		logger.Printf("[gc] capacity partition reconciliation confirmed dl=%d pt=%d", key.DeadlineIndex, key.PartitionIndex)
	}
}
