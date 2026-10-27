package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type persistedPartitionCoordinates struct {
	deadlineIndex  int
	partitionIndex int
}

// freezeRegisteredDataSectorAssignments makes the existing FileRegistrationSC
// record authoritative during an upgrade. It never migrates a live file: old
// coordinates are persisted locally, and any commitment mismatch stops startup.
func freezeRegisteredDataSectorAssignments(storage string, cfg ServerConfig) (int, error) {
	return freezeRegisteredDataSectorAssignmentsWithLookup(storage, cfg, rpcGetFileStorageRecord)
}

func freezeRegisteredDataSectorAssignmentsWithLookup(
	storage string,
	cfg ServerConfig,
	lookup func(string, string, string) (onChainFileStorageRecord, error),
) (int, error) {
	changed, _, err := freezeRegisteredDataSectorAssignmentsWithChecks(
		storage, cfg, lookup, rpcCommitmentHashIsActive,
	)
	return changed, err
}

// freezeRegisteredDataSectorAssignmentsWithChecks resolves each local sector's
// partition coordinates from its CURRENT on-chain file record.
//
// Two rules keep one inconsistency from becoming a keeper-wide outage:
//
//   - Only commitments the chain still reports as active take part. A piece may
//     be deleted and the identical content uploaded again; the old payment
//     record is kept for accounting and still names that piece root, so it would
//     otherwise be resolved onto the new sector and contribute a stale
//     coordinate. isActive returning an error is NOT "not active" — the refresh
//     stops so a live record is never silently dropped.
//
//   - Permanent per-sector disagreements isolate that one sector. Transient or
//     ambiguous failures still stop the whole refresh, because skipping them
//     could mean ignoring a live record and placing data in the wrong partition.
//
// The second return value maps each isolated sector to the reason it was left
// out, so callers and tests can see exactly what was skipped.
func freezeRegisteredDataSectorAssignmentsWithChecks(
	storage string,
	cfg ServerConfig,
	lookup func(string, string, string) (onChainFileStorageRecord, error),
	isActive func(ServerConfig, string) (bool, error),
) (int, map[string]string, error) {
	if cfg.RPCURL == "" || cfg.FileRegistrationContract == "" || cfg.VKAddress == "" {
		return 0, nil, nil
	}
	entries, err := os.ReadDir(paymentDir(storage))
	if os.IsNotExist(err) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, fmt.Errorf("partition backfill: read payment credentials: %w", err)
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return 0, nil, fmt.Errorf("partition backfill: list sectors: %w", err)
	}
	byID := make(map[string]SectorMeta, len(sectors))
	for _, sector := range sectors {
		byID[sector.SectorID] = sector
	}

	coordinates := make(map[string]persistedPartitionCoordinates)
	changed := make(map[string]SectorMeta)
	normalizeHex := func(value string) string {
		return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "0x"))
	}

	// isolated holds sectors whose on-chain records permanently disagree with
	// local state. They are reported and left untouched — no write, no delete —
	// so they stay visibly unproved and are retried on the next refresh.
	isolated := make(map[string]string)
	isolate := func(sectorID, reason string) {
		if _, seen := isolated[sectorID]; !seen {
			log.Printf("[partition] sector isolated this refresh; its proofs are deferred, healthy sectors continue sector=%s: %s",
				truncate(sectorID, 18), reason)
		}
		isolated[sectorID] = reason
		delete(changed, sectorID)
		delete(coordinates, sectorID)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(paymentDir(storage), entry.Name()))
		if readErr != nil {
			return 0, nil, fmt.Errorf("partition backfill: read %s: %w", entry.Name(), readErr)
		}
		var creds PaymentCredentials
		if err := json.Unmarshal(b, &creds); err != nil {
			// Corrupt payment data is permanent: retrying cannot repair it, and
			// refusing forever would stop every healthy sector. It names no sector,
			// so report it loudly and move on.
			log.Printf("[partition] unreadable payment record skipped this refresh file=%s: %v",
				entry.Name(), err)
			continue
		}
		if creds.CommitmentHash == "" || creds.PieceRoot == "" {
			continue // Unused quote credentials are not file records.
		}
		meta, metaErr := readMeta(storage, creds.PieceRoot)
		if os.IsNotExist(metaErr) {
			continue // Confirmed deletions retain payment history.
		}
		if metaErr != nil {
			return 0, nil, fmt.Errorf("partition backfill: read piece %s: %w", truncate(creds.PieceRoot, 18), metaErr)
		}
		sector, found := byID[meta.SectorID]
		if !found || sector.Status == "deleted" || sector.IsCapacity {
			continue
		}
		if _, bad := isolated[sector.SectorID]; bad {
			continue
		}

		record, recordErr := lookup(
			cfg.RPCURL, cfg.FileRegistrationContract, creds.CommitmentHash,
		)
		if recordErr != nil {
			return 0, nil, fmt.Errorf("partition backfill: read commitment %s: %w", truncate(creds.CommitmentHash, 18), recordErr)
		}
		if !record.Exists {
			log.Printf("[partition] audit required: local piece has no file registration piece=%s sector=%s",
				truncate(creds.PieceRoot, 18), truncate(sector.SectorID, 18))
			continue
		}
		// A historical commitment must not place a live sector. Its piece root can
		// still resolve here after a delete and an identical re-upload, and its
		// coordinates belong to the sector that is already gone.
		active, activeErr := isActive(cfg, creds.CommitmentHash)
		if activeErr != nil {
			// Unknown is not inactive: stopping costs one refresh, guessing could
			// drop a live record and place the sector in the wrong partition.
			return 0, nil, fmt.Errorf("partition backfill: read commitment active state %s: %w",
				truncate(creds.CommitmentHash, 18), activeErr)
		}
		if !active {
			continue
		}
		if !strings.EqualFold(record.VKAddress, cfg.VKAddress) {
			return 0, nil, fmt.Errorf("partition backfill: commitment %s belongs to VK %s, local VK is %s",
				truncate(creds.CommitmentHash, 18), record.VKAddress, cfg.VKAddress)
		}
		if normalizeHex(record.SectorRoot) != normalizeHex(sector.SectorRoot) {
			isolate(sector.SectorID, fmt.Sprintf("immutable sector root mismatch commitment=%s",
				truncate(creds.CommitmentHash, 18)))
			continue
		}
		if normalizeHex(record.ZKPieceCommitment) != normalizeHex(sector.ZKPieceCommitment) {
			isolate(sector.SectorID, fmt.Sprintf("immutable piece commitment mismatch commitment=%s",
				truncate(creds.CommitmentHash, 18)))
			continue
		}
		if record.DeadlineIndex < 0 || record.DeadlineIndex >= cfg.DeadlineCount ||
			record.PartitionIndex < partitionBaseIndex(PartitionKindData) ||
			record.PartitionIndex > partitionMaxIndex(PartitionKindData) {
			isolate(sector.SectorID, fmt.Sprintf("invalid on-chain coordinates dl=%d pt=%d commitment=%s",
				record.DeadlineIndex, record.PartitionIndex, truncate(creds.CommitmentHash, 18)))
			continue
		}
		coord := persistedPartitionCoordinates{record.DeadlineIndex, record.PartitionIndex}
		if previous, exists := coordinates[sector.SectorID]; exists && previous != coord {
			isolate(sector.SectorID, fmt.Sprintf(
				"active file records in conflicting partitions dl=%d pt=%d and dl=%d pt=%d",
				previous.deadlineIndex, previous.partitionIndex, coord.deadlineIndex, coord.partitionIndex))
			continue
		}
		coordinates[sector.SectorID] = coord
		if !sector.PartitionAssigned || sector.DeadlineIndex != coord.deadlineIndex || sector.PartitionIndex != coord.partitionIndex {
			sector.DeadlineIndex = coord.deadlineIndex
			sector.PartitionIndex = coord.partitionIndex
			sector.PartitionAssigned = true
			sector.PartitionAssignedAt = time.Now().UTC().Format(time.RFC3339)
			sector.UpdatedAt = nowRFC3339()
			changed[sector.SectorID] = sector
			byID[sector.SectorID] = sector
		}
	}

	counts := make(map[persistedPartitionCoordinates]int)
	for _, sector := range byID {
		if sector.IsCapacity || sector.Status == "deleted" || sector.SectorBlockCount <= 0 ||
			!validAssignedPartition(sector, PartitionKindData, cfg.DeadlineCount) {
			continue
		}
		if _, bad := isolated[sector.SectorID]; bad {
			continue
		}
		coord := persistedPartitionCoordinates{sector.DeadlineIndex, sector.PartitionIndex}
		counts[coord]++
		if counts[coord] > cfg.PartitionMaxSectors {
			// Isolate the sector that overflowed rather than the whole keeper, and
			// uncount it so the partition's remaining sectors stay usable.
			counts[coord]--
			isolate(sector.SectorID, fmt.Sprintf("partition dl=%d pt=%d exceeds configured maximum %d",
				coord.deadlineIndex, coord.partitionIndex, cfg.PartitionMaxSectors))
		}
	}
	for _, sector := range changed {
		if err := writeSector(storage, sector); err != nil {
			return 0, nil, fmt.Errorf("partition backfill: persist sector %s: %w", sector.SectorID, err)
		}
	}
	if len(isolated) > 0 {
		log.Printf("[partition] %d sector(s) isolated this refresh; they stay unproved and are retried next refresh",
			len(isolated))
	}
	return len(changed), isolated, nil
}
