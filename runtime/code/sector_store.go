package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ─── Path helpers ─────────────────────────────────────────────────────────────

func sectorPath(storage, sectorID string) string {
	return filepath.Join(sectorDir(storage), safeID(sectorID)+".json")
}

func sectorByRootPath(storage, sectorRoot string) string {
	return filepath.Join(sectorDir(storage), "root-"+safeID(sectorRoot)+".json")
}

func openSectorPath(storage string) string {
	return filepath.Join(sectorDir(storage), "open.json")
}

// ─── Sector R/W ───────────────────────────────────────────────────────────────

func writeSector(storage string, sector SectorMeta) error {
	b, err := json.MarshalIndent(sector, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(sectorPath(storage, sector.SectorID), b, 0600); err != nil {
		return err
	}
	_ = atomicWriteFile(sectorByRootPath(storage, sector.SectorRoot), b, 0600)
	// open.json is a convenience pointer to the most recently written open sector.
	if sector.Status == "open" {
		return atomicWriteFile(openSectorPath(storage), b, 0600)
	}
	return nil
}

func readSector(storage, sectorID string) (SectorMeta, error) {
	var sector SectorMeta
	b, err := os.ReadFile(sectorPath(storage, sectorID))
	if err != nil {
		return sector, err
	}
	err = json.Unmarshal(b, &sector)
	return sector, err
}

// readOpenSector intentionally removed: the new expiration-bucket placement logic
// scans all sectors via listSectors + findBestSectorForPiece.
// open.json is still written by writeSector (convenience for debugging) but
// is never used as the sole active-sector source.

func listSectors(storage string) ([]SectorMeta, error) {
	entries, err := os.ReadDir(sectorDir(storage))
	if err != nil {
		return nil, err
	}
	out := []SectorMeta{}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") ||
			e.Name() == "open.json" || strings.HasPrefix(e.Name(), "root-") {
			continue
		}
		var s SectorMeta
		b, err := os.ReadFile(filepath.Join(sectorDir(storage), e.Name()))
		if err != nil || json.Unmarshal(b, &s) != nil || seen[s.SectorID] {
			continue
		}
		seen[s.SectorID] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SectorID < out[j].SectorID })
	return out, nil
}

// ─── Expiration-bucket helpers ────────────────────────────────────────────────

// resolvedBuckets returns the configured buckets or the package defaults.
func resolvedBuckets(cfg ServerConfig) []int64 {
	if len(cfg.SectorExpirationBuckets) > 0 {
		return cfg.SectorExpirationBuckets
	}
	return DefaultSectorExpirationBuckets
}

// resolvedMaxExtension returns the configured max extension or the package default.
func resolvedMaxExtension(cfg ServerConfig) int64 {
	if cfg.SectorMaxExpirationExtension > 0 {
		return cfg.SectorMaxExpirationExtension
	}
	return DefaultSectorMaxExpirationExtension
}

// bucketIndexForServiceEnd returns which bucket index a piece's serviceEnd falls into.
// Bucket i covers service ends within buckets[i] seconds from now.
// Returns len(buckets)-1 for any serviceEnd beyond the largest bucket.
func bucketIndexForServiceEnd(serviceEnd int64, buckets []int64) int {
	now := time.Now().UTC().Unix()
	remaining := serviceEnd - now
	for i, dur := range buckets {
		if remaining <= dur {
			return i
		}
	}
	return len(buckets) - 1
}

// bucketExpiration returns the Unix timestamp when a bucket expires
// (now + buckets[idx]).  Always >= serviceEnd.
func bucketExpiration(bucketIdx int, buckets []int64, serviceEnd int64) int64 {
	now := time.Now().UTC().Unix()
	exp := now + buckets[bucketIdx]
	if exp < serviceEnd {
		exp = serviceEnd
	}
	return exp
}

// ─── ZK capacity helpers ──────────────────────────────────────────────────────

// estimatePieceLeaves returns the number of ZK leaves a piece file would
// produce, estimated from its on-disk size. Returns 1 for empty files (the
// implementation always produces at least one leaf).
func estimatePieceLeaves(storage, pieceRoot string, zkBlockSize int64) int {
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	info, err := os.Stat(piecePath(storage, pieceRoot))
	if err != nil || info.Size() == 0 {
		return 1
	}
	return int((info.Size() + zkBlockSize - 1) / zkBlockSize)
}

// minDepthForLeaves returns the smallest Merkle tree depth whose capacity
// (2^depth) is ≥ n. Capped at 30 to guard against nonsensical inputs.
func minDepthForLeaves(n int) int {
	if n <= 1 {
		return 1
	}
	depth := 0
	cap := 1
	for cap < n {
		depth++
		cap <<= 1
		if depth >= 30 {
			break
		}
	}
	return depth
}

// ─── Best-fit sector selection ────────────────────────────────────────────────

// sectorPlacementResult describes why a sector was chosen or created.
type sectorPlacementResult string

const (
	placementReuseExact  sectorPlacementResult = "reuse_exact_bucket"
	placementReuseExtend sectorPlacementResult = "reuse_extend"
	placementNewBucket   sectorPlacementResult = "new_sector_bucket"
	placementNewNoFit    sectorPlacementResult = "new_sector_no_fit"
)

// findBestSectorForPiece searches all open sectors for the best placement for a
// piece with the given serviceEnd.
//
// Selection rules (in priority order):
//  1. Open, not full, not expired, expiration >= serviceEnd, ZK capacity fits.
//     Among these prefer the one with the smallest expiration (closest fit).
//     If !SectorAllowLargeMixing, also reject sectors whose bucket is more
//     than one bucket above the piece's bucket.
//  2. Open, not full, not expired, expiration < serviceEnd by at most
//     SectorMaxExpirationExtension and AllowSectorExtend = true, ZK capacity fits.
//     Prefer the one needing the smallest extension.
//
// estimatedLeaves is the expected ZK leaf count for the new piece (0 = unknown,
// skip ZK capacity check). Sectors where SectorBlockCount + estimatedLeaves
// would exceed the sector's ZK tree capacity are always skipped.
//
// Returns (chosen sector, placement reason, needsExtension bool).
// If no suitable sector is found, returns (zero, placementNew*, false) and the
// caller must create a new sector.
func findBestSectorForPiece(sectors []SectorMeta, serviceEnd int64, cfg ServerConfig, estimatedLeaves int) (SectorMeta, sectorPlacementResult, bool) {
	now := time.Now().UTC().Unix()
	buckets := resolvedBuckets(cfg)
	maxExt := resolvedMaxExtension(cfg)
	pieceBucket := bucketIndexForServiceEnd(serviceEnd, buckets)

	type candidate struct {
		s         SectorMeta
		needsExt  bool
		extAmount int64 // 0 for exact-fit candidates
	}

	var exactFit []candidate
	var extensible []candidate

	for _, s := range sectors {
		if s.Status != "open" {
			continue
		}
		if s.IsCapacity {
			continue
		}
		if len(s.PieceRoots) >= s.SectorMaxPieces && s.SectorMaxPieces > 0 {
			continue
		}
		if cfg.FileRegistrationContract != "" && len(s.PieceRoots) > 0 {
			continue
		}
		if s.Expiration <= now {
			continue
		}

		if estimatedLeaves > 0 && s.ZKTreeDepth > 0 {
			zkCapacity := 1 << s.ZKTreeDepth
			if s.SectorBlockCount+estimatedLeaves > zkCapacity {
				log.Printf("[sector] reject %s: ZK capacity %d exceeded (current=%d + new=%d)",
					s.SectorID[:min(16, len(s.SectorID))], zkCapacity, s.SectorBlockCount, estimatedLeaves)
				continue
			}
		}

		if s.Expiration >= serviceEnd {
			// Sector already covers the piece's lifetime without extension.
			if !cfg.SectorAllowLargeMixing {
				// Reject if this sector's bucket is more than one step above the piece's.
				sectorBucket := bucketIndexForServiceEnd(s.Expiration, buckets)
				if sectorBucket > pieceBucket+1 {
					log.Printf("[sector] reject %s: bucket %d > piece bucket %d+1 (large-mixing disabled)",
						s.SectorID[:min(16, len(s.SectorID))], sectorBucket, pieceBucket)
					continue
				}
			}
			exactFit = append(exactFit, candidate{s: s, needsExt: false})
		} else if cfg.AllowSectorExtend {
			// Sector expires before the piece — check if extension is within policy.
			extNeeded := serviceEnd - s.Expiration
			if extNeeded <= maxExt {
				extensible = append(extensible, candidate{s: s, needsExt: true, extAmount: extNeeded})
			}
		}
	}

	// Sort exact-fit candidates by smallest expiration.
	sort.Slice(exactFit, func(i, j int) bool {
		return exactFit[i].s.Expiration < exactFit[j].s.Expiration
	})
	if len(exactFit) > 0 {
		return exactFit[0].s, placementReuseExact, false
	}

	// Sort extensible: least extension needed first.
	sort.Slice(extensible, func(i, j int) bool {
		return extensible[i].extAmount < extensible[j].extAmount
	})
	if len(extensible) > 0 {
		s := extensible[0].s
		s.Expiration = serviceEnd
		return s, placementReuseExtend, true
	}

	return SectorMeta{}, placementNewNoFit, false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Sector creation ──────────────────────────────────────────────────────────

func newSector(cfg ServerConfig, requiredUntil int64) SectorMeta {
	return newSectorWithID(cfg, requiredUntil, fmt.Sprintf("sector-%d", time.Now().UTC().UnixNano()))
}

func newSectorWithID(cfg ServerConfig, requiredUntil int64, sectorID string) SectorMeta {
	buckets := resolvedBuckets(cfg)
	now := time.Now().UTC()

	// Default lifetime expiration.
	lifetimeExp := now.Add(time.Duration(cfg.SectorLifetimeDays) * 24 * time.Hour).Unix()

	// Assign bucket based on the piece's required serviceEnd.
	bucketIdx := bucketIndexForServiceEnd(requiredUntil, buckets)
	bucketExp := bucketExpiration(bucketIdx, buckets, requiredUntil)

	// Sector expiration = max(lifetime default, bucket expiration).
	exp := lifetimeExp
	if bucketExp > exp {
		exp = bucketExp
	}
	if exp < requiredUntil {
		exp = requiredUntil
	}

	dl := 0
	if cfg.DeadlineCount > 0 {
		dl = sectorDeadlineIndex(sectorID, cfg.DeadlineCount)
	}

	log.Printf("[sector] new sector %s  bucket=%d  exp=%s  deadline=%d",
		sectorID[:min(26, len(sectorID))],
		bucketIdx,
		time.Unix(exp, 0).Local().Format("2006-01-02"),
		dl,
	)

	return SectorMeta{
		SectorID:         sectorID,
		SectorRoot:       fieldHexFromBytes(zkEmptyLeaf()),
		RootAlg:          RootAlgZKMiMCBN254,
		PieceRoots:       []string{},
		SectorBlockCount: 0,
		ZKBlockSize:      cfg.ZKBlockSize,
		ZKTreeDepth:      cfg.ZKTreeDepth,
		SectorMaxPieces:  cfg.SectorMaxPieces,
		Expiration:       exp,
		CreatedAt:        now.Format(time.RFC3339),
		UpdatedAt:        now.Format(time.RFC3339),
		Status:           "open",
		DeadlineIndex:    dl,
		ExpirationBucket: bucketIdx,
		MinServiceEnd:    0, // set to first piece's serviceEnd on insertion
		MaxServiceEnd:    0,
	}
}

// ─── Piece→sector placement ───────────────────────────────────────────────────

// commitReservedSectorSlot converts an upload operation's sector-cap reservation into committed
// occupancy exactly once, after its sector is durably written. The sector itself then holds the
// slot, so the reservation record is retired and no longer counted. A failure here cannot
// invalidate the durable sector: it is logged and left for B.4 reconciliation, and until then
// the slot is merely counted conservatively (twice) rather than lost.
func commitReservedSectorSlot(storage string, reservation **sectorSlotReservation, sectorID string) {
	if reservation == nil || *reservation == nil {
		return
	}
	operationID := (*reservation).OperationID
	if _, err := commitSectorSlotReservation(storage, operationID, sectorID); err != nil {
		log.Printf("[allocator] commit reservation op=%s sector=%s: %v", operationID, sectorID, err)
		return
	}
	*reservation = nil
}

func addPieceToSector(storage string, meta PieceMeta, cfg ServerConfig, leaseOut ...**partitionLifecycleLock) (receipt SectorReceipt, storedMeta PieceMeta, err error) {
	return addPieceToSectorAttempt(storage, meta, cfg, nil, 0, leaseOut...)
}

func addPieceToSectorWithMutation(storage string, meta PieceMeta, cfg ServerConfig, mutation *capacityMutationLease, leaseOut ...**partitionLifecycleLock) (receipt SectorReceipt, storedMeta PieceMeta, err error) {
	return addPieceToSectorAttempt(storage, meta, cfg, mutation, 0, leaseOut...)
}

func addPieceToSectorAttempt(storage string, meta PieceMeta, cfg ServerConfig, mutation *capacityMutationLease, attempt int, leaseOut ...**partitionLifecycleLock) (receipt SectorReceipt, storedMeta PieceMeta, err error) {
	if attempt >= 8 {
		// Bounded re-selection. No partition lock is held here (every re-selecting frame
		// released its own before recursing), so releasing the slot cannot invert lock order.
		if cfg.FileRegistrationContract != "" && cfg.DeadlineCount > 0 && cfg.PartitionMaxSectors > 0 {
			operationID := uploadOperationIdentity(mutation, meta)
			if _, releaseErr := releaseSectorSlotReservation(storage, operationID); releaseErr != nil {
				log.Printf("[allocator] release reservation after repeated re-selection op=%s: %v", operationID, releaseErr)
			}
		}
		return SectorReceipt{}, meta, fmt.Errorf("sector placement changed repeatedly while acquiring its partition lock")
	}
	var lifecycleLock *partitionLifecycleLock
	// B.1: this frame's sector-cap reservation, if it created or adopted one. It is released on
	// a terminal failure so the slot becomes selectable again; on an internal re-selection the
	// recursive frame reuses the same reservation instead of consuming another slot.
	var slotReservation *sectorSlotReservation
	reselected := false
	defer func() {
		callerOwnsLease := err == nil && len(leaseOut) > 0 && leaseOut[0] != nil
		if lifecycleLock != nil && !callerOwnsLease {
			lifecycleLock.Release()
		}
		if slotReservation != nil && !reselected && err != nil {
			if _, releaseErr := releaseSectorSlotReservation(storage, slotReservation.OperationID); releaseErr != nil {
				log.Printf("[allocator] release reservation op=%s: %v", slotReservation.OperationID, releaseErr)
			}
		}
	}()
	// Sanitize config defaults.
	if cfg.SectorMaxPieces <= 0 {
		cfg.SectorMaxPieces = DefaultSectorMaxPieces
	}
	if cfg.SectorLifetimeDays <= 0 {
		cfg.SectorLifetimeDays = DefaultSectorLifetimeDays
	}
	if cfg.ZKBlockSize <= 0 {
		cfg.ZKBlockSize = DefaultZKBlockSize
	}
	if cfg.ZKTreeDepth <= 0 {
		cfg.ZKTreeDepth = DefaultZKTreeDepth
	}
	serviceEnd := meta.ServiceEnd
	if serviceEnd <= 0 {
		serviceEnd = time.Now().UTC().Add(time.Duration(cfg.SectorLifetimeDays) * 24 * time.Hour).Unix()
	}

	// ── Find or create a sector for this piece ──────────────────────────────
	sectors, err := listSectors(storage)
	if err != nil {
		return SectorReceipt{}, meta, fmt.Errorf("list sectors: %w", err)
	}

	// Estimate ZK leaf count from file size so sector selection can check capacity.
	estimatedLeaves := estimatePieceLeaves(storage, meta.PieceRoot, cfg.ZKBlockSize)

	sector, placement, needsExtension := findBestSectorForPiece(sectors, serviceEnd, cfg, estimatedLeaves)
	newSectorCreated := false

	switch placement {
	case placementReuseExact:
		log.Printf("[sector] piece → sector %s  placement=%s  bucket=%d  exp=%s  pieces=%d/%d",
			sector.SectorID[:min(26, len(sector.SectorID))],
			placement,
			sector.ExpirationBucket,
			time.Unix(sector.Expiration, 0).Local().Format("2006-01-02"),
			len(sector.PieceRoots),
			sector.SectorMaxPieces,
		)

	case placementReuseExtend:
		log.Printf("[sector] piece → sector %s  placement=%s  extend_to=%s  pieces=%d/%d",
			sector.SectorID[:min(26, len(sector.SectorID))],
			placement,
			time.Unix(sector.Expiration, 0).Local().Format("2006-01-02"),
			len(sector.PieceRoots),
			sector.SectorMaxPieces,
		)

	default:
		// placementNewBucket or placementNewNoFit: create a fresh sector.
		// If the piece alone requires a deeper tree than the configured default,
		// bump ZKTreeDepth so the sector's Merkle root can accommodate it.
		if minDepth := minDepthForLeaves(estimatedLeaves); minDepth > cfg.ZKTreeDepth {
			log.Printf("[sector] piece requires ZK depth %d (configured default=%d, leaves≈%d)",
				minDepth, cfg.ZKTreeDepth, estimatedLeaves)
			cfg.ZKTreeDepth = minDepth
		}
		sector = newSector(cfg, serviceEnd)
		newSectorCreated = true
		if placement == placementNewNoFit {
			log.Printf("[sector] piece → new sector (no fitting open sector found)  serviceEnd=%s",
				time.Unix(serviceEnd, 0).Local().Format("2006-01-02"))
		}
	}

	_ = needsExtension // needsExtension already applied in findBestSectorForPiece
	if sector.IsCapacity {
		return SectorReceipt{}, meta, fmt.Errorf("refuse to store real piece in capacity-only sector %s", sector.SectorID)
	}
	priorSector := sector
	priorSectorExists := !newSectorCreated
	if newSectorCreated && cfg.FileRegistrationContract != "" {
		// B.1: a NEW sector consumes a sector-cap slot. Select the target and record the
		// reservation atomically across processes under the short allocator lock, counting
		// committed sectors AND outstanding reservations. Retrying this upload operation reuses
		// (or reconciles) its existing reservation rather than taking a second slot.
		if cfg.DeadlineCount > 0 && cfg.PartitionMaxSectors > 0 {
			operationID := uploadOperationIdentity(mutation, meta)
			reservation, reserveErr := reserveSectorSlotForUpload(
				storage, cfg, operationID, sector.SectorID, sector.ExpirationBucket,
			)
			if reserveErr != nil {
				return SectorReceipt{}, meta, reserveErr
			}
			slotReservation = &reservation
			if !strings.EqualFold(reservation.SectorID, sector.SectorID) {
				// A retry adopts the sector this operation already reserved.
				sector = newSectorWithID(cfg, serviceEnd, reservation.SectorID)
			}
			sector.DeadlineIndex = reservation.DeadlineIndex
			sector.PartitionIndex = reservation.PartitionIndex
			sector.PartitionAssigned = true
			sector.PartitionAssignedAt = nowRFC3339()
			priorSector = sector
		} else if err := assignPackedDataPartitionForNewSector(storage, &sector, cfg); err != nil {
			return SectorReceipt{}, meta, err
		}
	}
	if cfg.FileRegistrationContract != "" && validAssignedPartition(sector, PartitionKindData, cfg.DeadlineCount) {
		lifecycleLock, err = acquirePartitionLifecycleLock(storage, sector.DeadlineIndex, sector.PartitionIndex)
		if err != nil {
			return SectorReceipt{}, meta, err
		}
		// Re-check under the partition lock: a deletion may have claimed this
		// coordinate after assignPacked selected it (TOCTOU).
		pendingDeletion, pendingErr := partitionHasPendingDeletion(
			storage, sector.DeadlineIndex, sector.PartitionIndex,
		)
		if pendingErr != nil {
			return SectorReceipt{}, meta, pendingErr
		}
		if pendingDeletion {
			lifecycleLock.Release()
			lifecycleLock = nil
			if newSectorCreated {
				sector.PartitionAssigned = false
				sector.PartitionIndex = 0
				sector.DeadlineIndex = sectorDeadlineIndex(sector.SectorID, cfg.DeadlineCount)
			}
			// The retry reuses this operation's reservation (reconciling it onto another
			// target), so this frame must not release the slot on the way out.
			reselected = true
			return addPieceToSectorAttempt(storage, meta, cfg, mutation, attempt+1, leaseOut...)
		}
		// B.2: before ANY new-sector write begins, revalidate the already-reserved target
		// against freshly reloaded authoritative state while holding this partition lock. The
		// recheck never takes the allocator lock, and performs no writes — so an invalidation
		// leaves no sector write and no on-chain action behind. Existing-sector appends keep
		// using their own validation path below and never consume a new-sector reservation.
		if newSectorCreated && slotReservation != nil {
			verdict, recheckErr := revalidateReservedNewSectorTarget(storage, cfg, newSectorTargetRequest{
				OperationID:      slotReservation.OperationID,
				SectorID:         sector.SectorID,
				PartitionKind:    PartitionKindData,
				DeadlineIndex:    sector.DeadlineIndex,
				PartitionIndex:   sector.PartitionIndex,
				ExpirationBucket: sector.ExpirationBucket,
			})
			if recheckErr != nil {
				return SectorReceipt{}, meta, recheckErr
			}
			if !verdict.Valid {
				log.Printf("[allocator] new-sector recheck rejected dl%d-pt%d for op=%s: %s",
					sector.DeadlineIndex, sector.PartitionIndex, slotReservation.OperationID, verdict.Reason)
				// Lock order: drop the partition lock FIRST, then return to the B.1 allocator
				// path to reconcile the reservation or select another target.
				lifecycleLock.Release()
				lifecycleLock = nil
				sector.PartitionAssigned = false
				sector.PartitionIndex = 0
				sector.DeadlineIndex = sectorDeadlineIndex(sector.SectorID, cfg.DeadlineCount)
				reselected = true
				return addPieceToSectorAttempt(storage, meta, cfg, mutation, attempt+1, leaseOut...)
			}
		}
		if !newSectorCreated {
			latest, readErr := readSector(storage, sector.SectorID)
			stale := readErr != nil || latest.Status != sector.Status || latest.UpdatedAt != sector.UpdatedAt ||
				!sameRoot(latest.SectorRoot, sector.SectorRoot) || !sameRootSet(latest.PieceRoots, sector.PieceRoots)
			if stale {
				// Selection happened before the cross-process partition lock. An
				// expiration/delete/store may have changed that sector while this store
				// waited; release and select again rather than reviving stale metadata.
				lifecycleLock.Release()
				lifecycleLock = nil
				reselected = true
				return addPieceToSectorAttempt(storage, meta, cfg, mutation, attempt+1, leaseOut...)
			}
		}
		if len(leaseOut) > 0 && leaseOut[0] != nil {
			*leaseOut[0] = lifecycleLock
		}
	}

	// ── Dedup: piece already in this sector ────────────────────────────────
	for idx, existing := range sector.PieceRoots {
		if strings.EqualFold(existing, meta.PieceRoot) {
			proof, _ := computeSectorProof(sector.PieceRoots, idx)
			root, blockCount, zkPC, err := computeZKSectorRoot(storage, sector.PieceRoots, cfg.ZKBlockSize, cfg.ZKTreeDepth, cfg.ForceCapacityRebuild)
			if err != nil {
				return SectorReceipt{}, meta, err
			}
			sector.SectorRoot = root
			sector.SectorBlockCount = blockCount
			sector.ZKPieceCommitment = zkPC
			sector.RootAlg = RootAlgZKMiMCBN254
			sector.ZKBlockSize = cfg.ZKBlockSize
			sector.ZKTreeDepth = cfg.ZKTreeDepth
			if err := assignPartitionForSector(storage, &sector, cfg, PartitionKindData); err != nil {
				return SectorReceipt{}, meta, err
			}
			if err := mutation.PrepareSectorTransition(
				capacityMutationStateForSector(priorSector, priorSectorExists),
				capacityMutationStateForSector(sector, true),
			); err != nil {
				return SectorReceipt{}, meta, err
			}
			if err := writeSector(storage, sector); err != nil {
				return SectorReceipt{}, meta, err
			}
			meta.SectorID = sector.SectorID
			meta.SectorRoot = sector.SectorRoot
			meta.PiecePosition = idx
			_ = writeMeta(storage, meta)
			commitReservedSectorSlot(storage, &slotReservation, sector.SectorID)
			return SectorReceipt{
				SectorID:         sector.SectorID,
				SectorRoot:       sector.SectorRoot,
				SectorExpiration: sector.Expiration,
				PiecePosition:    idx,
				InclusionProof:   proof,
			}, meta, nil
		}
	}

	// ── Append piece ────────────────────────────────────────────────────────
	if cfg.FileRegistrationContract != "" && len(sector.PieceRoots) > 0 {
		return SectorReceipt{}, meta, fmt.Errorf("refuse to mutate registered data sector %s: one file per registered sector is required", sector.SectorID)
	}
	sector.PieceRoots = append(sector.PieceRoots, meta.PieceRoot)
	sectorRoot, sectorBlockCount, sectorZKPC, err := computeZKSectorRoot(storage, sector.PieceRoots, cfg.ZKBlockSize, cfg.ZKTreeDepth, cfg.ForceCapacityRebuild)
	if err != nil {
		return SectorReceipt{}, meta, err
	}
	sector.SectorRoot = sectorRoot
	sector.SectorBlockCount = sectorBlockCount
	sector.ZKPieceCommitment = sectorZKPC
	sector.RootAlg = RootAlgZKMiMCBN254
	sector.ZKBlockSize = cfg.ZKBlockSize
	sector.ZKTreeDepth = cfg.ZKTreeDepth
	sector.UpdatedAt = nowRFC3339()

	// Track min/max serviceEnd for the sector.
	if sector.MinServiceEnd == 0 || serviceEnd < sector.MinServiceEnd {
		sector.MinServiceEnd = serviceEnd
	}
	if serviceEnd > sector.MaxServiceEnd {
		sector.MaxServiceEnd = serviceEnd
	}

	if cfg.FileRegistrationContract != "" {
		sector.Status = "sealed"
		log.Printf("[sector] sector %s sealed for immutable file registration root",
			sector.SectorID[:min(26, len(sector.SectorID))])
	} else if len(sector.PieceRoots) >= sector.SectorMaxPieces {
		sector.Status = "sealed"
		log.Printf("[sector] sector %s sealed  pieces=%d",
			sector.SectorID[:min(26, len(sector.SectorID))], len(sector.PieceRoots))
	}
	if err := assignPartitionForSector(storage, &sector, cfg, PartitionKindData); err != nil {
		return SectorReceipt{}, meta, err
	}
	if err := mutation.PrepareSectorTransition(
		capacityMutationStateForSector(priorSector, priorSectorExists),
		capacityMutationStateForSector(sector, true),
	); err != nil {
		return SectorReceipt{}, meta, err
	}
	// B.3 test hook: fires at the partition-local write transition. Tests use it to prove that
	// two uploads on DIFFERENT partitions genuinely overlap here — under a broad global upload
	// lock they could not. Always nil in production.
	if barrier := partitionWriteBarrierForTest; barrier != nil {
		barrier(sector.DeadlineIndex, sector.PartitionIndex)
	}
	if err := writeSector(storage, sector); err != nil {
		return SectorReceipt{}, meta, err
	}

	pos := len(sector.PieceRoots) - 1
	proof, err := computeSectorProof(sector.PieceRoots, pos)
	if err != nil {
		return SectorReceipt{}, meta, err
	}
	meta.SectorID = sector.SectorID
	meta.SectorRoot = sector.SectorRoot
	meta.PiecePosition = pos
	if err := writeMeta(storage, meta); err != nil {
		return SectorReceipt{}, meta, err
	}
	// The sector is durable: its slot is now committed occupancy, so this operation's
	// reservation is converted (exactly once) and retired.
	commitReservedSectorSlot(storage, &slotReservation, sector.SectorID)

	return SectorReceipt{
		SectorID:         sector.SectorID,
		SectorRoot:       sector.SectorRoot,
		SectorExpiration: sector.Expiration,
		PiecePosition:    pos,
		InclusionProof:   proof,
	}, meta, nil
}

// removePieceFromSector removes pieceRoot from the sector that contains it,
// recomputes the ZK sector root without the deleted piece, and persists the
// updated sector. Returns the updated SectorMeta.
// If pieceRoot is not found in any sector, returns an error.
func removePieceFromSector(storage string, pieceRoot string, cfg ServerConfig) (SectorMeta, error) {
	return removePieceFromSectorWithMutation(storage, pieceRoot, cfg, nil)
}

func removePieceFromSectorWithMutation(storage string, pieceRoot string, cfg ServerConfig, mutation *capacityMutationLease) (SectorMeta, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return SectorMeta{}, fmt.Errorf("removePiece: list sectors: %w", err)
	}

	for _, sector := range sectors {
		for _, root := range sector.PieceRoots {
			if !strings.EqualFold(root, pieceRoot) {
				continue
			}
			if cfg.FileRegistrationContract != "" && len(sector.PieceRoots) > 1 {
				return SectorMeta{}, fmt.Errorf("refuse to delete from multi-piece registered sector %s: legacy sector requires explicit migration/backfill", sector.SectorID)
			}
			priorSector := sector
			// Build new PieceRoots slice without this piece.
			newRoots := make([]string, 0, len(sector.PieceRoots)-1)
			for _, r := range sector.PieceRoots {
				if !strings.EqualFold(r, pieceRoot) {
					newRoots = append(newRoots, r)
				}
			}
			sector.PieceRoots = newRoots

			if len(newRoots) == 0 {
				// Sector is now empty; mark deleted so proof scheduler skips it.
				sector.SectorRoot = strings.Repeat("0", 64)
				sector.ZKPieceCommitment = ""
				sector.SectorBlockCount = 0
				sector.Status = "deleted"
			} else {
				// Recompute ZK root without the deleted piece.
				zkBlockSize := cfg.ZKBlockSize
				if zkBlockSize <= 0 {
					zkBlockSize = DefaultZKBlockSize
				}
				zkTreeDepth := cfg.ZKTreeDepth
				if zkTreeDepth <= 0 {
					zkTreeDepth = DefaultZKTreeDepth
				}
				newRoot, newBlockCount, newZKPC, err := computeZKSectorRoot(storage, newRoots, zkBlockSize, zkTreeDepth, false)
				if err != nil {
					return SectorMeta{}, fmt.Errorf("removePiece: recompute sector root: %w", err)
				}
				sector.SectorRoot = newRoot
				sector.SectorBlockCount = newBlockCount
				sector.ZKPieceCommitment = newZKPC
			}
			sector.UpdatedAt = nowRFC3339()
			if len(newRoots) > 0 {
				if err := assignPartitionForSector(storage, &sector, cfg, PartitionKindData); err != nil {
					return SectorMeta{}, err
				}
			}

			if err := mutation.PrepareSectorTransition(
				capacityMutationStateForSector(priorSector, true),
				capacityMutationStateForSector(sector, sector.Status != "deleted"),
			); err != nil {
				return SectorMeta{}, fmt.Errorf("removePiece: persist capacity mutation: %w", err)
			}
			if err := writeSector(storage, sector); err != nil {
				return SectorMeta{}, fmt.Errorf("removePiece: write sector: %w", err)
			}
			log.Printf("[sector] piece removed  pieceRoot=%s  sector=%s  remaining=%d",
				truncate(pieceRoot, 18), sector.SectorID[:min(26, len(sector.SectorID))], len(newRoots))
			return sector, nil
		}
	}
	return SectorMeta{}, fmt.Errorf("removePiece: pieceRoot %s not found in any sector", truncate(pieceRoot, 18))
}

// findPieceStatus reports whether VK currently holds a piece by pieceRoot.
//
//   - has=true: piece data file exists and is in an active sector.
//   - has=false, deleted=true: VK once stored this piece but it has been deleted;
//     commitmentHash and commitmentNonce are returned so REQ can verify on-chain.
//   - has=false, deleted=false: VK has no record of this piece at all.
func findPieceStatus(storage, pieceRoot string) (has bool, deleted bool, commitmentHash, commitmentNonce string) {
	// Fast path: piece data file still present.
	if _, err := os.Stat(piecePath(storage, pieceRoot)); err == nil {
		return true, false, "", ""
	}

	// Scan payment credentials to find a record for this pieceRoot.
	dir := paymentDir(storage)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false, "", ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var creds PaymentCredentials
		if err := json.Unmarshal(b, &creds); err != nil {
			continue
		}
		if creds.PieceRoot != pieceRoot {
			continue
		}
		// Found credentials for this piece — data file is gone → deleted.
		return false, true, creds.CommitmentHash, creds.CommitmentNonce
	}
	return false, false, "", ""
}

// StorageInfo holds real-time capacity statistics for the VK.
type StorageInfo struct {
	TotalCapacityBytes             int64  `json:"totalCapacityBytes"`
	UsedBytes                      int64  `json:"usedBytes"`
	FreeBytes                      int64  `json:"freeBytes"`
	LogicalFreeBytes               int64  `json:"logicalFreeBytes,omitempty"`
	CapacityBackingBytes           int64  `json:"capacityBackingBytes,omitempty"`
	ProofOverheadBytes             int64  `json:"proofOverheadBytes,omitempty"`
	RealFileBytes                  int64  `json:"realFileBytes,omitempty"`
	CommittedBytes                 int64  `json:"committedBytes,omitempty"`
	CapacitySectorCount            int    `json:"capacitySectorCount,omitempty"`
	DataSectorCount                int    `json:"dataSectorCount,omitempty"`
	SectorCount                    int    `json:"sectorCount"`
	PieceCount                     int    `json:"pieceCount"`
	AccountingOK                   bool   `json:"accountingOk"`
	AccountingError                string `json:"accountingError,omitempty"`
	AdmissionClosed                bool   `json:"admissionClosed"`
	AdmissionFreeBytes             int64  `json:"admissionFreeBytes,omitempty"`
	AdmissionAllocatableBytes      int64  `json:"admissionAllocatableBytes,omitempty"`
	AdmissionMarginBytes           int64  `json:"admissionMarginBytes,omitempty"`
	AdmissionReason                string `json:"admissionReason,omitempty"`
	FreshCertifiedFreeCapacity     int64  `json:"freshCertifiedFreeCapacity,omitempty"`
	ActiveReservationBytes         int64  `json:"activeReservationBytes,omitempty"`
	SafeAllocatable                int64  `json:"safeAllocatable,omitempty"`
	RequestedBytes                 int64  `json:"requestedBytes,omitempty"`
	AdmissionOpen                  bool   `json:"admissionOpen"`
	AdmissionClosureReason         string `json:"admissionClosureReason,omitempty"`
	CertificationObservationBlock  uint64 `json:"certificationObservationBlock,omitempty"`
	ExpiredCertifiedBytes          int64  `json:"expiredCertifiedBytes,omitempty"`
	DirtyUncertifiedBytes          int64  `json:"dirtyUncertifiedBytes,omitempty"`
	CapacityBacklogDurationSeconds int64  `json:"capacityBacklogDuration,omitempty"`
	OldestDirtyAgeSeconds          int64  `json:"oldestDirtyAge,omitempty"`
	ProofSubsystemAvailable        bool   `json:"proofSubsystemAvailable"`
	RecoveryDisagreement           bool   `json:"recoveryDisagreement,omitempty"`
	ProofReady                     bool   `json:"proofReady"`
	Degraded                       bool   `json:"degraded,omitempty"`
	DegradedReason                 string `json:"degradedReason,omitempty"`
	// A.4 recovery + orphan-GC observability.
	RecoveryPending                int    `json:"recoveryPending,omitempty"`
	RecoveryTerminal               int    `json:"recoveryTerminal,omitempty"`
	OrphanArtifactsRetained        int    `json:"orphanArtifactsRetained,omitempty"`
	OrphanArtifactOldestAgeSeconds int64  `json:"orphanArtifactOldestAgeSeconds,omitempty"`
	OrphanArtifactGCError          string `json:"orphanArtifactGcError,omitempty"`
	// B.1 sector-cap reservation observability: outstanding reservations occupy real slots and
	// are counted against the sector cap alongside committed sectors.
	SectorSlotReservationsActive int    `json:"sectorSlotReservationsActive,omitempty"`
	SectorSlotReservationError   string `json:"sectorSlotReservationError,omitempty"`
	// B.4 reservation-recovery observability.
	ReservationsRecoveredCommitted int    `json:"reservationsRecoveredCommitted,omitempty"`
	ReservationsReleasedAbandoned  int    `json:"reservationsReleasedAbandoned,omitempty"`
	ReservationsRetainedAmbiguous  int    `json:"reservationsRetainedAmbiguous,omitempty"`
	ReservationsCorrupt            int    `json:"reservationsCorrupt,omitempty"`
	ReservationOldestUnresolvedAge int64  `json:"reservationOldestUnresolvedAgeSeconds,omitempty"`
	ReservationSweepAt             string `json:"reservationSweepAt,omitempty"`
	ReservationSweepError          string `json:"reservationSweepError,omitempty"`
	ReservationRecoveryComplete    bool   `json:"reservationRecoveryComplete"`
	// C.1 prover-lane overload observability.
	ProofLaneOverload             bool            `json:"proofLaneOverload,omitempty"`
	ProofLaneOverloadReason       string          `json:"proofLaneOverloadReason,omitempty"`
	ProofLaneOverloadDeadlineUnix int64           `json:"proofLaneOverloadDeadlineUnix,omitempty"`
	ProofLaneRequiredSeconds      int64           `json:"proofLaneRequiredSeconds,omitempty"`
	ProofLaneAvailableSeconds     int64           `json:"proofLaneAvailableSeconds,omitempty"`
	ProofLaneOverloadSince        string          `json:"proofLaneOverloadSince,omitempty"`
	ProofLaneOverloadClearedAt    string          `json:"proofLaneOverloadClearedAt,omitempty"`
	ProofLaneConfigured           bool            `json:"proofLaneConfigured"`
	PhysicalAvailableBytes        int64           `json:"physicalAvailableBytes,omitempty"`
	FilesystemReserveBytes        int64           `json:"filesystemReserveBytes,omitempty"`
	PhysicalAllocatableBytes      int64           `json:"physicalAllocatableBytes,omitempty"`
	Transfers                     transferMetrics `json:"transfers"`
}

func getStorageInfo(storage string, totalCapacityBytes int64) StorageInfo {
	accounting, err := computeCapacityAccounting(storage, totalCapacityBytes)
	info := StorageInfo{
		TotalCapacityBytes:   totalCapacityBytes,
		UsedBytes:            accounting.UsedBytes,
		FreeBytes:            accounting.FreeBytes,
		LogicalFreeBytes:     accounting.LogicalFreeBytes,
		CapacityBackingBytes: accounting.FreeBytes,
		ProofOverheadBytes:   accounting.ProofOverheadBytes,
		RealFileBytes:        accounting.RealFileBytes,
		CommittedBytes:       accounting.CommittedBytes,
		CapacitySectorCount:  accounting.CapacitySectorCount,
		DataSectorCount:      accounting.DataSectorCount,
		SectorCount:          accounting.SectorCount,
		PieceCount:           accounting.PieceCount,
		AccountingOK:         accounting.OK,
		AccountingError:      accounting.Error,
	}
	if err != nil {
		info.AccountingOK = false
		info.AccountingError = err.Error()
	}
	return info
}

type CapacityAccounting struct {
	TotalCapacityBytes  int64
	UsedBytes           int64
	FreeBytes           int64
	RealFileBytes       int64
	CommittedBytes      int64
	LogicalFreeBytes    int64
	ProofOverheadBytes  int64
	CapacitySectorCount int
	DataSectorCount     int
	SectorCount         int
	PieceCount          int
	OK                  bool
	Error               string
}

func committedSectorBytes(sector SectorMeta) int64 {
	zkBlockSize := sector.ZKBlockSize
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	if sector.SectorBlockCount <= 0 {
		return 0
	}
	return int64(sector.SectorBlockCount) * zkBlockSize
}

func capacityBytesRequiredForPiece(sizeBytes, zkBlockSize int64) int64 {
	if sizeBytes <= 0 {
		return 0
	}
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	return ((sizeBytes + zkBlockSize - 1) / zkBlockSize) * zkBlockSize
}

func computeCapacityAccounting(storage string, totalCapacityBytes int64) (CapacityAccounting, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return CapacityAccounting{}, fmt.Errorf("list sectors: %w", err)
	}
	out := CapacityAccounting{TotalCapacityBytes: totalCapacityBytes, OK: true}
	for _, s := range sectors {
		if s.Status == "deleted" {
			continue
		}
		bytes := committedSectorBytes(s)
		if s.IsCapacity {
			out.FreeBytes += bytes
			out.CapacitySectorCount++
			out.SectorCount++
			continue
		}
		out.UsedBytes += bytes
		out.DataSectorCount++
		out.SectorCount++
		for _, root := range s.PieceRoots {
			if m, err := readMeta(storage, root); err == nil && m.Name != "capacity" {
				out.RealFileBytes += m.Size
				out.PieceCount++
			}
		}
	}
	out.CommittedBytes = out.UsedBytes + out.FreeBytes
	if totalCapacityBytes > 0 {
		out.LogicalFreeBytes = totalCapacityBytes - out.UsedBytes
		if out.LogicalFreeBytes < 0 {
			out.LogicalFreeBytes = 0
		}
		if out.CommittedBytes > totalCapacityBytes {
			out.ProofOverheadBytes = out.CommittedBytes - totalCapacityBytes
		}
	}
	// Fixed immutable free-space chunks intentionally overlap incoming data by
	// less than one configured chunk until the next boundary is crossed. That
	// overlap is proof backing, not oversold capacity. Only committed data itself
	// exceeding the declaration is an accounting violation.
	if totalCapacityBytes > 0 && out.UsedBytes > totalCapacityBytes {
		out.OK = false
		out.Error = fmt.Sprintf("used data bytes %d exceed declared capacity %d", out.UsedBytes, totalCapacityBytes)
	}
	return out, nil
}

func ensureCapacityAvailableForPiece(storage string, totalCapacityBytes, pieceSize, zkBlockSize int64) error {
	if totalCapacityBytes <= 0 {
		return nil
	}
	accounting, err := computeCapacityAccounting(storage, totalCapacityBytes)
	if err != nil {
		return err
	}
	required := capacityBytesRequiredForPiece(pieceSize, zkBlockSize)
	if accounting.UsedBytes+required > totalCapacityBytes {
		return fmt.Errorf("insufficient proved capacity: used=%d required=%d declared=%d", accounting.UsedBytes, required, totalCapacityBytes)
	}
	return nil
}
