package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// sectorDeadlineIndex deterministically assigns a sector to a deadline index.
// Takes the first 8 bytes of SHA256(sectorID) as a uint64 and mods by deadlineCount.
// This is stable: sectorID never changes after creation.
func sectorDeadlineIndex(sectorID string, deadlineCount int) int {
	if deadlineCount <= 0 {
		return 0
	}
	h := sha256.Sum256([]byte(sectorID))
	n := binary.BigEndian.Uint64(h[:8])
	return int(n % uint64(deadlineCount))
}

// currentDeadlineIndexAt returns the index of the deadline window open at an
// explicit chain timestamp. Proof scheduling must pass the latest block time,
// rather than assuming the VK host's wall clock matches the chain.
func currentDeadlineIndexAt(chainTimestamp int64, deadlineCount int, periodSeconds int64) int {
	if deadlineCount <= 0 || periodSeconds <= 0 {
		return 0
	}
	if chainTimestamp < 0 {
		chainTimestamp = 0
	}

	// Scale the offset across deadlineCount instead of truncating the period to
	// periodSeconds/deadlineCount. This covers every second of a non-divisible
	// period and can never produce deadlineCount for the final remainder.
	posInPeriod := uint64(chainTimestamp % periodSeconds)
	hi, lo := bits.Mul64(posInPeriod, uint64(deadlineCount))
	index, _ := bits.Div64(hi, lo, uint64(periodSeconds))
	return int(index)
}

// currentDeadlineIndex is retained for standalone/off-chain callers. On-chain
// proof scheduling must use currentDeadlineIndexAt with chain-authoritative time.
func currentDeadlineIndex(deadlineCount int, periodSeconds int64) int {
	return currentDeadlineIndexAt(time.Now().UTC().Unix(), deadlineCount, periodSeconds)
}

// nextProofWindowDeadlineAt returns the end of the proof window containing an
// explicit chain timestamp. With deadline partitioning disabled it returns the
// end of the current proof period. The returned time represents chain time.
func nextProofWindowDeadlineAt(chainTimestamp, periodSeconds int64, deadlineCount int) time.Time {
	if periodSeconds <= 0 {
		periodSeconds = 24 * 60 * 60
	}
	if chainTimestamp < 0 {
		chainTimestamp = 0
	}
	periodStart := chainTimestamp - chainTimestamp%periodSeconds
	if deadlineCount <= 0 {
		return unixTimeAfter(periodStart, uint64(periodSeconds))
	}

	deadlineIndex := currentDeadlineIndexAt(chainTimestamp, deadlineCount, periodSeconds)
	// The end of window i is ceil((i+1)*period/count). Using 128-bit
	// multiply/divide keeps the helper correct even for large validated config
	// values without overflowing an int64 intermediate.
	hi, lo := bits.Mul64(uint64(deadlineIndex+1), uint64(periodSeconds))
	endOffset, remainder := bits.Div64(hi, lo, uint64(deadlineCount))
	if remainder != 0 {
		endOffset++
	}
	return unixTimeAfter(periodStart, endOffset)
}

func unixTimeAfter(start int64, offset uint64) time.Time {
	if offset > uint64(math.MaxInt64) || start > math.MaxInt64-int64(offset) {
		return time.Unix(math.MaxInt64, 0)
	}
	return time.Unix(start+int64(offset), 0)
}

// partitionDir returns the directory for partition state files inside a storage root.
func partitionDir(storage string) string {
	return filepath.Join(storage, "partitions")
}

// partitionStatePath returns the file path for a particular deadline/partition.
func partitionStatePath(storage string, deadlineIndex, partitionIndex int) string {
	return filepath.Join(partitionDir(storage), fmt.Sprintf("dl%d-pt%d.json", deadlineIndex, partitionIndex))
}

// writePartitionState persists partition proof-round state atomically.
func writePartitionState(storage string, p PartitionMeta) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(partitionStatePath(storage, p.DeadlineIndex, p.PartitionIndex), b, 0600)
}

// readPartitionState reads saved partition proof state; (_, false, nil) means no state file yet.
func readPartitionState(storage string, deadlineIndex, partitionIndex int) (PartitionMeta, bool, error) {
	var p PartitionMeta
	b, err := os.ReadFile(partitionStatePath(storage, deadlineIndex, partitionIndex))
	if os.IsNotExist(err) {
		return p, false, nil
	}
	if err != nil {
		return p, false, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, true, err
	}
	return p, true, nil
}

// computePartitionRoot computes SHA-256 over the concatenated (padded) sector roots.
// padTo is the circuit capacity N; the last real root is repeated for unused slots.
// Solidity: sha256(abi.encodePacked(roots...)) uses the same algorithm.
func computePartitionRoot(sectorRoots []string, padTo int) (string, error) {
	roots := paddedRoots(sectorRoots, padTo)
	var combined []byte
	for _, r := range roots {
		b, err := rootBytes(r)
		if err != nil {
			return "", fmt.Errorf("bad sector root %q: %w", r, err)
		}
		combined = append(combined, b...)
	}
	h := sha256.Sum256(combined)
	return "0x" + hex.EncodeToString(h[:]), nil
}

// paddedRoots returns sectorRoots padded to length padTo by repeating the last element.
// padTo must be > 0; if len(sectorRoots) == 0 an empty slice is returned.
func paddedRoots(sectorRoots []string, padTo int) []string {
	if len(sectorRoots) == 0 || padTo <= 0 {
		return sectorRoots
	}
	out := make([]string, padTo)
	copy(out, sectorRoots)
	last := sectorRoots[len(sectorRoots)-1]
	for i := len(sectorRoots); i < padTo; i++ {
		out[i] = last
	}
	return out
}

// paddedInts pads a []int slice to length padTo by repeating the last element.
func paddedInts(vals []int, padTo int) []int {
	if len(vals) == 0 || padTo <= 0 {
		return vals
	}
	out := make([]int, padTo)
	copy(out, vals)
	last := vals[len(vals)-1]
	for i := len(vals); i < padTo; i++ {
		out[i] = last
	}
	return out
}

type partitionBucketKey struct {
	deadlineIndex  int
	partitionIndex int
	kind           string
}

type legacyPartitionKey struct {
	deadlineIndex int
	kind          string
}

func partitionKindForSector(s SectorMeta) string {
	if s.IsCapacity {
		return PartitionKindCapacity
	}
	return PartitionKindData
}

func partitionBaseIndex(kind string) int {
	if kind == PartitionKindCapacity {
		return CapacityPartitionIndexOffset
	}
	return 0
}

func partitionMaxIndex(kind string) int {
	if kind == PartitionKindCapacity {
		return 255
	}
	return CapacityPartitionIndexOffset - 1
}

func sectorPartitionDeadline(s SectorMeta, deadlineCount int) int {
	if deadlineCount <= 0 {
		return 0
	}
	if s.DeadlineIndex >= 0 && s.DeadlineIndex < deadlineCount {
		return s.DeadlineIndex
	}
	return sectorDeadlineIndex(s.SectorID, deadlineCount)
}

func validAssignedPartition(s SectorMeta, kind string, deadlineCount int) bool {
	if !s.PartitionAssigned {
		return false
	}
	if s.DeadlineIndex < 0 || s.DeadlineIndex >= deadlineCount {
		return false
	}
	return s.PartitionIndex >= partitionBaseIndex(kind) && s.PartitionIndex <= partitionMaxIndex(kind)
}

func partitionContentHash(p PartitionMeta) string {
	h := sha256.New()
	fmt.Fprintf(h, "dl=%d|pt=%d|kind=%s|bytes=%d|exp=%d|n=%d|",
		p.DeadlineIndex, p.PartitionIndex, p.PartitionKind, p.CommittedBytes, p.Expiration, len(p.Sectors))
	for _, s := range p.Sectors {
		fmt.Fprintf(h, "sid=%s|root=%s|blocks=%d|pc=%s|exp=%d|cap=%t|",
			s.SectorID,
			strings.ToLower(s.SectorRoot),
			s.SectorBlockCount,
			strings.ToLower(s.ZKPieceCommitment),
			s.Expiration,
			s.IsCapacity,
		)
	}
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum)
}

func assignPartitionForSector(storage string, sector *SectorMeta, cfg ServerConfig, kind string) error {
	return assignPartitionForSectorAt(storage, sector, cfg, kind, time.Now().UTC().Unix())
}

func assignPartitionForSectorAt(storage string, sector *SectorMeta, cfg ServerConfig, kind string, activeAt int64) error {
	if sector == nil || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return nil
	}
	if kind == "" {
		kind = partitionKindForSector(*sector)
	}
	if sector.DeadlineIndex < 0 || sector.DeadlineIndex >= cfg.DeadlineCount {
		sector.DeadlineIndex = sectorDeadlineIndex(sector.SectorID, cfg.DeadlineCount)
	}
	if validAssignedPartition(*sector, kind, cfg.DeadlineCount) {
		return nil
	}

	// Sanctioned read protocol: reservations FIRST, committed sectors SECOND. Reading committed
	// state first could miss a slot whose reservation is unlinked (after its sector became
	// durable) between the two reads. See loadSectorSlotOccupancySnapshot.
	reservationRecords, err := listSectorSlotReservationsUnlocked(storage)
	if err != nil {
		return fmt.Errorf("assign partition: read sector slot reservations: %w", err)
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return fmt.Errorf("assign partition: list sectors: %w", err)
	}
	counts := map[int]int{}
	for _, p := range buildDeadlinePartitionsAt(sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors, activeAt) {
		if p.DeadlineIndex != sector.DeadlineIndex || p.PartitionKind != kind {
			continue
		}
		for _, s := range p.Sectors {
			if s.SectorID == sector.SectorID {
				continue
			}
			counts[p.PartitionIndex]++
		}
	}
	pendingDeletion := map[partitionBucketKey]bool{}
	// Outstanding sector-cap reservations occupy real slots. Counting only committed sectors
	// here would let this assignment overfill a partition another upload has already reserved.
	// A reservation whose sector is already committed is not counted twice.
	committedSectorIDs := map[partitionBucketKey]map[string]bool{}
	for _, existing := range sectors {
		if existing.Status == "deleted" {
			continue
		}
		key := partitionBucketKey{
			deadlineIndex:  sectorPartitionDeadline(existing, cfg.DeadlineCount),
			partitionIndex: existing.PartitionIndex, kind: partitionKindForSector(existing),
		}
		if committedSectorIDs[key] == nil {
			committedSectorIDs[key] = map[string]bool{}
		}
		committedSectorIDs[key][strings.ToLower(existing.SectorID)] = true
	}
	reserved := map[partitionBucketKey]int{}
	for _, record := range reservationRecords {
		if !record.active() {
			continue
		}
		key := record.bucketKey()
		if committedSectorIDs[key][strings.ToLower(record.SectorID)] {
			continue
		}
		reserved[key]++
	}
	if kind == PartitionKindData {
		pendingDeletion, err = pendingDeletionPartitionKeys(storage)
		if err != nil {
			return fmt.Errorf("assign partition: inspect pending deletions: %w", err)
		}
	}

	for pt := partitionBaseIndex(kind); pt <= partitionMaxIndex(kind); pt++ {
		key := partitionBucketKey{deadlineIndex: sector.DeadlineIndex, partitionIndex: pt, kind: kind}
		if pendingDeletion[key] {
			continue
		}
		if counts[pt]+reserved[key] < cfg.PartitionMaxSectors {
			sector.PartitionIndex = pt
			sector.PartitionAssigned = true
			sector.PartitionAssignedAt = nowRFC3339()
			return nil
		}
	}
	return fmt.Errorf("assign partition: no free %s partition slot for deadline %d", kind, sector.DeadlineIndex)
}

// packedDataPartitionState is the committed-sector view of data-partition occupancy: per-slot
// sector counts, which slots are sealed against new sectors, and the expiration buckets already
// committed there. B.1 combines it with the reservation view so a sector-cap decision always
// counts committed sectors AND outstanding reservations.
type packedDataPartitionState struct {
	counts  map[partitionBucketKey]int
	sealed  map[partitionBucketKey]bool
	buckets map[partitionBucketKey]map[int]bool
	// sectorIDs records which sectors are committed on each slot, so a reservation whose sector
	// has just become committed is counted once rather than twice.
	sectorIDs map[partitionBucketKey]map[string]bool
}

// loadPackedDataPartitionState reads committed occupancy. ignoreSectorID excludes one sector
// from the counts — used when an operation's own (possibly already written) sector must not be
// counted twice alongside its reservation.
func loadPackedDataPartitionState(storage string, cfg ServerConfig, ignoreSectorID string) (packedDataPartitionState, error) {
	state := packedDataPartitionState{
		counts:    map[partitionBucketKey]int{},
		sealed:    map[partitionBucketKey]bool{},
		buckets:   map[partitionBucketKey]map[int]bool{},
		sectorIDs: map[partitionBucketKey]map[string]bool{},
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return state, fmt.Errorf("assign packed data partition: list sectors: %w", err)
	}
	queues, queueErr := listPartitionProofSnapshotQueues(storage)
	if queueErr != nil {
		return state, fmt.Errorf("assign packed data partition: read proof snapshot queues: %w", queueErr)
	}
	for _, queue := range queues {
		if queue.PartitionKind == PartitionKindData && queue.Frozen != nil {
			state.sealed[partitionBucketKey{
				deadlineIndex: queue.DeadlineIndex, partitionIndex: queue.PartitionIndex,
				kind: PartitionKindData,
			}] = true
		}
	}
	// A durable deletion journal owns the coordinate until confirm. New uploads
	// must take another partition (or wait for a free slot) so they cannot bump
	// contentVersion and invalidate the exact deletion-successor snapshot.
	pendingDeletion, pendingErr := pendingDeletionPartitionKeys(storage)
	if pendingErr != nil {
		return state, fmt.Errorf("assign packed data partition: pending deletion scan: %w", pendingErr)
	}
	for key := range pendingDeletion {
		state.sealed[key] = true
	}
	// Deleted-but-still-assigned sectors reserve their coordinate until chain
	// lifecycle cleanup explicitly deactivates it. Reusing a pKey merely because
	// local bytes disappeared could supersede an obligation still active on-chain.
	for _, existing := range sectors {
		if existing.Status != "deleted" || !existing.PartitionAssigned ||
			existing.PartitionIndex >= CapacityPartitionIndexOffset {
			continue
		}
		state.sealed[partitionBucketKey{
			deadlineIndex: existing.DeadlineIndex, partitionIndex: existing.PartitionIndex,
			kind: PartitionKindData,
		}] = true
	}
	for _, p := range buildDeadlinePartitions(sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors) {
		if p.PartitionKind != PartitionKindData {
			continue
		}
		key := partitionBucketKey{
			deadlineIndex:  p.DeadlineIndex,
			partitionIndex: p.PartitionIndex,
			kind:           PartitionKindData,
		}
		count := 0
		for _, existing := range p.Sectors {
			if ignoreSectorID != "" && existing.SectorID == ignoreSectorID {
				continue
			}
			count++
			if state.buckets[key] == nil {
				state.buckets[key] = map[int]bool{}
			}
			state.buckets[key][existing.ExpirationBucket] = true
			if state.sectorIDs[key] == nil {
				state.sectorIDs[key] = map[string]bool{}
			}
			state.sectorIDs[key][strings.ToLower(existing.SectorID)] = true
		}
		state.counts[key] = count
		if count >= cfg.PartitionMaxSectors {
			continue
		}
		// A frozen generation must remain byte-for-byte immutable while its proof
		// runs. Once exact current content is proved, keep that active partition
		// sealed as well; new sectors use a successor coordinate. Deletion is the
		// only lifecycle allowed to update/reprove an existing coordinate.
		frozen, frozenErr := partitionHasFrozenProofSnapshot(
			storage, PartitionKindData, p.DeadlineIndex, p.PartitionIndex,
		)
		if frozenErr != nil {
			return state, fmt.Errorf("assign packed data partition: read frozen snapshot dl%d-pt%d: %w",
				p.DeadlineIndex, p.PartitionIndex, frozenErr)
		}
		proved := false
		if saved, found, stateErr := readPartitionState(storage, p.DeadlineIndex, p.PartitionIndex); stateErr != nil {
			return state, fmt.Errorf("assign packed data partition: read proof state dl%d-pt%d: %w",
				p.DeadlineIndex, p.PartitionIndex, stateErr)
		} else if found {
			proved = saved.LastProofRound > 0 && sameRoot(saved.ContentHash, p.ContentHash)
		}
		if frozen || proved {
			state.sealed[key] = true
		}
	}
	return state, nil
}

// sameBucketOnly reports whether every committed sector on this slot shares the given bucket.
func (s packedDataPartitionState) sameBucketOnly(key partitionBucketKey, bucket int) bool {
	for committed := range s.buckets[key] {
		if committed != bucket {
			return false
		}
	}
	return true
}

// selectPackedDataPartitionSlot chooses a data-partition slot for a new sector, counting
// committed sectors AND outstanding reservations against cfg.PartitionMaxSectors. It performs
// no mutation, so the allocator lock only has to span this selection plus the reservation write.
// It returns ErrNoFreeSectorSlot when every slot is taken by a sector or a reservation.
func selectPackedDataPartitionSlot(
	cfg ServerConfig, expirationBucket int, sectorID string,
	snapshot sectorSlotOccupancySnapshot, excludeOperationID string,
) (int, int, error) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return 0, 0, fmt.Errorf("assign packed data partition: partitioning is not configured")
	}

	type candidate struct {
		deadlineIndex  int
		partitionIndex int
		count          int
	}
	var candidates []candidate
	for key := range snapshot.state.counts {
		occupied := snapshot.occupied(key, excludeOperationID)
		if occupied >= cfg.PartitionMaxSectors || snapshot.sealed(key) {
			continue
		}
		// Bucket purity: pack only with sectors — committed or reserved — of the same bucket.
		if snapshot.bucketConflict(key, expirationBucket, excludeOperationID) {
			continue
		}
		candidates = append(candidates, candidate{
			deadlineIndex: key.deadlineIndex, partitionIndex: key.partitionIndex, count: occupied,
		})
	}
	if len(candidates) > 0 {
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].count != candidates[j].count {
				return candidates[i].count > candidates[j].count
			}
			if candidates[i].deadlineIndex != candidates[j].deadlineIndex {
				return candidates[i].deadlineIndex < candidates[j].deadlineIndex
			}
			return candidates[i].partitionIndex < candidates[j].partitionIndex
		})
		chosen := candidates[0]
		return chosen.deadlineIndex, chosen.partitionIndex, nil
	}

	preferredDL := sectorDeadlineIndex(sectorID, cfg.DeadlineCount)
	for off := 0; off < cfg.DeadlineCount; off++ {
		dl := (preferredDL + off) % cfg.DeadlineCount
		for pt := partitionBaseIndex(PartitionKindData); pt <= partitionMaxIndex(PartitionKindData); pt++ {
			key := partitionBucketKey{deadlineIndex: dl, partitionIndex: pt, kind: PartitionKindData}
			if snapshot.occupied(key, excludeOperationID) >= cfg.PartitionMaxSectors || snapshot.sealed(key) ||
				snapshot.bucketConflict(key, expirationBucket, excludeOperationID) {
				continue
			}
			return dl, pt, nil
		}
	}
	return 0, 0, fmt.Errorf("assign packed data partition: %w", ErrNoFreeSectorSlot)
}

// packedDataPartitionTargetUsable reports whether a previously reserved target is still a valid
// placement — used when an upload operation retries and wants to reuse its existing reservation
// rather than consume another slot.
func packedDataPartitionTargetUsable(
	cfg ServerConfig, deadlineIndex, partitionIndex, expirationBucket int,
	snapshot sectorSlotOccupancySnapshot, excludeOperationID string,
) bool {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return false
	}
	if deadlineIndex < 0 || deadlineIndex >= cfg.DeadlineCount ||
		partitionIndex < partitionBaseIndex(PartitionKindData) ||
		partitionIndex > partitionMaxIndex(PartitionKindData) {
		return false
	}
	key := partitionBucketKey{
		deadlineIndex: deadlineIndex, partitionIndex: partitionIndex, kind: PartitionKindData,
	}
	if snapshot.sealed(key) {
		return false
	}
	if snapshot.occupied(key, excludeOperationID) >= cfg.PartitionMaxSectors {
		return false
	}
	if snapshot.bucketConflict(key, expirationBucket, excludeOperationID) {
		return false
	}
	return true
}

func assignPackedDataPartitionForNewSector(storage string, sector *SectorMeta, cfg ServerConfig) error {
	if sector == nil || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return nil
	}
	if validAssignedPartition(*sector, PartitionKindData, cfg.DeadlineCount) {
		return nil
	}
	// Outstanding reservations hold real slots: selection must never ignore them, and the two
	// occupancy sources must be read in the sanctioned order (reservations first).
	snapshot, err := loadSectorSlotOccupancySnapshot(storage, cfg, sector.SectorID)
	if err != nil {
		return fmt.Errorf("assign packed data partition: read sector slot occupancy: %w", err)
	}
	dl, pt, err := selectPackedDataPartitionSlot(cfg, sector.ExpirationBucket, sector.SectorID, snapshot, "")
	if err != nil {
		return err
	}
	sector.DeadlineIndex = dl
	sector.PartitionIndex = pt
	sector.PartitionAssigned = true
	sector.PartitionAssignedAt = nowRFC3339()
	return nil
}

func ensureAllPartitionAssignments(storage string, cfg ServerConfig) error {
	return ensureAllPartitionAssignmentsAt(storage, cfg, time.Now().UTC().Unix())
}

// ensureAllPartitionAssignmentsAt backfills partition coordinates using an
// explicit authoritative timestamp. Chain-driven callers must pass the latest
// block timestamp so host clock drift cannot exclude a still-active sector or
// revive an expired one.
func ensureAllPartitionAssignmentsAt(storage string, cfg ServerConfig, activeAt int64) error {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return nil
	}
	assignmentLock, err := acquireLifecycleOperationLock(storage, "partition-assignment", "global")
	if err != nil {
		return fmt.Errorf("partition assignment: acquire startup lock: %w", err)
	}
	defer assignmentLock.Release()
	if frozen, err := freezeRegisteredDataSectorAssignments(storage, cfg); err != nil {
		return err
	} else if frozen > 0 {
		log.Printf("[partition] froze %d registered sector assignment(s) from on-chain records", frozen)
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return fmt.Errorf("partition assignment: list sectors: %w", err)
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || sector.SectorBlockCount <= 0 || sector.Expiration <= activeAt {
			continue
		}
		kind := partitionKindForSector(sector)
		if validAssignedPartition(sector, kind, cfg.DeadlineCount) {
			continue
		}
		assigned := false
		for attempt := 0; attempt < 8; attempt++ {
			if err := assignPartitionForSectorAt(storage, &sector, cfg, kind, activeAt); err != nil {
				return err
			}
			var partitionLock *partitionLifecycleLock
			if kind == PartitionKindData {
				partitionLock, err = acquirePartitionLifecycleLock(
					storage, sector.DeadlineIndex, sector.PartitionIndex,
				)
				if err != nil {
					return fmt.Errorf("partition assignment: lock sector %s: %w", sector.SectorID, err)
				}
				pending, pendingErr := partitionHasPendingDeletion(
					storage, sector.DeadlineIndex, sector.PartitionIndex,
				)
				if pendingErr != nil {
					partitionLock.Release()
					return fmt.Errorf("partition assignment: recheck deletion owner: %w", pendingErr)
				}
				if pending {
					partitionLock.Release()
					sector.PartitionAssigned = false
					sector.PartitionIndex = 0
					continue
				}
			}
			sector.UpdatedAt = nowRFC3339()
			writeErr := writeSector(storage, sector)
			if partitionLock != nil {
				partitionLock.Release()
			}
			if writeErr != nil {
				return fmt.Errorf("partition assignment: write sector %s: %w", sector.SectorID, writeErr)
			}
			assigned = true
			break
		}
		if !assigned {
			return fmt.Errorf("partition assignment: deletion ownership changed repeatedly for sector %s", sector.SectorID)
		}
	}
	return nil
}

func currentPartitionMetaForSector(sectorID string, sectors []SectorMeta, cfg ServerConfig) (PartitionMeta, bool) {
	return currentPartitionMetaForSectorAt(sectorID, sectors, cfg, time.Now().UTC().Unix())
}

func currentPartitionMetaForSectorAt(sectorID string, sectors []SectorMeta, cfg ServerConfig, activeAt int64) (PartitionMeta, bool) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return PartitionMeta{}, false
	}
	for _, p := range buildDeadlinePartitionsAt(sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors, activeAt) {
		for _, s := range p.Sectors {
			if s.SectorID == sectorID {
				return p, true
			}
		}
	}
	return PartitionMeta{}, false
}

func currentPartitionMetaByCoordinates(sectors []SectorMeta, cfg ServerConfig, deadlineIndex, partitionIndex int, kind string) (PartitionMeta, bool) {
	return currentPartitionMetaByCoordinatesAt(sectors, cfg, deadlineIndex, partitionIndex, kind, time.Now().UTC().Unix())
}

func currentPartitionMetaByCoordinatesAt(sectors []SectorMeta, cfg ServerConfig, deadlineIndex, partitionIndex int, kind string, activeAt int64) (PartitionMeta, bool) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return PartitionMeta{}, false
	}
	for _, p := range buildDeadlinePartitionsAt(sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors, activeAt) {
		if p.DeadlineIndex == deadlineIndex && p.PartitionIndex == partitionIndex && (kind == "" || p.PartitionKind == kind) {
			return p, true
		}
	}
	return PartitionMeta{}, false
}

func markDataPartitionLocallyDeactivated(storage string, deadlineIndex, partitionIndex int) error {
	lock, err := acquirePartitionLifecycleLock(storage, deadlineIndex, partitionIndex)
	if err != nil {
		return err
	}
	defer lock.Release()
	if frozen, err := partitionHasFrozenProofSnapshot(
		storage, PartitionKindData, deadlineIndex, partitionIndex,
	); err != nil {
		return err
	} else if frozen {
		return fmt.Errorf("frozen proof snapshot still owns the coordinate")
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return err
	}
	for _, sector := range sectors {
		if sector.Status != "deleted" && sector.PartitionAssigned &&
			sector.DeadlineIndex == deadlineIndex && sector.PartitionIndex == partitionIndex {
			return fmt.Errorf("active sector %s still owns the coordinate", sector.SectorID)
		}
	}
	for _, sector := range sectors {
		if sector.Status != "deleted" || !sector.PartitionAssigned ||
			sector.DeadlineIndex != deadlineIndex || sector.PartitionIndex != partitionIndex {
			continue
		}
		sector.PartitionAssigned = false
		sector.PartitionAssignedAt = ""
		sector.UpdatedAt = nowRFC3339()
		if err := writeSector(storage, sector); err != nil {
			return err
		}
	}
	if err := os.Remove(partitionStatePath(storage, deadlineIndex, partitionIndex)); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = clearPartitionProofRetry(storage, PartitionMeta{
		DeadlineIndex: deadlineIndex, PartitionIndex: partitionIndex, PartitionKind: PartitionKindData,
	})
	return nil
}

// runStaleDataPartitionReconciler keeps the chain's view of this keeper's data
// partitions in step with the disk, for as long as the keeper runs.
//
// cleanupStaleDataPartitionsOnChain used to be called exactly once, from startup.
// A partition that empties later therefore stays ACTIVE on chain for the rest of
// the process's life, and the delete that emptied it can then neither be proved
// nor retired:
//
//   - proving needs a live local identity, and the coordinate is now empty, so
//     selection reports "no exact selected work";
//   - retiring needs the coordinate to be chain-INACTIVE
//     (capacity_aggregate_retirement.go step 4), which is exactly what only this
//     reconciliation delivers.
//
// Live on 2026-09-29: vk_10 deleted the last sector of data:7:0 at 14:08, having
// started at 10:09. Its one pending mutation (journal seq 57) aged past the
// 1800 s hard lag with class=unowned_pending_deadline_work and
// detail="registered partition manifest changed; no exact selected work", while
// activePartitionCount still read 17 on chain and 64 MiB of free capacity stayed
// unproved with admission closed. Across all ten keepers the log line
// "deactivated stale on-chain data partition" had never appeared once.
//
// This is cheap and is not proof work: one chain read of the active data
// partitions, and one small transaction per coordinate that is genuinely stale.
// The prover is never involved, so running it on a timer costs nothing like a
// proof round. It reuses the quote reconciler's shape and its interval default so
// there is one fewer knob to reason about.
func runStaleDataPartitionReconciler(stop <-chan struct{}, cfg ServerConfig) {
	if cfg.ChainProofCmd == "" || cfg.FileRegistrationContract == "" {
		return
	}
	run := func() {
		if err := cleanupStaleDataPartitionsOnChain(cfg.Storage, cfg); err != nil {
			log.Printf("[partition] stale data cleanup warning: %v", err)
		}
	}
	run()
	interval := cfg.QuoteReservationReconcileSeconds
	if interval <= 0 {
		interval = DefaultQuoteReservationReconcileSeconds
	}
	// A partition only empties when a deletion lands, so a minute's granularity is
	// ample; the floor keeps a busy keeper from paying for this more often than it
	// can possibly matter.
	if interval < 60 {
		interval = 60
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			run()
		}
	}
}

func cleanupStaleDataPartitionsOnChain(storage string, cfg ServerConfig) error {
	if cfg.ChainProofCmd == "" || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return nil
	}
	if cfg.FileRegistrationContract == "" {
		return nil
	}
	fileReg, required, err := dataLifecycleGuardStatusOnChain(cfg.ChainProofCmd)
	if err != nil {
		return fmt.Errorf("data cleanup: guard status: %w", err)
	}
	if !required || fileReg == "" || strings.EqualFold(fileReg, "0x0000000000000000000000000000000000000000") {
		log.Printf("[partition] data cleanup skipped: StorageProofSC data lifecycle guard is not required")
		return nil
	}
	if !strings.EqualFold(fileReg, cfg.FileRegistrationContract) {
		log.Printf("[partition] data cleanup skipped: guard FileRegistrationSC mismatch chain=%s local=%s",
			fileReg, cfg.FileRegistrationContract)
		return nil
	}

	sectors, err := listSectors(storage)
	if err != nil {
		return fmt.Errorf("data cleanup: list sectors: %w", err)
	}
	pendingDeletion, err := pendingDeletionPartitionKeys(storage)
	if err != nil {
		return fmt.Errorf("data cleanup: inspect pending deletions: %w", err)
	}
	keep := map[partitionBucketKey]bool{}
	for _, p := range buildDeadlinePartitions(sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors) {
		if p.PartitionKind != PartitionKindData {
			continue
		}
		keep[partitionBucketKey{
			deadlineIndex:  p.DeadlineIndex,
			partitionIndex: p.PartitionIndex,
			kind:           p.PartitionKind,
		}] = true
	}

	onChain, err := listActiveDataPartitionsOnChain(cfg.ChainProofCmd)
	if err != nil {
		return fmt.Errorf("data cleanup: list on-chain data partitions: %w", err)
	}
	onChainKeys := map[partitionBucketKey]bool{}
	for _, p := range onChain {
		key := partitionBucketKey{
			deadlineIndex:  p.DeadlineIndex,
			partitionIndex: p.PartitionIndex,
			kind:           PartitionKindData,
		}
		onChainKeys[key] = true
		if keep[key] || pendingDeletion[key] {
			continue
		}
		tx, err := deactivatePartitionOnChain(cfg.ChainProofCmd, p.DeadlineIndex, p.PartitionIndex)
		if err != nil {
			log.Printf("[partition] stale data partition blocked by chain guard  dl=%d pt=%d err=%v",
				p.DeadlineIndex, p.PartitionIndex, err)
			continue
		}
		log.Printf("[partition] deactivated stale on-chain data partition  dl=%d pt=%d tx=%s",
			p.DeadlineIndex, p.PartitionIndex, tx)
		if err := markDataPartitionLocallyDeactivated(storage, p.DeadlineIndex, p.PartitionIndex); err != nil {
			return fmt.Errorf("mark data partition locally deactivated dl=%d pt=%d: %w",
				p.DeadlineIndex, p.PartitionIndex, err)
		}
	}
	// A deleted local coordinate may never have reached chain registration, or a
	// prior cleanup transaction may have succeeded before an RPC disconnect. The
	// authoritative active-list read above proves such a coordinate is reusable.
	seenLocal := map[partitionBucketKey]bool{}
	for _, sector := range sectors {
		if sector.Status != "deleted" || !sector.PartitionAssigned || sector.PartitionIndex >= CapacityPartitionIndexOffset {
			continue
		}
		key := partitionBucketKey{
			deadlineIndex: sector.DeadlineIndex, partitionIndex: sector.PartitionIndex, kind: PartitionKindData,
		}
		if keep[key] || onChainKeys[key] || pendingDeletion[key] || seenLocal[key] {
			continue
		}
		seenLocal[key] = true
		if err := markDataPartitionLocallyDeactivated(storage, key.deadlineIndex, key.partitionIndex); err != nil {
			return fmt.Errorf("release inactive local data partition dl=%d pt=%d: %w",
				key.deadlineIndex, key.partitionIndex, err)
		}
	}
	return nil
}

// buildDeadlinePartitions groups active sectors into deadline/partition slots.
// Persisted sector partition assignments are authoritative. Legacy sectors that
// predate partitionAssigned are packed only as a fallback until startup backfills
// their coordinates.
func buildDeadlinePartitions(sectors []SectorMeta, deadlineCount, partitionMaxSectors int) []PartitionMeta {
	return buildDeadlinePartitionsAt(sectors, deadlineCount, partitionMaxSectors, time.Now().UTC().Unix())
}

// buildDeadlinePartitionsAt constructs the active partition set at an explicit
// timestamp. Proof scheduling must use the chain's latest block timestamp; the
// wrapper above exists for standalone/local callers only.
func buildDeadlinePartitionsAt(sectors []SectorMeta, deadlineCount, partitionMaxSectors int, activeAt int64) []PartitionMeta {
	if deadlineCount <= 0 || partitionMaxSectors <= 0 {
		return nil
	}

	buckets := map[partitionBucketKey][]SectorMeta{}
	legacy := map[legacyPartitionKey][]SectorMeta{}
	for _, s := range sectors {
		if s.Status == "deleted" || s.SectorBlockCount <= 0 || s.Expiration <= activeAt {
			continue
		}
		kind := partitionKindForSector(s)
		dl := sectorPartitionDeadline(s, deadlineCount)
		s.DeadlineIndex = dl
		if validAssignedPartition(s, kind, deadlineCount) {
			key := partitionBucketKey{deadlineIndex: dl, partitionIndex: s.PartitionIndex, kind: kind}
			buckets[key] = append(buckets[key], s)
			continue
		}
		key := legacyPartitionKey{deadlineIndex: dl, kind: kind}
		legacy[key] = append(legacy[key], s)
	}

	legacyKeys := make([]legacyPartitionKey, 0, len(legacy))
	for key := range legacy {
		legacyKeys = append(legacyKeys, key)
	}
	sort.Slice(legacyKeys, func(i, j int) bool {
		if legacyKeys[i].deadlineIndex != legacyKeys[j].deadlineIndex {
			return legacyKeys[i].deadlineIndex < legacyKeys[j].deadlineIndex
		}
		return legacyKeys[i].kind < legacyKeys[j].kind
	})
	for _, key := range legacyKeys {
		secs := legacy[key]
		sort.Slice(secs, func(i, j int) bool { return secs[i].SectorID < secs[j].SectorID })
		for _, s := range secs {
			for pt := partitionBaseIndex(key.kind); pt <= partitionMaxIndex(key.kind); pt++ {
				bKey := partitionBucketKey{deadlineIndex: key.deadlineIndex, partitionIndex: pt, kind: key.kind}
				if len(buckets[bKey]) >= partitionMaxSectors {
					continue
				}
				s.DeadlineIndex = key.deadlineIndex
				s.PartitionIndex = pt
				buckets[bKey] = append(buckets[bKey], s)
				break
			}
		}
	}

	var result []PartitionMeta
	keys := make([]partitionBucketKey, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].deadlineIndex != keys[j].deadlineIndex {
			return keys[i].deadlineIndex < keys[j].deadlineIndex
		}
		if keys[i].kind != keys[j].kind {
			if keys[i].kind == PartitionKindData {
				return true
			}
			if keys[j].kind == PartitionKindData {
				return false
			}
			return keys[i].kind < keys[j].kind
		}
		return keys[i].partitionIndex < keys[j].partitionIndex
	})
	for _, key := range keys {
		batch := append([]SectorMeta(nil), buckets[key]...)
		if len(batch) == 0 {
			continue
		}
		sort.Slice(batch, func(i, j int) bool { return batch[i].SectorID < batch[j].SectorID })
		if len(batch) > partitionMaxSectors {
			batch = batch[:partitionMaxSectors]
		}
		minExp := int64(math.MaxInt64)
		var committedBytes int64
		for i := range batch {
			batch[i].DeadlineIndex = key.deadlineIndex
			batch[i].PartitionIndex = key.partitionIndex
			if batch[i].Expiration < minExp {
				minExp = batch[i].Expiration
			}
			committedBytes += committedSectorBytes(batch[i])
		}
		p := PartitionMeta{
			DeadlineIndex:  key.deadlineIndex,
			PartitionIndex: key.partitionIndex,
			PartitionKind:  key.kind,
			CommittedBytes: committedBytes,
			Sectors:        batch,
			Expiration:     minExp,
		}
		p.ContentHash = partitionContentHash(p)
		result = append(result, p)
	}
	return result
}

// duePartitions returns partitions that need a proof in round.
// It merges live sector data with persisted LastProofRound state.
func duePartitions(storage string, sectors []SectorMeta, round uint64, deadlineCount, partitionMaxSectors int) ([]PartitionMeta, error) {
	return duePartitionsAt(storage, sectors, round, deadlineCount, partitionMaxSectors, time.Now().UTC().Unix())
}

// duePartitionsAt is the chain-time-safe proof-planning entry point.
func duePartitionsAt(storage string, sectors []SectorMeta, round uint64, deadlineCount, partitionMaxSectors int, activeAt int64) ([]PartitionMeta, error) {
	urgent, scheduled, err := partitionProofPlanAt(storage, sectors, round, deadlineCount, partitionMaxSectors, activeAt)
	if err != nil {
		return nil, err
	}
	return append(urgent, scheduled...), nil
}

// partitionProofPlan separates proof work into:
//   - urgent: new partition content or content changed since the last local proof
//   - scheduled: same content, but not yet proven in the current round
//
// Urgent work is safe to prove outside the current deadline window because the
// contract keys proof validity to the current partition content hash. Scheduled
// work stays deadline-window based in the daemon to preserve the normal cadence.
func partitionProofPlan(storage string, sectors []SectorMeta, round uint64, deadlineCount, partitionMaxSectors int) ([]PartitionMeta, []PartitionMeta, error) {
	return partitionProofPlanAt(storage, sectors, round, deadlineCount, partitionMaxSectors, time.Now().UTC().Unix())
}

// partitionProofPlanAt plans proofs from the sector set active at activeAt.
// On-chain proof paths must supply chain time, never the VK host clock.
func partitionProofPlanAt(storage string, sectors []SectorMeta, round uint64, deadlineCount, partitionMaxSectors int, activeAt int64) ([]PartitionMeta, []PartitionMeta, error) {
	all := buildDeadlinePartitionsAt(sectors, deadlineCount, partitionMaxSectors, activeAt)
	var urgent []PartitionMeta
	var scheduled []PartitionMeta
	for _, p := range all {
		saved, found, err := readPartitionState(storage, p.DeadlineIndex, p.PartitionIndex)
		if err != nil {
			return nil, nil, fmt.Errorf("read partition state dl%d-pt%d: %w", p.DeadlineIndex, p.PartitionIndex, err)
		}
		if found {
			// Preserve scheduling age even when content changed. It is not part of
			// the partition commitment, but lets the daemon fairly choose among
			// continuously changing data and capacity partitions.
			p.LastProofRound = saved.LastProofRound
			p.LastProofAt = saved.LastProofAt
		}
		if !found || saved.ContentHash != p.ContentHash {
			urgent = append(urgent, p)
			continue
		}
		if saved.LastProofRound >= round {
			continue // already proved this exact partition content this round
		}
		if partitionProofIsLate(storage, p) {
			// Already past its deadline. Scheduled work waits for a window that comes
			// once per period, so a partition that missed one sits idle for a whole
			// period before it may even try — and a keeper returning from downtime
			// re-earns the same delay for every partition it missed while away. Being
			// late is itself the reason to hurry, so it joins urgent work instead.
			// Safe for the same reason urgent work is: the contract keys proof
			// validity to current content, which this proves exactly.
			urgent = append(urgent, p)
			continue
		}
		scheduled = append(scheduled, p)
	}
	return urgent, scheduled, nil
}

// partitionProofIsLate reports whether the durable proof-health record says this
// partition has already missed a recurring proof deadline.
//
// It reuses that record rather than re-deriving lateness, so there is exactly one
// definition of late in the keeper: the one the admission gate already enforces
// (a record exists only once CurrentRound exceeds LastProofRound + the chain's
// staleness threshold). The record is written atomically and read here without the
// health lock — it is a scheduling priority hint, never a correctness decision, and
// a missed read only defers the promotion by one scan.
func partitionProofIsLate(storage string, partition PartitionMeta) bool {
	_, err := os.Stat(proofHealthPath(storage, partition))
	return err == nil
}

func deadlinePartitions(partitions []PartitionMeta, deadlineIndex int) []PartitionMeta {
	out := make([]PartitionMeta, 0, len(partitions))
	for _, p := range partitions {
		if p.DeadlineIndex == deadlineIndex {
			out = append(out, p)
		}
	}
	return out
}

// markPartitionProofed records the completed proof round in partition state.
func markPartitionProofed(storage string, p PartitionMeta, round uint64) error {
	if p.ContentHash == "" {
		p.ContentHash = partitionContentHash(p)
	}
	p.LastProofRound = round
	p.LastProofAt = time.Now().Format(time.RFC3339)
	return writePartitionState(storage, p)
}

// logPartitionAssignment prints a human-readable summary of deadline/partition assignments.
func logPartitionAssignment(partitions []PartitionMeta, deadlineCount int, periodSeconds int64) {
	if len(partitions) == 0 {
		return
	}
	fmt.Printf("[partition] deadline_count=%d  proof_period_seconds=%d  deadline_duration_seconds=%d\n",
		deadlineCount, periodSeconds, periodSeconds/int64(deadlineCount))
	fmt.Printf("[partition] total_partitions=%d\n", len(partitions))
	for _, p := range partitions {
		sectorIDs := make([]string, len(p.Sectors))
		for i, s := range p.Sectors {
			sectorIDs[i] = s.SectorID
		}
		fmt.Printf("[partition] dl=%d pt=%d kind=%s committed=%d  sectors=%d  exp=%d  ids=%v\n",
			p.DeadlineIndex, p.PartitionIndex, p.PartitionKind, p.CommittedBytes, len(p.Sectors), p.Expiration, sectorIDs)
	}
}
