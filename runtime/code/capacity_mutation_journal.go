package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const capacityMutationJournalVersion = 1

const (
	capacityMutationStatusPlanned   = "planned"
	capacityMutationStatusApplied   = "applied"
	capacityMutationStatusSealed    = "sealed"
	capacityMutationStatusIncluded  = "included"
	capacityMutationStatusAbandoned = "abandoned"
	// resolved is terminal bookkeeping, not proof inclusion. It is used after a block-pinned
	// reconciliation proves either an aggregate rebuild's complete set or one orphaned exact
	// mutation's current successor is already freshly certified.
	capacityMutationStatusResolved = "resolved"
)

type capacityMutationSectorState struct {
	Exists         bool   `json:"exists"`
	SectorID       string `json:"sectorId,omitempty"`
	PartitionKind  string `json:"partitionKind,omitempty"`
	DeadlineIndex  int    `json:"deadlineIndex,omitempty"`
	PartitionIndex int    `json:"partitionIndex,omitempty"`
	ContentHash    string `json:"contentHash,omitempty"`
	CommittedBytes int64  `json:"committedBytes,omitempty"`
	Status         string `json:"status,omitempty"`
}

type capacityMutationTransition struct {
	Old capacityMutationSectorState `json:"old"`
	New capacityMutationSectorState `json:"new"`
}

type capacityMutationJournalRecord struct {
	Version                     int                          `json:"version"`
	Sequence                    uint64                       `json:"sequence"`
	OperationID                 string                       `json:"operationId"`
	MutationType                string                       `json:"mutationType"`
	AffectedBytes               int64                        `json:"affectedBytes"`
	Transitions                 []capacityMutationTransition `json:"transitions,omitempty"`
	Status                      string                       `json:"status"`
	InclusionEpochID            uint64                       `json:"inclusionEpochId,omitempty"`
	CoverageManifestFingerprint string                       `json:"coverageManifestFingerprint,omitempty"`
	CoverageSnapshotIDs         []string                     `json:"coverageSnapshotIds,omitempty"`
	ResolutionReason            string                       `json:"resolutionReason,omitempty"`
	ResolutionObservationBlock  uint64                       `json:"resolutionObservationBlock,omitempty"`
	ResolutionIdentitySetHash   string                       `json:"resolutionIdentitySetHash,omitempty"`
	ResolutionPartitionCount    uint32                       `json:"resolutionPartitionCount,omitempty"`
	ResolutionCertifiedBytes    uint64                       `json:"resolutionCertifiedBytes,omitempty"`
	ResolutionOldestProvedAt    uint64                       `json:"resolutionOldestProvedAt,omitempty"`
	CreatedAt                   string                       `json:"createdAt"`
	UpdatedAt                   string                       `json:"updatedAt"`
}

type capacityMutationJournalHead struct {
	Version        int    `json:"version"`
	LastSequence   uint64 `json:"lastSequence"`
	IndexedThrough uint64 `json:"indexedThrough,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
}

func capacityMutationJournalRoot(storage string) string {
	return filepath.Join(capacityCoordinationDir(storage), "mutation-journal")
}

func capacityMutationJournalRecordDir(storage string) string {
	return filepath.Join(capacityMutationJournalRoot(storage), "records")
}

func capacityMutationJournalIndexDir(storage string) string {
	return filepath.Join(capacityMutationJournalRoot(storage), "operations")
}

func capacityMutationJournalPendingDir(storage string) string {
	return filepath.Join(capacityMutationJournalRoot(storage), "pending")
}

func capacityMutationJournalPendingPath(storage string, sequence uint64) string {
	return filepath.Join(capacityMutationJournalPendingDir(storage), fmt.Sprintf("%020d.pending", sequence))
}

func capacityMutationJournalHeadPath(storage string) string {
	return filepath.Join(capacityMutationJournalRoot(storage), "head.json")
}

func capacityMutationJournalRecordPath(storage string, sequence uint64) string {
	return filepath.Join(
		capacityMutationJournalRecordDir(storage), fmt.Sprintf("%08d", sequence/10_000),
		fmt.Sprintf("%020d.json", sequence),
	)
}

func capacityMutationJournalIndexPath(storage, operationID string) string {
	hash := lifecycleOperationID(operationID)
	return filepath.Join(capacityMutationJournalIndexDir(storage), hash[:2], hash+".json")
}

func validateCapacityMutationJournalRecord(record capacityMutationJournalRecord) error {
	if record.Version != capacityMutationJournalVersion || record.Sequence == 0 ||
		strings.TrimSpace(record.OperationID) == "" || strings.TrimSpace(record.MutationType) == "" {
		return fmt.Errorf("capacity mutation journal identity/version is invalid")
	}
	switch record.Status {
	case capacityMutationStatusPlanned, capacityMutationStatusApplied,
		capacityMutationStatusSealed, capacityMutationStatusIncluded,
		capacityMutationStatusAbandoned, capacityMutationStatusResolved:
	default:
		return fmt.Errorf("capacity mutation %d has invalid status %q", record.Sequence, record.Status)
	}
	if record.Status == capacityMutationStatusSealed && record.InclusionEpochID == 0 {
		return fmt.Errorf("sealed capacity mutation %d has no inclusion epoch", record.Sequence)
	}
	if (record.Status == capacityMutationStatusSealed || record.Status == capacityMutationStatusIncluded) &&
		(record.CoverageManifestFingerprint == "" || len(record.CoverageSnapshotIDs) == 0) {
		return fmt.Errorf("capacity mutation %d has no exact epoch coverage evidence", record.Sequence)
	}
	if record.Status == capacityMutationStatusIncluded && record.InclusionEpochID == 0 {
		return fmt.Errorf("included capacity mutation %d has no inclusion epoch", record.Sequence)
	}
	if record.Status == capacityMutationStatusResolved {
		validResolution := (record.MutationType == "capacity_rebuild" &&
			record.ResolutionReason == capacityAggregateResolutionReason) ||
			record.ResolutionReason == capacityExactMutationResolutionReason ||
			record.ResolutionReason == capacityAbsentSuccessorResolutionReason
		if !validResolution ||
			record.ResolutionObservationBlock == 0 || record.ResolutionPartitionCount == 0 {
			return fmt.Errorf("resolved capacity mutation %d has incomplete terminal evidence", record.Sequence)
		}
		// An ABSENT successor has nothing to certify and nothing that was ever proved. Its
		// evidence must therefore carry zero certified bytes and zero proved-at — asserted
		// positively, so an absence resolution can never borrow a certification's numbers, and
		// a certified resolution can never omit them.
		if record.ResolutionReason == capacityAbsentSuccessorResolutionReason {
			if record.ResolutionCertifiedBytes != 0 || record.ResolutionOldestProvedAt != 0 {
				return fmt.Errorf(
					"absent-successor capacity mutation %d falsely carries certification evidence",
					record.Sequence)
			}
		} else if record.ResolutionCertifiedBytes == 0 || record.ResolutionOldestProvedAt == 0 {
			return fmt.Errorf("resolved capacity mutation %d has incomplete terminal evidence", record.Sequence)
		}
		if _, err := strictPartitionBytes32(record.ResolutionIdentitySetHash,
			"aggregate resolution identity-set hash"); err != nil {
			return fmt.Errorf("resolved capacity mutation %d: %w", record.Sequence, err)
		}
		if record.InclusionEpochID != 0 || record.CoverageManifestFingerprint != "" ||
			len(record.CoverageSnapshotIDs) != 0 {
			return fmt.Errorf("resolved capacity mutation %d falsely carries proof inclusion evidence", record.Sequence)
		}
	}
	return nil
}

func readCapacityMutationJournalRecord(storage string, sequence uint64) (capacityMutationJournalRecord, bool, error) {
	var record capacityMutationJournalRecord
	payload, err := os.ReadFile(capacityMutationJournalRecordPath(storage, sequence))
	if os.IsNotExist(err) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := json.Unmarshal(payload, &record); err != nil {
		return record, true, fmt.Errorf("decode capacity mutation %d: %w", sequence, err)
	}
	if err := validateCapacityMutationJournalRecord(record); err != nil {
		return record, true, err
	}
	return record, true, nil
}

func writeCapacityMutationJournalRecord(storage string, record capacityMutationJournalRecord) error {
	if record.Version == 0 {
		record.Version = capacityMutationJournalVersion
	}
	if record.CreatedAt == "" {
		record.CreatedAt = nowRFC3339()
	}
	record.UpdatedAt = nowRFC3339()
	if err := validateCapacityMutationJournalRecord(record); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := durableAtomicWriteFile(capacityMutationJournalRecordPath(storage, record.Sequence), payload, 0600); err != nil {
		return err
	}
	pendingPath := capacityMutationJournalPendingPath(storage, record.Sequence)
	if record.Status == capacityMutationStatusIncluded || record.Status == capacityMutationStatusAbandoned ||
		record.Status == capacityMutationStatusResolved {
		return durableRemoveCapacityMutationRecord(pendingPath)
	}
	return durableAtomicWriteFile(pendingPath, []byte(fmt.Sprintf("%d\n", record.Sequence)), 0600)
}

func readCapacityMutationJournalHead(storage string) (capacityMutationJournalHead, error) {
	head := capacityMutationJournalHead{Version: capacityMutationJournalVersion}
	payload, err := os.ReadFile(capacityMutationJournalHeadPath(storage))
	if os.IsNotExist(err) {
		return head, nil
	}
	if err != nil {
		return head, err
	}
	if json.Unmarshal(payload, &head) != nil || head.Version != capacityMutationJournalVersion ||
		head.IndexedThrough > head.LastSequence {
		return head, fmt.Errorf("capacity mutation journal head is invalid")
	}
	return head, nil
}

func writeCapacityMutationJournalHead(storage string, head capacityMutationJournalHead) error {
	head.Version = capacityMutationJournalVersion
	head.UpdatedAt = nowRFC3339()
	payload, err := json.MarshalIndent(head, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(capacityMutationJournalHeadPath(storage), payload, 0600)
}

func readCapacityMutationSequenceIndex(storage, operationID string) (uint64, bool, error) {
	payload, err := os.ReadFile(capacityMutationJournalIndexPath(storage, operationID))
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var indexed struct {
		Sequence uint64 `json:"sequence"`
	}
	if json.Unmarshal(payload, &indexed) != nil || indexed.Sequence == 0 {
		return 0, true, fmt.Errorf("capacity mutation operation index is invalid")
	}
	return indexed.Sequence, true, nil
}

func allocateCapacityMutationSequenceUnlocked(storage string) (uint64, error) {
	head, err := readCapacityMutationJournalHead(storage)
	if err != nil {
		return 0, err
	}
	if head.LastSequence == ^uint64(0) {
		return 0, fmt.Errorf("capacity mutation sequence overflow")
	}
	head.LastSequence++
	if err := writeCapacityMutationJournalHead(storage, head); err != nil {
		return 0, err
	}
	return head.LastSequence, nil
}

func repairCapacityMutationPendingIndexUnlocked(storage string) error {
	head, err := readCapacityMutationJournalHead(storage)
	if err != nil {
		return err
	}
	if head.IndexedThrough >= head.LastSequence {
		return nil
	}
	for sequence := head.IndexedThrough + 1; sequence <= head.LastSequence; sequence++ {
		record, found, readErr := readCapacityMutationJournalRecord(storage, sequence)
		if readErr != nil {
			return readErr
		}
		if found && record.Status != capacityMutationStatusIncluded &&
			record.Status != capacityMutationStatusAbandoned && record.Status != capacityMutationStatusResolved {
			if err := durableAtomicWriteFile(
				capacityMutationJournalPendingPath(storage, sequence),
				[]byte(fmt.Sprintf("%d\n", sequence)), 0600,
			); err != nil {
				return err
			}
		}
		if sequence == ^uint64(0) {
			break
		}
	}
	head.IndexedThrough = head.LastSequence
	return writeCapacityMutationJournalHead(storage, head)
}

func getOrCreateCapacityMutationRecordUnlocked(
	storage, operationID, mutationType string,
) (capacityMutationJournalRecord, error) {
	if sequence, found, err := readCapacityMutationSequenceIndex(storage, operationID); err != nil {
		return capacityMutationJournalRecord{}, err
	} else if found {
		record, recordFound, readErr := readCapacityMutationJournalRecord(storage, sequence)
		if readErr != nil {
			return capacityMutationJournalRecord{}, readErr
		}
		if !recordFound || record.OperationID != operationID || record.MutationType != mutationType {
			return capacityMutationJournalRecord{}, fmt.Errorf("capacity mutation operation index mismatch")
		}
		if record.Status == capacityMutationStatusAbandoned {
			// The same durable lifecycle may be retried after an earlier attempt
			// stopped before changing local state. Reuse its identity and sequence;
			// never allocate a duplicate capacity mutation.
			record.Status = capacityMutationStatusPlanned
			record.Transitions = nil
			record.AffectedBytes = 0
			record.InclusionEpochID = 0
			record.CoverageManifestFingerprint = ""
			record.CoverageSnapshotIDs = nil
			if err := writeCapacityMutationJournalRecord(storage, record); err != nil {
				return capacityMutationJournalRecord{}, err
			}
		}
		return record, nil
	}
	if err := repairCapacityMutationPendingIndexUnlocked(storage); err != nil {
		return capacityMutationJournalRecord{}, err
	}
	if pending, err := listPendingCapacityMutationJournalRecordsUnlocked(storage); err != nil {
		return capacityMutationJournalRecord{}, err
	} else {
		for _, record := range pending {
			if record.OperationID != operationID {
				continue
			}
			indexPayload, _ := json.MarshalIndent(struct {
				Sequence uint64 `json:"sequence"`
			}{Sequence: record.Sequence}, "", "  ")
			if err := durableAtomicWriteFile(capacityMutationJournalIndexPath(storage, operationID), indexPayload, 0600); err != nil {
				return capacityMutationJournalRecord{}, err
			}
			return record, nil
		}
	}
	sequence, err := allocateCapacityMutationSequenceUnlocked(storage)
	if err != nil {
		return capacityMutationJournalRecord{}, err
	}
	now := nowRFC3339()
	record := capacityMutationJournalRecord{
		Version: capacityMutationJournalVersion, Sequence: sequence,
		OperationID: operationID, MutationType: mutationType,
		Status: capacityMutationStatusPlanned, CreatedAt: now, UpdatedAt: now,
	}
	if err := writeCapacityMutationJournalRecord(storage, record); err != nil {
		return capacityMutationJournalRecord{}, err
	}
	indexPayload, _ := json.MarshalIndent(struct {
		Sequence uint64 `json:"sequence"`
	}{Sequence: sequence}, "", "  ")
	if err := durableAtomicWriteFile(capacityMutationJournalIndexPath(storage, operationID), indexPayload, 0600); err != nil {
		return capacityMutationJournalRecord{}, err
	}
	head, err := readCapacityMutationJournalHead(storage)
	if err != nil {
		return capacityMutationJournalRecord{}, err
	}
	if head.IndexedThrough < sequence {
		head.IndexedThrough = sequence
		if err := writeCapacityMutationJournalHead(storage, head); err != nil {
			return capacityMutationJournalRecord{}, err
		}
	}
	return record, nil
}

func beginCapacityMutationOperation(storage, operationID, mutationType string) (*capacityMutationLease, error) {
	operationID = strings.TrimSpace(operationID)
	mutationType = strings.TrimSpace(mutationType)
	if operationID == "" || mutationType == "" {
		return nil, fmt.Errorf("durable capacity mutation requires operation identity and type")
	}
	lease, err := beginCapacityMutation(storage, mutationType)
	if err != nil {
		return nil, err
	}
	err = withCapacityCoordinationLock(storage, func() error {
		record, err := getOrCreateCapacityMutationRecordUnlocked(storage, operationID, mutationType)
		if err != nil {
			return err
		}
		lease.operationID = operationID
		lease.journalSequence = record.Sequence
		return nil
	})
	if err != nil {
		lease.Release()
		return nil, err
	}
	return lease, nil
}

func storeCapacityMutationOperationID(commitmentHash, pieceRoot string) string {
	identity := strings.ToLower(strings.TrimSpace(commitmentHash))
	if identity == "" {
		identity = "legacy-piece:" + strings.ToLower(strings.TrimSpace(pieceRoot))
	}
	return "store:" + identity
}

func storeRollbackCapacityMutationOperationID(commitmentHash, pieceRoot string) string {
	return "rollback:" + storeCapacityMutationOperationID(commitmentHash, pieceRoot)
}

func capacityMutationStateForSector(sector SectorMeta, exists bool) capacityMutationSectorState {
	kind := PartitionKindData
	if sector.IsCapacity {
		kind = PartitionKindCapacity
	}
	committedBytes := committedSectorBytes(sector)
	contentHash := partitionContentHash(PartitionMeta{
		DeadlineIndex: sector.DeadlineIndex, PartitionIndex: sector.PartitionIndex,
		PartitionKind: kind, Sectors: []SectorMeta{sector}, CommittedBytes: committedBytes,
	})
	if !exists {
		committedBytes = 0
		contentHash = ""
	}
	return capacityMutationSectorState{
		Exists: exists, SectorID: sector.SectorID, PartitionKind: kind,
		DeadlineIndex: sector.DeadlineIndex, PartitionIndex: sector.PartitionIndex,
		ContentHash: contentHash, CommittedBytes: committedBytes, Status: sector.Status,
	}
}

func (lease *capacityMutationLease) PrepareSectorTransition(oldState, newState capacityMutationSectorState) error {
	if lease == nil || lease.journalSequence == 0 {
		return nil
	}
	return withCapacityCoordinationLock(lease.storage, func() error {
		record, found, err := readCapacityMutationJournalRecord(lease.storage, lease.journalSequence)
		if err != nil || !found {
			return err
		}
		if record.Status != capacityMutationStatusPlanned {
			return nil
		}
		for _, transition := range record.Transitions {
			if transition.Old == oldState && transition.New == newState {
				return nil
			}
		}
		record.Transitions = append(record.Transitions, capacityMutationTransition{Old: oldState, New: newState})
		record.AffectedBytes += newState.CommittedBytes - oldState.CommittedBytes
		return writeCapacityMutationJournalRecord(lease.storage, record)
	})
}

func (lease *capacityMutationLease) JournalSequence() uint64 {
	if lease == nil {
		return 0
	}
	return lease.journalSequence
}

// OperationID exposes the stable upload-operation identity this lease was opened with. B.1 binds
// a sector-cap reservation to it so a retry of the same operation reuses its reservation.
func (lease *capacityMutationLease) OperationID() string {
	if lease == nil {
		return ""
	}
	return lease.operationID
}

func (lease *capacityMutationLease) Complete() error {
	if lease == nil || lease.journalSequence == 0 {
		return nil
	}
	return withCapacityCoordinationLock(lease.storage, func() error {
		record, found, err := readCapacityMutationJournalRecord(lease.storage, lease.journalSequence)
		if err != nil || !found {
			return err
		}
		if record.Status == capacityMutationStatusApplied || record.Status == capacityMutationStatusSealed ||
			record.Status == capacityMutationStatusIncluded {
			return nil
		}
		if record.Status != capacityMutationStatusPlanned {
			return fmt.Errorf("capacity mutation %d cannot complete from %s", record.Sequence, record.Status)
		}
		if len(record.Transitions) == 0 {
			record.Status = capacityMutationStatusAbandoned
		} else {
			record.Status = capacityMutationStatusApplied
		}
		return writeCapacityMutationJournalRecord(lease.storage, record)
	})
}

func (lease *capacityMutationLease) FinalizePreparedTransition(newState capacityMutationSectorState) error {
	if lease == nil || lease.journalSequence == 0 {
		return nil
	}
	return withCapacityCoordinationLock(lease.storage, func() error {
		record, found, err := readCapacityMutationJournalRecord(lease.storage, lease.journalSequence)
		if err != nil || !found {
			return err
		}
		if record.Status != capacityMutationStatusPlanned {
			return nil
		}
		if len(record.Transitions) == 0 {
			return fmt.Errorf("capacity mutation %d has no prepared transition", record.Sequence)
		}
		index := len(record.Transitions) - 1
		record.AffectedBytes -= record.Transitions[index].New.CommittedBytes - record.Transitions[index].Old.CommittedBytes
		record.Transitions[index].New = newState
		record.AffectedBytes += newState.CommittedBytes - record.Transitions[index].Old.CommittedBytes
		return writeCapacityMutationJournalRecord(lease.storage, record)
	})
}

func (lease *capacityMutationLease) Abandon() error {
	if lease == nil || lease.journalSequence == 0 {
		return nil
	}
	return withCapacityCoordinationLock(lease.storage, func() error {
		record, found, err := readCapacityMutationJournalRecord(lease.storage, lease.journalSequence)
		if err != nil || !found {
			return err
		}
		if record.Status != capacityMutationStatusPlanned || len(record.Transitions) != 0 {
			return nil
		}
		record.Status = capacityMutationStatusAbandoned
		return writeCapacityMutationJournalRecord(lease.storage, record)
	})
}

func capacityMutationSectorStateMatches(storage string, want capacityMutationSectorState) (bool, error) {
	if want.SectorID == "" {
		return false, nil
	}
	sector, err := readSector(storage, want.SectorID)
	if os.IsNotExist(err) {
		return !want.Exists, nil
	}
	if err != nil {
		return false, err
	}
	if !want.Exists {
		return sector.Status == "deleted", nil
	}
	got := capacityMutationStateForSector(sector, true)
	return got.SectorID == want.SectorID && got.PartitionKind == want.PartitionKind &&
		got.DeadlineIndex == want.DeadlineIndex && got.PartitionIndex == want.PartitionIndex &&
		got.CommittedBytes == want.CommittedBytes && got.Status == want.Status &&
		sameRoot(got.ContentHash, want.ContentHash), nil
}

// ReconcilePlannedFromLocalState closes the crash window between persisting a
// transition and marking it applied. Callers invoke it from the owning durable
// lifecycle retry, after acquiring that operation's locks.
func (lease *capacityMutationLease) ReconcilePlannedFromLocalState() (bool, error) {
	if lease == nil || lease.journalSequence == 0 {
		return true, nil
	}
	resolved := false
	err := withCapacityCoordinationLock(lease.storage, func() error {
		record, found, err := readCapacityMutationJournalRecord(lease.storage, lease.journalSequence)
		if err != nil || !found {
			return err
		}
		if record.Status != capacityMutationStatusPlanned {
			resolved = true
			return nil
		}
		if len(record.Transitions) == 0 {
			return nil
		}
		allOld, allNew := true, true
		for _, transition := range record.Transitions {
			oldMatches, matchErr := capacityMutationSectorStateMatches(lease.storage, transition.Old)
			if matchErr != nil {
				return matchErr
			}
			newMatches, matchErr := capacityMutationSectorStateMatches(lease.storage, transition.New)
			if matchErr != nil {
				return matchErr
			}
			allOld = allOld && oldMatches
			allNew = allNew && newMatches
		}
		if allNew {
			record.Status = capacityMutationStatusApplied
			resolved = true
		} else if allOld {
			record.Status = capacityMutationStatusAbandoned
			resolved = true
		} else {
			return nil
		}
		return writeCapacityMutationJournalRecord(lease.storage, record)
	})
	return resolved, err
}

func listCapacityMutationJournalRecordsUnlocked(storage string) ([]capacityMutationJournalRecord, error) {
	shards, err := os.ReadDir(capacityMutationJournalRecordDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]capacityMutationJournalRecord, 0)
	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}
		entries, readErr := os.ReadDir(filepath.Join(capacityMutationJournalRecordDir(storage), shard.Name()))
		if readErr != nil {
			return nil, readErr
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			var sequence uint64
			if _, err := fmt.Sscanf(entry.Name(), "%d.json", &sequence); err != nil || sequence == 0 {
				return nil, fmt.Errorf("invalid capacity mutation journal filename %q", entry.Name())
			}
			record, found, err := readCapacityMutationJournalRecord(storage, sequence)
			if err != nil {
				return nil, err
			}
			if found {
				records = append(records, record)
			}
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
	return records, nil
}

func plannedCapacityMutationRecordsUnlocked(storage string) ([]capacityMutationJournalRecord, error) {
	if err := repairCapacityMutationPendingIndexUnlocked(storage); err != nil {
		return nil, err
	}
	records, err := listPendingCapacityMutationJournalRecordsUnlocked(storage)
	if err != nil {
		return nil, err
	}
	out := make([]capacityMutationJournalRecord, 0)
	for _, record := range records {
		if record.Status == capacityMutationStatusPlanned {
			out = append(out, record)
		}
	}
	return out, nil
}

func listPendingCapacityMutationJournalRecordsUnlocked(storage string) ([]capacityMutationJournalRecord, error) {
	entries, err := os.ReadDir(capacityMutationJournalPendingDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]capacityMutationJournalRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pending" {
			continue
		}
		var sequence uint64
		if _, err := fmt.Sscanf(entry.Name(), "%d.pending", &sequence); err != nil || sequence == 0 {
			return nil, fmt.Errorf("invalid pending capacity mutation filename %q", entry.Name())
		}
		record, found, err := readCapacityMutationJournalRecord(storage, sequence)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("pending capacity mutation %d has no durable record", sequence)
		}
		if record.Status != capacityMutationStatusIncluded &&
			record.Status != capacityMutationStatusAbandoned && record.Status != capacityMutationStatusResolved {
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
	return records, nil
}

func capacityMutationHighWatermarkUnlocked(storage string) (uint64, error) {
	head, err := readCapacityMutationJournalHead(storage)
	if err != nil {
		return 0, err
	}
	return head.LastSequence, nil
}

type capacityMutationEpochCoverage struct {
	sectorStates      map[string]capacityMutationSectorState
	snapshotIDs       map[string]string
	capacityAggregate capacityMutationSectorState
}

func loadCapacityMutationEpochCoverage(
	storage string,
	journal capacityEpochJournal,
) (capacityMutationEpochCoverage, error) {
	coverage := capacityMutationEpochCoverage{
		sectorStates: make(map[string]capacityMutationSectorState),
		snapshotIDs:  make(map[string]string),
		capacityAggregate: capacityMutationSectorState{
			Exists: true, PartitionKind: PartitionKindCapacity,
			DeadlineIndex: -1, PartitionIndex: -1, Status: "capacity_backing",
		},
	}
	capacitySectors := 0
	for _, member := range journal.Members {
		queue, found, err := readPartitionProofSnapshotQueue(
			storage, member.PartitionKind, member.DeadlineIndex, member.PartitionIndex,
		)
		if err != nil {
			return coverage, err
		}
		if !found || queue.Frozen == nil || queue.Frozen.ProofEpochID != journal.EpochID ||
			queue.Frozen.ID != member.SnapshotID || !sameRoot(queue.Frozen.ContentHash, member.ContentHash) {
			return coverage, fmt.Errorf(
				"capacity mutation epoch %d has no exact frozen coverage for %s dl%d-pt%d",
				journal.EpochID, member.PartitionKind, member.DeadlineIndex, member.PartitionIndex,
			)
		}
		coverage.snapshotIDs[member.SnapshotID] = member.ContentHash
		for _, sector := range queue.Frozen.Partition.Sectors {
			state := capacityMutationStateForSector(sector, true)
			coverage.sectorStates[sector.SectorID] = state
			if member.PartitionKind == PartitionKindCapacity {
				capacitySectors++
				coverage.capacityAggregate.CommittedBytes += state.CommittedBytes
			}
		}
	}
	coverage.capacityAggregate.ContentHash = fmt.Sprintf(
		"capacity:%d:%d", coverage.capacityAggregate.CommittedBytes, capacitySectors,
	)
	return coverage, nil
}

func capacityMutationStateEqual(a, b capacityMutationSectorState) bool {
	return a.Exists == b.Exists && a.SectorID == b.SectorID &&
		a.PartitionKind == b.PartitionKind && a.DeadlineIndex == b.DeadlineIndex &&
		a.PartitionIndex == b.PartitionIndex && a.CommittedBytes == b.CommittedBytes &&
		a.Status == b.Status && sameRoot(a.ContentHash, b.ContentHash)
}

func capacityMutationStateCovered(
	state capacityMutationSectorState,
	currentSequence, cutoff uint64,
	records []capacityMutationJournalRecord,
	coverage capacityMutationEpochCoverage,
	visited map[uint64]bool,
) bool {
	if state.SectorID == "" && state.PartitionKind == PartitionKindCapacity {
		return capacityMutationStateEqual(state, coverage.capacityAggregate)
	}
	if state.Exists {
		if frozen, found := coverage.sectorStates[state.SectorID]; found && capacityMutationStateEqual(state, frozen) {
			return true
		}
	} else if _, found := coverage.sectorStates[state.SectorID]; !found {
		return true
	}
	for _, later := range records {
		if later.Sequence <= currentSequence || later.Sequence > cutoff || visited[later.Sequence] ||
			(later.Status != capacityMutationStatusApplied && later.Status != capacityMutationStatusSealed) {
			continue
		}
		for _, transition := range later.Transitions {
			if !capacityMutationStateEqual(state, transition.Old) {
				continue
			}
			visited[later.Sequence] = true
			if capacityMutationStateCovered(transition.New, later.Sequence, cutoff, records, coverage, visited) {
				return true
			}
		}
		// A capacity rebuild is an exact full-capacity successor. It may recreate
		// a stable slot ID after an expired capacity sector was removed.
		if state.PartitionKind == PartitionKindCapacity && later.MutationType == "capacity_rebuild" &&
			len(later.Transitions) > 0 {
			visited[later.Sequence] = true
			if capacityMutationStateCovered(
				later.Transitions[len(later.Transitions)-1].New,
				later.Sequence, cutoff, records, coverage, visited,
			) {
				return true
			}
		}
	}
	return false
}

func reconcileCapacityMutationEpochUnlocked(
	storage string,
	journal capacityEpochJournal,
	terminal string,
) error {
	if err := repairCapacityMutationPendingIndexUnlocked(storage); err != nil {
		return err
	}
	records, err := listPendingCapacityMutationJournalRecordsUnlocked(storage)
	if err != nil {
		return err
	}
	failedEpoch := terminal == capacityEpochStateAborted || terminal == capacityEpochStateAbandoned
	incrementalEpoch := journal.EpochID&incrementalCapacityAuthorityFlag != 0
	// Incremental campaigns seal their exact covered subset before their first
	// proof is accepted, while every frozen input is still present. After progress
	// begins, a successful proof worker may consume its queue entry. Reloading the
	// whole manifest then would reject that correctly consumed member merely
	// because unrelated pre-cutoff mutations remain applied. From that point only
	// finalize records already sealed to this exact epoch; unrelated applied work
	// remains pending for the next production selection. Full sweeps keep their
	// strict all-at-cutoff coverage check in every state.
	//
	// `journal.ProvenPartitions` alone is not a reliable "progress has begun" signal: it is
	// refreshed from chain status, so there is a window — and, when the refresh lags, a
	// permanent state — in which a proof has already been accepted and its frozen queue entry
	// consumed while the counter still reads zero. An incremental epoch legitimately leaves
	// pre-cutoff mutations applied (they fall outside its exact manifest), so `needsCoverage`
	// stays true forever, and every later pass then demands a frozen input that the accepted
	// proof correctly consumed. That deadlocks reconciliation permanently.
	//
	// Sealing to this exact epoch is the durable, local, already-observed record that the
	// covered subset was taken while the manifest was whole. It is therefore the authoritative
	// "inputs may now be consumed" signal. Honouring it can only ever seal FEWER records, never
	// more: anything left applied stays pending for the next legally eligible proof, so no
	// mutation is retired without exact frozen coverage.
	sealedToThisEpoch := false
	for _, record := range records {
		if record.Status == capacityMutationStatusSealed && record.InclusionEpochID == journal.EpochID {
			sealedToThisEpoch = true
			break
		}
	}
	maySealApplied := !failedEpoch && (!incrementalEpoch ||
		(terminal == capacityEpochStateActive && journal.ProvenPartitions == 0 && !sealedToThisEpoch))
	needsCoverage := false
	for _, record := range records {
		if maySealApplied && record.Sequence <= journal.MutationCutoffSequence && record.Status == capacityMutationStatusApplied {
			needsCoverage = true
			break
		}
	}
	coverage := capacityMutationEpochCoverage{}
	if needsCoverage {
		var coverageErr error
		coverage, coverageErr = loadCapacityMutationEpochCoverage(storage, journal)
		if coverageErr != nil && terminal != capacityEpochStateAborted && terminal != capacityEpochStateAbandoned {
			return coverageErr
		}
	}
	for _, record := range records {
		changed := false
		if maySealApplied && record.Sequence <= journal.MutationCutoffSequence && record.Status == capacityMutationStatusApplied {
			covered := len(record.Transitions) > 0
			for _, transition := range record.Transitions {
				if !capacityMutationStateCovered(
					transition.New, record.Sequence, journal.MutationCutoffSequence,
					records, coverage, map[uint64]bool{record.Sequence: true},
				) {
					covered = false
					break
				}
			}
			if !covered {
				// An incremental campaign intentionally freezes only its selected
				// partitions. Mutations whose successor state is outside that exact
				// manifest remain applied for the next selection pass; treating them
				// as a corrupt cutoff would make a frozen chunk impossible to finish
				// whenever new work arrived before it opened. A full sweep still must
				// cover every mutation at or before its high-water mark.
				if journal.EpochID&incrementalCapacityAuthorityFlag != 0 {
					continue
				}
				return fmt.Errorf(
					"capacity mutation %d result is not covered by epoch %d immutable snapshots",
					record.Sequence, journal.EpochID,
				)
			}
			record.Status = capacityMutationStatusSealed
			record.InclusionEpochID = journal.EpochID
			record.CoverageManifestFingerprint = journal.ManifestFingerprint
			record.CoverageSnapshotIDs = record.CoverageSnapshotIDs[:0]
			for snapshotID := range coverage.snapshotIDs {
				record.CoverageSnapshotIDs = append(record.CoverageSnapshotIDs, snapshotID)
			}
			sort.Strings(record.CoverageSnapshotIDs)
			changed = true
		}
		if record.InclusionEpochID == journal.EpochID && record.Status == capacityMutationStatusSealed {
			switch terminal {
			case capacityEpochStateCompleted:
				if record.Sequence > journal.MutationCutoffSequence ||
					record.CoverageManifestFingerprint != journal.ManifestFingerprint ||
					len(record.CoverageSnapshotIDs) == 0 {
					return fmt.Errorf("capacity mutation %d has invalid completion coverage", record.Sequence)
				}
				memberIDs := make(map[string]bool, len(journal.Members))
				for _, member := range journal.Members {
					memberIDs[member.SnapshotID] = true
				}
				for _, snapshotID := range record.CoverageSnapshotIDs {
					if !memberIDs[snapshotID] {
						return fmt.Errorf(
							"capacity mutation %d references snapshot outside epoch %d manifest",
							record.Sequence, journal.EpochID,
						)
					}
				}
				record.Status = capacityMutationStatusIncluded
				changed = true
			case capacityEpochStateAborted, capacityEpochStateAbandoned:
				record.Status = capacityMutationStatusApplied
				record.InclusionEpochID = 0
				record.CoverageManifestFingerprint = ""
				record.CoverageSnapshotIDs = nil
				changed = true
			}
		}
		if changed {
			if err := writeCapacityMutationJournalRecord(storage, record); err != nil {
				return err
			}
		}
	}
	return nil
}
