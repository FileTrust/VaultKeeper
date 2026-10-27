package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	proofHealthRecordVersion       = 2
	legacyProofHealthRecordVersion = 1

	proofHealthFailureFirstProofMissed = "first_proof_missed"
	proofHealthFailureRecurringLapsed  = "recurring_proof_lapsed"

	// DefaultRecurringProofStalenessRounds matches StorageReceiptDispute's
	// deployment default. Production callers should supply the value read from
	// the deployed dispute contract so governance changes take effect locally.
	DefaultRecurringProofStalenessRounds uint64 = 2
)

// ProofHealthPolicy contains the chain policy needed to decide whether a
// previously proved partition has lapsed. The contract considers a proof
// lapsed when currentRound > lastProofRound + threshold.
type ProofHealthPolicy struct {
	RecurringProofStalenessRounds uint64
}

// proofHealthFailure is per VK and per exact partition content. Ordinary
// queued/building work never creates this record. Version 2 distinguishes a
// missed first proof for new content from a recurring proof that has lapsed.
// Fields retained from version 1 preserve backward compatibility on restart.
type proofHealthFailure struct {
	Version            int    `json:"version"`
	FailureKind        string `json:"failureKind,omitempty"`
	PartitionKind      string `json:"partitionKind"`
	DeadlineIndex      int    `json:"deadlineIndex"`
	PartitionIndex     int    `json:"partitionIndex"`
	ContentHash        string `json:"contentHash"`
	RegisteredAt       uint64 `json:"registeredAt,omitempty"`
	HardDeadline       uint64 `json:"hardDeadline,omitempty"`
	LastProofRound     uint64 `json:"lastProofRound,omitempty"`
	CurrentRound       uint64 `json:"currentRound,omitempty"`
	StalenessThreshold uint64 `json:"stalenessThreshold,omitempty"`
	ObservedAt         uint64 `json:"observedAt,omitempty"`
	ObservedAtHuman    string `json:"observedAtHuman,omitempty"`
}

type proofHealthRecordFile struct {
	path   string
	record proofHealthFailure
}

func proofHealthDir(storage string) string {
	return filepath.Join(storage, "proof-health")
}

func proofHealthPath(storage string, partition PartitionMeta) string {
	return filepath.Join(
		proofHealthDir(storage),
		fmt.Sprintf("%s-dl%d-pt%d.json", safeID(partition.PartitionKind), partition.DeadlineIndex, partition.PartitionIndex),
	)
}

func proofHealthLockPath(storage string) string {
	return filepath.Join(proofHealthDir(storage), ".lock")
}

// withProofHealthLock serializes health updates between the VK server and proof
// daemon, which are separate processes sharing one storage directory.
func withProofHealthLock(storage string, fn func() error) (err error) {
	if err := os.MkdirAll(proofHealthDir(storage), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(proofHealthLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock proof health: %w", err)
	}
	defer func() {
		if unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err == nil && unlockErr != nil {
			err = fmt.Errorf("unlock proof health: %w", unlockErr)
		}
	}()
	return fn()
}

func durableRemoveProofHealthFile(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func clearPartitionProofHealthUnlocked(storage string, partition PartitionMeta) error {
	return durableRemoveProofHealthFile(proofHealthPath(storage, partition))
}

func clearPartitionProofHealth(storage string, partition PartitionMeta) error {
	return withProofHealthLock(storage, func() error {
		return clearPartitionProofHealthUnlocked(storage, partition)
	})
}

func observedChainTime(timestamp uint64) string {
	if timestamp == 0 || timestamp > uint64(^uint64(0)>>1) {
		return ""
	}
	return time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
}

func saturatedAddUint64(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

func persistProofHealthFailure(path string, record proofHealthFailure) error {
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(path, payload, 0600)
}

// updatePartitionProofHealth keeps the original call surface for existing
// callers. New integration code should call updatePartitionProofHealthWithPolicy
// with the threshold read from the deployed StorageReceiptDispute contract.
func updatePartitionProofHealth(storage string, partition PartitionMeta, status PartitionVersionStatus) error {
	return updatePartitionProofHealthWithPolicy(storage, partition, status, ProofHealthPolicy{
		RecurringProofStalenessRounds: DefaultRecurringProofStalenessRounds,
	})
}

// updatePartitionProofHealthWithPolicy mirrors StorageReceiptDispute's two
// chain-authoritative failure conditions:
//  1. new/current content has not received its first proof by registeredAt + period;
//  2. content was proved, but currentRound > lastProofRound + threshold.
//
// Missing chain fields never create a failure or erase an existing one. A
// local/chain content mismatch and an inactive chain partition do erase the
// record because it no longer describes the current local obligation.
func updatePartitionProofHealthWithPolicy(
	storage string,
	partition PartitionMeta,
	status PartitionVersionStatus,
	policy ProofHealthPolicy,
) error {
	if policy.RecurringProofStalenessRounds == 0 {
		return fmt.Errorf("proof health recurring staleness threshold must be at least 1 round")
	}
	localContent := partitionContentHash(partition)
	path := proofHealthPath(storage, partition)

	return withProofHealthLock(storage, func() error {
		if !status.Active || strings.TrimSpace(status.ContentHash) == "" {
			return clearPartitionProofHealthUnlocked(storage, partition)
		}
		// Challenge count is part of StorageProofSC's content hash. Missing it is
		// incomplete chain evidence: preserve any existing record and wait for a
		// complete pinned snapshot rather than guessing with a local fingerprint.
		if status.ChallengeCount == 0 {
			return nil
		}
		expectedChainContent, chainHashErr := partitionChainContentHash(partition, status.ChallengeCount)
		if chainHashErr != nil {
			return fmt.Errorf("derive StorageProofSC partition content hash: %w", chainHashErr)
		}
		if !sameRoot(status.ContentHash, expectedChainContent) {
			return clearPartitionProofHealthUnlocked(storage, partition)
		}

		exactContentProven := status.CurrentContentProven &&
			strings.TrimSpace(status.LastProvenContentHash) != "" &&
			sameRoot(status.LastProvenContentHash, expectedChainContent)

		// The contract applies the first-proof grace rule both when the current
		// content is unproved and when lastProofRound is still zero.
		if !exactContentProven || status.LastProofRound == 0 {
			if status.RegisteredAt == 0 || status.ProofPeriodSeconds == 0 || status.ChainTimestamp == 0 {
				return nil
			}
			hardDeadline := saturatedAddUint64(status.RegisteredAt, status.ProofPeriodSeconds)
			if status.ChainTimestamp < hardDeadline {
				return clearPartitionProofHealthUnlocked(storage, partition)
			}
			record := proofHealthFailure{
				Version:         proofHealthRecordVersion,
				FailureKind:     proofHealthFailureFirstProofMissed,
				PartitionKind:   partition.PartitionKind,
				DeadlineIndex:   partition.DeadlineIndex,
				PartitionIndex:  partition.PartitionIndex,
				ContentHash:     localContent,
				RegisteredAt:    status.RegisteredAt,
				HardDeadline:    hardDeadline,
				CurrentRound:    status.CurrentRound,
				ObservedAt:      status.ChainTimestamp,
				ObservedAtHuman: observedChainTime(status.ChainTimestamp),
			}
			return persistProofHealthFailure(path, record)
		}

		// A last proof in round R remains healthy through R+threshold. This
		// overflow-safe comparison exactly matches Solidity's strict `>` rule.
		lapseBoundary := saturatedAddUint64(status.LastProofRound, policy.RecurringProofStalenessRounds)
		if status.CurrentRound == 0 {
			return nil
		}
		if status.CurrentRound <= lapseBoundary {
			return clearPartitionProofHealthUnlocked(storage, partition)
		}
		record := proofHealthFailure{
			Version:            proofHealthRecordVersion,
			FailureKind:        proofHealthFailureRecurringLapsed,
			PartitionKind:      partition.PartitionKind,
			DeadlineIndex:      partition.DeadlineIndex,
			PartitionIndex:     partition.PartitionIndex,
			ContentHash:        localContent,
			RegisteredAt:       status.RegisteredAt,
			LastProofRound:     status.LastProofRound,
			CurrentRound:       status.CurrentRound,
			StalenessThreshold: policy.RecurringProofStalenessRounds,
			ObservedAt:         status.ChainTimestamp,
			ObservedAtHuman:    observedChainTime(status.ChainTimestamp),
		}
		return persistProofHealthFailure(path, record)
	})
}

func normalizeProofHealthRecord(record proofHealthFailure) (proofHealthFailure, error) {
	if record.Version != legacyProofHealthRecordVersion && record.Version != proofHealthRecordVersion {
		return proofHealthFailure{}, fmt.Errorf("unsupported record version %d", record.Version)
	}
	if strings.TrimSpace(record.FailureKind) == "" && record.HardDeadline > 0 {
		// Version 1 had only the first-proof hard-deadline failure. Also accept
		// early version-2 records written before failureKind was introduced.
		record.FailureKind = proofHealthFailureFirstProofMissed
	}
	if strings.TrimSpace(record.PartitionKind) == "" || record.DeadlineIndex < 0 ||
		record.PartitionIndex < 0 || strings.TrimSpace(record.ContentHash) == "" {
		return proofHealthFailure{}, fmt.Errorf("record has incomplete partition identity")
	}
	switch record.FailureKind {
	case proofHealthFailureFirstProofMissed:
		if record.HardDeadline == 0 {
			return proofHealthFailure{}, fmt.Errorf("first-proof record has no hard deadline")
		}
	case proofHealthFailureRecurringLapsed:
		if record.LastProofRound == 0 || record.StalenessThreshold == 0 ||
			record.CurrentRound <= saturatedAddUint64(record.LastProofRound, record.StalenessThreshold) {
			return proofHealthFailure{}, fmt.Errorf("recurring-proof record has invalid round evidence")
		}
	default:
		return proofHealthFailure{}, fmt.Errorf("unknown failure kind %q", record.FailureKind)
	}
	return record, nil
}

func readProofHealthRecordsUnlocked(storage string) ([]proofHealthRecordFile, error) {
	entries, err := os.ReadDir(proofHealthDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]proofHealthRecordFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(proofHealthDir(storage), entry.Name())
		payload, readErr := os.ReadFile(path)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		var record proofHealthFailure
		if err := json.Unmarshal(payload, &record); err != nil {
			return nil, fmt.Errorf("invalid proof health record %s: %w", entry.Name(), err)
		}
		record, err = normalizeProofHealthRecord(record)
		if err != nil {
			return nil, fmt.Errorf("invalid proof health record %s: %w", entry.Name(), err)
		}
		records = append(records, proofHealthRecordFile{path: path, record: record})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].path < records[j].path })
	return records, nil
}

func proofHealthPartitionIdentity(kind string, deadlineIndex, partitionIndex int) string {
	return fmt.Sprintf("%s\x00%d\x00%d", kind, deadlineIndex, partitionIndex)
}

func currentProofHealthPartitionContent(partitions []PartitionMeta) (map[string]string, error) {
	current := make(map[string]string, len(partitions))
	for _, partition := range partitions {
		if strings.TrimSpace(partition.PartitionKind) == "" || partition.DeadlineIndex < 0 || partition.PartitionIndex < 0 {
			return nil, fmt.Errorf("current proof-health partition has incomplete identity")
		}
		key := proofHealthPartitionIdentity(partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)
		content := partitionContentHash(partition)
		if previous, exists := current[key]; exists && !sameRoot(previous, content) {
			return nil, fmt.Errorf(
				"conflicting current partition content for %s dl%d-pt%d",
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
			)
		}
		current[key] = content
	}
	return current, nil
}

func reconcileProofHealthRecordsUnlocked(storage string, partitions []PartitionMeta) ([]proofHealthFailure, error) {
	current, err := currentProofHealthPartitionContent(partitions)
	if err != nil {
		return nil, err
	}
	recordFiles, err := readProofHealthRecordsUnlocked(storage)
	if err != nil {
		return nil, err
	}
	active := make([]proofHealthFailure, 0, len(recordFiles))
	for _, item := range recordFiles {
		record := item.record
		key := proofHealthPartitionIdentity(record.PartitionKind, record.DeadlineIndex, record.PartitionIndex)
		content, exists := current[key]
		if !exists || !sameRoot(content, record.ContentHash) {
			// Missing means the local partition was removed/deactivated. A content
			// mismatch means the obligation now belongs to another version.
			if err := durableRemoveProofHealthFile(item.path); err != nil {
				return nil, err
			}
			continue
		}
		active = append(active, record)
	}
	return active, nil
}

// reconcileProofHealthRecords removes records that no longer match an
// authoritative snapshot of current local partitions. An empty slice is an
// authoritative statement that this VK has no active local partitions.
func reconcileProofHealthRecords(storage string, partitions []PartitionMeta) error {
	return withProofHealthLock(storage, func() error {
		_, err := reconcileProofHealthRecordsUnlocked(storage, partitions)
		return err
	})
}

// activeProofHealthFailureForPartitions reconciles every record before
// returning one. This prevents a stale record for a deleted or changed
// partition from keeping admission closed indefinitely.
func activeProofHealthFailureForPartitions(storage string, partitions []PartitionMeta) (record proofHealthFailure, active bool, err error) {
	err = withProofHealthLock(storage, func() error {
		records, reconcileErr := reconcileProofHealthRecordsUnlocked(storage, partitions)
		if reconcileErr != nil {
			return reconcileErr
		}
		if len(records) > 0 {
			record = records[0]
			active = true
		}
		return nil
	})
	return record, active, err
}

// activeProofHealthFailure is retained for callers that cannot yet supply an
// authoritative local snapshot. It validates v1/v2 records but deliberately
// does not guess whether local partitions were removed or changed.
func activeProofHealthFailure(storage string) (record proofHealthFailure, active bool, err error) {
	err = withProofHealthLock(storage, func() error {
		records, readErr := readProofHealthRecordsUnlocked(storage)
		if readErr != nil {
			return readErr
		}
		if len(records) > 0 {
			record = records[0].record
			active = true
		}
		return nil
	})
	return record, active, err
}
