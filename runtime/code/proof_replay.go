package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	partitionProofFailureRecordVersion = 2
	partitionProofFailureMaxBytes      = 16 << 20
	partitionProofMethodDeterministic  = "deterministic"
	partitionProofMethodLegacy         = "legacy"
	partitionProofMethodUnknown        = "unknown-legacy-record"
)

// partitionProofFailureRecord is the durable hand-off between proof generation
// and chain submission. A failed/ambiguous submission must remain replayable:
// generating a replacement proof first wastes the shared prover and can race a
// transaction that the RPC endpoint accepted before disconnecting.
type partitionProofFailureRecord struct {
	Version            int                `json:"version"`
	CreatedAt          string             `json:"createdAt"`
	UpdatedAt          string             `json:"updatedAt"`
	LastAttemptAt      string             `json:"lastAttemptAt,omitempty"`
	LastError          string             `json:"error"`
	SubmissionMethod   string             `json:"submissionMethod"`
	SubmissionAttempts uint64             `json:"submissionAttempts"`
	LocalContentHash   string             `json:"localContentHash"`
	Partition          PartitionMeta      `json:"partition"`
	Challenge          PartitionChallenge `json:"challenge"`
	Proof              ZKProofResult      `json:"proof"`
}

type partitionProofRetirementRecord struct {
	Version            int    `json:"version"`
	RetiredAt          string `json:"retiredAt"`
	Reason             string `json:"reason"`
	Source             string `json:"source"`
	SubmissionMethod   string `json:"submissionMethod,omitempty"`
	LocalContentHash   string `json:"localContentHash,omitempty"`
	PartitionKind      string `json:"partitionKind,omitempty"`
	DeadlineIndex      int    `json:"deadlineIndex"`
	PartitionIndex     int    `json:"partitionIndex"`
	Round              uint64 `json:"round,omitempty"`
	SubmissionAttempts uint64 `json:"submissionAttempts,omitempty"`
}

type persistedPartitionProof struct {
	path   string
	record partitionProofFailureRecord
}

type partitionProofReplayResult struct {
	Matched        bool
	Confirmed      bool
	ConfirmedRound uint64
	SubmitTx       string
}

// The operations are explicit so the state machine can be tested without a
// blockchain process. Production callers always use defaultPartitionReplayOps.
type partitionProofReplayOperations struct {
	status    func(string, PartitionMeta) (PartitionVersionStatus, error)
	challenge func(string, PartitionMeta, uint64, int, bool) (
		PartitionChallenge, []string, error,
	)
	submit    func(string, PartitionMeta, PartitionChallenge, ZKProofResult, bool) (string, error)
	confirm   func(string, PartitionMeta, uint64, bool) (PartitionVersionStatus, bool, error)
	authority func() error
}

var defaultPartitionReplayOps = partitionProofReplayOperations{
	status: partitionVersionStatusOnChain,
	challenge: func(chainCmd string, partition PartitionMeta, round uint64, challengeCount int, deterministic bool) (PartitionChallenge, []string, error) {
		if deterministic {
			challenge, publicInputs, err := getPartitionChallengeDeterministic(chainCmd, partition, round)
			return challenge, publicInputs, err
		}
		status, err := legacyPartitionChallengeStatus(chainCmd, partition, round)
		if err != nil {
			return PartitionChallenge{}, nil, fmt.Errorf("legacy partition challenge status: %w", err)
		}
		if !status.ChallengeExists {
			return PartitionChallenge{}, nil, &partitionProofReplayStaleError{reason: "legacy challenge no longer exists"}
		}
		if status.ChallengeDeadline > 0 && status.ChainTimestamp > status.ChallengeDeadline {
			return PartitionChallenge{}, nil, &partitionProofReplayStaleError{reason: "legacy challenge expired"}
		}
		// openPartitionChallenge reuses an existing challenge. It also refreshes
		// the partition registration only when required by the normal legacy
		// path, then returns the authoritative seed and public inputs.
		challenge, publicInputs, err := openPartitionChallenge(chainCmd, partition, round, challengeCount)
		return challenge, publicInputs, err
	},
	submit: func(chainCmd string, partition PartitionMeta, challenge PartitionChallenge, proof ZKProofResult, deterministic bool) (string, error) {
		if deterministic {
			return submitPartitionProofDeterministic(chainCmd, partition, challenge, proof)
		}
		return submitPartitionProofToChain(chainCmd, partition, challenge, proof)
	},
	confirm: confirmPartitionProofSubmission,
}

type partitionProofReplayStaleError struct{ reason string }

func (err *partitionProofReplayStaleError) Error() string { return err.reason }

func partitionProofFailuresDir(storage string) string {
	return filepath.Join(storage, "proof-failures")
}

func partitionProofFailureMethod(deterministic bool) string {
	if deterministic {
		return partitionProofMethodDeterministic
	}
	return partitionProofMethodLegacy
}

func partitionProofFailureLockPath(storage string, partition PartitionMeta) string {
	name := fmt.Sprintf("%s-dl%d-pt%d.lock", safeID(partition.PartitionKind), partition.DeadlineIndex, partition.PartitionIndex)
	return filepath.Join(partitionProofFailuresDir(storage), "locks", name)
}

func withPartitionProofFailureLock(storage string, partition PartitionMeta, fn func() error) error {
	path := partitionProofFailureLockPath(storage, partition)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create proof replay lock directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open proof replay lock: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire proof replay lock: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN) // best-effort; Close releases it after crashes too
	return fn()
}

func partitionProofFailureFilename(partition PartitionMeta, round uint64, method, contentHash string) string {
	hash := safeID(normalizeRoot(contentHash))
	return fmt.Sprintf("%s-dl%d-pt%d-r%d-%s-%s.json",
		safeID(partition.PartitionKind), partition.DeadlineIndex, partition.PartitionIndex,
		round, method, hash)
}

func validPartitionProofFailureRecord(record partitionProofFailureRecord) error {
	if record.Version != partitionProofFailureRecordVersion {
		return fmt.Errorf("unsupported proof failure record version %d", record.Version)
	}
	if record.SubmissionMethod != partitionProofMethodDeterministic &&
		record.SubmissionMethod != partitionProofMethodLegacy &&
		record.SubmissionMethod != partitionProofMethodUnknown {
		return fmt.Errorf("invalid proof submission method %q", record.SubmissionMethod)
	}
	if record.Partition.DeadlineIndex < 0 || record.Partition.PartitionIndex < 0 || strings.TrimSpace(record.Partition.PartitionKind) == "" {
		return fmt.Errorf("invalid partition coordinates")
	}
	if len(record.Partition.Sectors) == 0 {
		return fmt.Errorf("empty partition snapshot")
	}
	expectedHash := partitionContentHash(record.Partition)
	if !sameRoot(record.LocalContentHash, expectedHash) {
		return fmt.Errorf("record content hash does not match partition snapshot")
	}
	if record.Challenge.Round == 0 || record.Proof.Round != record.Challenge.Round {
		return fmt.Errorf("proof/challenge round mismatch")
	}
	if strings.TrimSpace(record.Challenge.PartitionKey) == "" || strings.TrimSpace(record.Challenge.ChallengeSeed) == "" {
		return fmt.Errorf("missing partition challenge identity")
	}
	if !record.Proof.OK || len(record.Proof.PublicInputs) == 0 {
		return fmt.Errorf("saved partition proof is incomplete")
	}
	if err := validatePartitionProofResponse(ZKPartitionProofRequest{
		Partition: record.Partition, Challenge: record.Challenge, PublicInputs: record.Proof.PublicInputs,
	}, record.Proof); err != nil {
		return err
	}
	return nil
}

func persistPartitionProofFailureRecord(
	storage string,
	partition PartitionMeta,
	challenge PartitionChallenge,
	proof ZKProofResult,
	deterministic bool,
	submitErr error,
) error {
	if submitErr == nil {
		return fmt.Errorf("cannot persist a successful partition proof submission")
	}
	method := partitionProofFailureMethod(deterministic)
	record := partitionProofFailureRecord{
		Version: partitionProofFailureRecordVersion, CreatedAt: nowRFC3339(), UpdatedAt: nowRFC3339(),
		LastAttemptAt: nowRFC3339(), LastError: submitErr.Error(), SubmissionMethod: method,
		SubmissionAttempts: 1, LocalContentHash: partitionContentHash(partition),
		Partition: partition, Challenge: challenge, Proof: proof,
	}
	if err := validPartitionProofFailureRecord(record); err != nil {
		return fmt.Errorf("refuse to persist invalid partition proof: %w", err)
	}
	return withPartitionProofFailureLock(storage, partition, func() error {
		dir := partitionProofFailuresDir(storage)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		path := filepath.Join(dir, partitionProofFailureFilename(partition, challenge.Round, method, record.LocalContentHash))
		if existing, err := readPartitionProofFailureFile(path); err == nil {
			record.CreatedAt = existing.CreatedAt
			record.SubmissionAttempts += existing.SubmissionAttempts
		}
		payload, err := json.MarshalIndent(record, "", "  ")
		if err != nil {
			return err
		}
		return durableAtomicWriteFile(path, payload, 0600)
	})
}

func readPartitionProofFailureFile(path string) (partitionProofFailureRecord, error) {
	var record partitionProofFailureRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() {
		return record, fmt.Errorf("proof failure record is not a regular file")
	}
	if info.Size() <= 0 || info.Size() > partitionProofFailureMaxBytes {
		return record, fmt.Errorf("proof failure record size %d is outside limits", info.Size())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(payload, &record); err != nil {
		return record, err
	}
	// Version 1 records predate explicit method/attempt metadata. Their exact
	// challenge is checked against the currently selected chain method before
	// replay, so they can be migrated without guessing or throwing away a valid
	// proof during an upgrade.
	if record.Version == 0 && record.SubmissionMethod == "" {
		record.Version = partitionProofFailureRecordVersion
		record.SubmissionMethod = partitionProofMethodUnknown
		if record.CreatedAt == "" {
			record.CreatedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
		}
		record.UpdatedAt = record.CreatedAt
		if record.SubmissionAttempts == 0 {
			record.SubmissionAttempts = 1
		}
	}
	if err := validPartitionProofFailureRecord(record); err != nil {
		return record, err
	}
	return record, nil
}

func syncProofReplayDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func quarantinePartitionProofFailure(path string, cause error) error {
	dir := filepath.Dir(path)
	quarantineDir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return err
	}
	target := filepath.Join(quarantineDir, fmt.Sprintf("%s.corrupt-%d", filepath.Base(path), time.Now().UnixNano()))
	if err := os.Rename(path, target); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	_ = durableAtomicWriteFile(target+".reason", []byte(cause.Error()+"\n"), 0600)
	if err := syncProofReplayDirectory(dir); err != nil {
		return err
	}
	return syncProofReplayDirectory(quarantineDir)
}

func retirePartitionProofFailure(item persistedPartitionProof, reason string) error {
	dir := filepath.Dir(item.path)
	retiredDir := filepath.Join(dir, "retired")
	if err := os.MkdirAll(retiredDir, 0700); err != nil {
		return err
	}
	tombstone := partitionProofRetirementRecord{
		Version: partitionProofFailureRecordVersion, RetiredAt: nowRFC3339(), Reason: reason,
		Source: filepath.Base(item.path), SubmissionMethod: item.record.SubmissionMethod,
		LocalContentHash: item.record.LocalContentHash, PartitionKind: item.record.Partition.PartitionKind,
		DeadlineIndex: item.record.Partition.DeadlineIndex, PartitionIndex: item.record.Partition.PartitionIndex,
		Round: item.record.Challenge.Round, SubmissionAttempts: item.record.SubmissionAttempts,
	}
	payload, err := json.MarshalIndent(tombstone, "", "  ")
	if err != nil {
		return err
	}
	tombstonePath := filepath.Join(retiredDir, fmt.Sprintf("%s.retired-%d.json", filepath.Base(item.path), time.Now().UnixNano()))
	if err := durableAtomicWriteFile(tombstonePath, payload, 0600); err != nil {
		return err
	}
	if err := os.Remove(item.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncProofReplayDirectory(dir)
}

func loadMatchingPartitionProofFailures(storage string, partition PartitionMeta, round uint64) ([]persistedPartitionProof, error) {
	dir := partitionProofFailuresDir(storage)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	items := make([]persistedPartitionProof, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		record, readErr := readPartitionProofFailureFile(path)
		if readErr != nil {
			if quarantineErr := quarantinePartitionProofFailure(path, readErr); quarantineErr != nil {
				return nil, fmt.Errorf("quarantine invalid proof replay %s: %w", entry.Name(), quarantineErr)
			}
			continue
		}
		if record.Partition.DeadlineIndex != partition.DeadlineIndex ||
			record.Partition.PartitionIndex != partition.PartitionIndex {
			continue
		}
		if record.Partition.PartitionKind != partition.PartitionKind ||
			!sameRoot(record.LocalContentHash, partitionContentHash(partition)) {
			if err := retirePartitionProofFailure(
				persistedPartitionProof{path: path, record: record}, "local partition content changed",
			); err != nil {
				return nil, err
			}
			continue
		}
		if record.Challenge.Round < round {
			if err := retirePartitionProofFailure(
				persistedPartitionProof{path: path, record: record}, "proof round superseded",
			); err != nil {
				return nil, err
			}
			continue
		}
		if record.Challenge.Round != round {
			// A future-round proof can be valid work queued by another process;
			// leave it durable until that chain round is scheduled.
			continue
		}
		items = append(items, persistedPartitionProof{path: path, record: record})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].record.UpdatedAt > items[j].record.UpdatedAt
	})
	return items, nil
}

func updatePartitionProofReplayAttempt(item *persistedPartitionProof, increment bool, attemptErr error) error {
	if increment {
		item.record.SubmissionAttempts++
		item.record.LastAttemptAt = nowRFC3339()
	}
	item.record.UpdatedAt = nowRFC3339()
	if attemptErr != nil {
		item.record.LastError = attemptErr.Error()
	}
	payload, err := json.MarshalIndent(item.record, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(item.path, payload, 0600)
}

func retireAllPartitionProofFailures(items []persistedPartitionProof, reason string) error {
	for _, item := range items {
		if err := retirePartitionProofFailure(item, reason); err != nil {
			return err
		}
	}
	return nil
}

func exactReplayChallengeMatches(record partitionProofFailureRecord, current PartitionChallenge, publicInputs []string) bool {
	return record.Challenge.Round == current.Round &&
		sameRoot(record.Challenge.PartitionKey, current.PartitionKey) &&
		sameRoot(record.Challenge.ChallengeSeed, current.ChallengeSeed) &&
		equalPublicInputs(record.Proof.PublicInputs, publicInputs)
}

// replayPersistedPartitionProof is called while the partition lifecycle lock is
// held and before invoking the expensive prover. It never treats an RPC/submit
// error as success. Uncertain outcomes remain durable for the next attempt.
func replayPersistedPartitionProof(
	storage string,
	partition PartitionMeta,
	round uint64,
	challengeCount int,
	chainCmd string,
	deterministic bool,
	ops partitionProofReplayOperations,
) (partitionProofReplayResult, error) {
	var result partitionProofReplayResult
	err := withPartitionProofFailureLock(storage, partition, func() error {
		items, err := loadMatchingPartitionProofFailures(storage, partition, round)
		if err != nil || len(items) == 0 {
			return err
		}
		method := partitionProofFailureMethod(deterministic)
		matchingMethod := make([]persistedPartitionProof, 0, len(items))
		for _, item := range items {
			if item.record.SubmissionMethod == method || item.record.SubmissionMethod == partitionProofMethodUnknown {
				matchingMethod = append(matchingMethod, item)
			} else if err := retirePartitionProofFailure(item, "submission method changed"); err != nil {
				return err
			}
		}
		if len(matchingMethod) == 0 {
			return nil
		}
		result.Matched = true

		status, err := ops.status(chainCmd, partition)
		if err != nil {
			return fmt.Errorf("check persisted partition proof status: %w", err)
		}
		if exactPartitionVersionAlreadyProven(status, partition, round) {
			if err := retireAllPartitionProofFailures(matchingMethod, "exact content and round confirmed on-chain"); err != nil {
				return err
			}
			result.Confirmed = true
			result.ConfirmedRound = status.LastProofRound
			return nil
		}
		if !status.Active || !partitionMatchesChainContent(status, partition) {
			result.Matched = false
			return retireAllPartitionProofFailures(matchingMethod, "partition inactive or content changed on-chain")
		}

		currentChallenge, publicInputs, err := ops.challenge(chainCmd, partition, round, challengeCount, deterministic)
		if err != nil {
			var stale *partitionProofReplayStaleError
			if errors.As(err, &stale) {
				result.Matched = false
				return retireAllPartitionProofFailures(matchingMethod, stale.Error())
			}
			return fmt.Errorf("validate persisted partition challenge: %w", err)
		}
		selected := -1
		for i := range matchingMethod {
			if exactReplayChallengeMatches(matchingMethod[i].record, currentChallenge, publicInputs) {
				selected = i
				break
			}
			if err := retirePartitionProofFailure(matchingMethod[i], "partition challenge or public inputs changed"); err != nil {
				return err
			}
		}
		if selected < 0 {
			result.Matched = false
			return nil
		}
		item := matchingMethod[selected]
		item.record.SubmissionMethod = method
		if err := updatePartitionProofReplayAttempt(&item, true, nil); err != nil {
			return fmt.Errorf("record partition proof replay attempt: %w", err)
		}
		matchingMethod[selected] = item
		// Challenge selection can involve RPC and durable replay bookkeeping.
		// Repeat both generation and chain identity checks at the transaction
		// boundary so a recovered proof cannot race a newer authoritative job.
		if ops.authority != nil {
			if err := ops.authority(); err != nil {
				return retireAllPartitionProofFailures(matchingMethod[selected:], "saved proof generation was superseded before replay")
			}
		}
		preSubmitStatus, statusErr := ops.status(chainCmd, partition)
		if statusErr != nil {
			return fmt.Errorf("recheck persisted partition proof status: %w", statusErr)
		}
		if exactPartitionVersionAlreadyProven(preSubmitStatus, partition, round) {
			if err := retireAllPartitionProofFailures(matchingMethod[selected:], "exact content and round confirmed before replay"); err != nil {
				return err
			}
			result.Confirmed = true
			result.ConfirmedRound = preSubmitStatus.LastProofRound
			return nil
		}
		if !preSubmitStatus.Active || !partitionMatchesChainContent(preSubmitStatus, partition) {
			result.Matched = false
			return retireAllPartitionProofFailures(matchingMethod[selected:], "partition changed immediately before replay submission")
		}
		tx, submitErr := ops.submit(chainCmd, partition, item.record.Challenge, item.record.Proof, deterministic)
		status, confirmed, confirmErr := ops.confirm(chainCmd, partition, round, true)
		if confirmErr == nil && confirmed {
			if err := retireAllPartitionProofFailures(matchingMethod[selected:], "replayed proof confirmed on-chain"); err != nil {
				return err
			}
			result.Confirmed = true
			result.ConfirmedRound = status.LastProofRound
			result.SubmitTx = tx
			return nil
		}
		if confirmErr == nil && (!status.Active || !partitionMatchesChainContent(status, partition)) {
			if err := retireAllPartitionProofFailures(matchingMethod[selected:], "partition changed while replaying proof"); err != nil {
				return err
			}
			return fmt.Errorf("partition content changed while replaying saved proof")
		}
		ambiguous := submitErr
		if ambiguous == nil {
			ambiguous = fmt.Errorf("submission returned without exact on-chain confirmation")
		}
		if confirmErr != nil {
			ambiguous = fmt.Errorf("%v; confirmation failed: %w", ambiguous, confirmErr)
		}
		if err := updatePartitionProofReplayAttempt(&item, false, ambiguous); err != nil {
			return fmt.Errorf("preserve ambiguous partition proof replay: %w", err)
		}
		return fmt.Errorf("saved partition proof submission remains unconfirmed: %w", ambiguous)
	})
	return result, err
}
