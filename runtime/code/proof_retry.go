package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const partitionProofRetryStateVersion = 1

type partitionProofRetryEntry struct {
	PartitionKind  string `json:"partitionKind"`
	DeadlineIndex  int    `json:"deadlineIndex"`
	PartitionIndex int    `json:"partitionIndex"`
	ContentHash    string `json:"contentHash"`
	Failures       int    `json:"failures"`
	NextAttemptAt  string `json:"nextAttemptAt"`
	LastError      string `json:"lastError,omitempty"`
	UpdatedAt      string `json:"updatedAt"`
	// A.4 durable recovery classification — all survive restart.
	FirstFailureAt string `json:"firstFailureAt,omitempty"` // when the streak began
	FailureClass   string `json:"failureClass,omitempty"`   // last recovery action (resume/supersede/…)
	Terminal       bool   `json:"terminal,omitempty"`       // permanently failed → stops auto retries
	TerminalReason string `json:"terminalReason,omitempty"` // diagnostic evidence, preserved
}

type partitionProofRetryState struct {
	Version int                                 `json:"version"`
	Entries map[string]partitionProofRetryEntry `json:"entries"`
}

func partitionProofRetryStatePath(storage string) string {
	return filepath.Join(storage, "proof-retry-state.json")
}

func partitionProofRetryLockPath(storage string) string {
	return filepath.Join(storage, "proof-retry-state.lock")
}

func partitionProofRetryKey(partition PartitionMeta) string {
	return fmt.Sprintf("%s:dl%d:pt%d", partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)
}

func withPartitionProofRetryState(storage string, mutate func(*partitionProofRetryState) error) error {
	if err := os.MkdirAll(storage, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(partitionProofRetryLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	state := partitionProofRetryState{
		Version: partitionProofRetryStateVersion,
		Entries: make(map[string]partitionProofRetryEntry),
	}
	path := partitionProofRetryStatePath(storage)
	var originalPayload []byte
	existed := false
	if payload, readErr := os.ReadFile(path); readErr == nil {
		existed = true
		originalPayload = append([]byte(nil), payload...)
		if err := json.Unmarshal(payload, &state); err != nil ||
			state.Version != partitionProofRetryStateVersion || state.Entries == nil {
			// Corrupt retry metadata must never suppress required proofs. Preserve it
			// for diagnosis, then recover with an empty state.
			quarantine := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UnixNano())
			_ = os.Rename(path, quarantine)
			existed = false
			originalPayload = nil
			state = partitionProofRetryState{
				Version: partitionProofRetryStateVersion,
				Entries: make(map[string]partitionProofRetryEntry),
			}
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	if err := mutate(&state); err != nil {
		return err
	}
	state.Version = partitionProofRetryStateVersion
	if len(state.Entries) == 0 {
		if !existed {
			return nil
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if dir, err := os.Open(storage); err == nil {
			defer dir.Close()
			return dir.Sync()
		}
		return nil
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if existed {
		var originalState partitionProofRetryState
		if json.Unmarshal(originalPayload, &originalState) == nil {
			canonicalOriginal, _ := json.MarshalIndent(originalState, "", "  ")
			if string(canonicalOriginal) == string(payload) {
				return nil
			}
		}
	}
	return durableAtomicWriteFile(path, payload, 0600)
}

func partitionProofRetryEligible(storage string, partition PartitionMeta, now time.Time) (bool, error) {
	eligible := true
	err := withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		key := partitionProofRetryKey(partition)
		entry, found := state.Entries[key]
		if !found {
			return nil
		}
		contentHash := partitionContentHash(partition)
		if !sameRoot(entry.ContentHash, contentHash) {
			delete(state.Entries, key)
			return nil
		}
		// A.4: a terminally-failed item stops automatic transactions until operator action —
		// it is never auto-eligible, but its record (diagnostic evidence) is preserved.
		if entry.Terminal {
			eligible = false
			return nil
		}
		next, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(entry.NextAttemptAt))
		if parseErr != nil {
			delete(state.Entries, key)
			return nil
		}
		eligible = !now.Before(next)
		return nil
	})
	return eligible, err
}

func partitionProofRetryDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	delay := 15 * time.Second
	for i := 1; i < failures && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return delay
}

func recordPartitionProofRetry(storage string, partition PartitionMeta, proofErr error, now time.Time) error {
	return withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		key := partitionProofRetryKey(partition)
		contentHash := partitionContentHash(partition)
		entry := state.Entries[key]
		if !sameRoot(entry.ContentHash, contentHash) {
			entry = partitionProofRetryEntry{
				PartitionKind: partition.PartitionKind, DeadlineIndex: partition.DeadlineIndex,
				PartitionIndex: partition.PartitionIndex, ContentHash: contentHash,
			}
		}
		if entry.FirstFailureAt == "" {
			entry.FirstFailureAt = now.UTC().Format(time.RFC3339Nano)
		}
		entry.Failures++
		entry.NextAttemptAt = now.Add(partitionProofRetryDelay(entry.Failures)).UTC().Format(time.RFC3339Nano)
		entry.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
		if proofErr != nil {
			entry.LastError = proofErr.Error()
		}
		// A.4: a retryable failure uses bounded backoff but cannot retry forever — once the
		// consecutive-failure budget is exhausted the item becomes terminal (stops automatic
		// attempts, degrades health, preserves evidence) until operator action clears it.
		if proofRecoveryMaxFailures > 0 && entry.Failures >= proofRecoveryMaxFailures && !entry.Terminal {
			entry.Terminal = true
			entry.FailureClass = string(recoveryTerminal)
			entry.TerminalReason = "consecutive proof failures exhausted the retry budget"
		}
		state.Entries[key] = entry
		return nil
	})
}

// proofRecoveryMaxFailures bounds automatic retries; beyond it the item is terminal.
var proofRecoveryMaxFailures = 50

// recordProofRecoveryClassification durably stamps the classifier's decision on the retry
// entry (creating one if needed). A terminal classification freezes automatic retries and
// preserves the diagnostic reason; a non-terminal one records the class for observability and
// keeps the bounded backoff schedule. All fields survive restart.
func recordProofRecoveryClassification(storage string, partition PartitionMeta, action proofRecoveryAction, reason string, now time.Time) error {
	return withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		key := partitionProofRetryKey(partition)
		contentHash := partitionContentHash(partition)
		entry, found := state.Entries[key]
		if !found || !sameRoot(entry.ContentHash, contentHash) {
			entry = partitionProofRetryEntry{
				PartitionKind: partition.PartitionKind, DeadlineIndex: partition.DeadlineIndex,
				PartitionIndex: partition.PartitionIndex, ContentHash: contentHash,
				FirstFailureAt: now.UTC().Format(time.RFC3339Nano),
			}
		}
		entry.FailureClass = string(action)
		entry.UpdatedAt = now.UTC().Format(time.RFC3339Nano)
		if action.terminal() {
			entry.Terminal = true
			entry.TerminalReason = reason
			// Freeze the schedule far out; only operator action (clear) resumes it.
			entry.NextAttemptAt = now.Add(100 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		}
		state.Entries[key] = entry
		return nil
	})
}

// proofRecoveryEntry returns the durable recovery record for a partition, if any.
func proofRecoveryEntry(storage string, partition PartitionMeta) (partitionProofRetryEntry, bool, error) {
	var out partitionProofRetryEntry
	found := false
	err := withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		if entry, ok := state.Entries[partitionProofRetryKey(partition)]; ok {
			out, found = entry, true
		}
		return nil
	})
	return out, found, err
}

// unresolvedProofRecovery reports whether any recovery work is outstanding (pending retries or
// terminal failures). Used by readiness/health: while any is present the VK is degraded and
// never healthy; it clears only when the durable records are removed on confirmed resolution.
func unresolvedProofRecovery(storage string) (pending int, terminal int, err error) {
	e := withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		for _, entry := range state.Entries {
			if entry.Terminal {
				terminal++
			} else {
				pending++
			}
		}
		return nil
	})
	return pending, terminal, e
}

// retirePartitionProofRetryForDeadObligations enforces the invariant that no persistent retry
// record may outlive the obligation it represents.
//
// A retry entry means "partition (kind, dl, pt) still owes a proof". That obligation dies when
// the coordinate stops holding any live sector: a fully deleted coordinate has nothing left to
// prove, so no future scan can ever discharge the record, and it would otherwise pin the vault
// keeper to degraded forever (unresolvedProofRecovery counts it, admission_control reports it).
//
// This is a safety net, not the primary path. The primary paths clear on the event itself —
// successful proof and partition deactivation. It exists because Run 11 showed a record can
// survive when a DIFFERENT valid path discharges the obligation: the daemon recorded a failure
// for data:dl39:pt0, the snapshot prover later proved that partition successfully, the
// partition was then deactivated, and the only sweep that would have cleared the record is
// activity-driven and stopped running when traffic stopped. The record then survived forever.
//
// It deliberately only retires DATA partitions whose coordinate holds no live sector. Capacity
// partitions are not backed by ordinary sectors the same way, so they keep their existing
// paths. A coordinate with any live sector still owes a proof and is never touched here.
func retirePartitionProofRetryForDeadObligations(storage string) (int, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return 0, err
	}
	live := map[string]bool{}
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.PartitionAssigned ||
			sector.PartitionIndex >= CapacityPartitionIndexOffset {
			continue
		}
		live[fmt.Sprintf("%s:dl%d:pt%d", PartitionKindData, sector.DeadlineIndex, sector.PartitionIndex)] = true
	}
	retired := 0
	err = withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		for key, entry := range state.Entries {
			if entry.PartitionKind != PartitionKindData ||
				entry.PartitionIndex >= CapacityPartitionIndexOffset {
				continue
			}
			if live[key] {
				continue
			}
			delete(state.Entries, key)
			retired++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return retired, nil
}

func clearPartitionProofRetry(storage string, partition PartitionMeta) error {
	return withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
		delete(state.Entries, partitionProofRetryKey(partition))
		return nil
	})
}
