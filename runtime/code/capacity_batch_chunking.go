package main

// G.2B — deterministic chunking of an oversized incremental selection.
//
// CapacityIncrementalBatchSC bounds one batch at MAX_INCREMENTAL_BATCH_MEMBERS members (32,
// chosen from measured `openBatch` gas). When a selection exceeds that, the VK splits it into
// sequential chunks rather than shrinking the selection or falling back to a full sweep.
//
// Invariants:
//   * no key is lost;
//   * no key appears in two chunks (a later mutation creates a NEW obligation, not a
//     duplicate of the pending one);
//   * ordering is stable and reproducible across restarts;
//   * exactly one chunk is active at a time, matching the on-chain campaign lock;
//   * remaining chunks stay durably pending;
//   * successor mutations accumulate independently and are never consumed by an active chunk.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// MaxIncrementalBatchMembers mirrors CapacityIncrementalBatchSC.MAX_INCREMENTAL_BATCH_MEMBERS.
// A mismatch is a deployment error, not a local policy choice: the plan pins it in the
// deployment manifest and startup verification compares the two.
const MaxIncrementalBatchMembers = 32

const capacityBatchChunkPlanVersion = 1

// capacityBatchChunk is one bounded, ordered slice of a larger selection.
type capacityBatchChunk struct {
	Index int      `json:"index"`
	Keys  []string `json:"keys"`
	// RecoveryEmergency means every identity is known but at least one was selected for
	// expedited recovery. FreshnessDeadline means at least one was selected because its
	// current certificate is expired/due. Both remain incremental trigger inputs.
	RecoveryEmergency bool   `json:"recoveryEmergency,omitempty"`
	FreshnessDeadline bool   `json:"freshnessDeadline,omitempty"`
	Opened            bool   `json:"opened,omitempty"`
	BatchID           uint64 `json:"batchId,omitempty"`
	Done              bool   `json:"done,omitempty"`
}

// capacityBatchChunkPlan is the durable split of one selection pass.
type capacityBatchChunkPlan struct {
	Version int                  `json:"version"`
	Mode    string               `json:"mode"`
	Chunks  []capacityBatchChunk `json:"chunks"`
	// Successors are mutations observed after the plan was frozen. They are never folded into
	// a pending chunk; they seed the NEXT selection pass.
	Successors []string `json:"successors,omitempty"`
	// UrgencyKeys records the exact coordinates inserted/claimed by qualified G.4B
	// lifecycle urgency. It is durable ownership provenance for the cross-authority
	// freeze arbiter; ordinary plan members never gain this precedence implicitly.
	UrgencyKeys []string `json:"urgencyKeys,omitempty"`
}

func capacityBatchChunkPlanPath(storage string) string {
	return filepath.Join(storage, "capacity-batch-chunks.json")
}

func capacityBatchChunkPlanLockPath(storage string) string {
	return filepath.Join(storage, "capacity-batch-chunks.lock")
}

func withCapacityBatchChunkLock(storage string, fn func() error) error {
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(capacityBatchChunkPlanLockPath(storage), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

// planCapacityBatchChunks splits a selection into deterministic bounded chunks.
//
// Ordering is by partition key, so the same selection always produces the same chunks
// regardless of candidate discovery order or restart timing.
func planCapacityBatchChunks(selection CapacityBatchSelection, maxMembers int) (capacityBatchChunkPlan, error) {
	if maxMembers <= 0 {
		return capacityBatchChunkPlan{}, fmt.Errorf("chunk size must be positive, got %d", maxMembers)
	}
	if selection.Mode != BatchModeIncremental {
		return capacityBatchChunkPlan{}, fmt.Errorf(
			"only an incremental selection is chunked; mode %q is a full sweep and must use the "+
				"full-epoch path", string(selection.Mode))
	}
	keys := make([]string, 0, len(selection.Selected))
	seen := map[string]struct{}{}
	reasonByKey := map[string]capacitySelectionReason{}
	for _, member := range selection.Selected {
		key := strings.ToLower(strings.TrimSpace(member.Identity.PartitionKey))
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			return capacityBatchChunkPlan{}, fmt.Errorf(
				"selection contains partition %s twice; chunking would duplicate an obligation", key)
		}
		seen[key] = struct{}{}
		reasonByKey[key] = member.Reason
		keys = append(keys, key)
	}
	sort.Strings(keys)

	plan := capacityBatchChunkPlan{Version: capacityBatchChunkPlanVersion, Mode: string(selection.Mode)}
	for start := 0; start < len(keys); start += maxMembers {
		end := start + maxMembers
		if end > len(keys) {
			end = len(keys)
		}
		chunk := capacityBatchChunk{
			Index: len(plan.Chunks),
			Keys:  append([]string(nil), keys[start:end]...),
		}
		for _, key := range chunk.Keys {
			switch reasonByKey[key] {
			case selectionReasonRecoveryRequired:
				chunk.RecoveryEmergency = true
			case selectionReasonExpired:
				chunk.FreshnessDeadline = true
			}
		}
		plan.Chunks = append(plan.Chunks, chunk)
	}
	return plan, nil
}

// nextPendingChunk returns the chunk to open next. Exactly one chunk may be open at a time,
// mirroring the on-chain campaign lock: if one is already open it is returned unchanged, so a
// restart resumes rather than opening a second batch.
func (plan capacityBatchChunkPlan) nextPendingChunk() (capacityBatchChunk, bool) {
	for _, chunk := range plan.Chunks {
		if chunk.Opened && !chunk.Done {
			return chunk, true
		}
	}
	for _, chunk := range plan.Chunks {
		if !chunk.Opened {
			return chunk, true
		}
	}
	return capacityBatchChunk{}, false
}

// complete reports whether every chunk has finished.
func (plan capacityBatchChunkPlan) complete() bool {
	for _, chunk := range plan.Chunks {
		if !chunk.Done {
			return false
		}
	}
	return true
}

// allKeys returns every key across every chunk, in plan order.
func (plan capacityBatchChunkPlan) allKeys() []string {
	keys := make([]string, 0)
	for _, chunk := range plan.Chunks {
		keys = append(keys, chunk.Keys...)
	}
	return keys
}

func validCapacityBatchChunkPlan(plan capacityBatchChunkPlan) bool {
	if plan.Version != capacityBatchChunkPlanVersion {
		return false
	}
	if CapacityBatchMode(plan.Mode) != BatchModeIncremental {
		return false
	}
	seen := map[string]struct{}{}
	openCount := 0
	for i, chunk := range plan.Chunks {
		if chunk.Index != i || len(chunk.Keys) == 0 || len(chunk.Keys) > MaxIncrementalBatchMembers {
			return false
		}
		if chunk.Opened && !chunk.Done {
			openCount++
		}
		for _, key := range chunk.Keys {
			if _, dup := seen[key]; dup {
				return false // a key in two chunks is a duplicated obligation
			}
			seen[key] = struct{}{}
		}
	}
	urgencySeen := map[string]struct{}{}
	for _, key := range plan.UrgencyKeys {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return false
		}
		if _, duplicate := urgencySeen[key]; duplicate {
			return false
		}
		if _, selected := seen[key]; !selected {
			return false
		}
		urgencySeen[key] = struct{}{}
	}
	return openCount <= 1
}

// qualifiedUrgencyPlanOwnsPartition reports whether an incomplete durable plan gives the exact
// coordinate qualified lifecycle-urgency ownership. Corrupt state fails closed via the normal
// plan reader; an ordinary plan member is never treated as urgent.
func qualifiedUrgencyPlanOwnsPartition(storage string, partition PartitionMeta) (bool, error) {
	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil || !found || plan.complete() {
		return false, err
	}
	key := strings.ToLower(strings.TrimSpace(epochPartitionKey(
		partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)))
	for _, urgent := range plan.UrgencyKeys {
		if strings.EqualFold(urgent, key) {
			return true, nil
		}
	}
	return false, nil
}

func readCapacityBatchChunkPlan(storage string) (capacityBatchChunkPlan, bool, error) {
	raw, err := os.ReadFile(capacityBatchChunkPlanPath(storage))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return capacityBatchChunkPlan{}, false, nil
		}
		return capacityBatchChunkPlan{}, false, err
	}
	var plan capacityBatchChunkPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return capacityBatchChunkPlan{}, false, fmt.Errorf(
			"%w: capacity batch chunk plan is unreadable: %v", ErrChainStateUnreadable, err)
	}
	if !validCapacityBatchChunkPlan(plan) {
		return capacityBatchChunkPlan{}, false, fmt.Errorf(
			"%w: capacity batch chunk plan failed validation", ErrChainStateUnreadable)
	}
	return plan, true, nil
}

func writeCapacityBatchChunkPlan(storage string, plan capacityBatchChunkPlan) error {
	if !validCapacityBatchChunkPlan(plan) {
		return fmt.Errorf("refusing to write an invalid capacity batch chunk plan")
	}
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(capacityBatchChunkPlanPath(storage), append(raw, '\n'), 0o600)
}

func clearCapacityBatchChunkPlan(storage string) error {
	if err := os.Remove(capacityBatchChunkPlanPath(storage)); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// freezeCapacityBatchChunkPlan durably records the split. Called once per selection pass.
func freezeCapacityBatchChunkPlan(storage string, plan capacityBatchChunkPlan) error {
	return withCapacityBatchChunkLock(storage, func() error {
		return writeCapacityBatchChunkPlan(storage, plan)
	})
}

// freezeCapacityBatchChunkPlanIfAbsent is the production selection cutoff. It never replaces
// an existing plan: a concurrent scheduler pass or restart winner owns that exact membership.
func freezeCapacityBatchChunkPlanIfAbsent(storage string, plan capacityBatchChunkPlan) (bool, error) {
	created := false
	err := withCapacityBatchChunkLock(storage, func() error {
		_, found, err := readCapacityBatchChunkPlan(storage)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
		if err := writeCapacityBatchChunkPlan(storage, plan); err != nil {
			return err
		}
		created = true
		return nil
	})
	return created, err
}

// markCapacityBatchChunkOpened records that a chunk was opened on chain, with its authority id.
// It refuses to open a second chunk while one is still in flight.
func markCapacityBatchChunkOpened(storage string, index int, batchID uint64) error {
	return withCapacityBatchChunkLock(storage, func() error {
		plan, ok, err := readCapacityBatchChunkPlan(storage)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no capacity batch chunk plan to open chunk %d against", index)
		}
		for _, chunk := range plan.Chunks {
			if chunk.Opened && !chunk.Done && chunk.Index != index {
				return fmt.Errorf(
					"chunk %d is still in flight; only one chunk may be open at a time", chunk.Index)
			}
		}
		if index < 0 || index >= len(plan.Chunks) {
			return fmt.Errorf("chunk index %d out of range", index)
		}
		if plan.Chunks[index].Done {
			return fmt.Errorf("chunk %d already completed", index)
		}
		if plan.Chunks[index].Opened && plan.Chunks[index].BatchID != batchID {
			return fmt.Errorf(
				"chunk %d already opened as batch %d; refusing to rebind to %d",
				index, plan.Chunks[index].BatchID, batchID)
		}
		plan.Chunks[index].Opened = true
		plan.Chunks[index].BatchID = batchID
		return writeCapacityBatchChunkPlan(storage, plan)
	})
}

// markCapacityBatchChunkDone records a chunk's completion. It is idempotent, so a retried
// completion cannot open the following chunk twice.
func markCapacityBatchChunkDone(storage string, index int) error {
	return withCapacityBatchChunkLock(storage, func() error {
		plan, ok, err := readCapacityBatchChunkPlan(storage)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if index < 0 || index >= len(plan.Chunks) {
			return fmt.Errorf("chunk index %d out of range", index)
		}
		if plan.Chunks[index].Done {
			return nil // idempotent
		}
		if !plan.Chunks[index].Opened {
			return fmt.Errorf("chunk %d was never opened", index)
		}
		plan.Chunks[index].Done = true
		return writeCapacityBatchChunkPlan(storage, plan)
	})
}

// recordCapacityBatchChunkSuccessor registers a mutation observed while a chunk plan is in
// flight. It never joins a pending chunk: it seeds the next selection pass.
func recordCapacityBatchChunkSuccessor(storage string, partitionKey string) error {
	key := strings.ToLower(strings.TrimSpace(partitionKey))
	if key == "" {
		return fmt.Errorf("successor needs a partition key")
	}
	return withCapacityBatchChunkLock(storage, func() error {
		plan, ok, err := readCapacityBatchChunkPlan(storage)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		for _, existing := range plan.Successors {
			if existing == key {
				return nil
			}
		}
		plan.Successors = append(plan.Successors, key)
		sort.Strings(plan.Successors)
		return writeCapacityBatchChunkPlan(storage, plan)
	})
}

// closeCapacityBatchChunkPlan clears a finished plan and returns the successor obligations it
// accumulated. Successors are never lost by closing a plan.
func closeCapacityBatchChunkPlan(storage string) ([]string, error) {
	var successors []string
	err := withCapacityBatchChunkLock(storage, func() error {
		plan, ok, err := readCapacityBatchChunkPlan(storage)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if !plan.complete() {
			return fmt.Errorf("refusing to close a chunk plan with unfinished chunks")
		}
		successors = append([]string(nil), plan.Successors...)
		return clearCapacityBatchChunkPlan(storage)
	})
	if err != nil {
		return nil, err
	}
	return successors, nil
}

// releaseTerminalCapacityBatchChunkBinding releases the ACTIVE ownership of a chunk whose batch
// ended WITHOUT completing (abandoned or invalidated on chain).
//
// Terminal semantics, and why they differ from completion:
//
//   - completion is recorded by markCapacityBatchChunkDone, which sets Done and preserves the
//     batch id as history. That path is untouched here.
//   - an abandoned batch never did the work, so the chunk must go back to PENDING: `Opened` and
//     `BatchID` are cleared while `Keys`, `Done` and the trigger flags are preserved, so the same
//     identities return to ordinary planning and can be bound by the next batch.
//
// Live 2026-08-13: without this, `capacity-batch-chunks.json` kept `opened=true,
// batchId=<abandoned>` after a successful on-chain abandonment, so the next batch was refused with
// "chunk N already opened as batch <old>; refusing to rebind to <new>" and the scheduler wedged a
// second time.
//
// Fail closed. The binding is released only for a chunk bound to EXACTLY the terminal batch; a
// chunk that is Done, unbound, or bound to a different batch is never touched. Callers must have
// authoritative chain evidence that `terminalBatchID` is no longer active.
func releaseTerminalCapacityBatchChunkBinding(storage string, terminalBatchID uint64) (bool, error) {
	if terminalBatchID == 0 {
		return false, fmt.Errorf("chunk binding release requires an exact terminal batch id")
	}
	released := false
	err := withCapacityBatchChunkLock(storage, func() error {
		plan, found, err := readCapacityBatchChunkPlan(storage)
		if err != nil || !found {
			return err
		}
		for index := range plan.Chunks {
			chunk := &plan.Chunks[index]
			if chunk.Done || !chunk.Opened || chunk.BatchID != terminalBatchID {
				continue
			}
			chunk.Opened = false
			chunk.BatchID = 0
			released = true
		}
		if !released {
			return nil
		}
		return writeCapacityBatchChunkPlan(storage, plan)
	})
	return released, err
}
