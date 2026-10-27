package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var deletionRecoveryTriggers = struct {
	sync.Mutex
	running map[string]bool
}{running: make(map[string]bool)}

// triggerDeletionLifecycleRecovery disconnects request lifetime from physical
// deletion/proof lifetime. Duplicate accepts coalesce by durable deletion id;
// the minute reconciler remains the restart-safe retry owner after failures.
func triggerDeletionLifecycleRecovery(cfg ServerConfig, commitmentHash string) {
	key := filepath.Clean(cfg.Storage) + "|" + strings.ToLower(strings.TrimSpace(commitmentHash))
	deletionRecoveryTriggers.Lock()
	if deletionRecoveryTriggers.running[key] {
		deletionRecoveryTriggers.Unlock()
		return
	}
	deletionRecoveryTriggers.running[key] = true
	deletionRecoveryTriggers.Unlock()
	go func() {
		defer func() {
			deletionRecoveryTriggers.Lock()
			delete(deletionRecoveryTriggers.running, key)
			deletionRecoveryTriggers.Unlock()
		}()
		operation, found, err := readDeletionLifecycleOperation(cfg.Storage, commitmentHash)
		if err != nil || !found {
			return
		}
		creds, err := LoadPaymentCredentials(cfg.Storage, commitmentHash)
		if err != nil {
			recordDeletionLifecycleError(cfg.Storage, commitmentHash, err)
			return
		}
		if _, err := resumeDeletionLifecycleOperation(cfg, creds, operation); err != nil {
			recordDeletionLifecycleError(cfg.Storage, commitmentHash, err)
			log.Printf("[lifecycle] asynchronous deletion pending commitment=%s: %v",
				truncate(commitmentHash, 18), err)
		}
	}()
}

const lifecycleJournalVersion = 1

const deletionLifecycleReleaseVersion = 1

type StoreLifecycleOperation struct {
	Version                          int    `json:"version"`
	PieceRoot                        string `json:"pieceRoot"`
	CommitmentHash                   string `json:"commitmentHash"`
	RegistrationCommitment           string `json:"registrationCommitment,omitempty"`
	SectorID                         string `json:"sectorId,omitempty"`
	DeadlineIndex                    int    `json:"deadlineIndex,omitempty"`
	PartitionIndex                   int    `json:"partitionIndex,omitempty"`
	CapacityMutationSequence         uint64 `json:"capacityMutationSequence,omitempty"`
	RollbackCapacityMutationSequence uint64 `json:"rollbackCapacityMutationSequence,omitempty"`
	Phase                            string `json:"phase"`
	LastError                        string `json:"lastError,omitempty"`
	// B.4: a conclusively failed upload operation. Its reservation may be released once local
	// sector state proves the reserved sector is not durable; liveness evidence alone never is.
	Terminal       bool   `json:"terminal,omitempty"`
	TerminalReason string `json:"terminalReason,omitempty"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

type DeletionLifecycleOperation struct {
	Version                  int    `json:"version"`
	CommitmentHash           string `json:"commitmentHash"`
	PieceRoot                string `json:"pieceRoot"`
	SectorID                 string `json:"sectorId,omitempty"`
	DeadlineIndex            int    `json:"deadlineIndex,omitempty"`
	PartitionIndex           int    `json:"partitionIndex,omitempty"`
	CapacityMutationSequence uint64 `json:"capacityMutationSequence,omitempty"`
	Phase                    string `json:"phase"`
	LastError                string `json:"lastError,omitempty"`
	RetryProofRound          uint64 `json:"retryProofRound,omitempty"`
	// SealedContentVersion / SealedContentHash record the immutable post-delete
	// successor that must be proved before confirm. Uploads are excluded from
	// this coordinate until the journal is removed.
	SealedContentVersion uint64 `json:"sealedContentVersion,omitempty"`
	SealedContentHash    string `json:"sealedContentHash,omitempty"`
	CreatedAt            string `json:"createdAt"`
	UpdatedAt            string `json:"updatedAt"`
	// DeclaredAtUnix is the durable host time the operation advanced to declared_pending.
	// It anchors the A.2.5 dispute-grace deadline used by the freeze-ownership arbiter and
	// survives restart. Zero while the operation is still accepted_queued.
	DeclaredAtUnix int64 `json:"declaredAtUnix,omitempty"`
	// SuccessorRegisteredAtUnix opens a bounded ownership-negotiation window after the exact
	// successor becomes visible. During it, qualified lifecycle urgency can durably claim the
	// incremental path before the standalone deletion worker takes the non-preemptible slot.
	SuccessorRegisteredAtUnix int64 `json:"successorRegisteredAtUnix,omitempty"`
}

type DeletionLifecycleResult struct {
	PartitionTx string
	ProofTx     string
	ConfirmTx   string
	ClaimTx     string
}

type deletionLifecycleReleaseRecord struct {
	Version         int    `json:"version"`
	CommitmentHash  string `json:"commitmentHash"`
	SourceCreatedAt string `json:"sourceCreatedAt,omitempty"`
	Phase           string `json:"phase,omitempty"`
	DeadlineIndex   int    `json:"deadlineIndex,omitempty"`
	PartitionIndex  int    `json:"partitionIndex,omitempty"`
	Reason          string `json:"reason"`
	ReleasedAt      string `json:"releasedAt"`
}

type lifecycleOperationLock struct {
	file *os.File
}

func acquireLifecycleOperationLock(storage, kind, key string) (*lifecycleOperationLock, error) {
	dir := filepath.Join(storage, "lifecycle", "locks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, kind+"-"+lifecycleOperationID(key)+".lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &lifecycleOperationLock{file: file}, nil
}

// tryAcquireLifecycleOperationLock takes the same lock without blocking, reporting
// acquired=false when another goroutine or process currently owns the operation.
//
// DEFECT F, second order. The background reconciler ran the store sweep and the deletion
// sweep sequentially in ONE goroutine, and took each store's operation lock with a BLOCKING
// flock. A store handler holds that lock for its whole body, including unbounded chain RPCs.
// So any single store that was slow — or, before the lock-order fix above, deadlocked —
// stopped the reconciler dead on its FIRST operation: deletions were never reconciled, and
// because the blocked acquisition logs nothing, the VK went completely silent. Smoke7 VK1
// emitted exactly two [lifecycle] lines and then nothing for twelve hours.
//
// A live owner means the reconciler has nothing to do for that operation: recovery exists for
// operations nobody is driving. Skipping is therefore not a weakening — the next sweep, one
// minute later, retries it. It is also not a timer or a grace period: no deadline is waited
// out and no state is forced, the sweep simply declines to fight the owner and moves on.
func tryAcquireLifecycleOperationLock(storage, kind, key string) (*lifecycleOperationLock, bool, error) {
	dir := filepath.Join(storage, "lifecycle", "locks")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, false, err
	}
	path := filepath.Join(dir, kind+"-"+lifecycleOperationID(key)+".lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &lifecycleOperationLock{file: file}, true, nil
}

func (lock *lifecycleOperationLock) Release() {
	if lock == nil || lock.file == nil {
		return
	}
	_ = syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	_ = lock.file.Close()
	lock.file = nil
}

func lifecycleOperationID(value string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(value))))
	return hex.EncodeToString(sum[:])
}

func storeLifecycleDir(storage string) string {
	return filepath.Join(storage, "lifecycle", "stores")
}

func storeLifecyclePath(storage, pieceRoot string) string {
	return filepath.Join(storeLifecycleDir(storage), lifecycleOperationID(pieceRoot)+".json")
}

func deletionLifecycleDir(storage string) string {
	return filepath.Join(storage, "lifecycle", "deletions")
}

func deletionLifecyclePath(storage, commitmentHash string) string {
	return filepath.Join(deletionLifecycleDir(storage), lifecycleOperationID(commitmentHash)+".json")
}

func deletionLifecycleCompletedPath(storage, commitmentHash string) string {
	return filepath.Join(deletionLifecycleDir(storage), lifecycleOperationID(commitmentHash)+".completed")
}

func deletionLifecycleReleaseDir(storage string) string {
	return filepath.Join(storage, "lifecycle", "deletion-releases")
}

func deletionLifecycleReleasePath(storage, commitmentHash string) string {
	return filepath.Join(
		deletionLifecycleReleaseDir(storage), lifecycleOperationID(commitmentHash)+".json",
	)
}

func markDeletionLifecycleCompleted(storage, commitmentHash string) error {
	return durableAtomicWriteFile(
		deletionLifecycleCompletedPath(storage, commitmentHash),
		[]byte(nowRFC3339()+"\n"), 0600,
	)
}

func writeDeletionLifecycleRelease(
	storage string, operation DeletionLifecycleOperation, reason string,
) error {
	if strings.TrimSpace(operation.CommitmentHash) == "" || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("write deletion lifecycle release: incomplete terminal record")
	}
	record := deletionLifecycleReleaseRecord{
		Version: deletionLifecycleReleaseVersion, CommitmentHash: operation.CommitmentHash,
		SourceCreatedAt: operation.CreatedAt, Phase: operation.Phase,
		DeadlineIndex: operation.DeadlineIndex, PartitionIndex: operation.PartitionIndex,
		Reason: reason, ReleasedAt: nowRFC3339(),
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(
		deletionLifecycleReleasePath(storage, operation.CommitmentHash), payload, 0600,
	)
}

func deletionLifecycleReleaseMatches(storage string, operation DeletionLifecycleOperation) (bool, error) {
	payload, err := os.ReadFile(deletionLifecycleReleasePath(storage, operation.CommitmentHash))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var record deletionLifecycleReleaseRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return false, err
	}
	return record.Version == deletionLifecycleReleaseVersion &&
		strings.EqualFold(record.CommitmentHash, operation.CommitmentHash) &&
		record.SourceCreatedAt == operation.CreatedAt, nil
}

func syncLifecycleDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func releaseDeletionLifecycleOwnership(
	storage string, operation DeletionLifecycleOperation, reason string,
) error {
	// Persist the terminal decision first. If the process stops before removing
	// the active journal, list recovery below observes this exact creation id and
	// finishes the removal without releasing a later retry of the same commitment.
	if err := writeDeletionLifecycleRelease(storage, operation, reason); err != nil {
		return err
	}
	if err := removeDeletionLifecycleOperation(storage, operation.CommitmentHash); err != nil {
		return err
	}
	_ = clearPartitionDeletionInProgress(storage, operation.DeadlineIndex, operation.PartitionIndex)
	return syncLifecycleDirectory(deletionLifecycleDir(storage))
}

func quarantineDeletionLifecycleFile(path string, cause error) error {
	dir := filepath.Dir(path)
	quarantineDir := filepath.Join(dir, "quarantine")
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return err
	}
	target := filepath.Join(
		quarantineDir, fmt.Sprintf("%s.invalid-%d", filepath.Base(path), time.Now().UnixNano()),
	)
	if err := os.Rename(path, target); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	_ = durableAtomicWriteFile(target+".reason", []byte(cause.Error()+"\n"), 0600)
	if err := syncLifecycleDirectory(dir); err != nil {
		return err
	}
	return syncLifecycleDirectory(quarantineDir)
}

func writeStoreLifecycleOperation(storage string, operation StoreLifecycleOperation) error {
	if operation.PieceRoot == "" {
		return fmt.Errorf("write store lifecycle operation: empty piece root")
	}
	if operation.Version == 0 {
		operation.Version = lifecycleJournalVersion
	}
	now := nowRFC3339()
	if operation.CreatedAt == "" {
		operation.CreatedAt = now
	}
	operation.UpdatedAt = now
	b, err := json.MarshalIndent(operation, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(storeLifecyclePath(storage, operation.PieceRoot), b, 0600)
}

func removeStoreLifecycleOperation(storage, pieceRoot string) error {
	err := os.Remove(storeLifecyclePath(storage, pieceRoot))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func writeDeletionLifecycleOperation(storage string, operation DeletionLifecycleOperation) error {
	if operation.CommitmentHash == "" {
		return fmt.Errorf("write deletion lifecycle operation: empty commitment hash")
	}
	if operation.Version == 0 {
		operation.Version = lifecycleJournalVersion
	}
	now := nowRFC3339()
	if operation.CreatedAt == "" {
		operation.CreatedAt = now
	}
	operation.UpdatedAt = now
	b, err := json.MarshalIndent(operation, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(deletionLifecyclePath(storage, operation.CommitmentHash), b, 0600)
}

func readDeletionLifecycleOperation(storage, commitmentHash string) (DeletionLifecycleOperation, bool, error) {
	var operation DeletionLifecycleOperation
	b, err := os.ReadFile(deletionLifecyclePath(storage, commitmentHash))
	if os.IsNotExist(err) {
		return operation, false, nil
	}
	if err != nil {
		return operation, false, err
	}
	if err := json.Unmarshal(b, &operation); err != nil {
		return operation, true, err
	}
	return operation, true, nil
}

func removeDeletionLifecycleOperation(storage, commitmentHash string) error {
	err := os.Remove(deletionLifecyclePath(storage, commitmentHash))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func recordDeletionLifecycleError(storage, commitmentHash string, lifecycleErr error) {
	operation, found, err := readDeletionLifecycleOperation(storage, commitmentHash)
	if err != nil || !found {
		return
	}
	operation.LastError = lifecycleErr.Error()
	_ = writeDeletionLifecycleOperation(storage, operation)
}

func partitionDeletionPendingPath(storage string, deadlineIndex, partitionIndex int) string {
	return filepath.Join(
		deletionLifecycleDir(storage),
		fmt.Sprintf("partition-dl%d-pt%d.pending", deadlineIndex, partitionIndex),
	)
}

func markPartitionDeletionInProgress(storage string, deadlineIndex, partitionIndex int) error {
	if err := os.MkdirAll(deletionLifecycleDir(storage), 0700); err != nil {
		return fmt.Errorf("create deletion lifecycle dir: %w", err)
	}
	return atomicWriteFile(
		partitionDeletionPendingPath(storage, deadlineIndex, partitionIndex),
		[]byte(nowRFC3339()+"\n"),
		0600,
	)
}

func clearPartitionDeletionInProgress(storage string, deadlineIndex, partitionIndex int) error {
	err := os.Remove(partitionDeletionPendingPath(storage, deadlineIndex, partitionIndex))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func partitionDeletionInProgress(storage string, deadlineIndex, partitionIndex int) bool {
	_, err := os.Stat(partitionDeletionPendingPath(storage, deadlineIndex, partitionIndex))
	return err == nil
}

func partitionHasPendingDeletion(storage string, deadlineIndex, partitionIndex int) (bool, error) {
	keys, err := pendingDeletionPartitionKeys(storage)
	if err != nil {
		return false, err
	}
	if keys[partitionBucketKey{
		deadlineIndex: deadlineIndex, partitionIndex: partitionIndex, kind: PartitionKindData,
	}] {
		return true, nil
	}
	if partitionDeletionInProgress(storage, deadlineIndex, partitionIndex) {
		// The journal is the durable owner of deletion work. The small partition
		// marker only coordinates a currently running process; after a crash it can
		// outlive the journal and must not suppress proofs forever.
		if err := clearPartitionDeletionInProgress(storage, deadlineIndex, partitionIndex); err != nil {
			return false, fmt.Errorf("clear orphan deletion marker: %w", err)
		}
		log.Printf("[delete] cleared orphan partition marker dl=%d pt=%d", deadlineIndex, partitionIndex)
	}
	return false, nil
}

// pendingDeletionPartitionKeys returns every data-partition coordinate that still
// has an open deletion lifecycle journal. Callers use this to seal those
// coordinates against new upload packing until confirm completes.
func pendingDeletionPartitionKeys(storage string) (map[partitionBucketKey]bool, error) {
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return nil, err
	}
	keys := make(map[partitionBucketKey]bool, len(operations))
	for _, operation := range operations {
		dl, pt, resolved, resolveErr := deletionOperationPartitionCoordinates(storage, operation)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if !resolved {
			continue
		}
		keys[partitionBucketKey{
			deadlineIndex: dl, partitionIndex: pt, kind: PartitionKindData,
		}] = true
	}
	return keys, nil
}

func deletionOperationPartitionCoordinates(
	storage string, operation DeletionLifecycleOperation,
) (int, int, bool, error) {
	dl := operation.DeadlineIndex
	pt := operation.PartitionIndex
	// SectorID records authentic coordinates including dl=0,pt=0. Non-zero
	// coordinates also mean that the journal already resolved its partition.
	resolved := strings.TrimSpace(operation.SectorID) != "" || dl != 0 || pt != 0
	if !resolved && operation.PieceRoot != "" {
		sector, found, err := sectorForDeletionOperation(storage, operation)
		if err != nil {
			return 0, 0, false, err
		}
		if found {
			dl = sector.DeadlineIndex
			pt = sector.PartitionIndex
			resolved = true
		}
	}
	return dl, pt, resolved, nil
}

type deletionPartitionCandidate struct {
	commitment string
	createdAt  string
}

// deletionPartitionSuccessorCandidates lists every locally-tracked deletion targeting
// this exact coordinate, ordered by the local FIFO tie-break: earliest createdAt first,
// ties (createdAt has only 1-second resolution) broken by lowest commitment hash.
func deletionPartitionSuccessorCandidates(
	storage string, deadlineIndex, partitionIndex int,
) ([]deletionPartitionCandidate, error) {
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return nil, err
	}
	candidates := make([]deletionPartitionCandidate, 0, len(operations))
	for _, operation := range operations {
		dl, pt, resolved, resolveErr := deletionOperationPartitionCoordinates(storage, operation)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if !resolved || dl != deadlineIndex || pt != partitionIndex {
			continue
		}
		candidates = append(candidates, deletionPartitionCandidate{
			commitment: operation.CommitmentHash,
			createdAt:  operation.CreatedAt,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].createdAt != candidates[j].createdAt {
			return candidates[i].createdAt < candidates[j].createdAt
		}
		return strings.ToLower(candidates[i].commitment) < strings.ToLower(candidates[j].commitment)
	})
	return candidates, nil
}

// deletionPartitionSuccessorOwner returns the one durable deletion allowed to
// mutate/prove a coordinate, predicted purely from local records (see
// deletionPartitionSuccessorCandidates). This is a PREDICTION, not a fact: it does not
// know which candidate's on-chain declaration transaction actually lands first.
// Callers gating an on-chain mutation must use deletionPartitionSuccessorOwnerChain
// instead, which defers to chain state when it is available.
func deletionPartitionSuccessorOwner(
	storage string, deadlineIndex, partitionIndex int,
) (string, bool, error) {
	candidates, err := deletionPartitionSuccessorCandidates(storage, deadlineIndex, partitionIndex)
	if err != nil {
		return "", false, err
	}
	if len(candidates) == 0 {
		return "", false, nil
	}
	return candidates[0].commitment, true, nil
}

// deletionPartitionSuccessorOwnerChain is the authoritative form of
// deletionPartitionSuccessorOwner.
//
// THE RACE THIS FIXES: two deletions on the same partition, requested in the same
// wall-clock second (createdAt has only 1-second resolution), tie-break identically
// on every VK process by commitment-hash order. That local prediction does NOT
// control which declaration transaction is actually mined first on chain. If the
// local "winner" loses that race, DeletionReleaseSC's per-partition lock
// (unresolvedOperationByPartition) is held by the local "loser" — who local-only code
// then permanently refuses to recognize as owner (it isn't the local prediction),
// while the local "winner" can never declare (the lock is already taken by the other
// one). Both operations wait on each other forever: a live deadlock, not a timing
// issue that resolves itself.
//
// The fix: walk the local candidates in local tie-break order, but the first
// candidate found to ALREADY have an on-chain DeletionReleaseSC operation is the real
// owner, regardless of local order — chain state is ground truth for "who got there
// first". Only when no candidate has reached chain yet does the local tie-break decide
// who may attempt to declare next.
func deletionPartitionSuccessorOwnerChain(
	ctx context.Context, cfg ServerConfig, deadlineIndex, partitionIndex int,
) (string, bool, error) {
	candidates, err := deletionPartitionSuccessorCandidates(cfg.Storage, deadlineIndex, partitionIndex)
	if err != nil {
		return "", false, err
	}
	if len(candidates) == 0 {
		return "", false, nil
	}
	if strings.TrimSpace(cfg.DeletionReleaseContract) == "" ||
		strings.TrimSpace(cfg.FileRegistrationContract) == "" {
		// Chain awareness unavailable (contracts not configured): fall back to the
		// local prediction exactly as deletionPartitionSuccessorOwner would.
		return candidates[0].commitment, true, nil
	}
	for _, candidate := range candidates {
		_, statusErr := deletionReleaseStatusOnChain(ctx, cfg, candidate.commitment)
		if statusErr == nil {
			// This candidate already has an on-chain operation: it is the real owner
			// regardless of local tie-break order.
			return candidate.commitment, true, nil
		}
		if !deletionReleaseOperationMissing(statusErr) {
			// A real RPC/transport failure must never be silently guessed through.
			return "", false, statusErr
		}
	}
	// No candidate has reached chain yet: the local tie-break decides who may attempt
	// to declare next.
	return candidates[0].commitment, true, nil
}

// deletionReleaseOperationMissing reports whether statusErr is
// deletionReleaseStatusOnChain's "no operation exists yet for this commitment" case,
// as opposed to a real RPC/transport/configuration failure.
func deletionReleaseOperationMissing(err error) bool {
	return err != nil && strings.Contains(err.Error(), "deletion release operation is missing")
}

func listDeletionLifecycleOperations(storage string) ([]DeletionLifecycleOperation, error) {
	entries, err := os.ReadDir(deletionLifecycleDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	operations := make([]DeletionLifecycleOperation, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(deletionLifecycleDir(storage), entry.Name())
		base := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if _, completedErr := os.Stat(filepath.Join(deletionLifecycleDir(storage), base+".completed")); completedErr == nil {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				return nil, removeErr
			}
			if syncErr := syncLifecycleDirectory(deletionLifecycleDir(storage)); syncErr != nil {
				return nil, syncErr
			}
			continue
		} else if !os.IsNotExist(completedErr) {
			return nil, completedErr
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		var operation DeletionLifecycleOperation
		if unmarshalErr := json.Unmarshal(b, &operation); unmarshalErr != nil {
			cause := fmt.Errorf("read deletion lifecycle %s: %w", entry.Name(), unmarshalErr)
			if quarantineErr := quarantineDeletionLifecycleFile(path, cause); quarantineErr != nil {
				return nil, fmt.Errorf("%v; quarantine failed: %w", cause, quarantineErr)
			}
			log.Printf("[lifecycle] quarantined invalid deletion journal %s: %v", entry.Name(), unmarshalErr)
			continue
		}
		if operation.Version != lifecycleJournalVersion ||
			strings.TrimSpace(operation.CommitmentHash) == "" ||
			entry.Name() != lifecycleOperationID(operation.CommitmentHash)+".json" {
			cause := fmt.Errorf("unsupported or mismatched deletion journal identity/version")
			if quarantineErr := quarantineDeletionLifecycleFile(path, cause); quarantineErr != nil {
				return nil, fmt.Errorf("%v; quarantine failed: %w", cause, quarantineErr)
			}
			log.Printf("[lifecycle] quarantined invalid deletion journal %s", entry.Name())
			continue
		}
		released, releaseErr := deletionLifecycleReleaseMatches(storage, operation)
		if releaseErr != nil {
			return nil, fmt.Errorf("read deletion release %s: %w", entry.Name(), releaseErr)
		}
		if released {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				return nil, removeErr
			}
			if syncErr := syncLifecycleDirectory(deletionLifecycleDir(storage)); syncErr != nil {
				return nil, syncErr
			}
			continue
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

func finalizeConfirmedDeletionLifecycle(storage string, operation DeletionLifecycleOperation) error {
	if operation.PieceRoot != "" {
		if err := os.Remove(piecePath(storage, operation.PieceRoot)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(metaPath(storage, operation.PieceRoot)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	// The marker is the durable terminal decision. A crash after it is written
	// cannot resurrect ownership: journal listing removes a matching active file.
	if err := markDeletionLifecycleCompleted(storage, operation.CommitmentHash); err != nil {
		return err
	}
	if err := removeDeletionLifecycleOperation(storage, operation.CommitmentHash); err != nil {
		return err
	}
	_ = clearPartitionDeletionInProgress(storage, operation.DeadlineIndex, operation.PartitionIndex)
	return syncLifecycleDirectory(deletionLifecycleDir(storage))
}

// pieceDeletionPending is the local access tombstone. Once an authorized
// deletion has a durable lifecycle journal, the bytes may remain for recovery
// but must no longer be advertised or served.
func pieceDeletionPending(storage, pieceRoot string) (bool, error) {
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return false, err
	}
	for _, operation := range operations {
		if strings.EqualFold(operation.PieceRoot, pieceRoot) {
			return true, nil
		}
	}
	return false, nil
}

func deletionPhaseAtLeast(phase, required string) bool {
	rank := map[string]int{
		// accepted_queued (durably accepted, not yet declared) and the legacy
		// "requested" name both rank 0 (default) — below "declared".
		"declared": 1, "declared_pending": 1, "partition_synced": 2,
		"partition_proven": 4,
		"confirmed":        5, "settled": 6,
	}
	return rank[strings.ToLower(strings.TrimSpace(phase))] >= rank[required]
}

// deletionMutationsBlockingCapacityEpoch is true while a deletion is still
// changing local/on-chain partition membership. Starting a new epoch in that
// narrow window would immediately require exclusion (or the under-backed abort
// fallback), so wait until the successor coordinate is stable. An already-sealed
// epoch is not stopped here and continues over its retained cutoff members.
// capacityEpochDeclaredDeletionBlockGraceSeconds bounds how long a declared deletion may gate a
// NEW capacity epoch's start (Fix Go-3, Run 16 VK2). It matches the 1800 s capacity hard-lag: a
// declared deletion should complete well within it, so staying declared past it means the deletion
// is stuck and must not be allowed to freeze capacity indefinitely.
const capacityEpochDeclaredDeletionBlockGraceSeconds = 1800

func deletionMutationsBlockingCapacityEpoch(storage string) (bool, error) {
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return false, err
	}
	nowUnix := time.Now().Unix()
	for _, operation := range operations {
		switch strings.ToLower(strings.TrimSpace(operation.Phase)) {
		// Only a DECLARED-but-not-yet-mutated deletion is imminently changing
		// partition membership and must gate a new epoch's start. An undeclared
		// accepted_queued deletion (still waiting for FIFO ownership and a DO
		// secret re-drive) has NOT touched the partition — blocking on it could
		// stall capacity indefinitely while the DO is offline. If such a deletion
		// later declares during an active epoch, the on-chain exclusion mechanism
		// removes that member (and capacity self-abandons its frozen snapshot where
		// necessary), so capacity does not need to be blocked on it up front.
		case "declared", "declared_pending":
			// FIX Go-3 (Run 16, VK2): BOUND the block. A declared deletion is expected to complete
			// promptly and may gate a NEW capacity epoch's start only while it is within its
			// completion grace. One stuck declared deletion blocked VK2's capacity for ~3.3h. Past
			// the grace it no longer blocks: capacity proceeds, the on-chain exclusion mechanism
			// still removes the member if the deletion later mutates during an active epoch, and the
			// overdue deletion is surfaced for its own recovery. The deletion is NEVER lost — it is
			// just no longer allowed to freeze the whole VK's capacity forever.
			if declaredAt := operation.DeclaredAtUnix; declaredAt > 0 &&
				nowUnix-declaredAt >= capacityEpochDeclaredDeletionBlockGraceSeconds {
				log.Printf("[capacity-epoch] declared deletion dl=%d pt=%d overdue %ds past declaration; "+
					"no longer blocking capacity start (deletion needs recovery)",
					operation.DeadlineIndex, operation.PartitionIndex, nowUnix-declaredAt)
				continue
			}
			return true, nil
		}
	}
	return false, nil
}

func uncommittedDeletionRequestExpired(operation DeletionLifecycleOperation, now time.Time) bool {
	if strings.ToLower(strings.TrimSpace(operation.Phase)) != "requested" {
		return false
	}
	raw := operation.CreatedAt
	if raw == "" {
		raw = operation.UpdatedAt
	}
	created, err := time.Parse(time.RFC3339Nano, raw)
	return err == nil && now.Sub(created) >= 5*time.Minute
}

func deletionDeclarationAbsentExpired(operation DeletionLifecycleOperation, now time.Time) bool {
	raw := operation.CreatedAt
	if raw == "" {
		raw = operation.UpdatedAt
	}
	created, err := time.Parse(time.RFC3339Nano, raw)
	// With an authoritative chain result of "not declared", an invalid/missing
	// creation time cannot justify permanent local ownership.
	return err != nil || now.Sub(created) >= 5*time.Minute
}

func sectorForDeletionOperation(storage string, operation DeletionLifecycleOperation) (SectorMeta, bool, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return SectorMeta{}, false, err
	}
	for _, sector := range sectors {
		if operation.SectorID != "" && sector.SectorID == operation.SectorID {
			return sector, true, nil
		}
		for _, root := range sector.PieceRoots {
			if strings.EqualFold(root, operation.PieceRoot) {
				return sector, true, nil
			}
		}
	}
	if operation.PieceRoot != "" {
		if meta, metaErr := readMeta(storage, operation.PieceRoot); metaErr == nil && meta.SectorID != "" {
			if sector, sectorErr := readSector(storage, meta.SectorID); sectorErr == nil {
				return sector, true, nil
			}
		}
	}
	if operation.SectorID != "" {
		return SectorMeta{
			SectorID:          operation.SectorID,
			DeadlineIndex:     operation.DeadlineIndex,
			PartitionIndex:    operation.PartitionIndex,
			PartitionAssigned: true,
		}, true, nil
	}
	return SectorMeta{}, false, nil
}

// deletionDeclarationClaimTimeout bounds the under-claim chain queries and broadcast via a
// context deadline. Every underlying step honours the context (HTTP requests are built
// with it, retry backoffs and the receipt wait select on it) AND has its own finite
// timeout (15s per RPC HTTP call), so the under-claim body always returns in bounded
// time. Overridable in tests.
var deletionDeclarationClaimTimeout = 90 * time.Second

// deletionDeclarationReconcileGrace bounds the post-broadcast-error landed-tx re-check,
// which runs with a fresh context because the primary context may already be expired.
var deletionDeclarationReconcileGrace = 15 * time.Second

// deletionDeclarationReplaceAfter is the bounded replacement policy for a DROPPED
// declaration transaction: a persisted pending attempt whose transaction is not mined, not
// in the mempool, and cannot be (or repeatedly fails to be) re-broadcast under its exact
// original hash may be replaced by a new attempt generation only after this age.
var deletionDeclarationReplaceAfter = 10 * time.Minute

const (
	declarationAttemptPending = "pending"
	declarationAttemptFailed  = "failed"
)

// deletionDeclarationAttempt is the durable record of ONE declaration nonce lineage. It
// is persisted BEFORE the network send, so an ambiguous outcome (timeout, cancellation,
// crash, lost reply) is always reconciled against the exact transaction hashes of this
// lineage before any new transaction may be created.
//
// One attempt = one sender nonce. Fee-bump REPLACEMENTS share the nonce (so at most one
// transaction in the lineage can ever mine) and only extend the lineage: the replaced
// hash moves to PriorTxHashes and TxHash becomes the active replacement. A NEW attempt
// generation (fresh nonce) is permitted only on proven consumption of this nonce:
// confirmed revert, declaration confirmed on-chain, or the chain's CONFIRMED account
// nonce advancing past Nonce while the contract remains undeclared.
//
// The record carries the full immutable transaction-envelope identity (chain id, sender,
// contract, type, value, calldata hash, nonce, gas fields) so deterministic
// reconstruction is guarded against configuration drift. It deliberately contains NO
// DeletionAuthSecret and NO raw transaction bytes: calldata is rebuilt from the
// request-supplied secret and must hash-match CalldataHash before anything is signed or
// broadcast.
type deletionDeclarationAttempt struct {
	Version        int    `json:"version"`
	CommitmentHash string `json:"commitmentHash"`
	Generation     uint64 `json:"generation"`
	// Active transaction hash (the latest fee-bump replacement, or the original).
	TxHash string `json:"txHash"`
	// Earlier same-nonce hashes in this lineage (original first). Every hash in
	// {PriorTxHashes ∪ TxHash} is reconciled: any of them may be the one that mined.
	PriorTxHashes []string `json:"priorTxHashes,omitempty"`
	// Immutable envelope identity.
	ChainID         int64  `json:"chainId"`
	Sender          string `json:"sender"`
	ContractAddress string `json:"contractAddress"`
	TxType          uint8  `json:"txType"`
	ValueWei        int64  `json:"valueWei"`
	CalldataHash    string `json:"calldataHash"`
	Nonce           uint64 `json:"nonce"`
	GasLimit        uint64 `json:"gasLimit"`
	// Fee field of the ACTIVE transaction (the only field a replacement may change).
	GasPriceWei int64  `json:"gasPriceWei"`
	State       string `json:"state"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// lineageHashes returns every transaction hash of the attempt's nonce lineage, active
// hash first.
func (a deletionDeclarationAttempt) lineageHashes() []string {
	out := make([]string, 0, 1+len(a.PriorTxHashes))
	if strings.TrimSpace(a.TxHash) != "" {
		out = append(out, a.TxHash)
	}
	out = append(out, a.PriorTxHashes...)
	return out
}

// bumpedDeclarationGasPrice is the bounded fee-replacement policy: +20%, minimum +1 wei,
// same nonce and envelope otherwise.
func bumpedDeclarationGasPrice(current int64) int64 {
	bumped := current + current/5
	if bumped <= current {
		bumped = current + 1
	}
	return bumped
}

// signedDeclaration bundles a freshly-built declaration transaction plus its full
// envelope identity for persistence. Release frees the account locks and must be called
// after the persist+broadcast sequence completes (or fails).
type signedDeclaration struct {
	TxHash          string
	Nonce           uint64
	GasLimit        uint64
	GasPriceWei     int64
	ChainID         int64
	Sender          string
	ContractAddress string
	CalldataHash    string
	RawHex          string
	Release         func()
}

func deletionDeclarationAttemptDir(storage string) string {
	return filepath.Join(storage, "lifecycle", "declare-attempts")
}

func deletionDeclarationAttemptPath(storage, commitment string) string {
	return filepath.Join(deletionDeclarationAttemptDir(storage), lifecycleOperationID(commitment)+".json")
}

func readDeletionDeclarationAttempt(storage, commitment string) (deletionDeclarationAttempt, bool, error) {
	var attempt deletionDeclarationAttempt
	payload, err := os.ReadFile(deletionDeclarationAttemptPath(storage, commitment))
	if os.IsNotExist(err) {
		return attempt, false, nil
	}
	if err != nil {
		return attempt, false, err
	}
	if err := json.Unmarshal(payload, &attempt); err != nil {
		return attempt, false, fmt.Errorf("decode declaration attempt: %w", err)
	}
	return attempt, true, nil
}

func writeDeletionDeclarationAttempt(storage string, attempt deletionDeclarationAttempt) error {
	if err := os.MkdirAll(deletionDeclarationAttemptDir(storage), 0700); err != nil {
		return err
	}
	if attempt.Version == 0 {
		attempt.Version = 1
	}
	now := nowRFC3339()
	if attempt.CreatedAt == "" {
		attempt.CreatedAt = now
	}
	attempt.UpdatedAt = now
	payload, err := json.MarshalIndent(attempt, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(deletionDeclarationAttemptPath(storage, attempt.CommitmentHash), payload, 0600)
}

func removeDeletionDeclarationAttempt(storage, commitment string) error {
	err := os.Remove(deletionDeclarationAttemptPath(storage, commitment))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func declarationAttemptAge(attempt deletionDeclarationAttempt, now time.Time) time.Duration {
	raw := attempt.CreatedAt
	if raw == "" {
		raw = attempt.UpdatedAt
	}
	created, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return 0
	}
	return now.Sub(created)
}

// declarationChainOps abstracts every chain interaction the declaration resolver needs, so
// the full ambiguous-transaction state machine is unit-testable without a chain.
type declarationChainOps struct {
	// declared reports the authoritative contract declaration state.
	declared func(ctx context.Context) (bool, error)
	// receiptStatus looks up the receipt for an exact lineage hash:
	// (found=false) → not mined; (found, success=true) → mined ok; (found, success=false) → reverted.
	receiptStatus func(ctx context.Context, txHash string) (found bool, success bool, err error)
	// inMempool reports whether the node still knows an exact lineage hash.
	inMempool func(ctx context.Context, txHash string) (bool, error)
	// confirmedNonce reports the sender's CONFIRMED ("latest", not "pending") account
	// nonce — the only trustworthy proof that a stored nonce has been consumed.
	confirmedNonce func(ctx context.Context) (uint64, error)
	// signNew builds and signs a brand-new declaration transaction (fresh nonce) WITHOUT
	// broadcasting; sd.Release frees the account locks and must be called after the
	// persist+broadcast sequence completes (or fails).
	signNew func(ctx context.Context) (signedDeclaration, error)
	// signSame deterministically reproduces the attempt's ACTIVE transaction after
	// verifying the full stored envelope (chain id, sender/signer, contract, type, value,
	// calldata hash); matches=false or err means the identical transaction could not be
	// safely reproduced and NOTHING may be broadcast under the old identity.
	signSame func(ctx context.Context, attempt deletionDeclarationAttempt) (rawHex string, matches bool, err error)
	// signReplacement builds the SAME-NONCE fee-bump replacement (identical envelope,
	// only the fee changes) after the same envelope verification.
	signReplacement func(ctx context.Context, attempt deletionDeclarationAttempt, newGasPriceWei int64) (txHash, rawHex string, err error)
	// sendRaw broadcasts a signed raw transaction.
	sendRaw func(ctx context.Context, rawHex string) error
	// logMined records a declaration that mined, with its real gas, in the VK
	// transaction log. Optional. Every other deletion transaction was logged; this
	// one was sent as a raw transaction and was not, so a measurement of what a
	// deletion costs the keeper silently left out its first and largest step.
	logMined func(ctx context.Context, txHash string)
}

// logMinedDeclaration records whichever of these hashes mined. They share one
// nonce, so at most one of them has a receipt; logMined writes nothing for the
// others. Called only on the paths that end an attempt of ours as declared, so a
// declaration is logged once.
func logMinedDeclaration(ctx context.Context, ops declarationChainOps, hashes ...string) {
	if ops.logMined == nil {
		return
	}
	for _, hash := range hashes {
		if strings.TrimSpace(hash) != "" {
			ops.logMined(ctx, hash)
		}
	}
}

func declarationDeclaredWithGrace(ops declarationChainOps) (bool, error) {
	graceCtx, cancel := context.WithTimeout(context.Background(), deletionDeclarationReconcileGrace)
	defer cancel()
	return ops.declared(graceCtx)
}

// declareDeletionResolveUnderClaim acquires the per-commitment declaration claim and runs
// the resolver SYNCHRONOUSLY under it (no worker goroutine — nothing can outlive the
// claim; the flock releases via defer only after the body has fully returned, and
// auto-releases on process death). The context deadline bounds every chain step.
func declareDeletionResolveUnderClaim(
	storage, commitment string, ops declarationChainOps,
) (declared bool, err error) {
	lock, lockErr := acquireLifecycleOperationLock(storage, "declare", commitment)
	if lockErr != nil {
		return false, lockErr
	}
	defer lock.Release() // strictly after the synchronous resolver has returned.

	ctx, cancel := context.WithTimeout(context.Background(), deletionDeclarationClaimTimeout)
	defer cancel()
	return resolveDeletionDeclarationLocked(ctx, storage, commitment, ops)
}

// resolveDeletionDeclarationLocked is the durable-attempt state machine. Invariants:
//   - a NEW SENDER NONCE is created ONLY on proven consumption of the stored nonce: a
//     confirmed revert of a lineage transaction, the declaration already confirmed
//     on-chain, or the chain's CONFIRMED account nonce having advanced past the stored
//     nonce while the contract remains undeclared. Absence from one node's mempool or a
//     pending-nonce reading is NEVER sufficient;
//   - a pending attempt is reconciled against EVERY exact hash in its nonce lineage:
//     mined+success → declared; reverted → terminal, next generation permitted; any hash
//     known to the node → wait; unknown everywhere → same-hash rebroadcast before the
//     replacement age, SAME-NONCE fee-bump replacement after it (identical envelope, only
//     the fee changes — at most one lineage transaction can ever mine);
//   - the full envelope (chain id, sender/signer, contract, type, value, calldata hash)
//     must verify before anything is signed or broadcast; drift STOPS the resolver with
//     an error rather than broadcasting or silently replacing;
//   - the attempt record is persisted BEFORE any network send (including replacements);
//   - (false, nil) means "in progress, nothing further to do this pass" — the operation
//     stays accepted_queued and the DO re-drive returns here.
func resolveDeletionDeclarationLocked(
	ctx context.Context, storage, commitment string, ops declarationChainOps,
) (bool, error) {
	attempt, exists, err := readDeletionDeclarationAttempt(storage, commitment)
	if err != nil {
		return false, err
	}

	if exists && attempt.State == declarationAttemptPending {
		// (1) Reconcile every hash in the nonce lineage — any of them may have mined.
		reverted := false
		for _, lineageHash := range attempt.lineageHashes() {
			found, success, rerr := ops.receiptStatus(ctx, lineageHash)
			if rerr != nil {
				return false, rerr
			}
			if !found {
				continue
			}
			if success {
				declared, derr := ops.declared(ctx)
				if derr != nil {
					return false, derr
				}
				if declared {
					logMinedDeclaration(ctx, ops, lineageHash)
					if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
						return false, err
					}
					return true, nil
				}
				return false, fmt.Errorf(
					"declaration tx %s mined but contract does not report declared; deferring",
					truncate(lineageHash, 18),
				)
			}
			// Confirmed revert: the nonce is consumed (same-nonce lineage ⇒ at most one
			// mines). This attempt is terminal; a new generation is permitted only now
			// that the terminal state is durably recorded.
			reverted = true
			break
		}
		if reverted {
			attempt.State = declarationAttemptFailed
			if err := writeDeletionDeclarationAttempt(storage, attempt); err != nil {
				return false, err
			}
		} else {
			// (2) No receipt anywhere. If ANY lineage hash is still known to the node it
			// is pending: never create or broadcast anything new.
			for _, lineageHash := range attempt.lineageHashes() {
				inPool, perr := ops.inMempool(ctx, lineageHash)
				if perr != nil {
					return false, perr
				}
				if inPool {
					return false, nil
				}
			}
			// (3) Unknown to THIS node — which does not prove the transaction is
			// dropped; it may be pending elsewhere and later mine. The only proof the
			// nonce is consumed is the CONFIRMED account nonce advancing past it.
			confirmed, nerr := ops.confirmedNonce(ctx)
			if nerr != nil {
				return false, nerr
			}
			if confirmed > attempt.Nonce {
				// Nonce consumed. Reconcile contract state before permitting anything.
				declared, derr := ops.declared(ctx)
				if derr != nil {
					return false, derr
				}
				if declared {
					logMinedDeclaration(ctx, ops, attempt.lineageHashes()...)
					if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
						return false, err
					}
					return true, nil
				}
				// Consumed while undeclared: terminal; new generation permitted below.
				attempt.State = declarationAttemptFailed
				if err := writeDeletionDeclarationAttempt(storage, attempt); err != nil {
					return false, err
				}
			} else if declarationAttemptAge(attempt, time.Now()) < deletionDeclarationReplaceAfter {
				// (4) Before the replacement age: re-broadcast the EXACT same signed
				// transaction (envelope-verified, hash-verified). No new nonce.
				rawHex, matches, serr := ops.signSame(ctx, attempt)
				if serr != nil {
					return false, fmt.Errorf(
						"declaration tx %s cannot be reproduced (envelope/config drift?); refusing to broadcast: %w",
						truncate(attempt.TxHash, 18), serr,
					)
				}
				if !matches {
					return false, fmt.Errorf(
						"declaration tx %s reproduction hash mismatch; refusing to broadcast under the old identity",
						truncate(attempt.TxHash, 18),
					)
				}
				if sendErr := ops.sendRaw(ctx, rawHex); sendErr != nil {
					if declaredNow, gerr := declarationDeclaredWithGrace(ops); gerr == nil && declaredNow {
						logMinedDeclaration(ctx, ops, attempt.lineageHashes()...)
						if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
							return false, err
						}
						return true, nil
					}
					return false, fmt.Errorf(
						"declaration tx %s rebroadcast rejected; will reconcile next pass: %w",
						truncate(attempt.TxHash, 18), sendErr,
					)
				}
				return false, nil // exact same hash re-broadcast; still pending.
			} else {
				// (5) Past the replacement age: SAME-NONCE fee-bump replacement.
				// Identical envelope, only the fee changes; the replaced hash stays in
				// the lineage and keeps being reconciled — at most one can mine.
				newPrice := bumpedDeclarationGasPrice(attempt.GasPriceWei)
				newHash, rawHex, serr := ops.signReplacement(ctx, attempt, newPrice)
				if serr != nil {
					return false, fmt.Errorf(
						"declaration tx %s replacement cannot be built (envelope/config drift?); refusing: %w",
						truncate(attempt.TxHash, 18), serr,
					)
				}
				attempt.PriorTxHashes = append(attempt.PriorTxHashes, attempt.TxHash)
				attempt.TxHash = newHash
				attempt.GasPriceWei = newPrice
				// Persist the extended lineage BEFORE the send.
				if err := writeDeletionDeclarationAttempt(storage, attempt); err != nil {
					return false, err
				}
				if sendErr := ops.sendRaw(ctx, rawHex); sendErr != nil {
					if declaredNow, gerr := declarationDeclaredWithGrace(ops); gerr == nil && declaredNow {
						logMinedDeclaration(ctx, ops, attempt.lineageHashes()...)
						if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
							return false, err
						}
						return true, nil
					}
					return false, fmt.Errorf(
						"declaration replacement %s broadcast rejected; will reconcile next pass: %w",
						truncate(newHash, 18), sendErr,
					)
				}
				return false, nil // replacement broadcast; still pending, same nonce.
			}
		}
		// Only a terminally-failed attempt falls through to the new-generation path.
		if attempt.State != declarationAttemptFailed {
			return false, nil
		}
	}

	// No attempt, or the previous attempt is terminal: authoritative declaration check
	// before any new transaction.
	declared, derr := ops.declared(ctx)
	if derr != nil {
		return false, derr
	}
	if declared {
		if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
			return false, err
		}
		return true, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		// Never begin a new attempt past the claim deadline.
		return false, fmt.Errorf("deletion declaration claim timed out before new attempt: %w", ctxErr)
	}

	generation := uint64(1)
	if exists {
		generation = attempt.Generation + 1
	}
	sd, berr := ops.signNew(ctx)
	if berr != nil {
		return false, berr
	}
	defer sd.Release()
	next := deletionDeclarationAttempt{
		Version:         1,
		CommitmentHash:  strings.ToLower(strings.TrimSpace(commitment)),
		Generation:      generation,
		TxHash:          sd.TxHash,
		ChainID:         sd.ChainID,
		Sender:          sd.Sender,
		ContractAddress: sd.ContractAddress,
		TxType:          0, // legacy transaction envelope
		ValueWei:        0,
		CalldataHash:    sd.CalldataHash,
		Nonce:           sd.Nonce,
		GasLimit:        sd.GasLimit,
		GasPriceWei:     sd.GasPriceWei,
		State:           declarationAttemptPending,
	}
	// Persist the attempt identity BEFORE the network send: any later ambiguity is
	// reconciled against this exact hash instead of re-declaring blindly.
	if err := writeDeletionDeclarationAttempt(storage, next); err != nil {
		return false, err
	}
	if sendErr := ops.sendRaw(ctx, sd.RawHex); sendErr != nil {
		// The send may have reached the node despite the error (cancelled reply). The
		// attempt record is durable; a grace declared-check catches the fast-mined case,
		// and the next pass reconciles by exact hash otherwise.
		if declaredNow, gerr := declarationDeclaredWithGrace(ops); gerr == nil && declaredNow {
			logMinedDeclaration(ctx, ops, sd.TxHash)
			if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, sendErr
	}
	// Broadcast accepted. Declared only when the chain reports it — often on a later
	// reconcile pass once the transaction mines.
	if declaredNow, derr2 := ops.declared(ctx); derr2 == nil && declaredNow {
		logMinedDeclaration(ctx, ops, sd.TxHash)
		if err := removeDeletionDeclarationAttempt(storage, commitment); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// markDeletionDeclaredPending advances a durably-accepted deletion to
// declared_pending exactly once its on-chain declaration is known to exist. It never
// regresses a further-advanced phase.
func markDeletionDeclaredPending(storage string, operation *DeletionLifecycleOperation) error {
	if deletionPhaseAtLeast(operation.Phase, "declared") {
		return nil
	}
	operation.Phase = "declared_pending"
	// A.2.5: anchor the dispute-grace deadline durably at the moment of declaration.
	if operation.DeclaredAtUnix == 0 {
		operation.DeclaredAtUnix = time.Now().Unix()
	}
	return writeDeletionLifecycleOperation(storage, *operation)
}

// attemptOwnerDeletionDeclaration declares a durably-accepted (accepted_queued)
// deletion on-chain, but only if this operation is the current durable FIFO owner of
// its partition. Declaration is performed in the request handler because an authorized
// deletion needs the request-supplied secret, which the VK must never persist.
//
// Properties:
//   - non-owner  → (false, nil): the operation stays accepted_queued and is re-driven
//     by the DO monitor until it becomes owner;
//   - revalidation: current partition/sector coordinates are re-resolved and persisted
//     before declaring, so a partition that advanced while queued is not declared
//     against stale coordinates;
//   - idempotent + crash-safe: on-chain declaration state is queried immediately before
//     sending and again after any send error, so a transaction that landed before a
//     crash does not produce a second declaration;
//   - transient failure → (false, err): the operation stays accepted_queued and
//     recoverable; it is never falsely marked declared.
//
// The secret is passed through to registerFileDeletionOnChain only; it is never
// persisted, logged, or returned in an error.
func attemptOwnerDeletionDeclaration(
	cfg ServerConfig, operation *DeletionLifecycleOperation, deletionAuthSecret string,
) (bool, error) {
	// A.2 gate: an on-chain deletion declaration mutates partition state and is a
	// proof-affecting transition. The deletion stays durably accepted_queued and is
	// re-driven once the startup barrier opens; only the mutation is blocked here.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return false, gateErr
	}
	// (a) Revalidate current partition/sector coordinates.
	affected, found, err := sectorForDeletionOperation(cfg.Storage, *operation)
	if err != nil {
		return false, err
	}
	if found && (operation.SectorID == "" ||
		operation.DeadlineIndex != affected.DeadlineIndex ||
		operation.PartitionIndex != affected.PartitionIndex) {
		operation.SectorID = affected.SectorID
		operation.DeadlineIndex = affected.DeadlineIndex
		operation.PartitionIndex = affected.PartitionIndex
		if werr := writeDeletionLifecycleOperation(cfg.Storage, *operation); werr != nil {
			return false, werr
		}
	}
	// (b) FIFO ownership: only the durable owner may declare. Non-owners wait.
	// Chain-aware: a candidate that has already reached chain is the real owner
	// regardless of the local tie-break (see deletionPartitionSuccessorOwnerChain).
	if found {
		owner, owned, ownerErr := deletionPartitionSuccessorOwnerChain(
			context.Background(), cfg, affected.DeadlineIndex, affected.PartitionIndex,
		)
		if ownerErr != nil {
			return false, ownerErr
		}
		if !owned || !strings.EqualFold(owner, operation.CommitmentHash) {
			return false, nil
		}
	}
	// (c)+(d) Durable-attempt declaration under the per-commitment claim: the resolver
	// reconciles any previously-persisted declaration transaction BY EXACT HASH (mined /
	// pending-in-mempool / dropped / reverted) before ever creating a new transaction, so
	// an ambiguous broadcast (timeout, crash, lost reply) can never lead to a second
	// distinct declaration while the first may still be pending. Safe under concurrent
	// requests and monitor re-drives overlapping direct retries.
	declared, err := declareDeletionResolveUnderClaim(
		cfg.Storage, operation.CommitmentHash,
		realDeletionDeclarationOps(cfg, operation.CommitmentHash, deletionAuthSecret),
	)
	if err != nil {
		return false, err
	}
	if declared {
		return true, markDeletionDeclaredPending(cfg.Storage, operation)
	}
	return false, nil
}

// realDeletionDeclarationOps wires the declaration resolver to the live chain. The secret
// is captured only in closures for calldata construction — never persisted or logged.
func realDeletionDeclarationOps(cfg ServerConfig, commitment, deletionAuthSecret string) declarationChainOps {
	return declarationChainOps{
		declared: func(ctx context.Context) (bool, error) {
			d, _, e := deletionStatusOnChainCtx(ctx, cfg, commitment)
			return d, e
		},
		receiptStatus: func(ctx context.Context, txHash string) (bool, bool, error) {
			receipt, err := rpcGetTransactionReceiptCtx(ctx, cfg.RPCURL, txHash)
			if err != nil {
				return false, false, err
			}
			if receipt == nil {
				return false, false, nil
			}
			return true, strings.EqualFold(strings.TrimSpace(receipt.Status), "0x1"), nil
		},
		inMempool: func(ctx context.Context, txHash string) (bool, error) {
			return rpcTransactionInMempoolCtx(ctx, cfg.RPCURL, txHash)
		},
		confirmedNonce: func(ctx context.Context) (uint64, error) {
			sender, err := declarationSenderAddress(cfg)
			if err != nil {
				return 0, err
			}
			return rpcGetConfirmedTransactionCountCtx(ctx, cfg.RPCURL, sender)
		},
		signNew: func(ctx context.Context) (signedDeclaration, error) {
			return newSignedDeletionDeclaration(ctx, cfg, commitment, deletionAuthSecret)
		},
		signSame: func(ctx context.Context, attempt deletionDeclarationAttempt) (string, bool, error) {
			return rebuildSignedDeletionDeclaration(cfg, commitment, deletionAuthSecret, attempt)
		},
		signReplacement: func(ctx context.Context, attempt deletionDeclarationAttempt, newGasPriceWei int64) (string, string, error) {
			return signDeletionDeclarationReplacement(cfg, commitment, deletionAuthSecret, attempt, newGasPriceWei)
		},
		logMined: func(ctx context.Context, txHash string) {
			receipt, err := rpcGetTransactionReceiptCtx(ctx, cfg.RPCURL, txHash)
			if err != nil || receipt == nil {
				return
			}
			sender, err := declarationSenderAddress(cfg)
			if err != nil {
				return
			}
			// The function name only: the secret itself is never logged.
			functionName := "registerFileDeletion"
			if strings.TrimSpace(deletionAuthSecret) != "" {
				functionName = "registerFileDeletionAuthorized"
			}
			logMinedTx("vk:FileRegistrationSC."+functionName, cfg.RPCURL, cfg.ChainID,
				sender, "FileRegistrationSC", functionName,
				strings.TrimSpace(cfg.FileRegistrationContract), nil, receipt, nil)
		},
		sendRaw: func(ctx context.Context, rawHex string) error {
			rawBytes, decodeErr := hex.DecodeString(strings.TrimPrefix(rawHex, "0x"))
			if decodeErr != nil {
				return fmt.Errorf("decode raw declaration tx: %w", decodeErr)
			}
			_, sendErr := rpcSendRawTransactionCtx(ctx, cfg.RPCURL, rawBytes)
			return sendErr
		},
	}
}

func resumeDeletionLifecycleOperation(cfg ServerConfig, creds PaymentCredentials, operation DeletionLifecycleOperation) (DeletionLifecycleResult, error) {
	var result DeletionLifecycleResult
	activity := beginForegroundActivity("delete")
	defer activity.Release()
	operationLock, err := acquireLifecycleOperationLock(cfg.Storage, "delete", operation.CommitmentHash)
	if err != nil {
		return result, err
	}
	defer operationLock.Release()
	// A request or the minute reconciler may have waited on this operation. Use
	// the newest durable phase instead of repeating work from its stale caller copy.
	if latest, found, readErr := readDeletionLifecycleOperation(cfg.Storage, operation.CommitmentHash); readErr != nil {
		return result, readErr
	} else if found {
		operation = latest
	}
	declared, confirmed, err := deletionStatusOnChain(cfg, operation.CommitmentHash)
	if err != nil {
		return result, err
	}
	if !declared {
		// accepted_queued: durably accepted but not yet declared on-chain. The VK
		// cannot declare from durable state alone (an authorized deletion needs the
		// request-supplied secret, which is never persisted); declaration happens in
		// handleDelete when this op is the FIFO owner and the DO re-drives the
		// secret-bearing request. Nothing to mutate/seal/prove yet — benign no-op,
		// not an error, so validly-queued deletions do not spam the error log.
		return result, nil
	}
	releaseSatisfied := false
	if strings.TrimSpace(cfg.DeletionReleaseContract) != "" {
		release, releaseErr := deletionReleaseStatusOnChain(
			context.Background(), cfg, operation.CommitmentHash,
		)
		if releaseErr != nil {
			return result, fmt.Errorf("deletion release reconciliation: %w", releaseErr)
		}
		if release.RecoveryRequired {
			return result, fmt.Errorf(
				"deletion release quarantined operation=%s reason=%d",
				truncate(release.OperationID, 18), release.RecoveryReason,
			)
		}
		switch release.State {
		case deletionReleaseAwaitingSuccessorIdentity:
			if deletionPhaseAtLeast(operation.Phase, "partition_synced") {
				return result, fmt.Errorf("deletion successor callback missing for operation %s",
					truncate(release.OperationID, 18))
			}
		case deletionReleaseAwaitingSuccessorProof:
			// The exact current revision is reconstructed by the snapshot queue below.
		case deletionReleaseSatisfied:
			releaseSatisfied = true
			operation.Phase = "partition_proven"
			operation.LastError = ""
			_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
		case deletionReleaseConfirmed:
			confirmed = true
		default:
			return result, fmt.Errorf("invalid deletion release state %d", release.State)
		}
	}

	affected, found, err := sectorForDeletionOperation(cfg.Storage, operation)
	if err != nil {
		return result, err
	}
	if found && (operation.SectorID == "" ||
		operation.DeadlineIndex != affected.DeadlineIndex ||
		operation.PartitionIndex != affected.PartitionIndex) {
		operation.SectorID = affected.SectorID
		operation.DeadlineIndex = affected.DeadlineIndex
		operation.PartitionIndex = affected.PartitionIndex
		// Persist coordinates before mutation so upload packing seals this
		// partition even if the process crashes mid-sync.
		if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
			return result, writeErr
		}
	}

	if !confirmed && found {
		owner, owned, ownerErr := deletionPartitionSuccessorOwnerChain(
			context.Background(), cfg, affected.DeadlineIndex, affected.PartitionIndex,
		)
		if ownerErr != nil {
			return result, ownerErr
		}
		if !owned || !strings.EqualFold(owner, operation.CommitmentHash) {
			return result, fmt.Errorf(
				"deletion successor dl=%d pt=%d is owned by earlier commitment %s",
				affected.DeadlineIndex, affected.PartitionIndex, truncate(owner, 18),
			)
		}
		if err := markPartitionDeletionInProgress(cfg.Storage, affected.DeadlineIndex, affected.PartitionIndex); err != nil {
			return result, err
		}
		defer func(dl, pt int) {
			if clearErr := clearPartitionDeletionInProgress(cfg.Storage, dl, pt); clearErr != nil {
				log.Printf("[delete] clear deletion marker warning dl=%d pt=%d: %v", dl, pt, clearErr)
			}
		}(affected.DeadlineIndex, affected.PartitionIndex)

		if !deletionPhaseAtLeast(operation.Phase, "partition_synced") {
			err = func() error {
				mutation, mutationErr := beginCapacityMutationOperation(
					cfg.Storage, "delete:"+strings.ToLower(operation.CommitmentHash), "delete",
				)
				if mutationErr != nil {
					return mutationErr
				}
				defer mutation.Release()
				operation.CapacityMutationSequence = mutation.JournalSequence()
				if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
					_ = mutation.Abandon()
					return writeErr
				}
				if localErr := func() error {
					storeCapacityMu.Lock()
					defer storeCapacityMu.Unlock()
					partitionLock, lockErr := acquirePartitionLifecycleLock(
						cfg.Storage, affected.DeadlineIndex, affected.PartitionIndex,
					)
					if lockErr != nil {
						return lockErr
					}
					defer partitionLock.Release()
					owner, owned, ownerErr := deletionPartitionSuccessorOwnerChain(
						context.Background(), cfg, affected.DeadlineIndex, affected.PartitionIndex,
					)
					if ownerErr != nil {
						return ownerErr
					}
					if !owned || !strings.EqualFold(owner, operation.CommitmentHash) {
						return fmt.Errorf(
							"deletion successor ownership changed dl=%d pt=%d owner=%s",
							affected.DeadlineIndex, affected.PartitionIndex, truncate(owner, 18),
						)
					}
					// The sector was first located before this cross-process lock. GC or a
					// recovered store may have changed it while deletion waited, so derive
					// the mutation from current durable state under the partition lock.
					if refreshed, refreshedFound, refreshErr := sectorForDeletionOperation(cfg.Storage, operation); refreshErr != nil {
						return refreshErr
					} else if refreshedFound {
						affected = refreshed
					}
					containsPiece := false
					for _, root := range affected.PieceRoots {
						if strings.EqualFold(root, operation.PieceRoot) {
							containsPiece = true
							break
						}
					}
					if containsPiece {
						affected, err = removePieceFromSectorWithMutation(
							cfg.Storage, operation.PieceRoot, cfg, mutation,
						)
						if err != nil {
							return err
						}
					}
					return mutation.Complete()
				}(); localErr != nil {
					return localErr
				}
				// The durable deletion-successor marker prevents reuse while the RPC runs;
				// neither the partition lock nor storeCapacityMu crosses this boundary.
				result.PartitionTx, err = syncDataPartitionAfterDelete(cfg, affected)
				return err
			}()
			if err != nil {
				return result, err
			}
			operation.Phase = "partition_synced"
			if operation.SuccessorRegisteredAtUnix == 0 {
				operation.SuccessorRegisteredAtUnix = time.Now().Unix()
			}
			operation.LastError = ""
			if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
				return result, writeErr
			}
		}

		// Pending-deletion sealing excludes new uploads from this coordinate.
		// Re-check the current successor on every retry; proveDeletionDataPartition
		// is a cheap no-op when the exact sealed version is already proved.
		if releaseSatisfied {
			goto confirmDeletion
		}
		sectors, listErr := listSectors(cfg.Storage)
		if listErr != nil {
			return result, listErr
		}
		clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
		if clockErr != nil {
			return result, fmt.Errorf("deletion partition clock: %w", clockErr)
		}
		partition, active := currentPartitionMetaByCoordinatesAt(
			sectors, cfg, affected.DeadlineIndex, affected.PartitionIndex, PartitionKindData,
			clock.ChainTimestamp,
		)
		if active {
			// Backfill the negotiation anchor for a pre-upgrade/recovered partition_synced
			// operation exactly once. Zero must not become an infinite fail-closed wait.
			if operation.SuccessorRegisteredAtUnix == 0 {
				operation.SuccessorRegisteredAtUnix = time.Now().Unix()
				if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
					return result, writeErr
				}
			}
			// Reconcile urgency here as well as in the proof daemon. This closes the normal
			// deletion-worker/scheduler race: once all four predicates qualify, the exact
			// successor obtains durable incremental ownership before either authority freezes.
			partitions := buildDeadlinePartitionsAt(
				sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors, clock.ChainTimestamp)
			outcome := evaluateProductionQualifiedUrgency(cfg.Storage, cfg, partitions, nil)
			if outcome.Evaluated && outcome.Result.Qualified &&
				strings.EqualFold(outcome.Result.SelectedIdentity.PartitionKey,
					epochPartitionKey(partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)) {
				if !persistUrgencyPriority(cfg.Storage, outcome.Result, partitions) {
					return result, fmt.Errorf(
						"qualified lifecycle urgency could not persist successor ownership")
				}
			}
			if deferred, detail, ownershipErr := directDeletionProofOwnershipDeferred(
				cfg.Storage, operation, partition, time.Now()); ownershipErr != nil {
				return result, ownershipErr
			} else if deferred {
				operation.LastError = detail
				_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
				return result, &deletionProofOwnershipDeferredError{Reason: detail}
			}
			if sealErr := sealDeletionSuccessorSnapshot(cfg, partition, clock); sealErr != nil {
				operation.LastError = sealErr.Error()
				_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
				return result, sealErr
			}
			if status, statusErr := partitionVersionStatusOnChain(cfg.ChainProofCmd, partition); statusErr == nil {
				operation.SealedContentVersion = status.ContentVersion
				operation.SealedContentHash = status.ContentHash
				_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
			}
			result.ProofTx, err = proveDeletionDataPartition(cfg, affected, partition)
			if err != nil {
				var deferred *partitionProofDeferredError
				if errors.As(err, &deferred) {
					operation.RetryProofRound = deferred.RetryRound
					operation.LastError = deferred.Error()
					_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
				}
				return result, err
			}
			operation.Phase = "partition_proven"
			operation.RetryProofRound = 0
			operation.LastError = ""
			if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
				return result, writeErr
			}
		} else {
			// G.4 empty successors are satisfied atomically by StorageProofSC's
			// authoritative transition receipt. No possession or capacity proof exists.
			operation.Phase = "partition_proven"
			operation.RetryProofRound = 0
			operation.LastError = ""
			if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
				return result, writeErr
			}
		}
	}

confirmDeletion:
	if !confirmed {
		result.ConfirmTx, err = confirmFileDeletionOnChain(cfg, operation.CommitmentHash)
		if err != nil {
			_, confirmedAfterError, statusErr := deletionStatusOnChain(cfg, operation.CommitmentHash)
			if statusErr != nil || !confirmedAfterError {
				return result, err
			}
			log.Printf("[delete] confirmation observed on-chain after submit error commitment=%s",
				truncate(operation.CommitmentHash, 18))
		}
		operation.Phase = "confirmed"
		operation.LastError = ""
		_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
	}

	if cfg.VKEscrowContract != "" && creds.Nullifier != "" {
		result.ClaimTx, err = claimEscrowOnDeletionChain(
			cfg, creds.Nullifier, creds.Secret, creds.RegNullifier, creds.RegSecret, creds.LinkNonce,
		)
		if err != nil {
			log.Printf("[delete] claimEscrowOnDeletion warning: %v", err)
			result.ClaimTx = ""
		}
	}

	storeCapacityMu.Lock()
	err = finalizeConfirmedDeletionLifecycle(cfg.Storage, operation)
	storeCapacityMu.Unlock()
	if err != nil {
		return result, err
	}
	return result, nil
}

func listStoreLifecycleOperations(storage string) ([]StoreLifecycleOperation, error) {
	entries, err := os.ReadDir(storeLifecycleDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	operations := make([]StoreLifecycleOperation, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(storeLifecycleDir(storage), entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		var operation StoreLifecycleOperation
		if unmarshalErr := json.Unmarshal(b, &operation); unmarshalErr != nil {
			return nil, fmt.Errorf("read store lifecycle %s: %w", entry.Name(), unmarshalErr)
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

// reconcileStoreLifecycleOperationLocked either observes a completed on-chain
// registration or removes an unregistered local sector from both the current
// partition and local storage. storeCapacityMu must be held by the caller.
func reconcileStoreLifecycleOperationLocked(cfg ServerConfig, operation StoreLifecycleOperation) (bool, error) {
	expired := false
	if operation.CommitmentHash != "" && cfg.FileRegistrationContract != "" {
		var expiredErr error
		expired, expiredErr = deletionBoolCall(
			context.Background(), cfg, expiredCommitmentHashSelector, operation.CommitmentHash,
		)
		if expiredErr != nil {
			return false, fmt.Errorf("check registration expiration: %w", expiredErr)
		}
		if !expired && operation.RegistrationCommitment != "" {
			expired, expiredErr = deletionBoolCall(
				context.Background(), cfg, expiredRegistrationCommitmentSelector, operation.RegistrationCommitment,
			)
			if expiredErr != nil {
				return false, fmt.Errorf("check registration-attempt expiration: %w", expiredErr)
			}
		}
		exists, existingVK, _, err := rpcGetRecordVKAddress(
			cfg.RPCURL, cfg.FileRegistrationContract, operation.CommitmentHash,
		)
		if err != nil {
			return false, fmt.Errorf("check file registration: %w", err)
		}
		if exists && !expired {
			if !strings.EqualFold(existingVK, cfg.VKAddress) {
				return false, fmt.Errorf("commitment registered by unexpected VK %s", existingVK)
			}
			mutation, mutationErr := beginCapacityMutationOperation(
				cfg.Storage, storeCapacityMutationOperationID(operation.CommitmentHash, operation.PieceRoot), "store",
			)
			if mutationErr != nil {
				return false, mutationErr
			}
			operation.CapacityMutationSequence = mutation.JournalSequence()
			_ = writeStoreLifecycleOperation(cfg.Storage, operation)
			if completeErr := mutation.Complete(); completeErr != nil {
				mutation.Release()
				return false, completeErr
			}
			mutation.Release()
			if err := removeStoreLifecycleOperation(cfg.Storage, operation.PieceRoot); err != nil {
				return true, err
			}
			return true, nil
		}
	}

	capacityMutation, err := beginCapacityMutationOperation(
		cfg.Storage, storeRollbackCapacityMutationOperationID(operation.CommitmentHash, operation.PieceRoot), "store_rollback",
	)
	if err != nil {
		return false, err
	}
	defer capacityMutation.Release()
	operation.RollbackCapacityMutationSequence = capacityMutation.JournalSequence()
	if err := writeStoreLifecycleOperation(cfg.Storage, operation); err != nil {
		_ = capacityMutation.Abandon()
		return false, err
	}

	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return false, err
	}
	affected := SectorMeta{
		SectorID:          operation.SectorID,
		DeadlineIndex:     operation.DeadlineIndex,
		PartitionIndex:    operation.PartitionIndex,
		PartitionAssigned: operation.SectorID != "",
	}
	containsPiece := false
	for _, sector := range sectors {
		for _, root := range sector.PieceRoots {
			if strings.EqualFold(root, operation.PieceRoot) {
				affected = sector
				containsPiece = true
				break
			}
		}
		if containsPiece {
			break
		}
	}
	storeMutation, storeMutationErr := beginCapacityMutationOperation(
		cfg.Storage, storeCapacityMutationOperationID(operation.CommitmentHash, operation.PieceRoot), "store",
	)
	if storeMutationErr != nil {
		return false, storeMutationErr
	}
	operation.CapacityMutationSequence = storeMutation.JournalSequence()
	_ = writeStoreLifecycleOperation(cfg.Storage, operation)
	if _, reconcileErr := storeMutation.ReconcilePlannedFromLocalState(); reconcileErr != nil {
		storeMutation.Release()
		return false, reconcileErr
	}
	if containsPiece {
		if completeErr := storeMutation.Complete(); completeErr != nil {
			storeMutation.Release()
			return false, completeErr
		}
	} else {
		_ = storeMutation.Abandon()
	}
	storeMutation.Release()

	var partitionLock *partitionLifecycleLock
	if affected.SectorID != "" {
		partitionLock, err = acquirePartitionLifecycleLock(cfg.Storage, affected.DeadlineIndex, affected.PartitionIndex)
		if err != nil {
			return false, err
		}
	}
	releasePartitionLock := func() {
		if partitionLock != nil {
			partitionLock.Release()
			partitionLock = nil
		}
	}
	if containsPiece {
		pendingDeletion, pendingErr := partitionHasPendingDeletion(
			cfg.Storage, affected.DeadlineIndex, affected.PartitionIndex,
		)
		if pendingErr != nil {
			releasePartitionLock()
			_ = capacityMutation.Abandon()
			return false, pendingErr
		}
		if pendingDeletion {
			releasePartitionLock()
			_ = capacityMutation.Abandon()
			return false, fmt.Errorf(
				"store rollback deferred: deletion owns successor dl=%d pt=%d",
				affected.DeadlineIndex, affected.PartitionIndex,
			)
		}
		affected, err = removePieceFromSectorWithMutation(
			cfg.Storage, operation.PieceRoot, cfg, capacityMutation,
		)
		if err != nil {
			releasePartitionLock()
			return false, err
		}
	}
	if err := capacityMutation.Complete(); err != nil {
		releasePartitionLock()
		return false, err
	}
	if affected.SectorID != "" && cfg.ChainProofCmd != "" {
		if _, err := syncDataPartitionAfterDelete(cfg, affected); err != nil {
			releasePartitionLock()
			return false, err
		}
		// Final proof generation acquires the host proof lock first and then
		// reacquires this partition lock. Never carry the partition lock into that
		// path: doing so self-deadlocks this process and creates the reverse lock
		// order of the normal proof daemon.
		releasePartitionLock()
		capacityMutation.Release()
		if expired {
			sectorsAfter, listErr := listSectors(cfg.Storage)
			if listErr != nil {
				return false, listErr
			}
			clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
			if clockErr != nil {
				return false, fmt.Errorf("expired store cleanup proof clock: %w", clockErr)
			}
			partition, active := currentPartitionMetaByCoordinatesAt(
				sectorsAfter, cfg, affected.DeadlineIndex, affected.PartitionIndex,
				PartitionKindData, clock.ChainTimestamp,
			)
			if active {
				if _, proofErr := proveDeletionDataPartition(cfg, affected, partition); proofErr != nil {
					return false, proofErr
				}
			}
		}
	}
	releasePartitionLock()
	if err := os.Remove(piecePath(cfg.Storage, operation.PieceRoot)); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := os.Remove(metaPath(cfg.Storage, operation.PieceRoot)); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err := removeStoreLifecycleOperation(cfg.Storage, operation.PieceRoot); err != nil {
		return false, err
	}
	return false, nil
}

func reconcileIncompleteStoreOperations(cfg ServerConfig) {
	operations, err := listStoreLifecycleOperations(cfg.Storage)
	if err != nil {
		log.Printf("[lifecycle] list incomplete stores failed: %v", err)
		return
	}
	for _, operation := range operations {
		// Never block here: a live owner would stall this goroutine's DELETION sweep too.
		operationLock, acquired, lockErr := tryAcquireLifecycleOperationLock(cfg.Storage, "store", operation.PieceRoot)
		if lockErr != nil {
			log.Printf("[lifecycle] store recovery lock failed piece=%s: %v", truncate(operation.PieceRoot, 18), lockErr)
			continue
		}
		if !acquired {
			log.Printf("[lifecycle] store recovery skipped piece=%s phase=%s: operation is owned by a live handler",
				truncate(operation.PieceRoot, 18), operation.Phase)
			continue
		}
		storeCapacityMu.Lock()
		registered, reconcileErr := reconcileStoreLifecycleOperationLocked(cfg, operation)
		storeCapacityMu.Unlock()
		operationLock.Release()
		if reconcileErr != nil {
			operation.LastError = reconcileErr.Error()
			_ = writeStoreLifecycleOperation(cfg.Storage, operation)
			log.Printf("[lifecycle] store recovery pending piece=%s phase=%s: %v",
				truncate(operation.PieceRoot, 18), operation.Phase, reconcileErr)
			continue
		}
		if registered {
			log.Printf("[lifecycle] store registration recovered piece=%s", truncate(operation.PieceRoot, 18))
		} else {
			log.Printf("[lifecycle] unregistered store reclaimed piece=%s", truncate(operation.PieceRoot, 18))
		}
	}
}

func reconcileIncompleteDeletionOperations(cfg ServerConfig) {
	operations, err := listDeletionLifecycleOperations(cfg.Storage)
	if err != nil {
		log.Printf("[lifecycle] list incomplete deletions failed: %v", err)
		return
	}
	clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
	if clockErr != nil {
		log.Printf("[lifecycle] deletion proof work deferred; chain proof clock unavailable: %v", clockErr)
	}
	for _, operation := range operations {
		// DEFECT F, second order. resumeDeletionLifecycleOperation takes this operation's lock
		// with a BLOCKING flock, which is right for a DO request — that caller must wait for the
		// owner — but wrong for this sweep, where waiting on one owned deletion stalls every
		// later deletion and the next tick's store sweep. Probe first and move on if a live
		// handler owns it; it is being driven, and the next sweep picks it up. The probe also
		// skips a pointless chain round-trip below. The blocking acquisition inside resume is
		// deliberately left alone, so request-path semantics are unchanged.
		if probe, acquired, probeErr := tryAcquireLifecycleOperationLock(
			cfg.Storage, "delete", operation.CommitmentHash,
		); probeErr != nil {
			log.Printf("[lifecycle] deletion recovery lock probe failed commitment=%s: %v",
				truncate(operation.CommitmentHash, 18), probeErr)
			continue
		} else if !acquired {
			log.Printf("[lifecycle] deletion recovery skipped commitment=%s phase=%s: operation is owned by a live handler",
				truncate(operation.CommitmentHash, 18), operation.Phase)
			continue
		} else {
			probe.Release()
		}
		declared, confirmed, statusErr := deletionStatusOnChain(cfg, operation.CommitmentHash)
		if statusErr != nil {
			log.Printf("[lifecycle] deletion terminal-state check deferred commitment=%s: %v",
				truncate(operation.CommitmentHash, 18), statusErr)
			continue
		}
		if confirmed {
			creds, loadErr := LoadPaymentCredentials(cfg.Storage, operation.CommitmentHash)
			if loadErr != nil {
				storeCapacityMu.Lock()
				finalizeErr := finalizeConfirmedDeletionLifecycle(cfg.Storage, operation)
				storeCapacityMu.Unlock()
				if finalizeErr != nil {
					log.Printf("[lifecycle] confirmed deletion cleanup failed commitment=%s: %v",
						truncate(operation.CommitmentHash, 18), finalizeErr)
				} else {
					log.Printf("[lifecycle] confirmed deletion ownership released without local payment credentials commitment=%s",
						truncate(operation.CommitmentHash, 18))
				}
				continue
			}
			result, resumeErr := resumeDeletionLifecycleOperation(cfg, creds, operation)
			if resumeErr != nil {
				recordDeletionLifecycleError(cfg.Storage, operation.CommitmentHash, resumeErr)
				log.Printf("[lifecycle] confirmed deletion finalization pending commitment=%s: %v",
					truncate(operation.CommitmentHash, 18), resumeErr)
			} else {
				log.Printf("[lifecycle] confirmed deletion recovered commitment=%s claimTx=%s",
					truncate(operation.CommitmentHash, 18), result.ClaimTx)
			}
			continue
		}
		if !declared {
			// The VK cannot declare here (no secret); declaration happens in the
			// request handler when this op is the FIFO owner and the DO re-drives the
			// secret-bearing request. A durably-accepted deletion must NEVER be
			// discarded merely because the DO was offline past a local grace: that
			// would lose a durable obligation and could let later same-partition
			// deletions overtake it. Instead, once overdue, surface a durable
			// escalation signal (for unhealthy/overdue metrics) and RETAIN the
			// operation so it still declares and converges when the DO returns.
			if deletionDeclarationAbsentExpired(operation, time.Now()) &&
				strings.TrimSpace(operation.LastError) == "" {
				operation.LastError = "declaration overdue: durably accepted, awaiting DO re-drive of the secret-bearing deletion request"
				if writeErr := writeDeletionLifecycleOperation(cfg.Storage, operation); writeErr != nil {
					log.Printf("[lifecycle] overdue deletion escalation write failed commitment=%s: %v",
						truncate(operation.CommitmentHash, 18), writeErr)
				} else {
					log.Printf("[lifecycle] deletion declaration overdue (retained, awaiting DO re-drive) commitment=%s",
						truncate(operation.CommitmentHash, 18))
				}
			}
			// OBSERVABILITY (logging only, no decision change). Before the overdue
			// escalation fires this branch was entirely silent, so a deletion waiting on the
			// DO looked identical to a deletion nobody was driving — the exact ambiguity that
			// cost a smoke run to diagnose. Emit the blocker, its owner, its age and the next
			// expected recovery action so a stall is readable from the log alone.
			logFailClosedWait(cfg.Storage, "deletion-awaiting-declaration",
				truncate(operation.CommitmentHash, 18), operation.Phase,
				"not declared on chain; VK holds no secret",
				"data owner re-drives the secret-bearing deletion request",
				deletionAcceptedAge(operation, time.Now()))
			continue
		}
		if clockErr != nil {
			logFailClosedWait(cfg.Storage, "deletion-awaiting-chain-clock",
				truncate(operation.CommitmentHash, 18), operation.Phase,
				"chain proof clock unavailable", "chain clock becomes readable", 0)
			continue
		}
		if operation.RetryProofRound > clock.CurrentRound {
			// Bounded by chain rounds, which the ticker guarantees advance.
			logFailClosedWait(cfg.Storage, "deletion-awaiting-proof-round",
				truncate(operation.CommitmentHash, 18), operation.Phase,
				fmt.Sprintf("retryProofRound=%d > currentRound=%d",
					operation.RetryProofRound, clock.CurrentRound),
				"chain round advances", 0)
			continue
		}
		creds, loadErr := LoadPaymentCredentials(cfg.Storage, operation.CommitmentHash)
		if loadErr != nil {
			operation.LastError = loadErr.Error()
			_ = writeDeletionLifecycleOperation(cfg.Storage, operation)
			log.Printf("[lifecycle] deletion recovery missing credentials commitment=%s: %v",
				truncate(operation.CommitmentHash, 18), loadErr)
			continue
		}
		result, resumeErr := resumeDeletionLifecycleOperation(cfg, creds, operation)
		if resumeErr != nil {
			recordDeletionLifecycleError(cfg.Storage, operation.CommitmentHash, resumeErr)
			log.Printf("[lifecycle] deletion recovery pending commitment=%s phase=%s: %v",
				truncate(operation.CommitmentHash, 18), operation.Phase, resumeErr)
			continue
		}
		log.Printf("[lifecycle] deletion recovered commitment=%s partitionTx=%s proofTx=%s confirmTx=%s",
			truncate(operation.CommitmentHash, 18), result.PartitionTx, result.ProofTx, result.ConfirmTx)
	}
}

func discoverLegacyDeletionOperations(cfg ServerConfig) {
	entries, err := os.ReadDir(paymentDir(cfg.Storage))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("[lifecycle] legacy deletion discovery failed: %v", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(paymentDir(cfg.Storage), entry.Name()))
		if readErr != nil {
			continue
		}
		var creds PaymentCredentials
		if json.Unmarshal(b, &creds) != nil || creds.CommitmentHash == "" || creds.PieceRoot == "" {
			continue
		}
		if _, found, _ := readDeletionLifecycleOperation(cfg.Storage, creds.CommitmentHash); found {
			continue
		}
		if _, doneErr := os.Stat(deletionLifecycleCompletedPath(cfg.Storage, creds.CommitmentHash)); doneErr == nil {
			continue
		}
		declared, confirmed, statusErr := deletionStatusOnChain(cfg, creds.CommitmentHash)
		if statusErr == nil && confirmed {
			if markerErr := markDeletionLifecycleCompleted(cfg.Storage, creds.CommitmentHash); markerErr != nil {
				log.Printf("[lifecycle] completed deletion marker failed commitment=%s: %v",
					truncate(creds.CommitmentHash, 18), markerErr)
			}
			continue
		}
		// Confirmed deletions are terminal. Rediscovering them recreates a journal
		// every minute and repeatedly attempts an already-paid escrow claim.
		if statusErr != nil || !declared {
			continue
		}
		operation := DeletionLifecycleOperation{
			Version:        lifecycleJournalVersion,
			CommitmentHash: creds.CommitmentHash,
			PieceRoot:      creds.PieceRoot,
			Phase:          "declared",
			CreatedAt:      nowRFC3339(),
		}
		if sector, found, findErr := sectorForDeletionOperation(cfg.Storage, operation); findErr == nil && found {
			operation.SectorID = sector.SectorID
			operation.DeadlineIndex = sector.DeadlineIndex
			operation.PartitionIndex = sector.PartitionIndex
		}
		if err := writeDeletionLifecycleOperation(cfg.Storage, operation); err == nil {
			log.Printf("[lifecycle] discovered legacy incomplete deletion commitment=%s",
				truncate(creds.CommitmentHash, 18))
		}
	}
}

func discoverExpiredRegistrationOperations(cfg ServerConfig) {
	chainTimestamp, chainErr := rpcLatestBlockTimestamp(cfg.RPCURL)
	if chainErr != nil {
		log.Printf("[lifecycle] expired registration chain-time check failed: %v", chainErr)
		return
	}
	entries, err := os.ReadDir(paymentDir(cfg.Storage))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("[lifecycle] expired registration discovery failed: %v", err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(paymentDir(cfg.Storage), entry.Name()))
		if readErr != nil {
			continue
		}
		var creds PaymentCredentials
		if json.Unmarshal(b, &creds) != nil {
			continue
		}
		// Only new timeout-aware credentials carry this snapshot. Filtering by the
		// chain clock avoids one RPC call per historical piece on every minute tick.
		if !registrationCredentialsPastDeadline(creds, chainTimestamp) {
			continue
		}
		expired := false
		var statusErr error
		if creds.RegistrationCommitment != "" {
			expired, statusErr = deletionBoolCall(
				context.Background(), cfg, expiredRegistrationCommitmentSelector, creds.RegistrationCommitment,
			)
		} else {
			expired, statusErr = deletionBoolCall(
				context.Background(), cfg, expiredCommitmentHashSelector, creds.CommitmentHash,
			)
		}
		if statusErr != nil || !expired {
			continue
		}
		if creds.CommitmentHash == "" || creds.PieceRoot == "" {
			removed := removeExpiredStoreTransferReservations(cfg.Storage, creds)
			if removeErr := os.Remove(filepath.Join(paymentDir(cfg.Storage), entry.Name())); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Printf("[lifecycle] expired quote cleanup warning commitment=%s: %v",
					truncate(creds.RegistrationCommitment, 18), removeErr)
			}
			if removed > 0 {
				log.Printf("[lifecycle] released %d expired transfer reservation(s) commitment=%s",
					removed, truncate(creds.RegistrationCommitment, 18))
				forceAdmissionRegistrySync(cfg)
			}
			continue
		}
		if _, metaErr := os.Stat(metaPath(cfg.Storage, creds.PieceRoot)); os.IsNotExist(metaErr) {
			if _, pieceErr := os.Stat(piecePath(cfg.Storage, creds.PieceRoot)); os.IsNotExist(pieceErr) {
				continue
			}
		}
		if _, journalErr := os.Stat(storeLifecyclePath(cfg.Storage, creds.PieceRoot)); journalErr == nil {
			continue
		}
		operation := StoreLifecycleOperation{
			Version: lifecycleJournalVersion, PieceRoot: creds.PieceRoot,
			CommitmentHash:         creds.CommitmentHash,
			RegistrationCommitment: creds.RegistrationCommitment,
			Phase:                  "registration_expired",
			CreatedAt:              nowRFC3339(),
		}
		if meta, metaErr := readMeta(cfg.Storage, creds.PieceRoot); metaErr == nil {
			// A delete followed by an identical re-upload leaves this historical
			// record naming a piece root that now resolves to a NEWER sector. The
			// sector belongs to whichever commitment is still active, so adopting it
			// here would aim an expiry cleanup at a live file. Every record that
			// reaches this point is itself inactive (that is what "expired" means),
			// so the discriminator is whether some OTHER commitment owns the piece.
			reowned, ownerErr := pieceRootHasOtherActiveCommitment(
				cfg, creds.PieceRoot, creds.CommitmentHash,
			)
			if ownerErr != nil {
				// Unknown ownership is not proof of ownership: stop this pass and
				// retry rather than risk pointing cleanup at a live sector.
				log.Printf("[lifecycle] expired registration ownership check failed commitment=%s: %v",
					truncate(creds.CommitmentHash, 18), ownerErr)
				return
			}
			if reowned {
				log.Printf("[lifecycle] expired registration left unlinked; piece was re-uploaded into a newer sector piece=%s commitment=%s",
					truncate(creds.PieceRoot, 18), truncate(creds.CommitmentHash, 18))
			} else {
				operation.SectorID = meta.SectorID
				if sectors, listErr := listSectors(cfg.Storage); listErr == nil {
					for _, sector := range sectors {
						if sector.SectorID == meta.SectorID {
							operation.DeadlineIndex = sector.DeadlineIndex
							operation.PartitionIndex = sector.PartitionIndex
							break
						}
					}
				}
			}
		}
		if writeErr := writeStoreLifecycleOperation(cfg.Storage, operation); writeErr == nil {
			log.Printf("[lifecycle] scheduled expired registration cleanup commitment=%s piece=%s",
				truncate(creds.CommitmentHash, 18), truncate(creds.PieceRoot, 18))
		}
	}
}

// pieceRootHasOtherActiveCommitment reports whether some commitment other than
// self is still the active registration for this piece root. That happens when a
// piece is deleted and identical content is uploaded again: the sector holding
// the piece now belongs to the newer commitment, so older records must not act
// on it. An error means the answer is unknown and must not be read as "no".
func pieceRootHasOtherActiveCommitment(cfg ServerConfig, pieceRoot, self string) (bool, error) {
	if cfg.RPCURL == "" || cfg.FileRegistrationContract == "" || strings.TrimSpace(pieceRoot) == "" {
		return false, nil
	}
	entries, err := os.ReadDir(paymentDir(cfg.Storage))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("payment credentials: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(paymentDir(cfg.Storage), entry.Name()))
		if readErr != nil {
			return false, fmt.Errorf("read %s: %w", entry.Name(), readErr)
		}
		var other PaymentCredentials
		if json.Unmarshal(b, &other) != nil {
			continue // corrupt record: it cannot prove ownership either way
		}
		if other.CommitmentHash == "" ||
			!strings.EqualFold(other.PieceRoot, pieceRoot) ||
			strings.EqualFold(other.CommitmentHash, self) {
			continue
		}
		active, activeErr := rpcCommitmentHashIsActive(cfg, other.CommitmentHash)
		if activeErr != nil {
			return false, fmt.Errorf("commitment %s active state: %w",
				truncate(other.CommitmentHash, 18), activeErr)
		}
		if active {
			return true, nil
		}
	}
	return false, nil
}

func registrationCredentialsPastDeadline(creds PaymentCredentials, chainTimestamp int64) bool {
	return creds.RegistrationDeadline > 0 && chainTimestamp > creds.RegistrationDeadline
}

func runLifecycleReconciler(ctx context.Context, cfg ServerConfig) {
	// The A.2 artifact migration + orphan sweep run in runArtifactStartupBarrier before this
	// reconciler is launched (see runServer / runProofDaemon); the proving gate stays closed
	// until they succeed, so this reconciler cannot trigger a proof on an unmigrated artifact.
	discoverExpiredRegistrationOperations(cfg)
	reconcileIncompleteStoreOperations(cfg)
	reconcilePartitionLinks(cfg)
	discoverLegacyDeletionOperations(cfg)
	reconcileIncompleteDeletionOperations(cfg)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	// A.4: continuous owner-safe orphan-artifact GC at a bounded interval.
	orphanGC := time.NewTicker(orphanArtifactGCInterval)
	defer orphanGC.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			discoverExpiredRegistrationOperations(cfg)
			reconcileIncompleteStoreOperations(cfg)
			reconcilePartitionLinks(cfg)
			reconcileEscrowExtensions(cfg)
			reconcileIncompleteDeletionOperations(cfg)
		case <-orphanGC.C:
			if _, err := runOrphanArtifactGCOnce(cfg.Storage, time.Now()); err != nil {
				log.Printf("[orphan-gc] sweep warning: %v", err)
			}
		}
	}
}

// orphanArtifactGCInterval bounds how often the runtime orphan-artifact GC runs.
var orphanArtifactGCInterval = 10 * time.Minute

// reconcileStoreLifecycleUnderAccountingLock runs the store-failure cleanup with the global
// accounting mutex held, which is reconcileStoreLifecycleOperationLocked's documented contract.
// B.3 narrowed that mutex out of the long-running store success path; the failure path still
// takes it, exactly as the background reconciler does.
func reconcileStoreLifecycleUnderAccountingLock(cfg ServerConfig, operation StoreLifecycleOperation) (bool, error) {
	storeCapacityMu.Lock()
	defer storeCapacityMu.Unlock()
	return reconcileStoreLifecycleOperationLocked(cfg, operation)
}
