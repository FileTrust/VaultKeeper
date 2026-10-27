package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// B.3.1 — expired-GC partition lifecycle transition, confined so no chain RPC runs under the
// partition lifecycle lock.
//
// The GC used to hold a partition's lifecycle lock across registerPartitionOnChain /
// deactivatePartitionOnChain so a local mutation could not race the call. B.3.1 replaces that
// with a durable, identity-bound two-phase transition:
//
//	under the partition lock: revalidate the exact lifecycle identity, durably CLAIM the
//	                          intended transition, capture the immutable call inputs
//	release the partition lock
//	                          perform the chain RPC (no lock held)
//	reacquire the partition lock: reconcile chain truth, verify the SAME lifecycle identity is
//	                          still current, then durably complete / retry / supersede
//
// Releasing the lock can therefore never let a local mutation invalidate the RPC silently: the
// claim pins the exact identity the call was made for, and phase 3 refuses to complete a
// transition whose identity has moved on — it supersedes it instead, so the next pass redoes the
// work against the new truth.

const gcPartitionTransitionVersion = 1

const (
	gcTransitionIntentRegister   = "register"
	gcTransitionIntentDeactivate = "deactivate"
)

const (
	gcTransitionStateClaimed    = "claimed"    // recorded, RPC not yet attempted
	gcTransitionStateAttempted  = "attempted"  // RPC issued, outcome not yet reconciled
	gcTransitionStateSuperseded = "superseded" // identity moved on; must be redone
)

// gcPartitionTransition is the durable claim on one partition's GC lifecycle transition.
type gcPartitionTransition struct {
	Version        int    `json:"version"`
	DeadlineIndex  int    `json:"deadlineIndex"`
	PartitionIndex int    `json:"partitionIndex"`
	PartitionKind  string `json:"partitionKind"`

	// Lifecycle identity the transition was decided against. Phase 3 refuses to complete if
	// this no longer matches the current local truth.
	ContentHash string `json:"contentHash"`
	SectorCount int    `json:"sectorCount"`
	Intent      string `json:"intent"`

	// Immutable call inputs captured under the lock in phase 1.
	CallDeadlineIndex  int    `json:"callDeadlineIndex"`
	CallPartitionIndex int    `json:"callPartitionIndex"`
	CallPartitionRoot  string `json:"callPartitionRoot,omitempty"`

	State     string `json:"state"`
	AttemptID string `json:"attemptId"`
	OwnerID   string `json:"ownerId"`
	StartedAt string `json:"startedAt"`
	UpdatedAt string `json:"updatedAt"`
	TxHash    string `json:"txHash,omitempty"`
	LastError string `json:"lastError,omitempty"`
}

func gcPartitionTransitionDir(storage string) string {
	return filepath.Join(storage, "gc", "partition-transitions")
}

func gcPartitionTransitionPath(storage string, deadlineIndex, partitionIndex int) string {
	return filepath.Join(gcPartitionTransitionDir(storage),
		fmt.Sprintf("dl%d-pt%d.json", deadlineIndex, partitionIndex))
}

func readGCPartitionTransition(storage string, deadlineIndex, partitionIndex int) (gcPartitionTransition, bool, error) {
	payload, err := os.ReadFile(gcPartitionTransitionPath(storage, deadlineIndex, partitionIndex))
	if os.IsNotExist(err) {
		return gcPartitionTransition{}, false, nil
	}
	if err != nil {
		return gcPartitionTransition{}, false, err
	}
	var record gcPartitionTransition
	if json.Unmarshal(payload, &record) != nil || record.Version != gcPartitionTransitionVersion {
		// Unreadable claim metadata must never be treated as "no transition in flight".
		return gcPartitionTransition{}, false, fmt.Errorf(
			"unreadable gc partition transition dl%d-pt%d", deadlineIndex, partitionIndex)
	}
	return record, true, nil
}

func writeGCPartitionTransition(storage string, record gcPartitionTransition) error {
	record.Version = gcPartitionTransitionVersion
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(gcPartitionTransitionDir(storage), 0700); err != nil {
		return err
	}
	return durableAtomicWriteFile(
		gcPartitionTransitionPath(storage, record.DeadlineIndex, record.PartitionIndex), payload, 0600)
}

func removeGCPartitionTransition(storage string, deadlineIndex, partitionIndex int) error {
	err := os.Remove(gcPartitionTransitionPath(storage, deadlineIndex, partitionIndex))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if dir, dirErr := os.Open(gcPartitionTransitionDir(storage)); dirErr == nil {
		defer dir.Close()
		_ = dir.Sync()
	}
	return nil
}

// newChainAttemptID mints a unique identity for one durable chain-attempt claim. B.3.1 uses it
// for expired-GC partition transitions and capacity-epoch open attempts alike.
func newChainAttemptID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("attempt-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// gcPartitionLifecycleIdentity is the exact local truth a transition is decided against.
type gcPartitionLifecycleIdentity struct {
	Active      bool
	ContentHash string
	SectorCount int
	Partition   PartitionMeta
}

// currentGCPartitionLifecycleIdentity reads the authoritative local identity for a coordinate.
// The caller MUST hold that partition's lifecycle lock.
func currentGCPartitionLifecycleIdentity(
	cfg ServerConfig, deadlineIndex, partitionIndex int, chainTimestamp int64,
) (gcPartitionLifecycleIdentity, error) {
	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return gcPartitionLifecycleIdentity{}, err
	}
	partition, active := currentPartitionMetaByCoordinatesAt(
		sectors, cfg, deadlineIndex, partitionIndex, PartitionKindData, chainTimestamp,
	)
	identity := gcPartitionLifecycleIdentity{Active: active, Partition: partition}
	if active {
		identity.ContentHash = partitionContentHash(partition)
		identity.SectorCount = len(partition.Sectors)
	}
	return identity, nil
}

func (t gcPartitionTransition) matchesIdentity(identity gcPartitionLifecycleIdentity) bool {
	wantIntent := gcTransitionIntentDeactivate
	if identity.Active {
		wantIntent = gcTransitionIntentRegister
	}
	if t.Intent != wantIntent {
		return false
	}
	if !identity.Active {
		return t.ContentHash == "" && t.SectorCount == 0
	}
	return sameRoot(t.ContentHash, identity.ContentHash) && t.SectorCount == identity.SectorCount
}

// claimGCPartitionTransition runs PHASE 1 under the partition lifecycle lock: it revalidates the
// exact lifecycle identity, records the intended transition durably, and captures the immutable
// call inputs. It returns the claim to execute without any lock held.
//
// An in-flight claim owned by another attempt is respected: this pass skips the coordinate rather
// than issuing a second, conflicting chain call for it.
func claimGCPartitionTransition(
	cfg ServerConfig, deadlineIndex, partitionIndex int, chainTimestamp int64,
) (gcPartitionTransition, gcPartitionLifecycleIdentity, bool, error) {
	var claim gcPartitionTransition
	var identity gcPartitionLifecycleIdentity
	claimed := false

	lock, err := acquirePartitionLifecycleLock(cfg.Storage, deadlineIndex, partitionIndex)
	if err != nil {
		return claim, identity, false, err
	}
	defer lock.Release()

	existing, found, err := readGCPartitionTransition(cfg.Storage, deadlineIndex, partitionIndex)
	if err != nil {
		return claim, identity, false, err
	}
	if found && existing.State == gcTransitionStateAttempted {
		// A previous attempt issued an RPC whose outcome is not yet reconciled. Resume THAT
		// attempt rather than starting a competing one.
		return existing, identity, false, nil
	}

	identity, err = currentGCPartitionLifecycleIdentity(cfg, deadlineIndex, partitionIndex, chainTimestamp)
	if err != nil {
		return claim, identity, false, err
	}

	intent := gcTransitionIntentDeactivate
	if identity.Active {
		intent = gcTransitionIntentRegister
	}
	now := nowRFC3339()
	claim = gcPartitionTransition{
		DeadlineIndex: deadlineIndex, PartitionIndex: partitionIndex, PartitionKind: PartitionKindData,
		ContentHash: identity.ContentHash, SectorCount: identity.SectorCount, Intent: intent,
		CallDeadlineIndex: deadlineIndex, CallPartitionIndex: partitionIndex,
		CallPartitionRoot: identity.Partition.ContentHash,
		State:             gcTransitionStateAttempted,
		AttemptID:         newChainAttemptID(), OwnerID: vkProcessInstanceID,
		StartedAt: now, UpdatedAt: now,
	}
	// The claim is durable BEFORE the RPC: a crash mid-call leaves an "attempted" record that
	// the next pass reconciles from chain truth instead of blindly re-issuing.
	if err := writeGCPartitionTransition(cfg.Storage, claim); err != nil {
		return claim, identity, false, err
	}
	claimed = true
	return claim, identity, claimed, nil
}

// reconcileGCPartitionTransition runs PHASE 3 under the partition lifecycle lock: it verifies the
// lifecycle identity is still the one the RPC was made for, reconciles chain truth, and durably
// completes, retries, or supersedes the transition.
//
// The outcome is decided as follows:
//
//	rpcErr == nil                              → the call was acknowledged: complete
//	rpcErr != nil, chain truth known & matches → the intended outcome already holds: complete
//	rpcErr != nil, chain truth known & differs → conclusive failure: drop the claim, retry later
//	rpcErr != nil, chain truth UNKNOWN         → UNRESOLVED: neither success nor failure, the
//	                                             durable attempt stays for the next pass
func reconcileGCPartitionTransition(
	cfg ServerConfig, claim gcPartitionTransition, chainTimestamp int64,
	txHash string, rpcErr error, chainTruthKnown, chainConfirmed bool,
) (bool, error) {
	completed := false
	lock, err := acquirePartitionLifecycleLock(cfg.Storage, claim.DeadlineIndex, claim.PartitionIndex)
	if err != nil {
		return false, err
	}
	defer lock.Release()

	current, found, err := readGCPartitionTransition(cfg.Storage, claim.DeadlineIndex, claim.PartitionIndex)
	if err != nil {
		return false, err
	}
	if !found || current.AttemptID != claim.AttemptID {
		// Another attempt owns the coordinate now; ours is void and must not complete anything.
		return false, nil
	}

	identity, err := currentGCPartitionLifecycleIdentity(
		cfg, claim.DeadlineIndex, claim.PartitionIndex, chainTimestamp,
	)
	if err != nil {
		return false, err
	}
	if !claim.matchesIdentity(identity) {
		// A local mutation changed the coordinate while the lock was released. The RPC referred
		// to a superseded identity, so it must NOT be treated as completing this coordinate.
		current.State = gcTransitionStateSuperseded
		current.UpdatedAt = nowRFC3339()
		current.TxHash = txHash
		if rpcErr != nil {
			current.LastError = rpcErr.Error()
		}
		if err := writeGCPartitionTransition(cfg.Storage, current); err != nil {
			return false, err
		}
		return false, nil
	}

	if rpcErr != nil {
		if !chainTruthKnown {
			// Ambiguous: the call may or may not have landed and chain truth is unreadable.
			// Leave the durable attempt in place — neither success nor failure — so the next
			// pass reconciles it rather than blindly re-issuing.
			current.State = gcTransitionStateAttempted
			current.TxHash = txHash
			current.UpdatedAt = nowRFC3339()
			current.LastError = "chain outcome unconfirmed: " + rpcErr.Error()
			if err := writeGCPartitionTransition(cfg.Storage, current); err != nil {
				return false, err
			}
			return false, nil
		}
		if !chainConfirmed {
			// Conclusive failure: drop the claim so the next pass re-decides from fresh truth.
			if err := removeGCPartitionTransition(cfg.Storage, claim.DeadlineIndex, claim.PartitionIndex); err != nil {
				return false, err
			}
			return false, rpcErr
		}
		// The intended outcome already holds on chain despite the error: treat as complete.
	}

	// The transition is settled against the still-current identity.
	if err := removeGCPartitionTransition(cfg.Storage, claim.DeadlineIndex, claim.PartitionIndex); err != nil {
		return false, err
	}
	completed = true
	return completed, nil
}

// gcTransitionChainConfirms reports whether chain truth matches the claimed intent.
func gcTransitionChainConfirms(claim gcPartitionTransition, active []CapacityPartitionInfo) bool {
	listed := activePartitionListed(active, claim.DeadlineIndex, claim.PartitionIndex)
	if strings.EqualFold(claim.Intent, gcTransitionIntentDeactivate) {
		return !listed
	}
	return listed
}
