package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	partitionProofSnapshotVersion = 2
	proofBacklogMetricsVersion    = 4

	proofSnapshotStateQueued     = "queued"
	proofSnapshotStateFrozen     = "frozen"
	proofSnapshotStateSealed     = "sealed"
	proofSnapshotStateProving    = "proving"
	proofSnapshotStateSubmitting = "submitting"

	proofBacklogStateUnavailable = "proof_state_unavailable"
	proofBacklogDeadlineAtRisk   = "proof_deadline_at_risk"
	proofBacklogCapacityStale    = "capacity_proof_stale"
	proofBacklogCapacityLag      = "capacity_proof_lag_at_risk"
)

var ErrPartitionProofSnapshotInvalidated = errors.New("partition proof snapshot invalidated")
var ErrPartitionProofSnapshotBatching = errors.New("partition proof snapshot batching")
var ErrPartitionProofSnapshotReanchored = errors.New("partition proof snapshot reanchored")

// ErrPartitionFreezeCrossAuthority (A.3) marks a refused attempt to freeze content that is
// already frozen under a DIFFERENT epoch/authority. The standalone-deletion↔capacity rebind is
// removed: the requesting authority must defer to the A.2.5 arbiter and freeze its own record
// once the single on-chain slot frees, never reuse or rebind the other authority's record.
var ErrPartitionFreezeCrossAuthority = errors.New("partition freeze cross-authority conflict; deferring (rebind removed)")

// ErrPartitionDeletionInProgress marks a partition skipped because a deletion owns its content
// right now. It is a DEFERRAL, not a proof failure: the prover was never asked to prove
// anything, and the condition clears when the deletion finishes.
//
// It has to be a sentinel because the retry recorder escalates any error it does not recognise.
// As a plain fmt.Errorf this skip counted as a failed proof, so a partition waiting on an
// ordinary deletion burned the recovery budget and marked ITSELF terminal — and a terminal
// record is never auto-eligible again (proof_retry.go:134-139), so the keeper permanently
// refused to prove a partition that had never actually failed to prove.
//
// Live on 2026-10-03, keeper 0xFABB0ac9: a data owner stored a piece and deleted it eleven
// seconds later. The skip repeated while the deletion waited for its freeze slot, reached
// failures=50, went terminal with "consecutive proof failures exhausted the retry budget", and
// the keeper stayed closed on oldest_dirty_hard_lag for 22 hours. Not one real proof had failed.
var ErrPartitionDeletionInProgress = errors.New("partition deletion in progress")

// requestedFreezeAuthorityKind classifies the authority of a requested freeze epoch id.
func requestedFreezeAuthorityKind(proofEpochID uint64) string {
	if proofEpochID&standaloneDeletionProofFlag != 0 {
		return "deletion"
	}
	if proofEpochID == 0 {
		return "successor"
	}
	return "capacity"
}

// ErrPartitionProofSnapshotSuperseded marks a worker whose held local generation no longer
// matches the live frozen slot (A.1). It must be raised as a fence immediately before any
// external or destructive action — proof dispatch, submit, abandon, reanchor, artifact
// cleanup, or record removal/replacement — so a stale worker never sends a transaction or
// deletes a newer generation's artifact after being overtaken.
var ErrPartitionProofSnapshotSuperseded = errors.New("partition proof snapshot generation superseded")

// verifyPartitionGenerationLive re-reads the durable frozen record and confirms the
// worker-held snapshot is still the live frozen slot at the same local generation. It fails
// closed (ErrPartitionProofSnapshotSuperseded) if the queue/record is gone, the content ID
// changed, or the generation no longer matches. Call it right before every external or
// destructive action; the residual TOCTOU window to an on-chain send is backstopped by the
// contract's frozenSnapshotNonce (A.0), while local mutations (advance/reanchor write) are
// re-fenced atomically under the partition lock.
func verifyPartitionGenerationLive(storage string, snapshot partitionProofSnapshot) error {
	queue, found, err := readPartitionProofSnapshotQueue(
		storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
	)
	if err != nil {
		return err
	}
	if !found || queue.Frozen == nil || queue.Frozen.ID != snapshot.ID ||
		!partitionGenerationIdentityOK(queue.Frozen.Generation, snapshot.Generation) {
		live := uint64(0)
		if found && queue.Frozen != nil {
			live = queue.Frozen.Generation
		}
		return fmt.Errorf(
			"%w: held generation %d, live generation %d (kind=%s dl=%d pt=%d)",
			ErrPartitionProofSnapshotSuperseded, snapshot.Generation, live,
			snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
		)
	}
	return nil
}

// partitionProofSnapshot is an immutable proof input.  Partition metadata and
// piece-file hard links are captured before the chain snapshot is frozen.  A
// later upload may therefore update the live partition without changing the
// bytes being proved.  ContentVersion is the chain-assigned version and is
// deliberately zero until freezePartitionSnapshot confirms the exact content.
type partitionProofSnapshot struct {
	Version          int           `json:"version"`
	ID               string        `json:"id"`
	Partition        PartitionMeta `json:"partition"`
	ContentHash      string        `json:"contentHash"`
	ChainContentHash string        `json:"chainContentHash,omitempty"`
	ProofEpochID     uint64        `json:"proofEpochId,omitempty"`
	ContentVersion   uint64        `json:"contentVersion,omitempty"`
	// SnapshotNonce is the on-chain persistent freeze-generation counter value for
	// this partition's active frozen slot (A.0 identity tuple member). Set at freeze,
	// advanced on reanchor; required for submit/abandon/reanchor.
	SnapshotNonce uint64 `json:"snapshotNonce,omitempty"`
	// Generation is the VK-LOCAL monotonic per-partition counter (A.1). It is allocated
	// from the durable generation ledger on every freeze attempt, reanchor, and successor
	// replacement, and is strictly greater than every generation previously handed out for
	// this partition. It disambiguates content-identical records so a stale worker cannot
	// clobber a newer frozen slot; a zero value denotes a legacy record that must not
	// silently participate in the A.1 protocol.
	Generation   uint64             `json:"generation,omitempty"`
	Round        uint64             `json:"round"`
	AnchorBlock  uint64             `json:"anchorBlock,omitempty"`
	DeadlineUnix int64              `json:"deadlineUnix,omitempty"`
	State        string             `json:"state"`
	ArtifactDir  string             `json:"artifactDir"`
	Challenge    PartitionChallenge `json:"challenge,omitempty"`
	PublicInputs []string           `json:"publicInputs,omitempty"`
	Proof        ZKProofResult      `json:"proof,omitempty"`
	CreatedAt    string             `json:"createdAt"`
	UpdatedAt    string             `json:"updatedAt"`
	LastError    string             `json:"lastError,omitempty"`
}

// One partition can have one chain-frozen snapshot and one coalesced successor.
// Repeated live changes replace Successor rather than creating an unbounded
// history. Replacing an append-only successor is safe: the immutable cutoff is
// still pinned, the latest live generation is retained, and the allocation
// ledger charges every intervening upload. `Saturated` is retained only for
// backward-compatible decoding of older queue files; it no longer closes
// admission.
type partitionProofSnapshotQueue struct {
	Version        int                     `json:"version"`
	PartitionKind  string                  `json:"partitionKind"`
	DeadlineIndex  int                     `json:"deadlineIndex"`
	PartitionIndex int                     `json:"partitionIndex"`
	Frozen         *partitionProofSnapshot `json:"frozen,omitempty"`
	Successor      *partitionProofSnapshot `json:"successor,omitempty"`
	Saturated      bool                    `json:"saturated,omitempty"` // deprecated
	Coalesced      uint64                  `json:"coalesced,omitempty"`
	UpdatedAt      string                  `json:"updatedAt"`
}

type proofBacklogMetrics struct {
	Version                     int                         `json:"version"`
	ObservedAt                  string                      `json:"observedAt"`
	PendingSnapshots            int                         `json:"pendingSnapshots"`
	OldestPendingUnix           int64                       `json:"oldestPendingUnix,omitempty"`
	NearestDeadlineUnix         int64                       `json:"nearestDeadlineUnix,omitempty"`
	ChainTimestamp              int64                       `json:"chainTimestamp,omitempty"`
	ChainClockAvailable         bool                        `json:"chainClockAvailable"`
	EstimatedCatchupNanos       int64                       `json:"estimatedCatchupNanos,omitempty"`
	DeadlineChecks              []proofBacklogDeadlineCheck `json:"deadlineChecks,omitempty"`
	CapacityAdmissionRequired   bool                        `json:"capacityAdmissionRequired,omitempty"`
	CapacityProofFreshUntilUnix int64                       `json:"capacityProofFreshUntilUnix,omitempty"`
	ProofObligationsPresent     bool                        `json:"proofObligationsPresent,omitempty"`
	StaleAfterSeconds           int64                       `json:"staleAfterSeconds"`
	// ObservedWritePeriodSeconds is how far apart this file's own writes have
	// actually been running. StaleAfterSeconds is derived from it so a daemon
	// that is slow because it is busy proving is never mistaken for a dead one.
	ObservedWritePeriodSeconds  int64  `json:"observedWritePeriodSeconds,omitempty"`
	CapacityLagAtRisk           bool   `json:"capacityLagAtRisk,omitempty"`
	CapacityLagBreached         bool   `json:"capacityLagBreached,omitempty"`
	CapacityPendingMutations    int    `json:"capacityPendingMutations,omitempty"`
	CapacityPendingBytes        int64  `json:"capacityPendingBytes,omitempty"`
	CapacityOldestMutationNanos int64  `json:"capacityOldestMutationNanos,omitempty"`
	CapacityMaximumLagNanos     int64  `json:"capacityMaximumLagNanos,omitempty"`
	CapacityLagReason           string `json:"capacityLagReason,omitempty"`
}

// Each check represents cumulative earliest-deadline-first prover work that
// must complete by one host-clock deadline. Coalesced successors without an
// active chain deadline are deliberately excluded.
type proofBacklogDeadlineCheck struct {
	DeadlineUnix  int64 `json:"deadlineUnix"`
	RequiredNanos int64 `json:"requiredNanos"`
}

// ProofBacklogAdmissionState is intentionally read-only and contains no chain
// calls. Admission can consume it on every quote/store request without adding
// RPC latency or preventing proof, deletion, or download work.
type ProofBacklogAdmissionState struct {
	Safe                    bool
	Reason                  string
	PendingSnapshots        int
	OldestPendingAt         time.Time
	NearestDeadline         time.Time
	EstimatedCatchup        time.Duration
	ObservedAt              time.Time
	CapacityProofFreshUntil time.Time
}

func partitionProofSnapshotRoot(storage string) string {
	return filepath.Join(storage, "proof-snapshots")
}

func partitionProofSnapshotQueueDir(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "queues")
}

func partitionProofSnapshotArtifactRoot(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "artifacts")
}

func partitionProofSnapshotMetricsPath(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "backlog.json")
}

func partitionProofSnapshotQueueName(kind string, deadlineIndex, partitionIndex int) string {
	return fmt.Sprintf("%s-dl%d-pt%d", safeID(kind), deadlineIndex, partitionIndex)
}

func partitionProofSnapshotQueuePath(storage, kind string, deadlineIndex, partitionIndex int) string {
	return filepath.Join(
		partitionProofSnapshotQueueDir(storage),
		partitionProofSnapshotQueueName(kind, deadlineIndex, partitionIndex)+".json",
	)
}

func partitionProofSnapshotLockPath(storage, kind string, deadlineIndex, partitionIndex int) string {
	return filepath.Join(
		partitionProofSnapshotQueueDir(storage),
		partitionProofSnapshotQueueName(kind, deadlineIndex, partitionIndex)+".lock",
	)
}

func withPartitionProofSnapshotLock(storage, kind string, deadlineIndex, partitionIndex int, fn func() error) error {
	if err := os.MkdirAll(partitionProofSnapshotQueueDir(storage), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(
		partitionProofSnapshotLockPath(storage, kind, deadlineIndex, partitionIndex),
		os.O_CREATE|os.O_RDWR, 0600,
	)
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

func readPartitionProofSnapshotQueueUnlocked(storage, kind string, deadlineIndex, partitionIndex int) (partitionProofSnapshotQueue, bool, error) {
	path := partitionProofSnapshotQueuePath(storage, kind, deadlineIndex, partitionIndex)
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return partitionProofSnapshotQueue{}, false, nil
	}
	if err != nil {
		return partitionProofSnapshotQueue{}, false, err
	}
	var queue partitionProofSnapshotQueue
	if err := json.Unmarshal(payload, &queue); err != nil {
		return partitionProofSnapshotQueue{}, true, fmt.Errorf("decode snapshot queue: %w", err)
	}
	if queue.Version == 1 {
		// V1 snapshots predate epoch binding. Their immutable artifacts remain
		// useful, but no old chain version/proof may cross into the new protocol.
		for _, snapshot := range []*partitionProofSnapshot{queue.Frozen, queue.Successor} {
			if snapshot == nil {
				continue
			}
			snapshot.Version = partitionProofSnapshotVersion
			snapshot.ProofEpochID = 0
			snapshot.ContentVersion = 0
			snapshot.ChainContentHash = ""
			snapshot.Round = 0
			snapshot.AnchorBlock = 0
			snapshot.DeadlineUnix = 0
			snapshot.State = proofSnapshotStateQueued
			snapshot.Challenge = PartitionChallenge{}
			snapshot.PublicInputs = nil
			snapshot.Proof = ZKProofResult{}
			snapshot.LastError = ""
		}
		queue.Version = partitionProofSnapshotVersion
		if err := writePartitionProofSnapshotQueueUnlocked(storage, queue); err != nil {
			return partitionProofSnapshotQueue{}, true, fmt.Errorf("migrate snapshot queue: %w", err)
		}
	}
	if queue.Version != partitionProofSnapshotVersion || queue.PartitionKind != kind ||
		queue.DeadlineIndex != deadlineIndex || queue.PartitionIndex != partitionIndex {
		return partitionProofSnapshotQueue{}, true, fmt.Errorf("snapshot queue identity/version mismatch")
	}
	return queue, true, nil
}

func readPartitionProofSnapshotQueue(storage, kind string, deadlineIndex, partitionIndex int) (queue partitionProofSnapshotQueue, found bool, err error) {
	err = withPartitionProofSnapshotLock(storage, kind, deadlineIndex, partitionIndex, func() error {
		queue, found, err = readPartitionProofSnapshotQueueUnlocked(storage, kind, deadlineIndex, partitionIndex)
		return err
	})
	return queue, found, err
}

func partitionHasFrozenProofSnapshot(storage, kind string, deadlineIndex, partitionIndex int) (bool, error) {
	queue, found, err := readPartitionProofSnapshotQueue(storage, kind, deadlineIndex, partitionIndex)
	if err != nil {
		return false, err
	}
	return found && queue.Frozen != nil, nil
}

func writePartitionProofSnapshotQueueUnlocked(storage string, queue partitionProofSnapshotQueue) error {
	queue.Version = partitionProofSnapshotVersion
	queue.UpdatedAt = nowRFC3339()
	payload, err := json.MarshalIndent(queue, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(
		partitionProofSnapshotQueuePath(storage, queue.PartitionKind, queue.DeadlineIndex, queue.PartitionIndex),
		payload, 0600,
	)
}

func removePartitionProofSnapshotQueueUnlocked(storage string, queue partitionProofSnapshotQueue) error {
	path := partitionProofSnapshotQueuePath(storage, queue.PartitionKind, queue.DeadlineIndex, queue.PartitionIndex)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func partitionProofSnapshotID(partition PartitionMeta) string {
	h := sha256.New()
	_, _ = h.Write([]byte("filetrust-partition-proof-snapshot-v1\x00"))
	_, _ = h.Write([]byte(partition.PartitionKind))
	_, _ = h.Write([]byte(fmt.Sprintf("\x00%d\x00%d\x00", partition.DeadlineIndex, partition.PartitionIndex)))
	_, _ = h.Write([]byte(partitionContentHash(partition)))
	for _, sector := range partition.Sectors {
		_, _ = h.Write([]byte("\x00" + sector.SectorID + "\x00" + sector.SectorRoot))
		for _, root := range sector.PieceRoots {
			_, _ = h.Write([]byte("\x00" + root))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// A.2 artifact identity — split artifact directories by proof authority.
//
// The record ID (partitionProofSnapshotID) is content-only, so capacity and deletion
// proofs of IDENTICAL bytes would otherwise share one artifact directory and one
// authority's cleanup could delete the other's inputs. The artifact directory is instead
// keyed by the full identity:
//
//     physical partition + proof authority/type + epoch-or-deletion-operation-ID
//         + Generation + content hash
//
// Distinct authorities, distinct operations, and distinct generations for the same content
// therefore get DISTINCT directories, and cleanup — which recomputes this key from the
// caller's own record — can only ever target the exact directory that record owns. A stale
// or cross-authority worker computes a different key and cannot reach the live directory.

// snapshotProofAuthorityKind classifies a snapshot's proof authority: a standalone deletion
// proof (flagged epoch id), a capacity-epoch member, or an unbound coalesced successor.
func snapshotProofAuthorityKind(snapshot partitionProofSnapshot) string {
	if snapshot.ProofEpochID&standaloneDeletionProofFlag != 0 {
		return "deletion"
	}
	if snapshot.ProofEpochID == 0 {
		return "successor"
	}
	return "capacity"
}

// snapshotProofAuthorityID is the capacity epoch id, or — for a standalone deletion proof —
// the deletion-operation id (the content version encoded under the flag).
func snapshotProofAuthorityID(snapshot partitionProofSnapshot) uint64 {
	if snapshot.ProofEpochID&standaloneDeletionProofFlag != 0 {
		return snapshot.ProofEpochID &^ standaloneDeletionProofFlag
	}
	return snapshot.ProofEpochID
}

// ErrArtifactIdentityInvalid marks a snapshot whose A.2 artifact identity cannot be formed
// (a required field is missing/default). ErrArtifactNotReadyForUse marks an artifact
// directory that failed a pre-use ownership check (mismatch, symlink, escape, or a manifest
// that does not match the complete identity).
var ErrArtifactIdentityInvalid = errors.New("partition proof artifact identity invalid")
var ErrArtifactNotReadyForUse = errors.New("partition proof artifact not ready for use")

// canonicalArtifactIdentity encodes the full A.2 identity with a versioned domain tag and
// LENGTH-PREFIXED fields, so no two distinct field tuples can share an encoding (unlike raw
// concatenation, where "a"+"bc" and "ab"+"c" collide). It rejects missing/default required
// fields rather than hashing empties: a zero generation is rejected while the A.1 protocol
// is active (the only mode that mints A.2 artifacts), and the partition kind and content
// hash must be present.
func canonicalArtifactIdentity(snapshot partitionProofSnapshot) ([]byte, error) {
	p := snapshot.Partition
	kind := strings.TrimSpace(p.PartitionKind)
	content := strings.TrimSpace(snapshot.ContentHash)
	authorityKind := snapshotProofAuthorityKind(snapshot)
	if kind == "" {
		return nil, fmt.Errorf("%w: empty partition kind", ErrArtifactIdentityInvalid)
	}
	if content == "" {
		return nil, fmt.Errorf("%w: empty content hash", ErrArtifactIdentityInvalid)
	}
	if authorityKind == "" {
		return nil, fmt.Errorf("%w: empty authority kind", ErrArtifactIdentityInvalid)
	}
	if requirePartitionGenerationIdentity && snapshot.Generation == 0 {
		return nil, fmt.Errorf("%w: zero generation under the generation-enforced snapshot protocol", ErrArtifactIdentityInvalid)
	}
	var buf bytes.Buffer
	writeField := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf.Write(n[:])
		buf.Write(b)
	}
	writeUint := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		buf.Write(n[:])
	}
	writeField([]byte("FileTrustArtifactV1")) // versioned domain separator
	writeField([]byte(kind))
	writeUint(uint64(uint32(p.DeadlineIndex)))
	writeUint(uint64(uint32(p.PartitionIndex)))
	writeField([]byte(authorityKind))
	writeUint(snapshotProofAuthorityID(snapshot))
	writeUint(snapshot.Generation)
	writeField([]byte(content))
	return buf.Bytes(), nil
}

// partitionProofArtifactID hashes the canonical A.2 artifact identity. It errors (never
// hashes empty/default values) when the identity is incomplete.
func partitionProofArtifactID(snapshot partitionProofSnapshot) (string, error) {
	encoded, err := canonicalArtifactIdentity(snapshot)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func partitionProofArtifactDir(storage string, snapshot partitionProofSnapshot) (string, error) {
	id, err := partitionProofArtifactID(snapshot)
	if err != nil {
		return "", err
	}
	return filepath.Join(partitionProofSnapshotArtifactRoot(storage), id), nil
}

// setPartitionArtifactDir stamps the record's ArtifactDir to match its current full A.2
// identity. It is called after the generation and epoch are final (and before pinning), so
// the directory name reflects authority, operation, generation, and content. It fails
// closed if the identity is incomplete.
func setPartitionArtifactDir(storage string, snapshot *partitionProofSnapshot) error {
	dir, err := partitionProofArtifactDir(storage, *snapshot)
	if err != nil {
		return err
	}
	snapshot.ArtifactDir = dir
	return nil
}

// verifyArtifactReadyForUse fails closed unless the persisted ArtifactDir is EXACTLY the
// directory recomputed from the record's complete A.2 identity, is a direct child of the
// configured artifact root, is a real directory (not a symlink), and carries a snapshot.json
// manifest that matches the full identity (partition, authority/type, epoch-or-operation id,
// generation, content hash). It MUST be called immediately before any artifact-consuming
// action (proof dispatch, recovery) so a forged/copied/stale ArtifactDir can never direct
// the external prover at another snapshot's directory.
func verifyArtifactReadyForUse(storage string, snapshot partitionProofSnapshot) error {
	wantDir, err := partitionProofArtifactDir(storage, snapshot)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArtifactNotReadyForUse, err)
	}
	actual := filepath.Clean(snapshot.ArtifactDir)
	if actual == "" || actual == "." {
		return fmt.Errorf("%w: empty ArtifactDir", ErrArtifactNotReadyForUse)
	}
	if actual != filepath.Clean(wantDir) {
		return fmt.Errorf("%w: ArtifactDir %s != durable snapshot identity dir %s", ErrArtifactNotReadyForUse, actual, wantDir)
	}
	root := filepath.Clean(partitionProofSnapshotArtifactRoot(storage))
	if actual == root || filepath.Dir(actual) != root {
		return fmt.Errorf("%w: ArtifactDir is not a direct child of the artifact root: %s", ErrArtifactNotReadyForUse, actual)
	}
	info, err := os.Lstat(actual)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArtifactNotReadyForUse, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: ArtifactDir is a symlink: %s", ErrArtifactNotReadyForUse, actual)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: ArtifactDir is not a directory: %s", ErrArtifactNotReadyForUse, actual)
	}
	// A present manifest is REQUIRED for use (stricter than cleanup, which tolerates a
	// missing one): the on-disk identity must match the record's complete identity.
	if _, statErr := os.Stat(filepath.Join(actual, "snapshot.json")); statErr != nil {
		return fmt.Errorf("%w: missing artifact manifest: %v", ErrArtifactNotReadyForUse, statErr)
	}
	if err := verifyArtifactManifestOwnership(actual, snapshot); err != nil {
		return fmt.Errorf("%w: %v", ErrArtifactNotReadyForUse, err)
	}
	return nil
}

func newPartitionProofSnapshot(storage string, partition PartitionMeta, proofEpochID, round uint64, deadline time.Time) partitionProofSnapshot {
	partition.ContentHash = partitionContentHash(partition)
	id := partitionProofSnapshotID(partition)
	now := nowRFC3339()
	deadlineUnix := int64(0)
	if !deadline.IsZero() {
		deadlineUnix = deadline.Unix()
	}
	// ArtifactDir is deliberately left empty here: the A.2 identity depends on the local
	// generation (allocated by the caller after this returns) and the final epoch binding.
	// The caller sets it via setPartitionArtifactDir before pinning the artifact.
	return partitionProofSnapshot{
		Version: partitionProofSnapshotVersion, ID: id, Partition: partition,
		ContentHash: partition.ContentHash, ProofEpochID: proofEpochID,
		Round: round, DeadlineUnix: deadlineUnix,
		State:     proofSnapshotStateQueued,
		CreatedAt: now, UpdatedAt: now,
	}
}

func uniqueSnapshotPieceRoots(partition PartitionMeta) []string {
	seen := make(map[string]bool)
	var roots []string
	for _, sector := range partition.Sectors {
		for _, root := range sector.PieceRoots {
			key := strings.ToLower(strings.TrimSpace(root))
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			roots = append(roots, root)
		}
	}
	sort.Strings(roots)
	return roots
}

func validatePartitionProofSnapshotArtifact(snapshot partitionProofSnapshot) error {
	if snapshot.ArtifactDir == "" || snapshot.ID == "" {
		return fmt.Errorf("snapshot artifact identity is incomplete")
	}
	for _, root := range uniqueSnapshotPieceRoots(snapshot.Partition) {
		path := piecePath(snapshot.ArtifactDir, root)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: pinned piece %s unavailable: %v", ErrPartitionProofSnapshotInvalidated, root, err)
		}
	}
	cachePath := filepath.Join(snapshot.ArtifactDir, ZKSectorCacheRootName)
	if info, err := os.Stat(cachePath); err != nil || !info.IsDir() {
		return fmt.Errorf("%w: snapshot cache view unavailable", ErrPartitionProofSnapshotInvalidated)
	}
	return nil
}

// ensurePartitionProofSnapshotArtifact pins every piece with a hard link. This
// costs no duplicate data blocks and keeps a capacity generation readable after
// the live name is retired. ZK caches are content-addressed and are pinned by
// cleanupObsoleteZKSectorCaches; a symlink gives the prover the normal layout.
func ensurePartitionProofSnapshotArtifact(storage string, snapshot *partitionProofSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("nil partition proof snapshot")
	}
	if err := validatePartitionProofSnapshotArtifact(*snapshot); err == nil {
		return nil
	}
	if err := os.MkdirAll(partitionProofSnapshotArtifactRoot(storage), 0700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(partitionProofSnapshotArtifactRoot(storage), ".tmp-"+snapshot.ID[:min(16, len(snapshot.ID))]+"-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := os.MkdirAll(pieceDir(tmp), 0700); err != nil {
		return err
	}
	for _, root := range uniqueSnapshotPieceRoots(snapshot.Partition) {
		source := piecePath(storage, root)
		target := piecePath(tmp, root)
		if info, statErr := os.Stat(source); statErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: source piece %s unavailable: %v", ErrPartitionProofSnapshotInvalidated, root, statErr)
		}
		if err := os.Link(source, target); err != nil {
			return fmt.Errorf("pin snapshot piece %s: %w", root, err)
		}
	}
	cacheTarget, err := filepath.Abs(zkSectorCacheBaseDir(storage))
	if err != nil {
		return err
	}
	if err := os.Symlink(cacheTarget, filepath.Join(tmp, ZKSectorCacheRootName)); err != nil {
		return fmt.Errorf("link snapshot cache view: %w", err)
	}
	manifest, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := durableAtomicWriteFile(filepath.Join(tmp, "snapshot.json"), manifest, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, snapshot.ArtifactDir); err != nil {
		// A crash may leave the destination directory behind, and POSIX rename
		// reports ENOTEMPTY rather than os.IsExist for that case. Reuse a complete
		// artifact; otherwise replace only this content-addressed, queue-locked
		// destination with the fully prepared temp directory.
		if validatePartitionProofSnapshotArtifact(*snapshot) == nil {
			return nil
		}
		if removeErr := os.RemoveAll(snapshot.ArtifactDir); removeErr != nil {
			return fmt.Errorf("remove incomplete snapshot artifact: %w", removeErr)
		}
		if retryErr := os.Rename(tmp, snapshot.ArtifactDir); retryErr != nil {
			return fmt.Errorf("publish snapshot artifact: %w (initial error: %v)", retryErr, err)
		}
	}
	return validatePartitionProofSnapshotArtifact(*snapshot)
}

// verifyArtifactManifestOwnership confirms the on-disk snapshot.json in an artifact
// directory belongs to the caller's authority, operation, generation, and content before
// the directory may be removed. A missing manifest is tolerated (the directory name is
// itself the full identity hash); a PRESENT manifest that disagrees fails closed, so a
// stale or cross-authority caller can never delete a directory it does not own.
func verifyArtifactManifestOwnership(dir string, snapshot partitionProofSnapshot) error {
	payload, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read artifact manifest for ownership check: %w", err)
	}
	var manifest partitionProofSnapshot
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return fmt.Errorf("decode artifact manifest for ownership check: %w", err)
	}
	if manifest.Generation != snapshot.Generation ||
		snapshotProofAuthorityKind(manifest) != snapshotProofAuthorityKind(snapshot) ||
		snapshotProofAuthorityID(manifest) != snapshotProofAuthorityID(snapshot) ||
		!sameRoot(manifest.ContentHash, snapshot.ContentHash) ||
		manifest.Partition.PartitionKind != snapshot.Partition.PartitionKind ||
		manifest.Partition.DeadlineIndex != snapshot.Partition.DeadlineIndex ||
		manifest.Partition.PartitionIndex != snapshot.Partition.PartitionIndex {
		return fmt.Errorf(
			"refuse to remove artifact owned by a different authority/generation (manifest gen=%d %s/%d, caller gen=%d %s/%d)",
			manifest.Generation, snapshotProofAuthorityKind(manifest), snapshotProofAuthorityID(manifest),
			snapshot.Generation, snapshotProofAuthorityKind(snapshot), snapshotProofAuthorityID(snapshot),
		)
	}
	return nil
}

func removePartitionProofSnapshotArtifact(storage string, snapshot *partitionProofSnapshot) error {
	if snapshot == nil || snapshot.ArtifactDir == "" {
		return nil
	}
	// A.2: recompute the expected directory from the caller's OWN full identity. A stale or
	// cross-authority record computes a different key and is refused before any removal.
	expectedDir, idErr := partitionProofArtifactDir(storage, *snapshot)
	if idErr != nil {
		return fmt.Errorf("refuse to remove snapshot artifact with invalid identity: %w", idErr)
	}
	expected := filepath.Clean(expectedDir)
	actual := filepath.Clean(snapshot.ArtifactDir)
	if snapshot.ID == "" || actual != expected {
		return fmt.Errorf("refuse to remove snapshot artifact outside its durable identity directory: actual=%s expected=%s", actual, expected)
	}
	if err := verifyArtifactManifestOwnership(actual, *snapshot); err != nil {
		return err
	}
	return os.RemoveAll(actual)
}

// removeSupersededPartitionArtifactDir removes a directory a record used to own after a
// re-pin (epoch binding, rebind, reanchor) or a pre-A.2 migration moved the record to a new
// directory. The CALLER MUST HOLD the (kind,dl,pt) partition lock. It verifies OWNERSHIP
// before deleting — path-containment alone is not proof — and returns (removed, err):
//   - the directory must be a direct child of the artifact root and NOT a symlink;
//   - its snapshot.json must be readable and attribute it to THIS partition;
//   - the manifest identity must map to this directory under the current A.2 scheme OR the
//     legacy content-only scheme (rejects a copied manifest planted in an unrelated dir);
//   - NO current queue record (Frozen/Successor) may reference it.
//
// Any failing check is a refusal (returned as an error, safe to log and skip) — an
// unattributable, symlinked, cross-partition, or still-referenced directory is never deleted.
func removeSupersededPartitionArtifactDir(storage, kind string, deadlineIndex, partitionIndex int, dir string) (bool, error) {
	if strings.TrimSpace(dir) == "" {
		return false, nil
	}
	root := filepath.Clean(partitionProofSnapshotArtifactRoot(storage))
	actual := filepath.Clean(dir)
	if actual == root || filepath.Dir(actual) != root {
		return false, fmt.Errorf("refuse to remove superseded artifact outside the artifact root: %s", actual)
	}
	info, err := os.Lstat(actual)
	if os.IsNotExist(err) {
		return false, nil // already gone
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("refuse to remove superseded artifact that is a symlink: %s", actual)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("refuse to remove superseded artifact that is not a directory: %s", actual)
	}
	payload, err := os.ReadFile(filepath.Join(actual, "snapshot.json"))
	if err != nil {
		return false, fmt.Errorf("refuse to remove unattributable superseded artifact %s: %w", actual, err)
	}
	var manifest partitionProofSnapshot
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return false, fmt.Errorf("refuse to remove superseded artifact with unreadable manifest %s: %w", actual, err)
	}
	if manifest.Partition.PartitionKind != kind ||
		manifest.Partition.DeadlineIndex != deadlineIndex ||
		manifest.Partition.PartitionIndex != partitionIndex {
		return false, fmt.Errorf(
			"refuse to remove superseded artifact %s attributed to a different partition (%s dl%d pt%d)",
			actual, manifest.Partition.PartitionKind, manifest.Partition.DeadlineIndex, manifest.Partition.PartitionIndex,
		)
	}
	// The manifest must map to this directory under the current OR the legacy content-only
	// scheme; anything else means the manifest was copied into an unrelated directory.
	matchesScheme := filepath.Clean(filepath.Join(root, partitionProofSnapshotID(manifest.Partition))) == actual
	if !matchesScheme {
		if wantDir, idErr := partitionProofArtifactDir(storage, manifest); idErr == nil && filepath.Clean(wantDir) == actual {
			matchesScheme = true
		}
	}
	if !matchesScheme {
		return false, fmt.Errorf("refuse to remove superseded artifact %s: manifest identity does not map to this directory (copied manifest?)", actual)
	}
	// No live record may still reference it (caller holds the partition lock).
	queue, found, err := readPartitionProofSnapshotQueueUnlocked(storage, kind, deadlineIndex, partitionIndex)
	if err != nil {
		return false, err
	}
	if found {
		for _, rec := range []*partitionProofSnapshot{queue.Frozen, queue.Successor} {
			if rec != nil && filepath.Clean(rec.ArtifactDir) == actual {
				return false, fmt.Errorf("refuse to remove superseded artifact still referenced by the live queue: %s", actual)
			}
		}
	}
	if err := os.RemoveAll(actual); err != nil {
		return false, err
	}
	return true, nil
}

// migratePartitionProofArtifactDirs is the A.2 pre-A.2 record policy: at startup, under each
// partition lock, it re-pins any durable record whose ArtifactDir does not match its current
// A.2 identity directory (e.g. a record written by a pre-A.2 binary under the old content-only
// scheme) into the correct directory and cleans the superseded one. A record whose identity
// cannot be formed (a legacy zero-generation record) is left untouched: it is never handed to
// the prover because verifyArtifactReadyForUse fails closed on it. Nothing silently continues
// to use an old content-only directory — it is either migrated here or fenced at use.
func migratePartitionProofArtifactDirs(storage string) (migrated int, err error) {
	queues, listErr := listPartitionProofSnapshotQueues(storage)
	if listErr != nil {
		return 0, listErr
	}
	for _, q := range queues {
		kind, dl, pt := q.PartitionKind, q.DeadlineIndex, q.PartitionIndex
		lockErr := withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
			queue, found, readErr := readPartitionProofSnapshotQueueUnlocked(storage, kind, dl, pt)
			if readErr != nil || !found {
				return readErr
			}
			var superseded []string
			changed := false
			for _, rec := range []*partitionProofSnapshot{queue.Successor, queue.Frozen} {
				if rec == nil {
					continue
				}
				wantDir, idErr := partitionProofArtifactDir(storage, *rec)
				if idErr != nil {
					// Legacy/incomplete identity — leave it; use is fenced elsewhere.
					continue
				}
				if filepath.Clean(rec.ArtifactDir) == filepath.Clean(wantDir) {
					continue
				}
				oldDir := rec.ArtifactDir
				rec.ArtifactDir = wantDir
				if pinErr := ensurePartitionProofSnapshotArtifact(storage, rec); pinErr != nil {
					return pinErr
				}
				if strings.TrimSpace(oldDir) != "" && filepath.Clean(oldDir) != filepath.Clean(wantDir) {
					superseded = append(superseded, oldDir)
				}
				changed = true
			}
			if !changed {
				return nil
			}
			if writeErr := writePartitionProofSnapshotQueueUnlocked(storage, queue); writeErr != nil {
				return writeErr
			}
			migrated++
			for _, dir := range superseded {
				if _, cleanErr := removeSupersededPartitionArtifactDir(storage, kind, dl, pt, dir); cleanErr != nil {
					log.Printf("[proof-snapshot] legacy migration superseded cleanup refused: %v", cleanErr)
				}
			}
			return nil
		})
		if lockErr != nil {
			return migrated, lockErr
		}
	}
	return migrated, nil
}

// sweepOrphanPartitionArtifactDirs removes artifact directories that no live record
// references — including directories orphaned by a crash between a re-pin and its cleanup.
// It is owner-safe and race-free: each candidate is attributed to its partition via its own
// snapshot.json manifest, and removed only while holding that partition's lock and only if
// the live queue's Frozen/Successor do not reference it. A directory with no readable
// manifest cannot be attributed and is left in place (logged), never blindly removed.
func sweepOrphanPartitionArtifactDirs(storage string) (removed int, err error) {
	root := partitionProofSnapshotArtifactRoot(storage)
	entries, readErr := os.ReadDir(root)
	if os.IsNotExist(readErr) {
		return 0, nil
	}
	if readErr != nil {
		return 0, readErr
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		dirPath := filepath.Join(root, entry.Name())
		payload, manErr := os.ReadFile(filepath.Join(dirPath, "snapshot.json"))
		if manErr != nil {
			log.Printf("[proof-snapshot] orphan sweep skipping unattributable artifact %s: %v", dirPath, manErr)
			continue
		}
		var manifest partitionProofSnapshot
		if json.Unmarshal(payload, &manifest) != nil || strings.TrimSpace(manifest.Partition.PartitionKind) == "" {
			log.Printf("[proof-snapshot] orphan sweep skipping artifact with unreadable manifest %s", dirPath)
			continue
		}
		kind := manifest.Partition.PartitionKind
		dl, pt := manifest.Partition.DeadlineIndex, manifest.Partition.PartitionIndex
		lockErr := withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
			// removeSupersededPartitionArtifactDir performs the ownership checks under the
			// lock (partition attribution, manifest-maps-to-dir, not-referenced, not-symlink)
			// and only deletes a genuine orphan of this partition. A refusal is a safe skip.
			didRemove, rmErr := removeSupersededPartitionArtifactDir(storage, kind, dl, pt, dirPath)
			if rmErr != nil {
				log.Printf("[proof-snapshot] orphan sweep skipping %s: %v", dirPath, rmErr)
				return nil
			}
			if didRemove {
				removed++
			}
			return nil
		})
		if lockErr != nil {
			return removed, lockErr
		}
	}
	return removed, nil
}

func samePartitionSnapshotContent(snapshot *partitionProofSnapshot, partition PartitionMeta) bool {
	return snapshot != nil && sameRoot(snapshot.ContentHash, partitionContentHash(partition))
}

// partitionTransitionRetainsFrozenData distinguishes append-only live updates
// from deletion/replacement. An append may safely run beside the frozen proof;
// a removed or changed data sector invalidates it. Capacity generations remain
// independently provable from pinned bytes and are harmless when historical,
// because the chain never credits a historical version as current backing.
func partitionTransitionRetainsFrozenData(frozen PartitionMeta, live PartitionMeta) bool {
	if frozen.PartitionKind != PartitionKindData {
		return true
	}
	liveByID := make(map[string]SectorMeta, len(live.Sectors))
	for _, sector := range live.Sectors {
		liveByID[sector.SectorID] = sector
	}
	for _, old := range frozen.Sectors {
		current, ok := liveByID[old.SectorID]
		if !ok || !sameRoot(current.SectorRoot, old.SectorRoot) ||
			current.SectorBlockCount != old.SectorBlockCount ||
			!sameRoot(current.ZKPieceCommitment, old.ZKPieceCommitment) ||
			!sameRootSet(current.PieceRoots, old.PieceRoots) {
			return false
		}
	}
	return true
}

// queuePartitionProofSnapshot returns the immutable generation that should be
// proved now. If content moved, the latest live state becomes the sole
// successor. `destructive` tells the caller to abandon the old chain snapshot
// before doing any prover work.
func queuePartitionProofSnapshot(storage string, live PartitionMeta, proofEpochID, round uint64, deadline time.Time) (frozen partitionProofSnapshot, destructive bool, err error) {
	// A.2 gate: freezing / re-pinning / creating an artifact is a proof-affecting write.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return partitionProofSnapshot{}, false, gateErr
	}
	if proofEpochID == 0 || round == 0 {
		return partitionProofSnapshot{}, false, fmt.Errorf("snapshot queue requires an active proof epoch and round")
	}
	err = withPartitionProofSnapshotLock(storage, live.PartitionKind, live.DeadlineIndex, live.PartitionIndex, func() error {
		queue, found, readErr := readPartitionProofSnapshotQueueUnlocked(
			storage, live.PartitionKind, live.DeadlineIndex, live.PartitionIndex,
		)
		if readErr != nil {
			return readErr
		}
		if !found {
			queue = partitionProofSnapshotQueue{
				Version: partitionProofSnapshotVersion, PartitionKind: live.PartitionKind,
				DeadlineIndex: live.DeadlineIndex, PartitionIndex: live.PartitionIndex,
			}
		}
		// A.2: directories superseded by a re-pin (epoch binding / rebind) are cleaned
		// AFTER the queue is written, so a crash can leak a directory but never leave a
		// record pointing at a removed one.
		var supersededDirs []string
		// repin stamps the record's ArtifactDir to its current A.2 identity and pins it,
		// recording any previous directory for post-write cleanup.
		repin := func(snapshot *partitionProofSnapshot, oldDir string) error {
			if err := setPartitionArtifactDir(storage, snapshot); err != nil {
				return err
			}
			if err := ensurePartitionProofSnapshotArtifact(storage, snapshot); err != nil {
				return err
			}
			if oldDir != "" && filepath.Clean(oldDir) != filepath.Clean(snapshot.ArtifactDir) {
				supersededDirs = append(supersededDirs, oldDir)
			}
			return nil
		}
		if queue.Frozen == nil {
			next := newPartitionProofSnapshot(storage, live, proofEpochID, round, deadline)
			// A.1: a new frozen record is a freeze attempt — allocate a strictly
			// greater local generation from the durable (never-reset) ledger.
			gen, genErr := allocatePartitionGenerationUnlocked(storage, live.PartitionKind, live.DeadlineIndex, live.PartitionIndex)
			if genErr != nil {
				return genErr
			}
			next.Generation = gen
			// A.2: pin under the full authority/epoch/generation/content identity.
			if err := repin(&next, ""); err != nil {
				return err
			}
			queue.Frozen = &next
			queue.Successor = nil
			queue.Saturated = false
		} else if samePartitionSnapshotContent(queue.Frozen, live) {
			// A.2: capture the pre-transition directory; any epoch binding / rebind below
			// changes the identity and must re-pin into a new directory.
			frozenOldDir := queue.Frozen.ArtifactDir
			if queue.Frozen.ProofEpochID == 0 {
				queue.Frozen.ProofEpochID = proofEpochID
				queue.Frozen.Round = round
				queue.Frozen.DeadlineUnix = 0
				if !deadline.IsZero() {
					queue.Frozen.DeadlineUnix = deadline.Unix()
				}
				queue.Frozen.State = proofSnapshotStateQueued
				queue.Frozen.LastError = ""
				// A.1: (re)freezing this slot into an epoch is a freeze attempt.
				// Heal a legacy zero-generation record and advance the generation so
				// a worker holding the prior generation is fenced off.
				gen, genErr := allocatePartitionGenerationUnlocked(storage, live.PartitionKind, live.DeadlineIndex, live.PartitionIndex)
				if genErr != nil {
					return genErr
				}
				queue.Frozen.Generation = gen
			} else if queue.Frozen.ProofEpochID != proofEpochID {
				// A.3: the standalone-deletion ↔ capacity REBIND is removed. Deletion and
				// capacity always retain INDEPENDENT snapshot records and artifact identities;
				// neither authority may change the authority/epoch/generation/artifact/lifecycle
				// of the other's frozen record. When the existing frozen record belongs to a
				// different epoch/authority, refuse to reuse or rebind it — the A.2.5 arbiter
				// serialises the single on-chain slot, so the requesting authority defers until
				// the slot frees, then freezes its OWN record. No legacy/fallback path may
				// silently reactivate rebind: this is the only cross-epoch transition and it
				// always rejects.
				return fmt.Errorf(
					"%w: frozen record epoch %d (%s) != requested epoch %d (%s); kind=%s dl=%d pt=%d",
					ErrPartitionFreezeCrossAuthority,
					queue.Frozen.ProofEpochID, snapshotProofAuthorityKind(*queue.Frozen),
					proofEpochID, requestedFreezeAuthorityKind(proofEpochID),
					live.PartitionKind, live.DeadlineIndex, live.PartitionIndex,
				)
			}
			// A.2: re-pin the (possibly re-bound, generation-advanced) frozen record to its
			// current identity and schedule the previous directory for cleanup. When nothing
			// changed this is an idempotent no-op on the same directory.
			if err := repin(queue.Frozen, frozenOldDir); err != nil {
				return err
			}
		} else {
			destructive = !partitionTransitionRetainsFrozenData(queue.Frozen.Partition, live)
			// The changed live version is not part of this epoch's cutoff. Keep one
			// immutable successor, but bind it only when the next epoch begins.
			next := newPartitionProofSnapshot(storage, live, 0, 0, time.Time{})
			// A.1: a successor (a replacement generation) is a freeze attempt — allocate
			// a strictly greater local generation. Replacing an existing successor
			// allocates again, so the retained successor always holds the latest.
			gen, genErr := allocatePartitionGenerationUnlocked(storage, live.PartitionKind, live.DeadlineIndex, live.PartitionIndex)
			if genErr != nil {
				return genErr
			}
			next.Generation = gen
			// A.2: pin the successor under its own (successor-authority) identity directory.
			if err := repin(&next, ""); err != nil {
				return err
			}
			if queue.Successor != nil && !sameRoot(queue.Successor.ContentHash, next.ContentHash) {
				if err := removePartitionProofSnapshotArtifact(storage, queue.Successor); err != nil {
					return err
				}
				queue.Coalesced++
			}
			// Append-only updates may coalesce without limit while retaining only
			// two immutable artifacts. They cannot invalidate the cutoff or create
			// uncharged capacity, so they must not stop new admission.
			queue.Saturated = false
			queue.Successor = &next
		}
		frozen = *queue.Frozen
		if err := writePartitionProofSnapshotQueueUnlocked(storage, queue); err != nil {
			return err
		}
		// A.2: the queue now references the new directories; clean the superseded ones
		// (ownership-verified: same partition, manifest maps to dir, no longer referenced).
		for _, dir := range supersededDirs {
			if _, err := removeSupersededPartitionArtifactDir(storage, live.PartitionKind, live.DeadlineIndex, live.PartitionIndex, dir); err != nil {
				log.Printf("[proof-snapshot] superseded artifact cleanup refused: %v", err)
			}
		}
		return nil
	})
	return frozen, destructive, err
}

func updatePartitionProofSnapshot(storage string, snapshot partitionProofSnapshot) error {
	return withPartitionProofSnapshotLock(
		storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
		func() error {
			queue, found, err := readPartitionProofSnapshotQueueUnlocked(
				storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
			)
			if err != nil {
				return err
			}
			if !found || queue.Frozen == nil || queue.Frozen.ID != snapshot.ID ||
				!partitionGenerationIdentityOK(queue.Frozen.Generation, snapshot.Generation) {
				// A.1: content-identical records can share an ID; a generation mismatch
				// (or a zero generation under the A.1 protocol) means this worker is
				// stale and must not clobber the live frozen slot.
				return fmt.Errorf("partition proof snapshot %s is no longer frozen at generation %d", snapshot.ID, snapshot.Generation)
			}
			snapshot.UpdatedAt = nowRFC3339()
			queue.Frozen = &snapshot
			return writePartitionProofSnapshotQueueUnlocked(storage, queue)
		},
	)
}

// reanchorUpdatePartitionProofSnapshot persists a reanchored frozen record and, per A.1,
// advances the local generation. It verifies (under the partition lock) that the worker's
// held generation still matches the live frozen slot before mutating — a stale worker's
// reanchor is refused — then allocates a strictly greater generation, stamps it on the
// record, and writes. The freshly allocated generation is returned to the caller so the
// in-memory snapshot stays consistent with the durable record.
func reanchorUpdatePartitionProofSnapshot(storage string, snapshot partitionProofSnapshot) (partitionProofSnapshot, error) {
	// A.2 gate: re-pinning a reanchored artifact is a proof-affecting write.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return partitionProofSnapshot{}, gateErr
	}
	err := withPartitionProofSnapshotLock(
		storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
		func() error {
			queue, found, err := readPartitionProofSnapshotQueueUnlocked(
				storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
			)
			if err != nil {
				return err
			}
			if !found || queue.Frozen == nil || queue.Frozen.ID != snapshot.ID ||
				!partitionGenerationIdentityOK(queue.Frozen.Generation, snapshot.Generation) {
				return fmt.Errorf("partition proof snapshot %s is no longer frozen at generation %d (reanchor)", snapshot.ID, snapshot.Generation)
			}
			gen, genErr := allocatePartitionGenerationUnlocked(
				storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
			)
			if genErr != nil {
				return genErr
			}
			snapshot.Generation = gen
			snapshot.UpdatedAt = nowRFC3339()
			// A.2: the new generation is a new artifact identity — re-pin into its own
			// directory (same content bytes, re-hardlinked) and clean the superseded one
			// after the queue is written.
			oldDir := snapshot.ArtifactDir
			if err := setPartitionArtifactDir(storage, &snapshot); err != nil {
				return err
			}
			if err := ensurePartitionProofSnapshotArtifact(storage, &snapshot); err != nil {
				return err
			}
			queue.Frozen = &snapshot
			if err := writePartitionProofSnapshotQueueUnlocked(storage, queue); err != nil {
				return err
			}
			if oldDir != "" && filepath.Clean(oldDir) != filepath.Clean(snapshot.ArtifactDir) {
				if _, cleanErr := removeSupersededPartitionArtifactDir(
					storage, snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex, oldDir,
				); cleanErr != nil {
					log.Printf("[proof-snapshot] superseded reanchor artifact cleanup refused: %v", cleanErr)
				}
			}
			return nil
		},
	)
	if err != nil {
		return partitionProofSnapshot{}, err
	}
	return snapshot, nil
}

// advancePartitionProofSnapshot removes the completed/abandoned generation and
// atomically promotes the one coalesced successor. Artifact removal happens
// after the queue no longer references it, so a crash can leak bytes but cannot
// make a durable job point at deleted inputs.
func advancePartitionProofSnapshot(storage string, completed partitionProofSnapshot) error {
	// A.2 gate: advancing/cleaning a snapshot is a proof-affecting write.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return gateErr
	}
	var remove *partitionProofSnapshot
	err := withPartitionProofSnapshotLock(
		storage, completed.Partition.PartitionKind, completed.Partition.DeadlineIndex, completed.Partition.PartitionIndex,
		func() error {
			queue, found, err := readPartitionProofSnapshotQueueUnlocked(
				storage, completed.Partition.PartitionKind, completed.Partition.DeadlineIndex, completed.Partition.PartitionIndex,
			)
			if err != nil {
				return err
			}
			if !found || queue.Frozen == nil || queue.Frozen.ID != completed.ID ||
				!partitionGenerationIdentityOK(queue.Frozen.Generation, completed.Generation) {
				// A.1: a stale worker (older or zero generation) must not advance/remove
				// a frozen slot that was already replaced or reanchored.
				return nil
			}
			remove = queue.Frozen
			queue.Frozen = queue.Successor
			queue.Successor = nil
			queue.Saturated = false
			if queue.Frozen == nil {
				return removePartitionProofSnapshotQueueUnlocked(storage, queue)
			}
			queue.Frozen.ContentVersion = 0
			queue.Frozen.ProofEpochID = 0
			queue.Frozen.ChainContentHash = ""
			queue.Frozen.AnchorBlock = 0
			queue.Frozen.Round = 0
			queue.Frozen.DeadlineUnix = 0
			queue.Frozen.State = proofSnapshotStateQueued
			queue.Frozen.Challenge = PartitionChallenge{}
			queue.Frozen.PublicInputs = nil
			queue.Frozen.Proof = ZKProofResult{}
			queue.Frozen.LastError = ""
			return writePartitionProofSnapshotQueueUnlocked(storage, queue)
		},
	)
	if err == nil {
		if removeErr := removePartitionProofSnapshotArtifact(storage, remove); removeErr != nil {
			// The durable queue already advanced, so proof/deletion liveness must
			// not be rolled back. Refuse the unsafe path and leave a bounded leak
			// for the ordinary artifact GC/operator to inspect.
			log.Printf("[proof-snapshot] artifact cleanup refused: %v", removeErr)
		}
	}
	return err
}

func listPartitionProofSnapshotQueues(storage string) ([]partitionProofSnapshotQueue, error) {
	entries, err := os.ReadDir(partitionProofSnapshotQueueDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var queues []partitionProofSnapshotQueue
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(partitionProofSnapshotQueueDir(storage), entry.Name()))
		if err != nil {
			return nil, err
		}
		var queue partitionProofSnapshotQueue
		if json.Unmarshal(payload, &queue) != nil || queue.PartitionKind == "" {
			return nil, fmt.Errorf("invalid partition proof snapshot queue %s", entry.Name())
		}
		migrated, found, err := readPartitionProofSnapshotQueue(
			storage, queue.PartitionKind, queue.DeadlineIndex, queue.PartitionIndex,
		)
		if err != nil {
			return nil, err
		}
		if found {
			queues = append(queues, migrated)
		}
	}
	return queues, nil
}

func pinnedProofSnapshotSectorRootIDs(storage string) (map[string]struct{}, error) {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return nil, err
	}
	roots := make(map[string]struct{})
	for _, queue := range queues {
		for _, snapshot := range []*partitionProofSnapshot{queue.Frozen, queue.Successor} {
			if snapshot == nil {
				continue
			}
			for _, sector := range snapshot.Partition.Sectors {
				root := safeID(strings.TrimSpace(sector.SectorRoot))
				if root != "" {
					roots[root] = struct{}{}
				}
			}
		}
	}
	return roots, nil
}

func parseSnapshotTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	return parsed
}

// readProofBacklogMetrics loads the durable health snapshot, reporting absence
// separately from corruption so a first run is never read as a failure.
func readProofBacklogMetrics(storage string) (proofBacklogMetrics, bool, error) {
	var metrics proofBacklogMetrics
	payload, err := os.ReadFile(partitionProofSnapshotMetricsPath(storage))
	if os.IsNotExist(err) {
		return metrics, false, nil
	}
	if err != nil {
		return metrics, false, err
	}
	if json.Unmarshal(payload, &metrics) != nil ||
		metrics.Version != proofBacklogMetricsVersion {
		return proofBacklogMetrics{}, false, nil
	}
	return metrics, true, nil
}

// Bounds on the published freshness budget. The floor keeps a quiet keeper on the
// old, tight promise. The ceiling is what still makes a genuinely dead proof
// daemon detectable: past it, admission closes no matter how busy the keeper
// claims to have been.
const (
	proofBacklogFreshnessFloorSeconds   = 120
	proofBacklogFreshnessCeilingSeconds = 1800
	proofBacklogFreshnessSafetyFactor   = 3
)

// proofBacklogFreshnessBudget reports the write period this file has actually
// been achieving, and the staleness budget to publish for it.
//
// The budget used to be max(120, pollSeconds*3) -- derived from the POLL
// interval alone. But this file is written at the END of a scheduler pass, after
// the proof work, so its real period is the poll interval PLUS however long that
// work took. Those are different quantities, and under load the second dominates.
// The consumer then reads "observation older than 180 s" as "this keeper has no
// working proof subsystem" and refuses every store.
//
// Live on 2026-09-29: ten keepers sharing one prover on a box at load average
// 10.8 were each submitting 20-38 proofs per fifteen minutes -- unmistakably
// alive -- while their observations aged 261 to 451 seconds against that 180 s
// budget. Four to seven of ten were reporting proof_subsystem_unavailable at any
// moment, no upload could find enough willing keepers, and nothing completed for
// thirty minutes. Deletes and downloads kept working because they need no
// admission, which is exactly what made it look like broken uploads rather than
// a saturated cluster.
//
// The period rises immediately to the last gap observed and decays by a quarter
// per write, so one quick pass cannot yank the budget back down and re-trigger
// the false alarm. The capacity numbers admission decides on come from the chain,
// not from this file, so trusting a late-but-alive daemon costs no safety.
func proofBacklogFreshnessBudget(
	storage string, pollSeconds int64, now time.Time,
) (periodSeconds int64, staleAfterSeconds int64) {
	previous, found, err := readProofBacklogMetrics(storage)
	if err == nil && found {
		if observed := parseSnapshotTime(previous.ObservedAt); !observed.IsZero() {
			gap := int64(now.Sub(observed) / time.Second)
			if gap > 0 {
				periodSeconds = gap
			}
		}
		if decayed := previous.ObservedWritePeriodSeconds * 3 / 4; decayed > periodSeconds {
			periodSeconds = decayed
		}
	}
	budget := max(int64(proofBacklogFreshnessFloorSeconds), pollSeconds*3)
	if scaled := periodSeconds * proofBacklogFreshnessSafetyFactor; scaled > budget {
		budget = scaled
	}
	if budget > proofBacklogFreshnessCeilingSeconds {
		budget = proofBacklogFreshnessCeilingSeconds
	}
	return periodSeconds, budget
}

func refreshProofBacklogMetrics(
	storage string,
	proofObligationsPresent bool,
	pollSeconds int64,
	chainTimestamp int64,
	chainClockAvailable bool,
	capacityAdmissionRequired bool,
	capacityProofFreshUntilChain int64,
) error {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return err
	}
	metrics := proofBacklogMetrics{
		Version: proofBacklogMetricsVersion, ObservedAt: nowRFC3339(),
		ProofObligationsPresent:   proofObligationsPresent,
		ChainTimestamp:            chainTimestamp,
		ChainClockAvailable:       chainClockAvailable,
		CapacityAdmissionRequired: capacityAdmissionRequired,
	}
	if pollSeconds <= 0 {
		pollSeconds = 60
	}
	metrics.ObservedWritePeriodSeconds, metrics.StaleAfterSeconds =
		proofBacklogFreshnessBudget(storage, pollSeconds, time.Now())
	if lag, found, lagErr := readCapacityProofLagSnapshot(storage); lagErr != nil {
		return lagErr
	} else if found {
		metrics.CapacityLagAtRisk = lag.AtRisk
		metrics.CapacityLagBreached = lag.Breached
		metrics.CapacityPendingMutations = lag.PendingMutations
		metrics.CapacityPendingBytes = lag.PendingBytes
		metrics.CapacityOldestMutationNanos = lag.OldestMutationAgeNanos
		metrics.CapacityMaximumLagNanos = lag.MaximumLagNanos
		metrics.CapacityLagReason = lag.Reason
	}
	type deadlineJob struct {
		deadline int64
		estimate int64
	}
	deadlineJobs := make([]deadlineJob, 0)
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	for _, queue := range queues {
		for _, snapshot := range []*partitionProofSnapshot{queue.Frozen, queue.Successor} {
			if snapshot == nil {
				continue
			}
			metrics.PendingSnapshots++
			created := parseSnapshotTime(snapshot.CreatedAt)
			if !created.IsZero() && (metrics.OldestPendingUnix == 0 || created.Unix() < metrics.OldestPendingUnix) {
				metrics.OldestPendingUnix = created.Unix()
			}
			proofDeadline := snapshot.DeadlineUnix
			// Capacity-epoch jobs are durable obligations as soon as the cutoff is
			// queued, before each partition receives its short freeze challenge.
			// Budget those unstarted jobs against the chain's capacity-freshness
			// deadline. A coalesced successor has ProofEpochID zero and remains
			// intentionally excluded until the next immutable cutoff binds it.
			if proofDeadline == 0 && snapshot.ProofEpochID != 0 &&
				capacityAdmissionRequired && capacityProofFreshUntilChain > 0 {
				proofDeadline = capacityProofFreshUntilChain
			}
			if proofDeadline > 0 {
				estimate := int64(time.Minute)
				if chainClockAvailable && proofDeadline > chainTimestamp {
					// Until this hardware/profile has a measured duration, reserve a
					// conservative third of the available chain window. Proof work
					// continues while admission is closed and immediately replaces
					// this fallback with its persistent measured estimate.
					fallback := time.Duration(proofDeadline-chainTimestamp) * time.Second / 3
					if int64(fallback) > estimate {
						estimate = int64(fallback)
					}
				}
				if lockPath != "" {
					class := fmt.Sprintf(
						"%s-final-n%d", snapshot.Partition.PartitionKind, len(snapshot.Partition.Sectors),
					)
					if measured := readProofWorkEstimate(lockPath, class); measured > 0 {
						estimate = measured
					}
				}
				deadlineJobs = append(deadlineJobs, deadlineJob{
					deadline: proofDeadline,
					estimate: estimate,
				})
			}
		}
	}
	if chainClockAvailable {
		hostNow := time.Now()
		if capacityAdmissionRequired && capacityProofFreshUntilChain > 0 {
			metrics.CapacityProofFreshUntilUnix = chainDeadlineHostDue(
				capacityProofFreshUntilChain, chainTimestamp, hostNow,
			).Unix()
		}
		sort.Slice(deadlineJobs, func(i, j int) bool {
			return deadlineJobs[i].deadline < deadlineJobs[j].deadline
		})
		var cumulative int64
		const maxInt64 = int64(^uint64(0) >> 1)
		for _, job := range deadlineJobs {
			if job.estimate > maxInt64-cumulative {
				cumulative = maxInt64
			} else {
				cumulative += job.estimate
			}
			metrics.DeadlineChecks = append(metrics.DeadlineChecks, proofBacklogDeadlineCheck{
				DeadlineUnix: chainDeadlineHostDue(
					job.deadline, chainTimestamp, hostNow,
				).Unix(),
				RequiredNanos: cumulative,
			})
		}
		if len(metrics.DeadlineChecks) > 0 {
			metrics.NearestDeadlineUnix = metrics.DeadlineChecks[0].DeadlineUnix
			metrics.EstimatedCatchupNanos = metrics.DeadlineChecks[len(metrics.DeadlineChecks)-1].RequiredNanos
		}
	}
	payload, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(partitionProofSnapshotMetricsPath(storage), payload, 0600)
}

func proofBacklogAdmissionState(storage string, now time.Time) ProofBacklogAdmissionState {
	state := ProofBacklogAdmissionState{Safe: true}
	payload, err := os.ReadFile(partitionProofSnapshotMetricsPath(storage))
	if os.IsNotExist(err) {
		return state
	}
	if err != nil {
		state.Safe, state.Reason = false, proofBacklogStateUnavailable
		return state
	}
	var metrics proofBacklogMetrics
	if json.Unmarshal(payload, &metrics) != nil || metrics.Version != proofBacklogMetricsVersion {
		state.Safe, state.Reason = false, proofBacklogStateUnavailable
		return state
	}
	state.PendingSnapshots = metrics.PendingSnapshots
	state.OldestPendingAt = time.Unix(metrics.OldestPendingUnix, 0)
	state.NearestDeadline = time.Unix(metrics.NearestDeadlineUnix, 0)
	state.EstimatedCatchup = time.Duration(metrics.EstimatedCatchupNanos)
	state.ObservedAt = parseSnapshotTime(metrics.ObservedAt)
	state.CapacityProofFreshUntil = time.Unix(metrics.CapacityProofFreshUntilUnix, 0)
	staleAfter := time.Duration(metrics.StaleAfterSeconds) * time.Second
	if staleAfter <= 0 {
		staleAfter = 3 * time.Minute
	}
	if metrics.ProofObligationsPresent && (state.ObservedAt.IsZero() || now.Sub(state.ObservedAt) > staleAfter) {
		state.Safe, state.Reason = false, proofBacklogStateUnavailable
		return state
	}
	if (metrics.ProofObligationsPresent || metrics.PendingSnapshots > 0) && !metrics.ChainClockAvailable {
		state.Safe, state.Reason = false, proofBacklogStateUnavailable
		return state
	}
	if metrics.CapacityAdmissionRequired {
		if metrics.CapacityProofFreshUntilUnix <= 0 {
			state.Safe, state.Reason = false, proofBacklogStateUnavailable
			return state
		}
		if !now.Before(state.CapacityProofFreshUntil) {
			state.Safe, state.Reason = false, proofBacklogCapacityStale
			return state
		}
		if metrics.CapacityLagAtRisk || metrics.CapacityLagBreached {
			state.Safe, state.Reason = false, proofBacklogCapacityLag
			return state
		}
	}
	if len(metrics.DeadlineChecks) > 0 {
		for _, check := range metrics.DeadlineChecks {
			required := time.Duration(check.RequiredNanos)
			deadline := time.Unix(check.DeadlineUnix, 0)
			safety := required / 10
			if safety < 30*time.Second {
				safety = 30 * time.Second
			}
			if !now.Add(required + safety).Before(deadline) {
				state.Safe, state.Reason = false, proofBacklogDeadlineAtRisk
				state.EstimatedCatchup = required
				state.NearestDeadline = deadline
				return state
			}
		}
	} else if metrics.PendingSnapshots > 0 && metrics.NearestDeadlineUnix > 0 {
		// Backward-compatible fallback for a metrics record written during a
		// rolling binary update. Version validation normally makes this path
		// unnecessary, but retaining it keeps the invariant explicit.
		// Keep ten percent (at least 30 seconds) for chain submission/finality.
		safety := state.EstimatedCatchup / 10
		if safety < 30*time.Second {
			safety = 30 * time.Second
		}
		if !now.Add(state.EstimatedCatchup + safety).Before(state.NearestDeadline) {
			state.Safe, state.Reason = false, proofBacklogDeadlineAtRisk
		}
	}
	return state
}
