package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const defaultChainProofCommandTimeout = 180 * time.Second

var chainProofCommandTimeoutNanos atomic.Int64

func configuredChainProofCommandTimeout() time.Duration {
	if configured := time.Duration(chainProofCommandTimeoutNanos.Load()); configured > 0 {
		return configured
	}
	return defaultChainProofCommandTimeout
}

func setChainProofCommandTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("chain proof command timeout must be positive")
	}
	chainProofCommandTimeoutNanos.Store(int64(timeout))
	return nil
}

// ─── Per-sector chain protocol (existing, unchanged) ─────────────────────────

type ChainProofCommandRequest struct {
	Action         string          `json:"action"`
	Sector         SectorMeta      `json:"sector"`
	Round          uint64          `json:"round"`
	ChallengeCount int             `json:"challengeCount"`
	Challenge      SectorChallenge `json:"challenge,omitempty"`
	Proof          ZKProofResult   `json:"proof,omitempty"`
	// Partition fields (populated only for partition actions)
	Partition  PartitionMeta      `json:"partition,omitempty"`
	PChallenge PartitionChallenge `json:"partitionChallenge,omitempty"`
	// Capacity reporting fields
	TotalCapacityBytes int64 `json:"totalCapacityBytes,omitempty"`
	UsedBytes          int64 `json:"usedBytes,omitempty"`
	DeadlineIndex      int   `json:"deadlineIndex,omitempty"`
	PartitionIndex     int   `json:"partitionIndex,omitempty"`
	// Snapshot protocol fields. ContentVersion is always the version returned by
	// freezePartitionSnapshot; it is never inferred again from mutable live state.
	PartitionKey   string `json:"partitionKey,omitempty"`
	ProofEpochID   uint64 `json:"proofEpochId,omitempty"`
	AbandonReason  uint8  `json:"reason,omitempty"`
	ContentVersion uint64 `json:"contentVersion,omitempty"`
	// ContentHash and SnapshotNonce complete the frozen-snapshot identity tuple
	// (proofEpochId + contentVersion + contentHash + snapshotNonce) enforced by
	// PartitionSnapshotProofSC on submit, abandon, and reanchor.
	ContentHash   string `json:"contentHash,omitempty"`
	SnapshotNonce uint64 `json:"snapshotNonce,omitempty"`
	// A.2.5 sender-nonce coordination: when the Go caller holds the sender-wide account
	// transaction flock and has durably reserved+journalled the exact Ethereum sender nonce,
	// it passes that nonce explicitly. The subprocess MUST use exactly this nonce (never
	// re-select another) and MUST NOT re-acquire the account flock (the caller holds it).
	SenderTxNonce          uint64 `json:"senderTxNonce,omitempty"`
	HasSenderTxNonce       bool   `json:"hasSenderTxNonce,omitempty"`
	CallerHoldsAccountLock bool   `json:"callerHoldsAccountLock,omitempty"`
	// BlockNumber pins read-only health queries to the same chain snapshot as
	// the scheduler clock. Zero asks the chain client to select latest.
	BlockNumber uint64 `json:"blockNumber,omitempty"`
	// Partitions is used by the batched proof-health snapshot action. Keeping
	// this read in one subprocess avoids one Python/RPC setup per partition.
	Partitions []PartitionMeta `json:"partitions,omitempty"`
	// PartitionKeys is the exact frozen membership of an incremental capacity batch.
	PartitionKeys []string `json:"partitionKeys,omitempty"`
	// BatchMode is the CapacityProofSC/CapacityIncrementalBatchSC campaign reason code.
	BatchMode uint8 `json:"batchMode,omitempty"`
}

type ChainProofCommandResponse struct {
	OK               bool     `json:"ok"`
	Err              string   `json:"err,omitempty"`
	Round            uint64   `json:"round,omitempty"`
	ChallengeSeed    string   `json:"challengeSeed,omitempty"`
	ChallengeIndexes []uint64 `json:"challengeIndexes,omitempty"`
	PublicInputs     []string `json:"publicInputs,omitempty"`
	OpenTx           string   `json:"openTx,omitempty"`
	RegisterTx       string   `json:"registerTx,omitempty"`
	SubmitTx         string   `json:"submitTx,omitempty"`
	// SenderNonce is the exact Ethereum sender nonce the subprocess used for the transaction,
	// echoed back so the Go caller can verify it equals the reserved+journalled nonce.
	SenderNonce uint64 `json:"senderNonce,omitempty"`
	// Partition-specific fields
	PartitionKey            string                   `json:"partitionKey,omitempty"`
	PerSectorIndexes        [][]uint64               `json:"perSectorIndexes,omitempty"`
	CapacityPartitions      []CapacityPartitionInfo  `json:"capacityPartitions,omitempty"`
	DataPartitions          []CapacityPartitionInfo  `json:"dataPartitions,omitempty"`
	FileRegistration        string                   `json:"fileRegistration,omitempty"`
	DataGuardRequired       bool                     `json:"dataGuardRequired,omitempty"`
	ProofEpochID            uint64                   `json:"proofEpochId,omitempty"`
	ContentHash             string                   `json:"contentHash,omitempty"`
	ContentVersion          uint64                   `json:"contentVersion,omitempty"`
	LastProvenContentHash   string                   `json:"lastProvenContentHash,omitempty"`
	CurrentContentProven    bool                     `json:"currentContentProven,omitempty"`
	PartitionActive         bool                     `json:"partitionActive,omitempty"`
	LastProofRound          uint64                   `json:"lastProofRound,omitempty"`
	RegisteredAt            uint64                   `json:"registeredAt,omitempty"`
	ChallengeExists         bool                     `json:"challengeExists,omitempty"`
	ChallengeDeadline       uint64                   `json:"challengeDeadline,omitempty"`
	ChallengeProven         bool                     `json:"challengeProven,omitempty"`
	ChainTimestamp          uint64                   `json:"chainTimestamp,omitempty"`
	CurrentRound            uint64                   `json:"currentRound,omitempty"`
	ProofPeriodSeconds      uint64                   `json:"proofPeriodSeconds,omitempty"`
	PartitionChallengeCount uint64                   `json:"partitionChallengeCount,omitempty"`
	BlockNumber             uint64                   `json:"blockNumber,omitempty"`
	StalenessThreshold      uint64                   `json:"stalenessThreshold,omitempty"`
	PartitionStatuses       []PartitionVersionStatus `json:"partitionStatuses,omitempty"`
	// G.2 production selection snapshot. Every entry, the certification slot, and the
	// observation block are returned by one read-only adapter invocation pinned to one block.
	CapacitySelectionEntries []CapacitySelectionSnapshotEntry `json:"capacitySelectionEntries,omitempty"`
	CurrentCertificationSlot uint64                           `json:"currentCertificationSlot,omitempty"`
	// ActiveCapacityPartitionKeys is the complete set of active capacity bytes32 keys at
	// the same pinned block as CapacitySelectionEntries. Aggregate terminal reconciliation
	// uses it to prove that no removed or unknown chain identity remains active.
	ActiveCapacityPartitionKeys []string `json:"activeCapacityPartitionKeys,omitempty"`
	SnapshotExists              bool     `json:"snapshotExists,omitempty"`
	SnapshotCurrent             bool     `json:"snapshotCurrent,omitempty"`
	SnapshotProven              bool     `json:"snapshotProven,omitempty"`
	AnchorBlock                 uint64   `json:"anchorBlock,omitempty"`
	SnapshotDeadline            uint64   `json:"snapshotDeadline,omitempty"`
	SnapshotNonce               uint64   `json:"snapshotNonce,omitempty"`
	EpochCutoffNonce            uint64   `json:"epochCutoffNonce,omitempty"`
	EpochExpectedPartitions     uint32   `json:"epochExpectedPartitions,omitempty"`
	EpochProvenPartitions       uint32   `json:"epochProvenPartitions,omitempty"`
	EpochExpectedBytes          uint64   `json:"epochExpectedBytes,omitempty"`
	EpochActive                 bool     `json:"epochActive,omitempty"`
	EpochInvalidated            bool     `json:"epochInvalidated,omitempty"`
	IncrementalBatchID          uint64   `json:"incrementalBatchId,omitempty"`
	IncrementalBatchActive      bool     `json:"incrementalBatchActive,omitempty"`
	IncrementalBatchComplete    bool     `json:"incrementalBatchComplete,omitempty"`
	IncrementalSelected         uint32   `json:"incrementalSelectedPartitions,omitempty"`
	IncrementalAccepted         uint32   `json:"incrementalAcceptedPartitions,omitempty"`
	IncrementalSelectedBytes    uint64   `json:"incrementalSelectedBytes,omitempty"`
	IncrementalAcceptedBytes    uint64   `json:"incrementalAcceptedBytes,omitempty"`
	EpochVersionExcluded        bool     `json:"epochVersionExcluded,omitempty"`
	ExcludedBytes               uint64   `json:"excludedBytes,omitempty"`
	DeclaredCapacityBytes       uint64   `json:"declaredCapacityBytes,omitempty"`
	RegisteredFreeBytes         uint64   `json:"registeredFreeBytes,omitempty"`
	RegisteredDataBytes         uint64   `json:"registeredDataBytes,omitempty"`
	ProvedFreeBytes             uint64   `json:"provedFreeBytes,omitempty"`
	ProvedDataBytes             uint64   `json:"provedDataBytes,omitempty"`
	QuoteReservedBytes          uint64   `json:"quoteReservedBytes,omitempty"`
	AllocatedStoredBytes        uint64   `json:"allocatedStoredBytes,omitempty"`
	ConservativeFreeBytes       uint64   `json:"conservativeFreeBytes,omitempty"`
	LastCapacityProofAt         uint64   `json:"lastCapacityProofAt,omitempty"`
	CapacityProofFresh          bool     `json:"capacityProofFresh,omitempty"`
	CapacityProofSequence       uint64   `json:"capacityProofSequence,omitempty"`
	ProvedBackingBytes          uint64   `json:"provedBackingBytes,omitempty"`
	CheckpointFreeBytes         uint64   `json:"checkpointFreeBytes,omitempty"`
	CheckpointDataBytes         uint64   `json:"checkpointDataBytes,omitempty"`
	CheckpointProofRound        uint64   `json:"checkpointProofRound,omitempty"`
	CheckpointProofAt           uint64   `json:"checkpointProofAt,omitempty"`
	MaxProofAgeSeconds          uint64   `json:"maxProofAgeSeconds,omitempty"`
	MaxManifestOverheadBytes    uint64   `json:"maxManifestOverheadBytes,omitempty"`
	// G.5 block-pinned rolling certification admission fields. These values are
	// returned by one adapter action and therefore always describe one chain block.
	FreshCertifiedFreeCapacity    uint64 `json:"freshCertifiedFreeCapacity,omitempty"`
	RingCertifiedFreeCapacity     uint64 `json:"ringCertifiedFreeCapacity,omitempty"`
	CertifiedDataBytes            uint64 `json:"certifiedDataBytes,omitempty"`
	ExpiredCertifiedBytes         uint64 `json:"expiredCertifiedBytes,omitempty"`
	CertificationObservationBlock uint64 `json:"certificationObservationBlock,omitempty"`
	CertificationChainTimestamp   uint64 `json:"certificationChainTimestamp,omitempty"`

	// IncrementalBatchMembers is the CHAIN-AUTHORITATIVE selected-member set of an incremental
	// batch (the contract's selectedMemberKeys). Recovery uses it to enumerate a stuck batch's
	// members when local records (journal + chunk plan) were destroyed by a restart mid-deletion.
	IncrementalBatchMembers []IncrementalBatchMember `json:"members,omitempty"`
}

// IncrementalBatchMember is one selected member of an incremental capacity batch as reported by
// chain. Key is the "kind:deadline:partition" partition key; Accepted members keep their
// accounting and are never retired; Frozen members still hold a live selected snapshot that must
// be released before the batch can be abandoned.
type IncrementalBatchMember struct {
	Key      string `json:"key"`
	Accepted bool   `json:"accepted"`
	Frozen   bool   `json:"frozen"`
}

// CapacitySelectionSnapshotEntry joins one current registered identity to the certification
// record and canonical identity hash read for that same chain partition key and block.
// Identity.PartitionKey remains the stable local kind/deadline/partition coordinate used by
// durable plans; ChainPartitionKey is the exact bytes32 contract identity.
type CapacitySelectionSnapshotEntry struct {
	Identity              PartitionIdentity            `json:"identity"`
	Certification         PartitionCertificationRecord `json:"certification"`
	CanonicalIdentityHash string                       `json:"canonicalIdentityHash"`
	ChainPartitionKey     string                       `json:"chainPartitionKey"`
	ChallengeCount        uint16                       `json:"challengeCount"`
}

// ProofClockStatus is the chain-authoritative clock used by proof scheduling.
// Wall-clock time on the VK host must not be used to select an on-chain round:
// a correctly synchronized host can still differ from the latest block time.
type ProofClockStatus struct {
	ChainTimestamp     int64
	CurrentRound       uint64
	ProofPeriodSeconds int64
	BlockNumber        uint64
}

func parseProofClockStatus(resp ChainProofCommandResponse) (ProofClockStatus, error) {
	if resp.BlockNumber == 0 {
		return ProofClockStatus{}, fmt.Errorf("proof clock response is missing block number")
	}
	if resp.ChainTimestamp == 0 {
		return ProofClockStatus{}, fmt.Errorf("proof clock response is missing chain timestamp")
	}
	if resp.ProofPeriodSeconds == 0 {
		return ProofClockStatus{}, fmt.Errorf("proof clock response is missing proof period")
	}
	const maxInt64AsUint = uint64(1<<63 - 1)
	if resp.ChainTimestamp > maxInt64AsUint {
		return ProofClockStatus{}, fmt.Errorf("proof clock chain timestamp exceeds int64")
	}
	if resp.ProofPeriodSeconds > maxInt64AsUint {
		return ProofClockStatus{}, fmt.Errorf("proof clock period exceeds int64")
	}
	expectedRound := resp.ChainTimestamp / resp.ProofPeriodSeconds
	if resp.CurrentRound != expectedRound {
		return ProofClockStatus{}, fmt.Errorf(
			"proof clock round mismatch: got %d expected %d from timestamp %d and period %d",
			resp.CurrentRound, expectedRound, resp.ChainTimestamp, resp.ProofPeriodSeconds,
		)
	}
	return ProofClockStatus{
		ChainTimestamp:     int64(resp.ChainTimestamp),
		CurrentRound:       resp.CurrentRound,
		ProofPeriodSeconds: int64(resp.ProofPeriodSeconds),
		BlockNumber:        resp.BlockNumber,
	}, nil
}

func proofClockStatusOnChain(chainCmd string) (ProofClockStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{Action: "proof_clock_status"})
	if err != nil {
		return ProofClockStatus{}, fmt.Errorf("proof clock status: %w", err)
	}
	return parseProofClockStatus(resp)
}

func legacyPartitionChallengeStatus(chainCmd string, partition PartitionMeta, round uint64) (ChainProofCommandResponse, error) {
	return runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "partition_challenge_status", Partition: partition, Round: round,
	})
}

type PartitionVersionStatus struct {
	PartitionKey          string `json:"partitionKey,omitempty"`
	PartitionKind         string `json:"partitionKind,omitempty"`
	DeadlineIndex         int    `json:"deadlineIndex"`
	PartitionIndex        int    `json:"partitionIndex"`
	ContentHash           string `json:"contentHash,omitempty"`
	ContentVersion        uint64 `json:"contentVersion,omitempty"`
	LastProvenContentHash string `json:"lastProvenContentHash,omitempty"`
	CurrentContentProven  bool   `json:"currentContentProven,omitempty"`
	Active                bool   `json:"partitionActive,omitempty"`
	LastProofRound        uint64 `json:"lastProofRound,omitempty"`
	RegisteredAt          uint64 `json:"registeredAt,omitempty"`
	ChainTimestamp        uint64 `json:"chainTimestamp,omitempty"`
	CurrentRound          uint64 `json:"currentRound,omitempty"`
	ProofPeriodSeconds    uint64 `json:"proofPeriodSeconds,omitempty"`
	ChallengeCount        uint16 `json:"partitionChallengeCount,omitempty"`
	BlockNumber           uint64 `json:"blockNumber,omitempty"`
}

type PartitionProofHealthSnapshot struct {
	BlockNumber        uint64
	StalenessThreshold uint64
	Statuses           []PartitionVersionStatus
}

// FrozenPartitionSnapshotStatus is the chain-authoritative identity of one
// immutable proof generation. Historical versions may be accepted by the
// contract for audit/liveness, but SnapshotCurrent is required before they can
// affect current capacity, deletion, or dispute state.
type FrozenPartitionSnapshotStatus struct {
	Exists         bool
	PartitionKey   string
	ProofEpochID   uint64
	ContentVersion uint64
	ContentHash    string
	Round          uint64
	AnchorBlock    uint64
	ChallengeSeed  string
	Deadline       uint64
	Proven         bool
	Current        bool
	// SnapshotNonce is the partition's persistent freeze-generation counter.
	SnapshotNonce uint64
}

// CapacityProofEpochStatus is one chain-pinned view of both the rolling proof
// epoch and the authoritative capacity ledger. It is deliberately obtained in
// one helper invocation so scheduler decisions are not assembled from mutable
// local counters or unrelated RPC snapshots.
type CapacityProofEpochStatus struct {
	ProofEpochID             uint64
	TargetRound              uint64
	CutoffNonce              uint64
	ExpectedPartitions       uint32
	ProvenPartitions         uint32
	ExpectedBytes            uint64
	Active                   bool
	Invalidated              bool
	DeclaredCapacityBytes    uint64
	RegisteredFreeBytes      uint64
	RegisteredDataBytes      uint64
	ProvedFreeBytes          uint64
	ProvedDataBytes          uint64
	QuoteReservedBytes       uint64
	AllocatedStoredBytes     uint64
	ConservativeFreeBytes    uint64
	LastCapacityProofAt      uint64
	ProofFresh               bool
	CapacityProofSequence    uint64
	ProvedBackingBytes       uint64
	CheckpointFreeBytes      uint64
	CheckpointDataBytes      uint64
	CheckpointProofRound     uint64
	CheckpointProofAt        uint64
	MaxProofAgeSeconds       uint64
	MaxManifestOverheadBytes uint64
}

// CertifiedCapacityAdmissionStatus is the only chain capacity source upload
// admission may consume. The adapter obtains the bounded expiry-ring aggregate,
// expiry observability, and chain timestamp at ObservationBlock in one action.
type CertifiedCapacityAdmissionStatus struct {
	FreshCertifiedFreeCapacity int64
	RingCertifiedFreeCapacity  int64
	AllocatedStoredBytes       int64
	CertifiedDataBytes         int64
	ExpiredCertifiedBytes      int64
	ObservationBlock           uint64
	ChainTimestamp             int64
}

func parseCertifiedCapacityAdmissionStatus(resp ChainProofCommandResponse) (CertifiedCapacityAdmissionStatus, error) {
	if resp.CertificationObservationBlock == 0 || resp.CertificationChainTimestamp == 0 {
		return CertifiedCapacityAdmissionStatus{}, fmt.Errorf("certified capacity response is missing its chain observation")
	}
	const maxInt64 = uint64(1<<63 - 1)
	if resp.FreshCertifiedFreeCapacity > maxInt64 || resp.RingCertifiedFreeCapacity > maxInt64 ||
		resp.AllocatedStoredBytes > maxInt64 || resp.CertifiedDataBytes > maxInt64 ||
		resp.ExpiredCertifiedBytes > maxInt64 || resp.CertificationChainTimestamp > maxInt64 {
		return CertifiedCapacityAdmissionStatus{}, fmt.Errorf("certified capacity response exceeds local accounting bounds")
	}
	if resp.FreshCertifiedFreeCapacity > resp.RingCertifiedFreeCapacity {
		return CertifiedCapacityAdmissionStatus{}, fmt.Errorf("ledger-clamped certified capacity exceeds certification ring total")
	}
	return CertifiedCapacityAdmissionStatus{
		FreshCertifiedFreeCapacity: int64(resp.FreshCertifiedFreeCapacity),
		RingCertifiedFreeCapacity:  int64(resp.RingCertifiedFreeCapacity),
		AllocatedStoredBytes:       int64(resp.AllocatedStoredBytes),
		CertifiedDataBytes:         int64(resp.CertifiedDataBytes),
		ExpiredCertifiedBytes:      int64(resp.ExpiredCertifiedBytes),
		ObservationBlock:           resp.CertificationObservationBlock,
		ChainTimestamp:             int64(resp.CertificationChainTimestamp),
	}, nil
}

func certifiedCapacityAdmissionStatusOnChain(chainCmd string) (CertifiedCapacityAdmissionStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "certified_capacity_admission_status",
	})
	if err != nil {
		return CertifiedCapacityAdmissionStatus{}, err
	}
	return parseCertifiedCapacityAdmissionStatus(resp)
}

type CapacityPartitionInfo struct {
	PartitionKey   string `json:"partitionKey,omitempty"`
	DeadlineIndex  int    `json:"deadlineIndex"`
	PartitionIndex int    `json:"partitionIndex"`
	PartitionKind  int    `json:"partitionKind,omitempty"`
	Active         bool   `json:"active,omitempty"`
	CommittedBytes int64  `json:"committedBytes,omitempty"`
	ContentHash    string `json:"contentHash,omitempty"`
	ContentVersion uint64 `json:"contentVersion,omitempty"`
	ChallengeCount uint16 `json:"challengeCount,omitempty"`
}

func runChainProofCommand(command string, req ChainProofCommandRequest) (ChainProofCommandResponse, error) {
	// DEFECT H: a transaction-producing action must hold the ONE sender-wide account lock,
	// so the adapter's own lock can never hand the same nonce to a concurrent Go raw-RPC
	// sender. Reads and callers that already hold the lock pass straight through — see
	// chain_sender_serialization.go for the invariant and the acyclicity argument.
	return withChainSenderSerialization(req, func(callerHoldsAccountLock bool) (ChainProofCommandResponse, error) {
		// The Python storage-proof client uses the same per-sender flock as Go.
		// Propagate ownership acquired above so the child does not recursively
		// acquire its parent's lock and wait until the command timeout.
		req.CallerHoldsAccountLock = callerHoldsAccountLock
		return runChainProofCommandLocked(command, req)
	})
}

func runChainProofCommandLocked(command string, req ChainProofCommandRequest) (ChainProofCommandResponse, error) {
	// B.1: chain RPC must never run under the short allocator lock.
	noteLockConfinedWork("chain-proof-command")
	if command == "" {
		return ChainProofCommandResponse{}, fmt.Errorf("chain proof command is not configured")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return ChainProofCommandResponse{}, err
	}
	timeout := configuredChainProofCommandTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	// The command commonly launches vks.py through a shell. Put the complete
	// helper tree in its own process group so timeout cannot leave an orphaned
	// Python process holding files or submitting a late transaction.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return ChainProofCommandResponse{}, fmt.Errorf("chain proof command timed out after %s", timeout)
		}
		var resp ChainProofCommandResponse
		if jsonErr := json.Unmarshal(stdout.Bytes(), &resp); jsonErr == nil && resp.Err != "" {
			return resp, fmt.Errorf("chain proof command failed: %w: %s", err, resp.Err)
		}
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return ChainProofCommandResponse{}, fmt.Errorf("chain proof command failed: %w: %s", err, detail)
	}
	var resp ChainProofCommandResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return ChainProofCommandResponse{}, fmt.Errorf("chain proof command returned invalid json: %w: %s", err, stdout.String())
	}
	if !resp.OK {
		return resp, fmt.Errorf("chain proof command returned error: %s", resp.Err)
	}
	return resp, nil
}

func openStorageProofChallenge(chainCmd string, sector SectorMeta, round uint64, challengeCount int) (SectorChallenge, []string, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:         "open_challenge",
		Sector:         sector,
		Round:          round,
		ChallengeCount: challengeCount,
	})
	if err != nil {
		return SectorChallenge{}, nil, err
	}
	if resp.Round != 0 {
		round = resp.Round
	}
	challenge := SectorChallenge{
		SectorRoot:       sector.SectorRoot,
		Round:            round,
		ChallengeSeed:    resp.ChallengeSeed,
		ChallengeIndexes: resp.ChallengeIndexes,
		CreatedAt:        nowRFC3339(),
	}
	if len(challenge.ChallengeIndexes) == 0 {
		return SectorChallenge{}, nil, fmt.Errorf("chain did not return challenge indexes")
	}
	if challenge.ChallengeSeed == "" {
		return SectorChallenge{}, nil, fmt.Errorf("chain did not return challenge seed")
	}
	return challenge, resp.PublicInputs, nil
}

func submitStorageProofToChain(chainCmd string, sector SectorMeta, challenge SectorChallenge, proof ZKProofResult) error {
	if !proof.OK || proof.Proof == "" {
		return fmt.Errorf("invalid zk proof result")
	}
	_, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:    "submit_proof",
		Sector:    sector,
		Round:     challenge.Round,
		Challenge: challenge,
		Proof:     proof,
	})
	return err
}

func markSectorProofed(storage string, sector SectorMeta, round uint64) error {
	sector.LastProofRound = round
	sector.LastProofAt = time.Now().Format(time.RFC3339)
	sector.UpdatedAt = sector.LastProofAt
	return writeSector(storage, sector)
}

// ─── Partition chain protocol (new) ──────────────────────────────────────────

// openPartitionChallenge registers/updates all sectors in the partition on-chain,
// registers the partition itself, opens the partition challenge, and returns the
// PartitionChallenge plus the expected public inputs array for the ZK prover.
func openPartitionChallenge(chainCmd string, partition PartitionMeta, round uint64, challengeCount int) (PartitionChallenge, []string, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:         "open_partition_challenge",
		Partition:      partition,
		Round:          round,
		ChallengeCount: challengeCount,
	})
	if err != nil {
		return PartitionChallenge{}, nil, err
	}
	if resp.Round != 0 {
		round = resp.Round
	}
	if resp.ChallengeSeed == "" {
		return PartitionChallenge{}, nil, fmt.Errorf("chain did not return challenge seed for partition")
	}
	challenge := PartitionChallenge{
		PartitionKey:  resp.PartitionKey,
		Round:         round,
		ChallengeSeed: resp.ChallengeSeed,
		CreatedAt:     nowRFC3339(),
	}
	return challenge, resp.PublicInputs, nil
}

func registerPartitionOnChain(chainCmd string, partition PartitionMeta, challengeCount int) (string, error) {
	tx, _, err := registerPartitionVersionOnChain(chainCmd, partition, challengeCount)
	return tx, err
}

func registerPartitionVersionOnChain(chainCmd string, partition PartitionMeta, challengeCount int) (string, uint64, error) {
	if challengeCount <= 0 {
		return "", 0, fmt.Errorf("partition registration challenge count must be positive")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:         "register_partition",
		Partition:      partition,
		ChallengeCount: challengeCount,
	})
	if err != nil {
		return "", 0, err
	}
	if resp.ContentVersion == 0 {
		return "", 0, fmt.Errorf("partition registration did not return a content version")
	}
	return resp.RegisterTx, resp.ContentVersion, nil
}

// registerConfiguredPartitionOnChain is the only production entry point for publishing a
// live partition. Keeping the configured circuit challenge count here prevents callers from
// silently registering content under a different (or invalid zero) contract identity.
func registerConfiguredPartitionOnChain(cfg ServerConfig, partition PartitionMeta) (string, error) {
	if cfg.ChallengeCount <= 0 {
		return "", fmt.Errorf("partition registration challenge count must be positive")
	}
	return registerPartitionOnChain(cfg.ChainProofCmd, partition, cfg.ChallengeCount)
}

func deactivatePartitionOnChain(chainCmd string, deadlineIndex, partitionIndex int) (string, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:         "deactivate_partition",
		DeadlineIndex:  deadlineIndex,
		PartitionIndex: partitionIndex,
	})
	if err != nil {
		return "", err
	}
	return resp.RegisterTx, nil
}

func listActiveCapacityPartitionsOnChain(chainCmd string) ([]CapacityPartitionInfo, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "list_active_capacity_partitions",
	})
	if err != nil {
		return nil, err
	}
	return resp.CapacityPartitions, nil
}

func listActiveDataPartitionsOnChain(chainCmd string) ([]CapacityPartitionInfo, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "list_active_data_partitions",
	})
	if err != nil {
		return nil, err
	}
	return resp.DataPartitions, nil
}

func dataLifecycleGuardStatusOnChain(chainCmd string) (string, bool, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "data_lifecycle_guard_status",
	})
	if err != nil {
		return "", false, err
	}
	return resp.FileRegistration, resp.DataGuardRequired, nil
}

func partitionVersionStatusOnChain(chainCmd string, partition PartitionMeta) (PartitionVersionStatus, error) {
	return partitionVersionStatusAtBlockOnChain(chainCmd, partition, 0)
}

func partitionVersionStatusAtBlockOnChain(chainCmd string, partition PartitionMeta, blockNumber uint64) (PartitionVersionStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "partition_version_status", Partition: partition, BlockNumber: blockNumber,
	})
	if err != nil {
		return PartitionVersionStatus{}, err
	}
	return PartitionVersionStatus{
		PartitionKey:          resp.PartitionKey,
		PartitionKind:         partition.PartitionKind,
		DeadlineIndex:         partition.DeadlineIndex,
		PartitionIndex:        partition.PartitionIndex,
		ContentHash:           resp.ContentHash,
		ContentVersion:        resp.ContentVersion,
		LastProvenContentHash: resp.LastProvenContentHash,
		CurrentContentProven:  resp.CurrentContentProven,
		Active:                resp.PartitionActive,
		LastProofRound:        resp.LastProofRound,
		RegisteredAt:          resp.RegisteredAt,
		ChainTimestamp:        resp.ChainTimestamp,
		CurrentRound:          resp.CurrentRound,
		ProofPeriodSeconds:    resp.ProofPeriodSeconds,
		ChallengeCount:        uint16(resp.PartitionChallengeCount),
		BlockNumber:           resp.BlockNumber,
	}, nil
}

type CapacityIncrementalSelectionSnapshot struct {
	BlockNumber                 uint64
	CurrentCertificationSlot    uint64
	Entries                     []CapacitySelectionSnapshotEntry
	ActiveCapacityPartitionKeys []string
}

func capacityIncrementalSelectionSnapshotOnChain(
	chainCmd string, partitions []PartitionMeta, blockNumber uint64,
) (CapacityIncrementalSelectionSnapshot, error) {
	if blockNumber == 0 {
		return CapacityIncrementalSelectionSnapshot{}, fmt.Errorf("incremental selection snapshot requires a pinned block")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "capacity_incremental_selection_snapshot", Partitions: partitions,
		BlockNumber: blockNumber,
	})
	if err != nil {
		return CapacityIncrementalSelectionSnapshot{}, err
	}
	if resp.BlockNumber != blockNumber {
		return CapacityIncrementalSelectionSnapshot{}, fmt.Errorf(
			"incremental selection snapshot block mismatch: got %d want %d", resp.BlockNumber, blockNumber)
	}
	if resp.CurrentCertificationSlot == 0 {
		return CapacityIncrementalSelectionSnapshot{}, fmt.Errorf("incremental selection snapshot is missing certification slot")
	}
	return CapacityIncrementalSelectionSnapshot{
		BlockNumber: resp.BlockNumber, CurrentCertificationSlot: resp.CurrentCertificationSlot,
		Entries:                     append([]CapacitySelectionSnapshotEntry(nil), resp.CapacitySelectionEntries...),
		ActiveCapacityPartitionKeys: append([]string(nil), resp.ActiveCapacityPartitionKeys...),
	}, nil
}

// partitionProofHealthSnapshotOnChain reads every local partition status and
// the dispute contract's recurring-proof threshold from one pinned block. A
// failure returns no partial snapshot: partial evidence must never close VK
// admission or erase a valid prior health record.
func partitionProofHealthSnapshotOnChain(chainCmd string, partitions []PartitionMeta, blockNumber uint64) (PartitionProofHealthSnapshot, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "partition_health_snapshot", Partitions: partitions, BlockNumber: blockNumber,
	})
	if err != nil {
		return PartitionProofHealthSnapshot{}, err
	}
	return parsePartitionProofHealthSnapshot(resp, partitions, blockNumber)
}

func parsePartitionProofHealthSnapshot(resp ChainProofCommandResponse, partitions []PartitionMeta, blockNumber uint64) (PartitionProofHealthSnapshot, error) {
	if resp.BlockNumber == 0 {
		return PartitionProofHealthSnapshot{}, fmt.Errorf("partition health snapshot is missing block number")
	}
	if blockNumber != 0 && resp.BlockNumber != blockNumber {
		return PartitionProofHealthSnapshot{}, fmt.Errorf(
			"partition health snapshot block mismatch: got %d want %d", resp.BlockNumber, blockNumber,
		)
	}
	if resp.StalenessThreshold == 0 {
		return PartitionProofHealthSnapshot{}, fmt.Errorf("partition health snapshot returned zero staleness threshold")
	}
	if len(resp.PartitionStatuses) != len(partitions) {
		return PartitionProofHealthSnapshot{}, fmt.Errorf(
			"partition health snapshot returned %d statuses for %d partitions",
			len(resp.PartitionStatuses), len(partitions),
		)
	}
	for i := range partitions {
		status := &resp.PartitionStatuses[i]
		partition := partitions[i]
		if status.DeadlineIndex != partition.DeadlineIndex || status.PartitionIndex != partition.PartitionIndex ||
			status.PartitionKind != partition.PartitionKind {
			return PartitionProofHealthSnapshot{}, fmt.Errorf("partition health snapshot order/identity mismatch at index %d", i)
		}
		if status.BlockNumber != resp.BlockNumber {
			return PartitionProofHealthSnapshot{}, fmt.Errorf("partition health status block mismatch at index %d", i)
		}
	}
	return PartitionProofHealthSnapshot{
		BlockNumber: resp.BlockNumber, StalenessThreshold: resp.StalenessThreshold,
		Statuses: resp.PartitionStatuses,
	}, nil
}

// ── Deterministic challenge functions (new) ───────────────────────────────────

// getPartitionChallengeDeterministic fetches the deterministic challenge inputs
// via a pure view call (no on-chain tx). The contract derives the seed from the
// challenge anchor recorded at registration time.
func getPartitionChallengeDeterministic(chainCmd string, partition PartitionMeta, round uint64) (PartitionChallenge, []string, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:    "get_partition_challenge_deterministic",
		Partition: partition,
		Round:     round,
	})
	if err != nil {
		return PartitionChallenge{}, nil, err
	}
	if resp.Round != 0 {
		round = resp.Round
	}
	if resp.ChallengeSeed == "" {
		return PartitionChallenge{}, nil, fmt.Errorf("chain did not return deterministic challenge seed")
	}
	challenge := PartitionChallenge{
		PartitionKey:  resp.PartitionKey,
		Round:         round,
		ChallengeSeed: resp.ChallengeSeed,
		CreatedAt:     nowRFC3339(),
	}
	return challenge, resp.PublicInputs, nil
}

// submitPartitionProofDeterministic calls submitPartitionZkProofDeterministic —
// one tx, no prior openPartitionChallenge required.
func submitPartitionProofDeterministic(chainCmd string, partition PartitionMeta, challenge PartitionChallenge, proof ZKProofResult) (string, error) {
	if !proof.OK || proof.Proof == "" {
		return "", fmt.Errorf("invalid zk partition proof result")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:     "submit_partition_proof_deterministic",
		Partition:  partition,
		Round:      challenge.Round,
		PChallenge: challenge,
		Proof:      proof,
	})
	if err != nil {
		return "", err
	}
	return resp.SubmitTx, nil
}

// submitPartitionProofToChain submits a single batch ZK proof that covers all
// sectors in the partition.
func submitPartitionProofToChain(chainCmd string, partition PartitionMeta, challenge PartitionChallenge, proof ZKProofResult) (string, error) {
	if !proof.OK || proof.Proof == "" {
		return "", fmt.Errorf("invalid zk partition proof result")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:     "submit_partition_proof",
		Partition:  partition,
		Round:      challenge.Round,
		PChallenge: challenge,
		Proof:      proof,
	})
	if err != nil {
		return "", err
	}
	return resp.SubmitTx, nil
}

func frozenPartitionSnapshotStatusOnChain(chainCmd string, partition PartitionMeta) (FrozenPartitionSnapshotStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "frozen_partition_snapshot_status", Partition: partition,
	})
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, err
	}
	return FrozenPartitionSnapshotStatus{
		Exists: resp.SnapshotExists, PartitionKey: resp.PartitionKey,
		ProofEpochID:   resp.ProofEpochID,
		ContentVersion: resp.ContentVersion, ContentHash: resp.ContentHash,
		Round: resp.Round, AnchorBlock: resp.AnchorBlock,
		ChallengeSeed: resp.ChallengeSeed, Deadline: resp.SnapshotDeadline,
		Proven: resp.SnapshotProven, Current: resp.SnapshotCurrent,
		SnapshotNonce: resp.SnapshotNonce,
	}, nil
}

func freezePartitionSnapshotOnChain(chainCmd string, partition PartitionMeta, proofEpochID, round uint64) (FrozenPartitionSnapshotStatus, string, error) {
	status, tx, _, err := freezePartitionSnapshotOnChainWithNonce(chainCmd, partition, proofEpochID, round, 0, false, false)
	return status, tx, err
}

// freezePartitionSnapshotOnChainWithNonce forwards an explicitly-reserved Ethereum sender
// nonce (and the caller-holds-account-lock flag) to the subprocess and returns the exact
// sender nonce the subprocess used, so the Go caller can verify it equals what it journalled.
func freezePartitionSnapshotOnChainWithNonce(chainCmd string, partition PartitionMeta, proofEpochID, round, senderNonce uint64, hasNonce, callerHoldsLock bool) (FrozenPartitionSnapshotStatus, string, uint64, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "freeze_partition_snapshot", Partition: partition,
		ProofEpochID: proofEpochID, Round: round,
		SenderTxNonce: senderNonce, HasSenderTxNonce: hasNonce, CallerHoldsAccountLock: callerHoldsLock,
	})
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", 0, err
	}
	return FrozenPartitionSnapshotStatus{
		Exists: resp.SnapshotExists, PartitionKey: resp.PartitionKey,
		ProofEpochID:   resp.ProofEpochID,
		ContentVersion: resp.ContentVersion, ContentHash: resp.ContentHash,
		Round: resp.Round, AnchorBlock: resp.AnchorBlock,
		ChallengeSeed: resp.ChallengeSeed, Deadline: resp.SnapshotDeadline,
		Proven: resp.SnapshotProven, Current: resp.SnapshotCurrent,
		SnapshotNonce: resp.SnapshotNonce,
	}, resp.OpenTx, resp.SenderNonce, nil
}

func sealPartitionSnapshotOnChain(chainCmd string, partition PartitionMeta, contentVersion uint64) (FrozenPartitionSnapshotStatus, string, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "seal_partition_snapshot", Partition: partition, ContentVersion: contentVersion,
	})
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", err
	}
	return FrozenPartitionSnapshotStatus{
		Exists: resp.SnapshotExists, PartitionKey: resp.PartitionKey,
		ProofEpochID:   resp.ProofEpochID,
		ContentVersion: resp.ContentVersion, ContentHash: resp.ContentHash,
		Round: resp.Round, AnchorBlock: resp.AnchorBlock,
		ChallengeSeed: resp.ChallengeSeed, Deadline: resp.SnapshotDeadline,
		Proven: resp.SnapshotProven, Current: resp.SnapshotCurrent,
		SnapshotNonce: resp.SnapshotNonce,
	}, resp.OpenTx, nil
}

func reanchorFrozenPartitionSnapshotOnChain(
	chainCmd string,
	snapshot partitionProofSnapshot,
) (FrozenPartitionSnapshotStatus, string, error) {
	if snapshot.ContentVersion == 0 || snapshot.ProofEpochID == 0 || snapshot.Round == 0 ||
		snapshot.ChainContentHash == "" || snapshot.SnapshotNonce == 0 {
		return FrozenPartitionSnapshotStatus{}, "", fmt.Errorf("frozen snapshot identity is incomplete")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "reanchor_frozen_partition_snapshot", Partition: snapshot.Partition,
		ProofEpochID: snapshot.ProofEpochID, ContentVersion: snapshot.ContentVersion,
		Round:       snapshot.Round,
		ContentHash: snapshot.ChainContentHash, SnapshotNonce: snapshot.SnapshotNonce,
	})
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", err
	}
	return FrozenPartitionSnapshotStatus{
		Exists: resp.SnapshotExists, PartitionKey: resp.PartitionKey,
		ProofEpochID:   resp.ProofEpochID,
		ContentVersion: resp.ContentVersion, ContentHash: resp.ContentHash,
		Round: resp.Round, AnchorBlock: resp.AnchorBlock,
		ChallengeSeed: resp.ChallengeSeed, Deadline: resp.SnapshotDeadline,
		Proven: resp.SnapshotProven, Current: resp.SnapshotCurrent,
		SnapshotNonce: resp.SnapshotNonce,
	}, resp.OpenTx, nil
}

func frozenPartitionChallengeOnChain(chainCmd string, snapshot partitionProofSnapshot) (PartitionChallenge, []string, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "expected_frozen_partition_public_inputs", Partition: snapshot.Partition,
		ProofEpochID: snapshot.ProofEpochID, Round: snapshot.Round,
		ContentVersion: snapshot.ContentVersion,
	})
	if err != nil {
		return PartitionChallenge{}, nil, err
	}
	if resp.ContentVersion != 0 && resp.ContentVersion != snapshot.ContentVersion {
		return PartitionChallenge{}, nil, fmt.Errorf(
			"frozen challenge content version mismatch: got %d want %d", resp.ContentVersion, snapshot.ContentVersion,
		)
	}
	if resp.ProofEpochID != 0 && resp.ProofEpochID != snapshot.ProofEpochID {
		return PartitionChallenge{}, nil, fmt.Errorf(
			"frozen challenge epoch mismatch: got %d want %d", resp.ProofEpochID, snapshot.ProofEpochID,
		)
	}
	if resp.ChallengeSeed == "" || len(resp.PublicInputs) == 0 {
		return PartitionChallenge{}, nil, fmt.Errorf("frozen partition challenge is incomplete")
	}
	return PartitionChallenge{
		PartitionKey: resp.PartitionKey, Round: snapshot.Round,
		ChallengeSeed: resp.ChallengeSeed, CreatedAt: nowRFC3339(),
	}, resp.PublicInputs, nil
}

func submitFrozenPartitionProofOnChain(chainCmd string, snapshot partitionProofSnapshot, challenge PartitionChallenge, proof ZKProofResult) (string, error) {
	if snapshot.ContentVersion == 0 {
		return "", fmt.Errorf("frozen partition snapshot has no chain content version")
	}
	if snapshot.SnapshotNonce == 0 {
		return "", fmt.Errorf("frozen partition snapshot has no snapshot nonce")
	}
	if !proof.OK || proof.Proof == "" {
		return "", fmt.Errorf("invalid frozen partition proof result")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "submit_frozen_partition_zk_proof", Partition: snapshot.Partition,
		PartitionKey: challenge.PartitionKey, ProofEpochID: snapshot.ProofEpochID,
		Round:          snapshot.Round,
		ContentVersion: snapshot.ContentVersion,
		ContentHash:    snapshot.ChainContentHash, SnapshotNonce: snapshot.SnapshotNonce,
		PChallenge: challenge, Proof: proof,
	})
	if err != nil {
		return "", err
	}
	return resp.SubmitTx, nil
}

func abandonFrozenPartitionSnapshotOnChain(chainCmd string, snapshot partitionProofSnapshot) (string, error) {
	if snapshot.ContentVersion == 0 {
		return "", nil
	}
	if snapshot.SnapshotNonce == 0 {
		return "", fmt.Errorf("frozen partition snapshot has no snapshot nonce; refusing abandon")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "abandon_frozen_partition_snapshot", Partition: snapshot.Partition,
		ProofEpochID: snapshot.ProofEpochID, ContentVersion: snapshot.ContentVersion,
		ContentHash: snapshot.ChainContentHash, SnapshotNonce: snapshot.SnapshotNonce,
	})
	if err != nil {
		return "", err
	}
	return resp.RegisterTx, nil
}

func capacityProofStatusOnChain(chainCmd string) (CapacityProofEpochStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{Action: "capacity_proof_status"})
	if err != nil {
		return CapacityProofEpochStatus{}, err
	}
	if resp.DeclaredCapacityBytes == 0 {
		return CapacityProofEpochStatus{}, fmt.Errorf("capacity proof status has no declared capacity")
	}
	if resp.MaxProofAgeSeconds == 0 {
		return CapacityProofEpochStatus{}, fmt.Errorf("capacity proof status has no maximum proof age")
	}
	if resp.MaxManifestOverheadBytes == 0 {
		return CapacityProofEpochStatus{}, fmt.Errorf("capacity proof status has no manifest overhead bound")
	}
	return capacityProofStatusFromResponse(resp), nil
}

// capacityProofStatusFromResponse is the single lossless mapping for the CapacityProofSC
// ledger and durable full-baseline checkpoint. Incremental campaign status must preserve
// these fields exactly: it overlays campaign progress, not a replacement ledger.
func capacityProofStatusFromResponse(resp ChainProofCommandResponse) CapacityProofEpochStatus {
	return CapacityProofEpochStatus{
		ProofEpochID:             resp.ProofEpochID,
		TargetRound:              resp.Round,
		CutoffNonce:              resp.EpochCutoffNonce,
		ExpectedPartitions:       resp.EpochExpectedPartitions,
		ProvenPartitions:         resp.EpochProvenPartitions,
		ExpectedBytes:            resp.EpochExpectedBytes,
		Active:                   resp.EpochActive,
		Invalidated:              resp.EpochInvalidated,
		DeclaredCapacityBytes:    resp.DeclaredCapacityBytes,
		RegisteredFreeBytes:      resp.RegisteredFreeBytes,
		RegisteredDataBytes:      resp.RegisteredDataBytes,
		ProvedFreeBytes:          resp.ProvedFreeBytes,
		ProvedDataBytes:          resp.ProvedDataBytes,
		QuoteReservedBytes:       resp.QuoteReservedBytes,
		AllocatedStoredBytes:     resp.AllocatedStoredBytes,
		ConservativeFreeBytes:    resp.ConservativeFreeBytes,
		LastCapacityProofAt:      resp.LastCapacityProofAt,
		ProofFresh:               resp.CapacityProofFresh,
		CapacityProofSequence:    resp.CapacityProofSequence,
		ProvedBackingBytes:       resp.ProvedBackingBytes,
		CheckpointFreeBytes:      resp.CheckpointFreeBytes,
		CheckpointDataBytes:      resp.CheckpointDataBytes,
		CheckpointProofRound:     resp.CheckpointProofRound,
		CheckpointProofAt:        resp.CheckpointProofAt,
		MaxProofAgeSeconds:       resp.MaxProofAgeSeconds,
		MaxManifestOverheadBytes: resp.MaxManifestOverheadBytes,
	}
}

type capacityEpochExclusionStatus struct {
	Excluded       bool
	ContentVersion uint64
	ContentHash    string
	ExcludedBytes  uint64
}

func capacityEpochExclusionStatusOnChain(
	chainCmd string, epochID uint64, member capacityEpochMemberRef,
) (capacityEpochExclusionStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "capacity_epoch_exclusion_status", ProofEpochID: epochID,
		Partition: PartitionMeta{
			PartitionKind: member.PartitionKind, DeadlineIndex: member.DeadlineIndex,
			PartitionIndex: member.PartitionIndex,
		},
	})
	if err != nil {
		return capacityEpochExclusionStatus{}, err
	}
	return capacityEpochExclusionStatus{
		Excluded: resp.EpochVersionExcluded, ContentVersion: resp.ContentVersion,
		ContentHash: resp.ContentHash, ExcludedBytes: resp.ExcludedBytes,
	}, nil
}

func beginCapacityProofEpochOnChain(chainCmd string, epochID, round uint64, batchMode uint8) (string, error) {
	if epochID == 0 || round == 0 {
		return "", fmt.Errorf("capacity proof epoch and round must be positive")
	}
	if batchMode <= 1 || batchMode > 7 {
		return "", fmt.Errorf("capacity full-sweep mode %d is invalid", batchMode)
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "begin_capacity_proof_epoch", ProofEpochID: epochID, Round: round,
		BatchMode: batchMode,
	})
	if err != nil {
		return "", err
	}
	if resp.ProofEpochID != 0 && resp.ProofEpochID != epochID {
		return "", fmt.Errorf("capacity proof epoch response mismatch: got %d want %d", resp.ProofEpochID, epochID)
	}
	return resp.OpenTx, nil
}

type CapacityIncrementalBatchStatus struct {
	BatchID, TargetRound, CutoffNonce      uint64
	SelectedPartitions, AcceptedPartitions uint32
	SelectedBytes, AcceptedBytes           uint64
	Active, Completed                      bool
}

func openCapacityIncrementalBatchOnChain(
	chainCmd string, round uint64, partitionKeys []string,
) (CapacityIncrementalBatchStatus, string, error) {
	if round == 0 || len(partitionKeys) == 0 {
		return CapacityIncrementalBatchStatus{}, "", fmt.Errorf("incremental batch needs a round and exact membership")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "open_capacity_incremental_batch", Round: round,
		PartitionKeys: append([]string(nil), partitionKeys...), BatchMode: 1,
	})
	if err != nil {
		return CapacityIncrementalBatchStatus{}, "", err
	}
	status := CapacityIncrementalBatchStatus{
		BatchID: resp.IncrementalBatchID, TargetRound: resp.Round,
		SelectedPartitions: resp.IncrementalSelected,
		AcceptedPartitions: resp.IncrementalAccepted,
		SelectedBytes:      resp.IncrementalSelectedBytes,
		AcceptedBytes:      resp.IncrementalAcceptedBytes,
		Active:             resp.IncrementalBatchActive, Completed: resp.IncrementalBatchComplete,
	}
	if status.BatchID == 0 || !status.Active || status.TargetRound != round ||
		status.SelectedPartitions != uint32(len(partitionKeys)) {
		return CapacityIncrementalBatchStatus{}, "", fmt.Errorf("incremental batch response does not match the exact requested plan")
	}
	return status, resp.OpenTx, nil
}

const incrementalCapacityAuthorityFlag uint64 = uint64(1) << 62

func capacityIncrementalBatchStatusOnChain(
	chainCmd string, batchID uint64,
) (CapacityIncrementalBatchStatus, CapacityProofEpochStatus, error) {
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "capacity_incremental_batch_status", ProofEpochID: batchID,
	})
	if err != nil {
		return CapacityIncrementalBatchStatus{}, CapacityProofEpochStatus{}, err
	}
	batch := CapacityIncrementalBatchStatus{
		BatchID: resp.IncrementalBatchID, TargetRound: resp.Round,
		SelectedPartitions: resp.IncrementalSelected,
		AcceptedPartitions: resp.IncrementalAccepted,
		SelectedBytes:      resp.IncrementalSelectedBytes,
		AcceptedBytes:      resp.IncrementalAcceptedBytes,
		Active:             resp.IncrementalBatchActive, Completed: resp.IncrementalBatchComplete,
	}
	ledger := capacityProofStatusFromResponse(resp)
	return batch, ledger, nil
}

// capacityCampaignStatusOnChain returns the one active campaign, preferring the contract's
// exact incremental campaign when present. Ledger/admission fields remain owned by
// CapacityProofSC and are copied without alteration.
func capacityCampaignStatusOnChain(chainCmd string) (CapacityProofEpochStatus, error) {
	full, err := capacityProofStatusOnChain(chainCmd)
	if err != nil {
		return CapacityProofEpochStatus{}, err
	}
	batch, ledger, err := capacityIncrementalBatchStatusOnChain(chainCmd, 0)
	if err != nil {
		return CapacityProofEpochStatus{}, err
	}
	if !batch.Active {
		return full, nil
	}
	ledger.ProofEpochID = batch.BatchID
	ledger.TargetRound = batch.TargetRound
	ledger.CutoffNonce = batch.CutoffNonce
	ledger.ExpectedPartitions = batch.SelectedPartitions
	ledger.ProvenPartitions = batch.AcceptedPartitions
	ledger.ExpectedBytes = batch.SelectedBytes
	ledger.Active = true
	return ledger, nil
}

func capacityCampaignStatusForStorage(
	storage, chainCmd string,
) (CapacityProofEpochStatus, error) {
	status, err := capacityCampaignStatusOnChain(chainCmd)
	if err != nil {
		return status, err
	}
	if status.Active {
		if status.ProofEpochID&incrementalCapacityAuthorityFlag != 0 {
			if cleanupErr := retireSupersededTerminalCapacityEpochJournal(
				storage, status.ProofEpochID,
			); cleanupErr != nil {
				return status, cleanupErr
			}
			if bindErr := reconcileOpenedCapacityBatchChunk(
				storage, chainCmd, status.ProofEpochID,
			); bindErr != nil {
				return status, bindErr
			}
		}
		return status, nil
	}
	journal, found, journalErr := readCapacityEpochJournal(storage)
	if journalErr != nil || !found || journal.EpochID&incrementalCapacityAuthorityFlag == 0 {
		return status, journalErr
	}
	batch, ledger, batchErr := capacityIncrementalBatchStatusOnChain(chainCmd, journal.EpochID)
	if batchErr != nil {
		return CapacityProofEpochStatus{}, batchErr
	}
	if batch.BatchID != journal.EpochID {
		return status, nil
	}
	ledger.ProofEpochID = batch.BatchID
	ledger.TargetRound = batch.TargetRound
	ledger.ExpectedPartitions = batch.SelectedPartitions
	ledger.ProvenPartitions = batch.AcceptedPartitions
	ledger.ExpectedBytes = batch.SelectedBytes
	ledger.Active = batch.Active
	if batch.Completed {
		plan, ok, planErr := readCapacityBatchChunkPlan(storage)
		if planErr != nil {
			return CapacityProofEpochStatus{}, planErr
		}
		if ok {
			for _, chunk := range plan.Chunks {
				if chunk.BatchID == batch.BatchID && !chunk.Done {
					if doneErr := markCapacityBatchChunkDone(storage, chunk.Index); doneErr != nil {
						return CapacityProofEpochStatus{}, doneErr
					}
					break
				}
			}
			updated, stillPresent, readErr := readCapacityBatchChunkPlan(storage)
			if readErr != nil {
				return CapacityProofEpochStatus{}, readErr
			}
			if stillPresent && updated.complete() {
				successors, closeErr := closeCapacityBatchChunkPlan(storage)
				if closeErr != nil {
					return CapacityProofEpochStatus{}, closeErr
				}
				if len(successors) > 0 {
					log.Printf("[capacity-batch] completed plan retained %d successor candidate(s) in the mutation journal", len(successors))
				}
			}
		}
	}
	return ledger, nil
}

// capacityIncrementalBatchMembersOnChain reads the CHAIN-AUTHORITATIVE selected-member set of an
// incremental batch (the contract's selectedMemberKeys / selectedMember). This is the enumeration
// source recovery uses when the local journal AND chunk plan were destroyed by a restart that
// landed while the members were being deleted (Run-18 VK2). Chain is the authority: an active
// on-chain batch always has an enumerable member set, so recovery always has a terminal path.
func capacityIncrementalBatchMembersOnChain(chainCmd string, batchID uint64) ([]IncrementalBatchMember, error) {
	if batchID == 0 {
		return nil, fmt.Errorf("incremental batch member read requires a batch authority id")
	}
	if batchID&incrementalCapacityAuthorityFlag == 0 {
		return nil, fmt.Errorf(
			"authority domain mismatch: %d is not an incremental batch id", batchID)
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "capacity_incremental_batch_members", ProofEpochID: batchID,
	})
	if err != nil {
		return nil, err
	}
	return resp.IncrementalBatchMembers, nil
}

// abandonIncrementalBatchOnChain is the AUTHORISED recovery for a stuck incremental batch:
//
//	VK -> PartitionSnapshotProofSC.abandonIncrementalBatch(reason)
//	   -> CapacityIncrementalBatchSC.abandonBatch(vk, reason)   [onlySnapshotProof]
//
// CapacityIncrementalBatchSC.abandonBatch is never called directly, and `onlySnapshotProof`
// is untouched. This must NEVER be replaced by abortCapacityProofEpochOnChain: that primitive
// belongs to the FULL proof-epoch authority (CapacityProofSC) and silently does nothing for an
// incremental batch, which is exactly how the 2026-08-13 live attempt failed.
func abandonIncrementalBatchOnChain(chainCmd string, proofEpochID uint64, reason uint8) (string, error) {
	if proofEpochID == 0 {
		return "", fmt.Errorf("abandon incremental batch requires a batch authority id")
	}
	if proofEpochID&incrementalCapacityAuthorityFlag == 0 {
		return "", fmt.Errorf(
			"authority domain mismatch: %d is not an incremental batch id; "+
				"the full proof-epoch authority must not be abandoned through this path", proofEpochID)
	}
	if proofEpochID&standaloneDeletionProofFlag != 0 {
		return "", fmt.Errorf("standalone deletion proof ids are not incremental batches")
	}
	if reason < 1 || reason > 4 {
		return "", fmt.Errorf("abandon reason must be 1..4, got %d", reason)
	}
	if chainCmd == "" {
		return "", fmt.Errorf("chain command is required to abandon an incremental batch")
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "abandon_incremental_batch", ProofEpochID: proofEpochID, AbandonReason: reason,
	})
	if err != nil {
		return "", err
	}
	return resp.RegisterTx, nil
}

func abortCapacityProofEpochOnChain(chainCmd string, epochID uint64) (string, error) {
	if epochID == 0 {
		return "", nil
	}
	resp, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action: "abort_capacity_proof_epoch", ProofEpochID: epochID,
	})
	if err != nil {
		return "", err
	}
	return resp.RegisterTx, nil
}

func declareCapacityOnChain(chainCmd string, totalCapacityBytes int64) bool {
	if chainCmd == "" || totalCapacityBytes <= 0 {
		return false
	}
	_, err := runChainProofCommand(chainCmd, ChainProofCommandRequest{
		Action:             "declare_capacity",
		TotalCapacityBytes: totalCapacityBytes,
	})
	if err != nil {
		log.Printf("[capacity] declare on-chain failed: %v", err)
		return false
	} else {
		log.Printf("[capacity] declared %.1f MB on-chain", float64(totalCapacityBytes)/1e6)
	}
	return true
}
