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

const capacityEpochJournalVersion = 1

const (
	capacityEpochStatePrepared  = "prepared"
	capacityEpochStateOpening   = "opening"
	capacityEpochStateActive    = "active"
	capacityEpochStateCompleted = "completed"
	capacityEpochStateAborted   = "aborted"
	capacityEpochStateAbandoned = "abandoned"
)

// capacityEpochMemberRef deliberately references, rather than duplicates, an
// immutable partitionProofSnapshot. The snapshot queue remains the owner of
// partition metadata, pinned piece bytes, challenges, proofs, and successors.
type capacityEpochMemberRef struct {
	PartitionKind  string `json:"partitionKind"`
	DeadlineIndex  int    `json:"deadlineIndex"`
	PartitionIndex int    `json:"partitionIndex"`
	SnapshotID     string `json:"snapshotId"`
	// ContentVersion + ContentHash are the epoch member's PINNED exclusion identity
	// (A.3.5): exclusion belongs to the capacity epoch's partition-version account, so the
	// on-chain contentVersion at the epoch cutoff is part of the identity — NOT the
	// frozen-slot's snapshotNonce or the local Generation, which identify a slot incarnation.
	ContentVersion uint64 `json:"contentVersion,omitempty"`
	ContentHash    string `json:"contentHash"`
	CommittedBytes int64  `json:"committedBytes"`
}

type capacityEpochExclusionRef struct {
	SnapshotID     string `json:"snapshotId"`
	PartitionKind  string `json:"partitionKind"`
	DeadlineIndex  int    `json:"deadlineIndex"`
	PartitionIndex int    `json:"partitionIndex"`
	ContentVersion uint64 `json:"contentVersion"`
	ContentHash    string `json:"contentHash"`
	ExcludedBytes  uint64 `json:"excludedBytes"`
	// Classification (A.3.5) records how the chain exclusion matched the member's pinned
	// identity: "exact" (same epoch/partition/version/hash) or "superseded" (the partition
	// advanced to a newer successor version). Persisted so restart preserves the resolved
	// classification even if the chain is momentarily unreachable.
	Classification string `json:"classification,omitempty"`
}

const (
	exclusionClassExact      = "exact"
	exclusionClassSuperseded = "superseded"
)

// capacityEpochJournal is the authoritative local recovery record for one
// capacity-proof cutoff. Contract state remains authoritative for exclusion and
// completion; snapshot queues remain authoritative for the immutable witnesses.
type capacityEpochJournal struct {
	Version                int                      `json:"version"`
	EpochID                uint64                   `json:"epochId"`
	TargetRound            uint64                   `json:"targetRound"`
	State                  string                   `json:"state"`
	ManifestFingerprint    string                   `json:"manifestFingerprint"`
	Members                []capacityEpochMemberRef `json:"members"`
	MutationCutoffSequence uint64                   `json:"mutationCutoffSequence,omitempty"`
	AdoptedLegacy          bool                     `json:"adoptedLegacy,omitempty"`
	ProvenAtAdoption       uint32                   `json:"provenAtAdoption,omitempty"`
	// FullSweepMode/Reason are durable because a prepared full opening may be resumed after a
	// crash. Legacy journals without them are initial mode (2).
	FullSweepMode   uint8  `json:"fullSweepMode,omitempty"`
	FullSweepReason string `json:"fullSweepReason,omitempty"`
	// FullBaselineCandidate is the chain/deployment/VK/layout-bound target captured before
	// a full epoch opens. Only authoritative successful full completion may commit it.
	FullBaselineCandidate *fullCapacityBaselineCandidate `json:"fullBaselineCandidate,omitempty"`

	// B.3.1 open-attempt identity. Written durably BEFORE the epoch-opening chain call and
	// while the coordination lock is held, so the lock can be released for the RPC without
	// letting another process open or submit a conflicting epoch operation.
	OpenAttemptID    string `json:"openAttemptId,omitempty"`
	OpenAttemptOwner string `json:"openAttemptOwner,omitempty"`
	OpenAttemptAt    string `json:"openAttemptAt,omitempty"`

	CutoffNonce uint64 `json:"cutoffNonce,omitempty"`

	// TWO BASELINES, DELIBERATELY SEPARATE. Run 12 wedged two vault keepers for good
	// because one pair of fields carried both meanings and a subtraction mixed them.
	//
	// LOCAL SNAPSHOT — what THIS vault keeper's member list held when the epoch was
	// prepared. Measured locally, from committed bytes on disk.
	LocalSnapshotPartitions uint32 `json:"localSnapshotPartitions"`
	LocalSnapshotBytes      uint64 `json:"localSnapshotBytes"`
	// CHAIN CUTOFF — the contract's OWN totals for this epoch at its cutoff nonce
	// (CapacityProofSC seeds expectedPartitions=activePartitionCount and
	// expectedBytes=registeredTotal). Authoritative for what the epoch must prove.
	ChainCutoffExpectedPartitions uint32 `json:"chainCutoffExpectedPartitions"`
	ChainCutoffExpectedBytes      uint64 `json:"chainCutoffExpectedBytes"`
	// ChainCutoffAdopted records that the chain baseline above came from an authoritative
	// chain read. Until it is true the chain baseline is UNKNOWN and must not be used in
	// any comparison — fail closed rather than guess a provenance.
	ChainCutoffAdopted bool `json:"chainCutoffAdopted"`

	// Legacy ambiguous fields, retained ONLY so existing journals can be migrated with
	// deterministic provenance (see migrateCapacityEpochJournalBaselines). Never written
	// by new code and never used in a comparison.
	LegacyInitialExpectedPartitions uint32 `json:"initialExpectedPartitions,omitempty"`
	LegacyInitialExpectedBytes      uint64 `json:"initialExpectedBytes,omitempty"`

	// RegistrationLagBytes is how far the LOCAL member snapshot runs ahead of the chain
	// cutoff total. Under sustained upload a StoreV3 can complete locally before its
	// registration lands at the cutoff, so this is a NORMAL observable condition — never
	// an exclusion, never a failure. Recording it is what stops it being mistaken for one.
	RegistrationLagBytes uint64 `json:"registrationLagBytes,omitempty"`

	ExpectedPartitions uint32                      `json:"expectedPartitions"`
	ProvenPartitions   uint32                      `json:"provenPartitions"`
	ExpectedBytes      uint64                      `json:"expectedBytes"`
	ExcludedPartitions uint32                      `json:"excludedPartitions,omitempty"`
	ExcludedBytes      uint64                      `json:"excludedBytes,omitempty"`
	ExcludedMembers    []capacityEpochExclusionRef `json:"excludedMembers,omitempty"`
	// CutoffUnresolvableSinceUnix is the first moment the immutable cutoff could not be
	// resolved locally. It is durable so the recovery grace survives a daemon restart and so a
	// wedged epoch cannot be terminated on the strength of one transient scan.
	CutoffUnresolvableSinceUnix int64 `json:"cutoffUnresolvableSinceUnix,omitempty"`

	DeclaredCapacityBytes uint64 `json:"declaredCapacityBytes"`
	RegisteredFreeBytes   uint64 `json:"registeredFreeBytes"`
	RegisteredDataBytes   uint64 `json:"registeredDataBytes"`
	ProvedFreeBytes       uint64 `json:"provedFreeBytes"`
	ProvedDataBytes       uint64 `json:"provedDataBytes"`
	QuoteReservedBytes    uint64 `json:"quoteReservedBytes"`
	AllocatedStoredBytes  uint64 `json:"allocatedStoredBytes"`

	BeginTx   string `json:"beginTx,omitempty"`
	LastError string `json:"lastError,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func capacityEpochJournalPath(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "capacity-epoch-journal.json")
}

func capacityEpochJournalLockPath(storage string) string {
	return capacityEpochJournalPath(storage) + ".lock"
}

func withCapacityEpochJournalLock(storage string, fn func() error) error {
	path := capacityEpochJournalLockPath(storage)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
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

func readCapacityEpochJournalUnlocked(storage string) (capacityEpochJournal, bool, error) {
	var journal capacityEpochJournal
	payload, err := os.ReadFile(capacityEpochJournalPath(storage))
	if os.IsNotExist(err) {
		return journal, false, nil
	}
	if err != nil {
		return journal, false, err
	}
	if err := json.Unmarshal(payload, &journal); err != nil {
		return journal, true, fmt.Errorf("decode capacity epoch journal: %w", err)
	}
	if err := migrateCapacityEpochJournalBaselines(&journal); err != nil {
		return journal, true, err
	}
	if err := validateCapacityEpochJournal(journal); err != nil {
		return journal, true, err
	}
	return journal, true, nil
}

// migrateCapacityEpochJournalBaselines upgrades a journal written before the local and chain
// baselines were separated.
//
// Provenance is DETERMINABLE, not guessed: the two historical writers are distinguishable by
// AdoptedLegacy. The prepare path seeded InitialExpected* from the LOCAL member snapshot and
// left AdoptedLegacy false; the legacy-adoption path seeded them from CHAIN status and set
// AdoptedLegacy true. Anything that does not match either shape fails closed rather than
// having a baseline invented for it — mixing these two meanings is exactly what wedged Run 12.
func migrateCapacityEpochJournalBaselines(journal *capacityEpochJournal) error {
	if journal == nil {
		return nil
	}
	if journal.LocalSnapshotPartitions != 0 || journal.LocalSnapshotBytes != 0 ||
		journal.ChainCutoffAdopted {
		return nil // already in the separated schema
	}
	if journal.LegacyInitialExpectedPartitions == 0 && journal.LegacyInitialExpectedBytes == 0 {
		if len(journal.Members) == 0 {
			return nil // nothing to migrate
		}
		return fmt.Errorf(
			"capacity epoch journal %d has members but no baseline provenance; refusing to guess",
			journal.EpochID)
	}
	var memberBytes uint64
	for _, member := range journal.Members {
		if member.CommittedBytes < 0 {
			return fmt.Errorf("capacity epoch journal %d member has negative bytes", journal.EpochID)
		}
		memberBytes += uint64(member.CommittedBytes)
	}
	if journal.AdoptedLegacy {
		// Chain-seeded. The legacy values are the CHAIN cutoff baseline; the LOCAL snapshot
		// is measured from the member list, which is its definition.
		journal.ChainCutoffExpectedPartitions = journal.LegacyInitialExpectedPartitions
		journal.ChainCutoffExpectedBytes = journal.LegacyInitialExpectedBytes
		journal.ChainCutoffAdopted = true
		journal.LocalSnapshotPartitions = uint32(len(journal.Members))
		journal.LocalSnapshotBytes = memberBytes
	} else {
		// Local-seeded. The legacy values must equal the member snapshot, which is how the
		// prepare path constructed them; if they do not, provenance is not established.
		if int(journal.LegacyInitialExpectedPartitions) != len(journal.Members) ||
			journal.LegacyInitialExpectedBytes != memberBytes {
			return fmt.Errorf(
				"capacity epoch journal %d baseline provenance is ambiguous: legacy totals "+
					"(%d/%d) match neither the member snapshot (%d/%d) nor a chain adoption",
				journal.EpochID, journal.LegacyInitialExpectedPartitions,
				journal.LegacyInitialExpectedBytes, len(journal.Members), memberBytes)
		}
		journal.LocalSnapshotPartitions = journal.LegacyInitialExpectedPartitions
		journal.LocalSnapshotBytes = journal.LegacyInitialExpectedBytes
		// The chain baseline was never recorded separately. Leave it UNADOPTED so the next
		// authoritative chain read supplies it; comparisons against it are skipped until then.
		journal.ChainCutoffAdopted = false
	}
	// Any exclusion totals carried by an old journal were derived by the discredited
	// local-minus-chain subtraction. Drop them; they are re-derived from chain records.
	journal.ExcludedPartitions = 0
	journal.ExcludedBytes = 0
	journal.ExcludedMembers = nil
	journal.LegacyInitialExpectedPartitions = 0
	journal.LegacyInitialExpectedBytes = 0
	return nil
}

func readCapacityEpochJournal(storage string) (journal capacityEpochJournal, found bool, err error) {
	err = withCapacityEpochJournalLock(storage, func() error {
		journal, found, err = readCapacityEpochJournalUnlocked(storage)
		return err
	})
	return journal, found, err
}

func writeCapacityEpochJournalUnlocked(storage string, journal capacityEpochJournal) error {
	if journal.Version == 0 {
		journal.Version = capacityEpochJournalVersion
	}
	if journal.CreatedAt == "" {
		journal.CreatedAt = nowRFC3339()
	}
	journal.UpdatedAt = nowRFC3339()
	if err := validateCapacityEpochJournal(journal); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(capacityEpochJournalPath(storage), payload, 0600)
}

func writeCapacityEpochJournal(storage string, journal capacityEpochJournal) error {
	return withCapacityEpochJournalLock(storage, func() error {
		return writeCapacityEpochJournalUnlocked(storage, journal)
	})
}

func createCapacityEpochJournal(storage string, journal capacityEpochJournal) error {
	return withCapacityEpochJournalLock(storage, func() error {
		existing, found, err := readCapacityEpochJournalUnlocked(storage)
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("capacity epoch journal %d state=%s is still retained",
				existing.EpochID, existing.State)
		}
		return writeCapacityEpochJournalUnlocked(storage, journal)
	})
}

func updateCapacityEpochJournal(
	storage string,
	epochID uint64,
	update func(*capacityEpochJournal) error,
) error {
	return withCapacityEpochJournalLock(storage, func() error {
		journal, found, err := readCapacityEpochJournalUnlocked(storage)
		if err != nil {
			return err
		}
		if !found || journal.EpochID != epochID {
			return fmt.Errorf("capacity epoch journal %d is unavailable", epochID)
		}
		if err := update(&journal); err != nil {
			return err
		}
		return writeCapacityEpochJournalUnlocked(storage, journal)
	})
}

// discardUnopenableCapacityEpochJournal removes a PREPARED journal whose epoch id can
// never be accepted on chain.
//
// It refuses unless the journal is still the one named, is still prepared, and its id is
// genuinely out of the full-epoch domain — so it can never delete work that merely has not
// been opened yet. Such an epoch has no on-chain existence, so nothing is lost; what is
// gained is that a keeper stops being blocked from every future campaign by one record it
// could neither open nor retire.
func discardUnopenableCapacityEpochJournal(storage string, epochID uint64) error {
	if epochID&capacityAuthorityDomainMask == 0 {
		return fmt.Errorf("capacity epoch %d is inside the full-epoch domain; refusing to discard", epochID)
	}
	return withCapacityCoordinationLock(storage, func() error {
		journal, found, err := readCapacityEpochJournalUnlocked(storage)
		if err != nil {
			return err
		}
		if !found || journal.EpochID != epochID {
			return nil // already gone or replaced: nothing to do
		}
		if journal.State != capacityEpochStatePrepared {
			return fmt.Errorf("capacity epoch %d is in state %s, not prepared; refusing to discard",
				epochID, journal.State)
		}
		return removeCapacityEpochJournalUnlocked(storage)
	})
}

func removeCapacityEpochJournalUnlocked(storage string) error {
	path := capacityEpochJournalPath(storage)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validateCapacityEpochJournal(journal capacityEpochJournal) error {
	if journal.Version != capacityEpochJournalVersion || journal.EpochID == 0 || journal.TargetRound == 0 {
		return fmt.Errorf("capacity epoch journal identity/version is invalid")
	}
	switch journal.State {
	case capacityEpochStatePrepared, capacityEpochStateOpening, capacityEpochStateActive,
		capacityEpochStateCompleted, capacityEpochStateAborted, capacityEpochStateAbandoned:
	default:
		return fmt.Errorf("capacity epoch journal state %q is invalid", journal.State)
	}
	if !journal.AdoptedLegacy && len(journal.Members) == 0 {
		return fmt.Errorf("capacity epoch journal has no immutable members")
	}
	seen := make(map[string]bool, len(journal.Members))
	var memberBytes uint64
	for _, member := range journal.Members {
		if member.PartitionKind != PartitionKindCapacity && member.PartitionKind != PartitionKindData {
			return fmt.Errorf("capacity epoch journal member has invalid kind %q", member.PartitionKind)
		}
		if strings.TrimSpace(member.SnapshotID) == "" || strings.TrimSpace(member.ContentHash) == "" || member.CommittedBytes <= 0 {
			return fmt.Errorf("capacity epoch journal member %s dl%d-pt%d is incomplete",
				member.PartitionKind, member.DeadlineIndex, member.PartitionIndex)
		}
		key := epochPartitionKey(member.PartitionKind, member.DeadlineIndex, member.PartitionIndex)
		if seen[key] {
			return fmt.Errorf("capacity epoch journal contains duplicate member %s", key)
		}
		seen[key] = true
		amount := uint64(member.CommittedBytes)
		if memberBytes > ^uint64(0)-amount {
			return fmt.Errorf("capacity epoch journal member bytes overflow")
		}
		memberBytes += amount
	}
	// The LOCAL snapshot must match the immutable member list — that is its definition, and
	// it holds for every journal regardless of how the chain baseline was obtained. The old
	// assertion applied this to the ambiguous InitialExpected* fields, which a chain-seeded
	// (legacy-adopted) journal could never satisfy, so the two writers contradicted one
	// another on the same field.
	if int(journal.LocalSnapshotPartitions) != len(journal.Members) ||
		journal.LocalSnapshotBytes != memberBytes {
		return fmt.Errorf("capacity epoch journal local snapshot totals do not match immutable members")
	}
	// Chain progress is validated against the CHAIN baseline only. Comparing chain progress
	// against the local snapshot is a mixed-authority comparison: local may legitimately be
	// ahead (registration lag) or, after exclusions, the chain may be below it for a
	// different reason entirely.
	if journal.ChainCutoffAdopted {
		if journal.ExpectedPartitions > journal.ChainCutoffExpectedPartitions ||
			journal.ExpectedBytes > journal.ChainCutoffExpectedBytes {
			return fmt.Errorf("capacity epoch journal chain progress exceeds its chain cutoff baseline")
		}
	}
	if journal.ProvenPartitions > journal.ExpectedPartitions {
		return fmt.Errorf("capacity epoch journal chain progress is invalid")
	}
	memberBySnapshot := make(map[string]capacityEpochMemberRef, len(journal.Members))
	for _, member := range journal.Members {
		memberBySnapshot[member.SnapshotID] = member
	}
	seenExclusions := make(map[string]bool, len(journal.ExcludedMembers))
	var excludedBytes uint64
	for _, exclusion := range journal.ExcludedMembers {
		member, exists := memberBySnapshot[exclusion.SnapshotID]
		// A.3.5: an exclusion references its member by (partition + snapshot) and pins
		// contentVersion+contentHash. A "superseded" exclusion legitimately carries a NEWER
		// version than the member's pinned version (and therefore a different hash); an "exact"
		// exclusion must carry the same version AND the same hash. A version older than the
		// pinned member, or a same-version hash mismatch, is invalid.
		invalid := !exists || seenExclusions[exclusion.SnapshotID] || exclusion.ContentVersion == 0 ||
			exclusion.PartitionKind != member.PartitionKind ||
			exclusion.DeadlineIndex != member.DeadlineIndex ||
			exclusion.PartitionIndex != member.PartitionIndex ||
			exclusion.ContentVersion < member.ContentVersion ||
			(exclusion.ContentVersion == member.ContentVersion && !sameRoot(exclusion.ContentHash, member.ContentHash))
		if invalid {
			return fmt.Errorf("capacity epoch journal exclusion identity is invalid")
		}
		seenExclusions[exclusion.SnapshotID] = true
		if excludedBytes > ^uint64(0)-exclusion.ExcludedBytes {
			return fmt.Errorf("capacity epoch journal exclusion bytes overflow")
		}
		excludedBytes += exclusion.ExcludedBytes
	}
	if uint32(len(journal.ExcludedMembers)) > journal.ExcludedPartitions ||
		excludedBytes > journal.ExcludedBytes {
		return fmt.Errorf("capacity epoch journal exclusions exceed chain totals")
	}
	return nil
}

func capacityEpochMembersFromQueues(
	storage string,
	epochID uint64,
	partitions []PartitionMeta,
) ([]capacityEpochMemberRef, error) {
	members := make([]capacityEpochMemberRef, 0, len(partitions))
	for _, partition := range partitions {
		queue, found, err := readPartitionProofSnapshotQueue(
			storage, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
		)
		if err != nil {
			return nil, err
		}
		if !found || queue.Frozen == nil || queue.Frozen.ProofEpochID != epochID ||
			!samePartitionSnapshotContent(queue.Frozen, partition) {
			return nil, fmt.Errorf("capacity epoch member %s dl%d-pt%d has no exact frozen snapshot reference",
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)
		}
		members = append(members, capacityEpochMemberRef{
			PartitionKind: partition.PartitionKind, DeadlineIndex: partition.DeadlineIndex,
			PartitionIndex: partition.PartitionIndex, SnapshotID: queue.Frozen.ID,
			ContentVersion: queue.Frozen.ContentVersion,
			ContentHash:    queue.Frozen.ContentHash, CommittedBytes: partition.CommittedBytes,
		})
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].PartitionKind != members[j].PartitionKind {
			return members[i].PartitionKind < members[j].PartitionKind
		}
		if members[i].DeadlineIndex != members[j].DeadlineIndex {
			return members[i].DeadlineIndex < members[j].DeadlineIndex
		}
		return members[i].PartitionIndex < members[j].PartitionIndex
	})
	return members, nil
}

func newCapacityEpochJournal(
	storage string,
	epochID, round uint64,
	status CapacityProofEpochStatus,
	partitions []PartitionMeta,
) (capacityEpochJournal, error) {
	fingerprint, partitionCount, err := capacityEpochManifestFingerprint(partitions)
	if err != nil {
		return capacityEpochJournal{}, err
	}
	members, err := capacityEpochMembersFromQueues(storage, epochID, partitions)
	if err != nil {
		return capacityEpochJournal{}, err
	}
	var expectedBytes uint64
	for _, member := range members {
		amount := uint64(member.CommittedBytes)
		if expectedBytes > ^uint64(0)-amount {
			return capacityEpochJournal{}, fmt.Errorf("capacity epoch journal bytes overflow")
		}
		expectedBytes += amount
	}
	if partitionCount != len(members) || partitionCount > int(^uint32(0)) {
		return capacityEpochJournal{}, fmt.Errorf("capacity epoch journal partition count is invalid")
	}
	now := nowRFC3339()
	mutationCutoff, err := capacityMutationHighWatermarkUnlocked(storage)
	if err != nil {
		return capacityEpochJournal{}, fmt.Errorf("read capacity mutation cutoff: %w", err)
	}
	return capacityEpochJournal{
		Version: capacityEpochJournalVersion, EpochID: epochID, TargetRound: round,
		State: capacityEpochStatePrepared, ManifestFingerprint: fingerprint, Members: members,
		MutationCutoffSequence: mutationCutoff,
		// LOCAL baseline: this vault keeper's own member snapshot at prepare time.
		LocalSnapshotPartitions: uint32(partitionCount), LocalSnapshotBytes: expectedBytes,
		// The CHAIN baseline is unknown until an authoritative epoch status is read; it is
		// adopted by applyCapacityEpochChainStatus. Never seed it from local totals.
		ChainCutoffAdopted: false,
		ExpectedPartitions: uint32(partitionCount), ExpectedBytes: expectedBytes,
		DeclaredCapacityBytes: status.DeclaredCapacityBytes,
		RegisteredFreeBytes:   status.RegisteredFreeBytes, RegisteredDataBytes: status.RegisteredDataBytes,
		ProvedFreeBytes: status.ProvedFreeBytes, ProvedDataBytes: status.ProvedDataBytes,
		QuoteReservedBytes: status.QuoteReservedBytes, AllocatedStoredBytes: status.AllocatedStoredBytes,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

func applyCapacityEpochChainStatus(journal *capacityEpochJournal, status CapacityProofEpochStatus) {
	if journal == nil {
		return
	}
	journal.CutoffNonce = status.CutoffNonce
	journal.ExpectedPartitions = status.ExpectedPartitions
	journal.ProvenPartitions = status.ProvenPartitions
	journal.ExpectedBytes = status.ExpectedBytes
	journal.DeclaredCapacityBytes = status.DeclaredCapacityBytes
	journal.RegisteredFreeBytes = status.RegisteredFreeBytes
	journal.RegisteredDataBytes = status.RegisteredDataBytes
	journal.ProvedFreeBytes = status.ProvedFreeBytes
	journal.ProvedDataBytes = status.ProvedDataBytes
	journal.QuoteReservedBytes = status.QuoteReservedBytes
	journal.AllocatedStoredBytes = status.AllocatedStoredBytes
	// The chain's cutoff totals are authoritative for this epoch. Adopt them; never
	// recompute them from local committed bytes.
	if !journal.ChainCutoffAdopted {
		journal.ChainCutoffExpectedPartitions = status.ExpectedPartitions
		journal.ChainCutoffExpectedBytes = status.ExpectedBytes
		journal.ChainCutoffAdopted = true
	}
	// REGISTRATION LAG, NOT EXCLUSION. The local member snapshot may legitimately run ahead
	// of the chain cutoff: a StoreV3 can complete locally before its registration lands at
	// the cutoff nonce. Run 12 subtracted the chain total from the local total and called
	// the difference `ExcludedBytes`, manufacturing a phantom exclusion of 67108864 B for a
	// partition the contract never excluded — an unsatisfiable state that wedged two vault
	// keepers permanently. Record the difference as what it is and move on.
	if journal.LocalSnapshotBytes > journal.ChainCutoffExpectedBytes {
		journal.RegistrationLagBytes = journal.LocalSnapshotBytes - journal.ChainCutoffExpectedBytes
	} else {
		journal.RegistrationLagBytes = 0
	}
	// Exclusions are NOT derived here. CapacityProofSC writes a ProofEpochExclusion for every
	// real exclusion and always decrements BOTH expectedPartitions and expectedBytes together
	// (CapacityProofSC.sol:914-935), so the authoritative record is the per-member chain
	// exclusion status. reconcileCapacityEpochExclusionIdentities derives both totals from it.
}

type capacityEpochExclusionLookup func(
	member capacityEpochMemberRef,
) (capacityEpochExclusionStatus, error)

func reconcileCapacityEpochExclusionIdentities(
	journal *capacityEpochJournal, lookup capacityEpochExclusionLookup,
) error {
	if journal == nil {
		return nil
	}
	if lookup == nil {
		return nil
	}
	// A.3.5: the reconciliation recomputes the excluded set from scratch each call (idempotent;
	// it never increments/decrements a running counter, so repeated runs and restart cannot
	// double-resolve or double-decrement). The exclusion identity is pinned to
	// epoch + partition + contentVersion + contentHash (the lookup is epoch+partition scoped;
	// contentVersion+hash come from the member). Any lookup error fails the WHOLE pass closed —
	// the persisted journal (and its prior classification) is left unwritten and retried.
	excluded := make([]capacityEpochExclusionRef, 0, journal.ExcludedPartitions)
	var excludedBytes uint64
	for _, member := range journal.Members {
		status, err := lookup(member)
		if err != nil {
			// RPC/decode uncertainty: leave the member UNRESOLVED and retry; never resolve or
			// decrement on a failed query.
			return fmt.Errorf("query epoch exclusion %s dl%d-pt%d: %w",
				member.PartitionKind, member.DeadlineIndex, member.PartitionIndex, err)
		}
		if !status.Excluded {
			continue
		}
		if status.ContentVersion == 0 {
			return fmt.Errorf("epoch exclusion for %s dl%d-pt%d reports no content version; unresolved",
				member.PartitionKind, member.DeadlineIndex, member.PartitionIndex)
		}
		var class string
		switch {
		case status.ContentVersion == member.ContentVersion:
			// Exact identity: the same version MUST carry the same content hash.
			if !sameRoot(status.ContentHash, member.ContentHash) {
				return fmt.Errorf(
					"epoch exclusion for %s dl%d-pt%d: version %d content hash differs from the pinned member; refusing to match",
					member.PartitionKind, member.DeadlineIndex, member.PartitionIndex, status.ContentVersion)
			}
			class = exclusionClassExact
		case status.ContentVersion > member.ContentVersion:
			// The partition advanced to a NEWER successor version — the member's version was
			// superseded. This is a converged resolution, not a mismatch to retry forever.
			class = exclusionClassSuperseded
		default:
			// A chain exclusion for an OLDER version than the pinned member is inconsistent;
			// fail closed and retry rather than resolve against a stale version.
			return fmt.Errorf(
				"epoch exclusion for %s dl%d-pt%d reports version %d older than the pinned member version %d; unresolved",
				member.PartitionKind, member.DeadlineIndex, member.PartitionIndex, status.ContentVersion, member.ContentVersion)
		}
		excluded = append(excluded, capacityEpochExclusionRef{
			SnapshotID: member.SnapshotID, PartitionKind: member.PartitionKind,
			DeadlineIndex: member.DeadlineIndex, PartitionIndex: member.PartitionIndex,
			ContentVersion: status.ContentVersion, ContentHash: status.ContentHash,
			ExcludedBytes: status.ExcludedBytes, Classification: class,
		})
		if excludedBytes > ^uint64(0)-status.ExcludedBytes {
			return fmt.Errorf("epoch exclusion bytes overflow")
		}
		excludedBytes += status.ExcludedBytes
	}
	// CHAIN IS AUTHORITATIVE. Both totals are DERIVED from the per-member exclusion records
	// the contract actually wrote — they are never validated against a locally computed
	// figure. The previous code demanded
	//     excludedBytes == journal.ExcludedBytes
	// where journal.ExcludedBytes had been manufactured by subtracting the chain total from
	// the LOCAL member sum. When a vault keeper's local members ran ahead of chain
	// registration that predicate became arithmetically unsatisfiable: with zero excluded
	// members the scan can only ever produce zero bytes, while the journal demanded
	// 67108864. It failed on every scan forever and the epoch never reached a terminal state.
	sort.Slice(excluded, func(i, j int) bool { return excluded[i].SnapshotID < excluded[j].SnapshotID })
	journal.ExcludedMembers = excluded
	journal.ExcludedPartitions = uint32(len(excluded))
	journal.ExcludedBytes = excludedBytes
	return nil
}

func capacityEpochJournalHasSnapshotRefs(storage string, epochID uint64) (bool, error) {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return false, err
	}
	for _, queue := range queues {
		if queue.Frozen != nil && queue.Frozen.ProofEpochID == epochID {
			return true, nil
		}
	}
	return false, nil
}

// adoptActiveCapacityEpochJournal is a one-time rolling-upgrade bridge. A newly
// created epoch always records every member before its chain transaction. An
// already-running legacy epoch may have completed members whose local snapshots
// were advanced, so the adoption is explicitly marked and records only unresolved
// immutable references.
func adoptActiveCapacityEpochJournal(storage string, status CapacityProofEpochStatus) (capacityEpochJournal, error) {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return capacityEpochJournal{}, err
	}
	members := make([]capacityEpochMemberRef, 0)
	for _, queue := range queues {
		if queue.Frozen == nil || queue.Frozen.ProofEpochID != status.ProofEpochID {
			continue
		}
		members = append(members, capacityEpochMemberRef{
			PartitionKind: queue.PartitionKind, DeadlineIndex: queue.DeadlineIndex,
			PartitionIndex: queue.PartitionIndex, SnapshotID: queue.Frozen.ID,
			ContentVersion: queue.Frozen.ContentVersion,
			ContentHash:    queue.Frozen.ContentHash, CommittedBytes: queue.Frozen.Partition.CommittedBytes,
		})
	}
	remaining := int(status.ExpectedPartitions - status.ProvenPartitions)
	if len(members) != remaining {
		return capacityEpochJournal{}, fmt.Errorf(
			"cannot adopt active capacity epoch %d: immutable unresolved members=%d chain=%d",
			status.ProofEpochID, len(members), remaining,
		)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].PartitionKind != members[j].PartitionKind {
			return members[i].PartitionKind < members[j].PartitionKind
		}
		if members[i].DeadlineIndex != members[j].DeadlineIndex {
			return members[i].DeadlineIndex < members[j].DeadlineIndex
		}
		return members[i].PartitionIndex < members[j].PartitionIndex
	})
	var adoptedMemberBytes uint64
	for _, member := range members {
		if member.CommittedBytes < 0 {
			return capacityEpochJournal{}, fmt.Errorf(
				"cannot adopt active capacity epoch %d: member has negative bytes", status.ProofEpochID)
		}
		adoptedMemberBytes += uint64(member.CommittedBytes)
	}
	journal := capacityEpochJournal{
		Version: capacityEpochJournalVersion, EpochID: status.ProofEpochID,
		TargetRound: status.TargetRound, State: capacityEpochStateActive,
		ManifestFingerprint: "legacy-adopted", Members: members, AdoptedLegacy: true,
		ProvenAtAdoption: status.ProvenPartitions,
		// Adopted from an authoritative chain read, so the CHAIN baseline is known here.
		ChainCutoffExpectedPartitions: status.ExpectedPartitions,
		ChainCutoffExpectedBytes:      status.ExpectedBytes,
		ChainCutoffAdopted:            true,
		// The LOCAL snapshot is ALWAYS measured from this journal's own member list — never
		// copied from chain totals. Adopting a legacy epoch is exactly the case where the two
		// legitimately differ, so conflating them here is what created the ambiguity.
		LocalSnapshotPartitions: uint32(len(members)),
		LocalSnapshotBytes:      adoptedMemberBytes,
		CreatedAt:               nowRFC3339(),
	}
	applyCapacityEpochChainStatus(&journal, status)
	return journal, nil
}

// reconcileCapacityEpochJournal maps the durable local record onto the current
// contract epoch. It never reconstructs proof inputs from live sector state.
func reconcileCapacityEpochJournal(
	storage string,
	status CapacityProofEpochStatus,
	currentRound uint64,
) (journal capacityEpochJournal, found bool, err error) {
	return reconcileCapacityEpochJournalWithExclusions(storage, status, currentRound, nil)
}

// retireSupersededTerminalCapacityEpochJournal clears a terminal local authority
// before binding a different active incremental authority discovered on chain.
// A proof worker may already have consumed every frozen input, so mutation
// reconciliation must use only the exact records sealed to the terminal epoch;
// unrelated applied successors stay pending for the new plan.
func retireSupersededTerminalCapacityEpochJournal(storage string, activeEpochID uint64) error {
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil || !found || journal.EpochID == activeEpochID {
		return err
	}
	if journal.State == capacityEpochStatePrepared {
		// A DIFFERENT epoch is active on chain (the caller returns early when the
		// ids match), and this local journal never left `prepared` -- the state
		// advances to `opening` before any transaction is broadcast, so a prepared
		// journal has no on-chain obligation to protect. The chain moving to
		// another epoch makes it conclusively obsolete, the same conclusion
		// reconcileCapacityEpochJournalWithExclusions already draws when a
		// prepared intent is overtaken.
		//
		// Refusing it instead deadlocks the keeper. Live on 2026-09-17: vk_3 and
		// vk_10 each held a prepared journal superseded by a newer chain epoch and
		// logged "status unavailable; proof scheduling deferred" on every scan for
		// hours. That defer blocks ALL proof scheduling, which is the only thing
		// that could have driven the prepared journal to a terminal state -- so it
		// never resolved, capacity never re-certified, admission stayed closed on
		// certified_capacity_insufficient, and every upload routed to those keepers
		// failed for 4.5 hours while deletes and downloads carried on normally.
		//
		// Mark it abandoned and fall through to the ordinary terminal retirement,
		// which still refuses to remove a journal that owns frozen snapshots.
		journal.State = capacityEpochStateAbandoned
		if err := withCapacityEpochJournalLock(storage, func() error {
			current, currentFound, readErr := readCapacityEpochJournalUnlocked(storage)
			if readErr != nil || !currentFound {
				return readErr
			}
			if current.EpochID != journal.EpochID ||
				current.State != capacityEpochStatePrepared {
				return fmt.Errorf(
					"superseded prepared capacity epoch journal %d changed before abandonment",
					journal.EpochID)
			}
			current.State = capacityEpochStateAbandoned
			return writeCapacityEpochJournalUnlocked(storage, current)
		}); err != nil {
			return err
		}
	} else if journal.State != capacityEpochStateCompleted && journal.State != capacityEpochStateAborted &&
		journal.State != capacityEpochStateAbandoned {
		// `opening` stays an error on purpose: its transaction may have been
		// broadcast and its response lost, so abandoning it could open a second
		// campaign for the same intent. `active` is a real obligation.
		return fmt.Errorf(
			"active capacity epoch %d conflicts with non-terminal durable journal %d state=%s",
			activeEpochID, journal.EpochID, journal.State,
		)
	}
	hasRefs, err := capacityEpochJournalHasSnapshotRefs(storage, journal.EpochID)
	if err != nil {
		return err
	}
	if hasRefs {
		// Not yet -- not a failure. The journal is terminal by this point, and a
		// terminal journal does not conflict with the active epoch, so nothing is
		// blocked by leaving it in place until the snapshot lifecycle releases its
		// frozen references. Retirement happens on a later scan.
		//
		// Returning an error here is what kept vk_3 and vk_10 wedged: the caller
		// treats it as a failed status read and defers ALL proof scheduling, which
		// is the very thing that would have released those snapshots.
		// reconcileCapacityEpochJournalWithExclusions already takes this same
		// "persist and wait" path when it abandons a journal holding references.
		return nil
	}
	if err := withCapacityCoordinationLock(storage, func() error {
		return reconcileCapacityMutationEpochUnlocked(storage, journal, journal.State)
	}); err != nil {
		return fmt.Errorf("reconcile terminal capacity mutations for epoch %d: %w", journal.EpochID, err)
	}
	return withCapacityEpochJournalLock(storage, func() error {
		current, currentFound, readErr := readCapacityEpochJournalUnlocked(storage)
		if readErr != nil || !currentFound {
			return readErr
		}
		if current.EpochID != journal.EpochID || current.State != journal.State {
			return fmt.Errorf("terminal capacity epoch journal changed before successor cleanup")
		}
		currentHasRefs, refsErr := capacityEpochJournalHasSnapshotRefs(storage, current.EpochID)
		if refsErr != nil {
			return refsErr
		}
		if currentHasRefs {
			return fmt.Errorf(
				"terminal capacity epoch journal %d regained frozen snapshot references",
				current.EpochID,
			)
		}
		return removeCapacityEpochJournalUnlocked(storage)
	})
}

func reconcileCapacityEpochJournalWithExclusions(
	storage string,
	status CapacityProofEpochStatus,
	currentRound uint64,
	lookup capacityEpochExclusionLookup,
) (journal capacityEpochJournal, found bool, err error) {
	removeAfterMutationReconcile := false
	err = withCapacityEpochJournalLock(storage, func() error {
		journal, found, err = readCapacityEpochJournalUnlocked(storage)
		if err != nil {
			return err
		}
		if !found {
			if !status.Active {
				return nil
			}
			journal, err = adoptActiveCapacityEpochJournal(storage, status)
			if err != nil {
				return err
			}
			found = true
			return writeCapacityEpochJournalUnlocked(storage, journal)
		}
		if status.Active {
			if journal.EpochID != status.ProofEpochID || journal.TargetRound != status.TargetRound {
				return fmt.Errorf(
					"active capacity epoch does not match durable journal: chain=%d/%d local=%d/%d",
					status.ProofEpochID, status.TargetRound, journal.EpochID, journal.TargetRound,
				)
			}
			journal.State = capacityEpochStateActive
			journal.LastError = ""
			applyCapacityEpochChainStatus(&journal, status)
			if err := reconcileCapacityEpochExclusionIdentities(&journal, lookup); err != nil {
				return err
			}
			return writeCapacityEpochJournalUnlocked(storage, journal)
		}

		if status.ProofEpochID == journal.EpochID {
			if status.Invalidated {
				journal.State = capacityEpochStateAborted
			} else {
				journal.State = capacityEpochStateCompleted
			}
			applyCapacityEpochChainStatus(&journal, status)
			if err := reconcileCapacityEpochExclusionIdentities(&journal, lookup); err != nil {
				return err
			}
			if journal.State == capacityEpochStateCompleted {
				if err := commitCompletedFullCapacityBaseline(storage, journal, status); err != nil {
					return fmt.Errorf("commit completed full capacity baseline: %w", err)
				}
			}
		} else if status.ProofEpochID < journal.EpochID {
			// Prepared means no broadcast was attempted and is safe to resume.
			// Opening is deliberately ambiguous: the helper may have broadcast and
			// lost its response. While the target round is still current, retain the
			// exact intent and never submit a second transaction. Once the round has
			// advanced, beginProofEpoch(targetRound) can no longer succeed, so a
			// pending/replaced/reverted attempt is conclusively obsolete.
			if (journal.State == capacityEpochStatePrepared || journal.State == capacityEpochStateOpening) &&
				currentRound <= journal.TargetRound {
				return writeCapacityEpochJournalUnlocked(storage, journal)
			}
			journal.State = capacityEpochStateAbandoned
		} else {
			return fmt.Errorf("capacity epoch journal %d was overtaken by chain epoch %d",
				journal.EpochID, status.ProofEpochID)
		}
		hasRefs, refsErr := capacityEpochJournalHasSnapshotRefs(storage, journal.EpochID)
		if refsErr != nil {
			return refsErr
		}
		if hasRefs {
			return writeCapacityEpochJournalUnlocked(storage, journal)
		}
		// Keep the terminal epoch record until its mutation inclusion states are
		// durably settled below. Removing it first would strand sealed mutations
		// if the process crashed between the two journal updates.
		removeAfterMutationReconcile = true
		return writeCapacityEpochJournalUnlocked(storage, journal)
	})
	if err == nil && journal.EpochID != 0 {
		mutationErr := withCapacityCoordinationLock(storage, func() error {
			return reconcileCapacityMutationEpochUnlocked(
				storage, journal, journal.State,
			)
		})
		if mutationErr != nil {
			return journal, found, fmt.Errorf("reconcile capacity mutations for epoch %d: %w", journal.EpochID, mutationErr)
		}
	}
	if err == nil && removeAfterMutationReconcile {
		err = withCapacityEpochJournalLock(storage, func() error {
			current, currentFound, readErr := readCapacityEpochJournalUnlocked(storage)
			if readErr != nil || !currentFound {
				return readErr
			}
			if current.EpochID != journal.EpochID || current.State != journal.State {
				return fmt.Errorf("capacity epoch journal changed before terminal cleanup")
			}
			hasRefs, refsErr := capacityEpochJournalHasSnapshotRefs(storage, current.EpochID)
			if refsErr != nil {
				return refsErr
			}
			if hasRefs {
				return nil
			}
			if removeErr := removeCapacityEpochJournalUnlocked(storage); removeErr != nil {
				return removeErr
			}
			found = false
			return nil
		})
	}
	return journal, found, err
}

func capacityEpochJournalCandidates(
	storage string,
	status CapacityProofEpochStatus,
	emptyDeletionPending bool,
) ([]partitionProofCandidate, error) {
	return capacityEpochJournalCandidatesWithLagDeadline(storage, status, emptyDeletionPending, 0)
}

func capacityEpochJournalCandidatesWithLagDeadline(
	storage string,
	status CapacityProofEpochStatus,
	emptyDeletionPending bool,
	mutationDeadlineUnix int64,
) ([]partitionProofCandidate, error) {
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil {
		return nil, err
	}
	if !found || journal.EpochID != status.ProofEpochID || journal.TargetRound != status.TargetRound {
		return nil, fmt.Errorf("active capacity epoch %d has no matching durable journal", status.ProofEpochID)
	}
	if journal.State != capacityEpochStateActive && journal.State != capacityEpochStateOpening {
		return nil, fmt.Errorf("capacity epoch journal %d is not active", journal.EpochID)
	}
	if status.ProvenPartitions > status.ExpectedPartitions {
		return nil, fmt.Errorf("capacity epoch chain progress is invalid")
	}
	unresolved := int(status.ExpectedPartitions - status.ProvenPartitions)
	out := make([]partitionProofCandidate, 0, unresolved)
	excludedSnapshots := make(map[string]bool, len(journal.ExcludedMembers))
	var excludedBytes uint64
	for _, exclusion := range journal.ExcludedMembers {
		excludedSnapshots[exclusion.SnapshotID] = true
		excludedBytes += exclusion.ExcludedBytes
	}
	// SECOND COPY of the same assumption that wedged Run 12, in a different function.
	// ExcludedPartitions/ExcludedBytes are now DERIVED from the chain's own exclusion
	// records, so the only thing worth asserting here is internal self-consistency of the
	// member list — never an equality against a locally computed byte figure.
	if uint32(len(excludedSnapshots)) != journal.ExcludedPartitions {
		return nil, fmt.Errorf("capacity epoch %d exclusion identities are incomplete", journal.EpochID)
	}
	if excludedBytes != journal.ExcludedBytes {
		return nil, fmt.Errorf(
			"capacity epoch %d exclusion bytes disagree with its own identity records: %d vs %d",
			journal.EpochID, excludedBytes, journal.ExcludedBytes)
	}
	urgentDeadline := time.Now()
	for _, member := range journal.Members {
		if excludedSnapshots[member.SnapshotID] {
			continue
		}
		queue, queueFound, queueErr := readPartitionProofSnapshotQueue(
			storage, member.PartitionKind, member.DeadlineIndex, member.PartitionIndex,
		)
		if queueErr != nil {
			return nil, queueErr
		}
		if !queueFound || queue.Frozen == nil || queue.Frozen.ProofEpochID != journal.EpochID ||
			queue.Frozen.ID != member.SnapshotID || !sameRoot(queue.Frozen.ContentHash, member.ContentHash) {
			continue
		}
		deadline := time.Time{}
		if queue.Frozen.DeadlineUnix > 0 {
			deadline = time.Unix(queue.Frozen.DeadlineUnix, 0)
		}
		if mutationDeadlineUnix > 0 {
			mutationDeadline := time.Unix(mutationDeadlineUnix, 0)
			if deadline.IsZero() || mutationDeadline.Before(deadline) {
				deadline = mutationDeadline
			}
		}
		if emptyDeletionPending {
			deadline = urgentDeadline
		}
		out = append(out, partitionProofCandidate{
			Partition: queue.Frozen.Partition,
			Priority:  queue.Frozen.Partition.PartitionKind + "-frozen-snapshot",
			Urgent:    true, Deadline: deadline,
		})
	}
	if len(out) != unresolved {
		return nil, fmt.Errorf(
			"capacity epoch %d immutable cutoff is incomplete: local unresolved=%d chain unresolved=%d",
			journal.EpochID, len(out), unresolved,
		)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Deadline.Equal(b.Deadline) {
			if a.Deadline.IsZero() {
				return false
			}
			if b.Deadline.IsZero() {
				return true
			}
			return a.Deadline.Before(b.Deadline)
		}
		if emptyDeletionPending && a.Partition.PartitionKind != b.Partition.PartitionKind {
			return a.Partition.PartitionKind == PartitionKindCapacity
		}
		if a.Partition.DeadlineIndex != b.Partition.DeadlineIndex {
			return a.Partition.DeadlineIndex < b.Partition.DeadlineIndex
		}
		return a.Partition.PartitionIndex < b.Partition.PartitionIndex
	})
	return out, nil
}
