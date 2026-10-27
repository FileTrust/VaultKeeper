package main

// Zero-new-proof terminal reconciliation for an aggregate capacity-rebuild parent.
//
// A capacity_rebuild record with the synthetic coordinate capacity:-1:-1 is bookkeeping for
// one rolling catch-up lifecycle. It is not a contract partition and can never itself receive a
// proof. Normal selection expands it into the current exact capacity identities. When that
// expansion selects no work, this file permits the parent to become terminal only after one
// block-pinned snapshot proves the complete chain/local identity set and every member's exact
// current certification. The terminal status is deliberately `resolved`, never `included`:
// no proof, campaign, epoch, or snapshot evidence is fabricated.

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
)

// capacityCatchupOwnershipReason names the one "hold" that is not an owner of a pending
// rebuild parent, but the thing waiting on it. Kept as a constant so the retirement path
// can recognise it by identity rather than by matching prose.
const capacityCatchupOwnershipReason = "capacity catch-up ownership is still present"

const capacityAggregateResolutionReason = "exact_current_capacity_set_certified"
const capacityExactMutationResolutionReason = "exact_current_mutation_successor_certified"

// capacityAbsentSuccessorResolutionReason is the terminal state of a mutation whose successor is
// ABSENCE — a deletion that emptied its data partition. No proof exists or can exist for an
// absent identity, which is exactly why StorageProofSC satisfies a G.4 empty successor
// atomically from its transition receipt (lifecycle_reconcile.go, the `else` arm that promotes
// such an operation straight to `partition_proven`).
//
// That path resolves the DELETION obligation. It does NOT touch the capacity mutation journal,
// and the emptied coordinate is absent from the registered manifest, so the record produces no
// candidate, `selection.CandidateCount` is 0 and neither existing terminal resolver is reached.
// Proven end-to-end through the real delete path in
// capacity_empty_partition_convergence_test.go: the record stayed `applied` across 8 quiescent
// passes and across restarts. It then ages against the 1800 s hard lag and closes admission,
// with no proof work possible and no owner able to retire it — the same defect class as
// Smoke 10, reached by a different route.
const capacityAbsentSuccessorResolutionReason = "exact_absent_successor_deactivated"

// activeDataPartitionCoordinatesReaderForTest overrides the authoritative on-chain active-data
// partition set. Production always reads the chain.
var activeDataPartitionCoordinatesReaderForTest func(string) (map[string]struct{}, error)

// activeDataPartitionCoordinatesOnChain returns the coordinates the CHAIN still considers active
// data partitions. This is the same oracle `syncDataPartitionAfterDelete` consults before
// deactivating an emptied partition, and it is deliberately independent of the local manifest:
// "absent from our own partition list" is our own belief, not evidence.
func activeDataPartitionCoordinatesOnChain(chainCmd string) (map[string]struct{}, error) {
	if activeDataPartitionCoordinatesReaderForTest != nil {
		return activeDataPartitionCoordinatesReaderForTest(chainCmd)
	}
	listed, err := listActiveDataPartitionsOnChain(chainCmd)
	if err != nil {
		return nil, err
	}
	active := make(map[string]struct{}, len(listed))
	for _, info := range listed {
		active[strings.ToLower(epochPartitionKey(
			PartitionKindData, info.DeadlineIndex, info.PartitionIndex))] = struct{}{}
	}
	return active, nil
}

type capacityAggregateResolutionEvidence struct {
	ObservationBlock uint64
	IdentitySetHash  string
	PartitionCount   uint32
	CertifiedBytes   uint64
	OldestProvedAt   uint64
}

type capacityAggregateResolutionIdentity struct {
	Coordinate     string `json:"coordinate"`
	ChainKey       string `json:"chainKey"`
	ContentVersion uint64 `json:"contentVersion"`
	ContentHash    string `json:"contentHash"`
	CommittedBytes uint64 `json:"committedBytes"`
	RegisteredAt   uint64 `json:"registeredAt"`
	IdentityHash   string `json:"identityHash"`
	ProvedAt       uint64 `json:"provedAt"`
	ExpirySlot     uint64 `json:"expirySlot"`
}

func isAggregateCapacityState(state capacityMutationSectorState) bool {
	return state.Exists && state.SectorID == "" && state.PartitionKind == PartitionKindCapacity &&
		state.DeadlineIndex < 0 && state.PartitionIndex < 0 && state.CommittedBytes >= 0 &&
		state.Status == "capacity_backing" && strings.HasPrefix(state.ContentHash, "capacity:")
}

func evaluateCapacityAggregateResolution(
	record capacityMutationJournalRecord,
	snapshot CapacityIncrementalSelectionSnapshot,
	partitions []PartitionMeta,
	cfg ServerConfig,
) (capacityAggregateResolutionEvidence, error) {
	var evidence capacityAggregateResolutionEvidence
	if record.Status != capacityMutationStatusApplied || record.MutationType != "capacity_rebuild" ||
		len(record.Transitions) != 1 || !isAggregateCapacityState(record.Transitions[0].Old) ||
		!isAggregateCapacityState(record.Transitions[0].New) {
		return evidence, fmt.Errorf("mutation %d is not one applied aggregate capacity-rebuild parent", record.Sequence)
	}
	_, err := newPinnedCapacitySelectionView(snapshot, partitions, cfg)
	if err != nil {
		return evidence, err
	}
	if len(snapshot.ActiveCapacityPartitionKeys) == 0 {
		return evidence, fmt.Errorf("pinned snapshot has no complete active-capacity key set")
	}

	expectedChainKeys := make(map[string]struct{})
	identities := make([]capacityAggregateResolutionIdentity, 0)
	for _, entry := range snapshot.Entries {
		identity := entry.Identity
		if identity.Kind != PartitionKindCapacity {
			continue
		}
		chainKey := strings.ToLower(strings.TrimSpace(entry.ChainPartitionKey))
		if _, err := strictPartitionBytes32(chainKey, "active capacity chain key"); err != nil {
			return evidence, err
		}
		if _, duplicate := expectedChainKeys[chainKey]; duplicate {
			return evidence, fmt.Errorf("pinned snapshot duplicated active capacity key %s", chainKey)
		}
		expectedChainKeys[chainKey] = struct{}{}

		record := entry.Certification
		if identity.RegisteredAt == 0 || !record.Exists || record.ProvedAt == 0 ||
			record.ProvedAt < identity.RegisteredAt {
			return evidence, fmt.Errorf("capacity identity %s lacks a certification ordered after its current version registration",
				identity.PartitionKey)
		}
		if record.CertifiedExpirySlot <= snapshot.CurrentCertificationSlot ||
			record.CertifiedKind != PartitionKindCapacity || record.CertifiedBytes != identity.CommittedBytes ||
			!strings.EqualFold(record.VK, identity.VK) ||
			!strings.EqualFold(record.CertifiedIdentityHash, entry.CanonicalIdentityHash) {
			return evidence, fmt.Errorf("capacity identity %s is not fresh and exact-current certified",
				identity.PartitionKey)
		}
		if evidence.CertifiedBytes > math.MaxUint64-identity.CommittedBytes {
			return evidence, fmt.Errorf("aggregate certified-capacity bytes overflow")
		}
		evidence.CertifiedBytes += identity.CommittedBytes
		if evidence.OldestProvedAt == 0 || record.ProvedAt < evidence.OldestProvedAt {
			evidence.OldestProvedAt = record.ProvedAt
		}
		identities = append(identities, capacityAggregateResolutionIdentity{
			Coordinate: strings.ToLower(identity.PartitionKey), ChainKey: chainKey,
			ContentVersion: identity.ContentVersion, ContentHash: strings.ToLower(identity.ContentHash),
			CommittedBytes: identity.CommittedBytes, RegisteredAt: identity.RegisteredAt,
			IdentityHash: strings.ToLower(entry.CanonicalIdentityHash), ProvedAt: record.ProvedAt,
			ExpirySlot: record.CertifiedExpirySlot,
		})
	}
	if len(identities) == 0 || len(identities) > math.MaxUint32 {
		return evidence, fmt.Errorf("current capacity identity count is invalid")
	}

	actualChainKeys := make(map[string]struct{}, len(snapshot.ActiveCapacityPartitionKeys))
	for _, raw := range snapshot.ActiveCapacityPartitionKeys {
		key := strings.ToLower(strings.TrimSpace(raw))
		if _, err := strictPartitionBytes32(key, "pinned active capacity key"); err != nil {
			return evidence, err
		}
		if _, duplicate := actualChainKeys[key]; duplicate {
			return evidence, fmt.Errorf("pinned active-capacity set duplicated key %s", key)
		}
		actualChainKeys[key] = struct{}{}
	}
	if len(actualChainKeys) != len(expectedChainKeys) {
		return evidence, fmt.Errorf("chain/local active capacity identity set is incomplete: chain=%d local=%d",
			len(actualChainKeys), len(expectedChainKeys))
	}
	for key := range expectedChainKeys {
		if _, found := actualChainKeys[key]; !found {
			return evidence, fmt.Errorf("current local capacity identity %s is absent from the complete chain set", key)
		}
	}

	sort.Slice(identities, func(i, j int) bool { return identities[i].Coordinate < identities[j].Coordinate })
	evidence.IdentitySetHash, err = hashCanonicalJSON(identities)
	if err != nil {
		return capacityAggregateResolutionEvidence{}, err
	}
	evidence.ObservationBlock = snapshot.BlockNumber
	evidence.PartitionCount = uint32(len(identities))
	return evidence, nil
}

// capacityTerminalResolutionOwnership reports what currently OWNS capacity work, split into a
// global hold and a set of owned coordinates.
//
// SMOKE 11. `aggregateRetirementOwnershipFree` answers one global yes/no, and it says NO whenever
// any durable plan exists. On a busy VK a plan almost always exists, so terminal reconciliation
// of records that plan has nothing to do with could never run. Live evidence: VK1 held 25 pending
// mutations across 8 coordinates while selection could see only 2 of them — five coordinates were
// absent from the registered manifest entirely — and a one-member plan on data:14:0 blocked
// terminal resolution of all of them until the 1800 s hard lag.
//
// Ownership is a PER-COORDINATE property. A frozen plan owns the coordinates it will prove; it
// owns nothing else. Only a whole-manifest rewrite (catch-up) or unresolved batch recovery is a
// genuine global hold.
func capacityTerminalResolutionOwnership(
	storage string,
) (bool, string, map[string]struct{}, error) {
	owned := map[string]struct{}{}
	// Catch-up is recorded but does NOT short-circuit. Returning here left `owned` empty,
	// so a caller permitted to pass through the catch-up hold could not see that a live
	// plan or journal still owned coordinates — it would have had to choose between
	// blocking on everything or checking nothing. Scanning first makes the per-coordinate
	// answer available in every case, and catch-up is reported at the end exactly as before.
	catchupPending := capacityProofCatchupPending(storage)
	if state, found, err := readCapacityIncrementalBatchState(storage); err != nil {
		return true, "", owned, err
	} else if found && strings.TrimSpace(state.RecoveryState) != "" {
		return true, "capacity batch recovery is unresolved", owned, nil
	}
	if plan, found, err := readCapacityBatchChunkPlan(storage); err != nil {
		return true, "", owned, err
	} else if found {
		for _, key := range plan.allKeys() {
			owned[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
		}
	}
	if journal, found, err := readCapacityEpochJournal(storage); err != nil {
		return true, "", owned, err
	} else if found {
		switch journal.State {
		case capacityEpochStatePrepared, capacityEpochStateOpening, capacityEpochStateActive:
			for _, member := range journal.Members {
				owned[strings.ToLower(epochPartitionKey(
					member.PartitionKind, member.DeadlineIndex, member.PartitionIndex))] = struct{}{}
			}
		}
	}
	if catchupPending {
		return true, capacityCatchupOwnershipReason, owned, nil
	}
	return false, "", owned, nil
}

func aggregateRetirementOwnershipFree(storage string) (bool, string, error) {
	if capacityProofCatchupPending(storage) {
		return false, "capacity catch-up ownership is still present", nil
	}
	if plan, found, err := readCapacityBatchChunkPlan(storage); err != nil {
		return false, "", err
	} else if found && len(plan.Chunks) > 0 {
		return false, "a durable incremental plan still owns work", nil
	}
	if journal, found, err := readCapacityEpochJournal(storage); err != nil {
		return false, "", err
	} else if found {
		switch journal.State {
		case capacityEpochStatePrepared, capacityEpochStateOpening, capacityEpochStateActive:
			return false, "a capacity epoch still owns work or recovery", nil
		}
	}
	if state, found, err := readCapacityIncrementalBatchState(storage); err != nil {
		return false, "", err
	} else if found && strings.TrimSpace(state.RecoveryState) != "" {
		return false, "capacity batch recovery is unresolved", nil
	}
	return true, "", nil
}

// tryResolveFreshCapacityAggregate is called only after normal G.2 selection found candidates but
// selected zero exact members. It returns resolved=false for legitimate non-terminal states and
// errors only for unreadable/ambiguous evidence.
func tryResolveFreshCapacityAggregate(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	certified CertifiedCapacityAdmissionStatus,
) (bool, error) {
	passedCatchupHold := false
	globalHold, holdReason, ownedCoordinates, err := capacityTerminalResolutionOwnership(storage)
	if err != nil {
		return false, err
	}
	if globalHold && holdReason != capacityCatchupOwnershipReason {
		// A genuine owner — unresolved batch recovery — still wins.
		return false, nil
	}
	if globalHold {
		// CATCH-UP IS NOT AN OWNER OF THIS RECORD — it is what waits on it.
		//
		// The catch-up marker clears only once the keeper converges, and it cannot
		// converge while an aggregate rebuild parent stays `applied`: that pending
		// record keeps the hard mutation lag breached, which keeps admission shut, which
		// stops the traffic that would converge it. Treating the marker as a global hold
		// made each side wait for the other.
		//
		// Live 2026-09-22: vk_5 held journal sequence 35 — an applied capacity_rebuild —
		// for four days behind capacity-proof-catchup.pending, closed as
		// oldest_dirty_hard_lag, with no log line explaining it because this exit was
		// silent. Its three capacity coordinates were meanwhile fresh and exact-current
		// certified on chain (expiry slots 994504/994504/994505 against slot 994489,
		// certified bytes equal to local bytes), so the evidence check below would have
		// passed on any scan that reached it.
		//
		// Passing through is safe on its own terms: this function writes nothing to chain
		// and retires a record only after evaluateCapacityAggregateResolution proves every
		// active capacity coordinate is freshly and exactly certified. The per-coordinate
		// check just below still protects anything a live plan or campaign holds.
		// Logged below, only once a rebuild parent actually exists to retire. Announcing
		// it here would fire on every scan of a keeper with nothing pending — noise that
		// makes a healthy keeper look wedged, which is the failure mode this whole
		// investigation was buried under.
		passedCatchupHold = true
	}
	// An aggregate rebuild expands to every current capacity coordinate. A data-only
	// plan is unrelated and must not block retirement, but any capacity coordinate
	// already owned by a durable plan/campaign remains proof work and wins.
	if containsCapacityCoordinate(ownedCoordinates) {
		return false, nil
	}

	var pending []capacityMutationJournalRecord
	var highWatermark uint64
	err = withCapacityCoordinationLock(storage, func() error {
		var readErr error
		pending, readErr = listPendingCapacityMutationJournalRecordsUnlocked(storage)
		if readErr != nil {
			return readErr
		}
		highWatermark, readErr = capacityMutationHighWatermarkUnlocked(storage)
		return readErr
	})
	if err != nil {
		return false, err
	}
	if len(pending) == 0 {
		return false, nil
	}
	targets := make([]capacityMutationJournalRecord, 0, len(pending))
	for _, record := range pending {
		if record.Status != capacityMutationStatusApplied || record.MutationType != "capacity_rebuild" {
			continue
		}
		// A malformed rebuild-shaped record is not silently skipped. Evaluating it below
		// keeps every aggregate parent pending unless the same pinned current-set evidence
		// discharges it.
		targets = append(targets, record)
	}
	if len(targets) == 0 {
		return false, nil
	}
	if passedCatchupHold {
		log.Printf("[capacity-batch] retiring %d rebuild parent(s) through catch-up ownership: "+
			"catch-up is what waits on them", len(targets))
	}

	snapshot, err := readCapacityIncrementalSelectionSnapshot(
		cfg.ChainProofCmd, partitions, certified.ObservationBlock)
	if err != nil {
		return false, err
	}
	if snapshot.BlockNumber != certified.ObservationBlock {
		return false, fmt.Errorf("aggregate resolution observation blocks disagree: g5=%d g2=%d",
			certified.ObservationBlock, snapshot.BlockNumber)
	}
	evidenceBySequence := make(map[uint64]capacityAggregateResolutionEvidence, len(targets))
	for _, target := range targets {
		evidence, evalErr := evaluateCapacityAggregateResolution(target, snapshot, partitions, cfg)
		if evalErr != nil {
			// This is an ordinary not-yet-resolved state. The selector remains responsible for
			// generating real proof work when one member is not exact-current. Keep the reason
			// observable: otherwise an all-fresh zero selection and an incomplete terminal proof
			// are indistinguishable in production.
			log.Printf("[capacity-batch] aggregate terminal resolution deferred sequence=%d block=%d: %v",
				target.Sequence, certified.ObservationBlock, evalErr)
			return false, nil
		}
		evidenceBySequence[target.Sequence] = evidence
	}

	resolvedSequences := make([]uint64, 0, len(targets))
	err = withCapacityCoordinationLock(storage, func() error {
		currentHighWatermark, err := capacityMutationHighWatermarkUnlocked(storage)
		if err != nil {
			return err
		}
		currentPending, err := listPendingCapacityMutationJournalRecordsUnlocked(storage)
		if err != nil {
			return err
		}
		// The complete pending set must be unchanged since the pinned evidence was
		// evaluated. New work or a concurrent terminal transition forces a fresh scan.
		if currentHighWatermark != highWatermark || len(currentPending) != len(pending) {
			return nil
		}
		currentStatus := make(map[uint64]string, len(currentPending))
		for _, record := range currentPending {
			currentStatus[record.Sequence] = record.Status
		}
		for _, record := range pending {
			if status, found := currentStatus[record.Sequence]; !found || status != record.Status {
				return nil
			}
		}
		for _, target := range targets {
			evidence := evidenceBySequence[target.Sequence]
			record := target
			record.Status = capacityMutationStatusResolved
			record.ResolutionReason = capacityAggregateResolutionReason
			record.ResolutionObservationBlock = evidence.ObservationBlock
			record.ResolutionIdentitySetHash = evidence.IdentitySetHash
			record.ResolutionPartitionCount = evidence.PartitionCount
			record.ResolutionCertifiedBytes = evidence.CertifiedBytes
			record.ResolutionOldestProvedAt = evidence.OldestProvedAt
			if err := writeCapacityMutationJournalRecord(storage, record); err != nil {
				return err
			}
			resolvedSequences = append(resolvedSequences, record.Sequence)
		}
		return nil
	})
	if err != nil || len(resolvedSequences) == 0 {
		return false, err
	}
	for _, target := range targets {
		evidence := evidenceBySequence[target.Sequence]
		log.Printf("[capacity-batch] terminally resolved aggregate mutation sequence=%d block=%d partitions=%d bytes=%d reason=%s",
			target.Sequence, evidence.ObservationBlock, evidence.PartitionCount,
			evidence.CertifiedBytes, capacityAggregateResolutionReason)
	}
	return true, nil
}

// exactEvidenceIdentity is the per-coordinate terminal evidence recorded on a resolved
// mutation. It is block-pinned and never derived from local belief.
type exactEvidenceIdentity struct {
	Coordinate     string `json:"coordinate"`
	IdentityHash   string `json:"identityHash"`
	RegisteredAt   uint64 `json:"registeredAt"`
	ProvedAt       uint64 `json:"provedAt"`
	CertifiedBytes uint64 `json:"certifiedBytes"`
}

// absentEvidenceCoordinate is the per-coordinate terminal evidence for an ABSENT successor.
// It records what was checked, never a certification it does not have.
type absentEvidenceCoordinate struct {
	Coordinate      string `json:"coordinate"`
	SectorID        string `json:"sectorId"`
	LocallyAbsent   bool   `json:"locallyAbsent"`
	ChainInactive   bool   `json:"chainInactive"`
	ObservationBloc uint64 `json:"observationBlock"`
}

// exactMutationResolutionCandidate is one pending record together with the coordinates its
// terminal evidence depends on.
//
// A record resolves by exactly ONE route — every transition certified-current, or every
// transition absent-terminal. Mixed records are left pending for an ordinary campaign so the two
// evidence shapes never blend.
type exactMutationResolutionCandidate struct {
	record          capacityMutationJournalRecord
	reason          string
	coordinates     map[string]struct{}
	identities      []exactEvidenceIdentity
	absences        []absentEvidenceCoordinate
	identitySetHash string
	certifiedBytes  uint64
	oldestProvedAt  uint64
}

// exactMutationSuccessorCoordinate maps one journal transition onto the coordinate whose
// CURRENT chain identity must carry the certification.
//
// A deletion transition records New.Exists=false because the removed sector no longer exists,
// while the physical partition may still have a smaller live successor. Its old coordinate is
// the exact candidate whose current chain identity must be certified.
func exactMutationSuccessorCoordinate(
	transition capacityMutationTransition, mutationType string,
) (string, bool) {
	state := transition.New
	if !state.Exists && transition.Old.Exists && mutationType == "delete" {
		state = transition.Old
	}
	if !state.Exists || state.DeadlineIndex < 0 || state.PartitionIndex < 0 ||
		(state.PartitionKind != PartitionKindCapacity && state.PartitionKind != PartitionKindData) {
		return "", false
	}
	return strings.ToLower(epochPartitionKey(
		state.PartitionKind, state.DeadlineIndex, state.PartitionIndex)), true
}

// pendingMutationTouchedCoordinates reports every coordinate a record could still be an
// obligation for, over BOTH sides of every transition. It is deliberately wider than
// exactMutationSuccessorCoordinate: it is used to decide what an UNRESOLVED record blocks, so
// it must never under-report. The second result reports an aggregate capacity-rebuild parent,
// whose synthetic coordinate expands to every capacity identity.
func pendingMutationTouchedCoordinates(
	record capacityMutationJournalRecord,
) (map[string]struct{}, bool) {
	coordinates := map[string]struct{}{}
	aggregate := false
	for _, transition := range record.Transitions {
		for _, state := range []capacityMutationSectorState{transition.Old, transition.New} {
			if !state.Exists {
				continue
			}
			if state.SectorID == "" && state.PartitionKind == PartitionKindCapacity &&
				state.DeadlineIndex < 0 && state.PartitionIndex < 0 {
				aggregate = true
				continue
			}
			if state.DeadlineIndex < 0 || state.PartitionIndex < 0 {
				continue
			}
			coordinates[strings.ToLower(epochPartitionKey(
				state.PartitionKind, state.DeadlineIndex, state.PartitionIndex))] = struct{}{}
		}
	}
	if record.MutationType == "capacity_rebuild" {
		aggregate = true
	}
	return coordinates, aggregate
}

func coordinateSetsIntersect(a, b map[string]struct{}) bool {
	small, large := a, b
	if len(large) < len(small) {
		small, large = large, small
	}
	for key := range small {
		if _, found := large[key]; found {
			return true
		}
	}
	return false
}

func containsCapacityCoordinate(coordinates map[string]struct{}) bool {
	for key := range coordinates {
		if strings.HasPrefix(key, PartitionKindCapacity+":") {
			return true
		}
	}
	return false
}

// evaluateExactMutationResolution builds the block-pinned terminal evidence for ONE pending
// record. It returns ok=false for every ordinary not-yet-terminal state and errors only on
// arithmetic that cannot be represented.
func evaluateExactMutationResolution(
	storage string,
	record capacityMutationJournalRecord,
	snapshot CapacityIncrementalSelectionSnapshot,
	entries map[string]CapacitySelectionSnapshotEntry,
	activeDataCoordinates map[string]struct{},
) (exactMutationResolutionCandidate, bool, error) {
	var candidate exactMutationResolutionCandidate
	if record.Status != capacityMutationStatusApplied || record.MutationType == "capacity_rebuild" ||
		len(record.Transitions) == 0 {
		return candidate, false, nil
	}
	// ROUTE B — every transition's successor is ABSENCE, confirmed locally AND on chain.
	// Checked first because such a record has no identity to certify at all, so route A can
	// only ever reject it. A record that qualifies here never reaches route A, and vice versa:
	// the two evidence shapes are disjoint by construction.
	if absent, ok, absentErr := evaluateAbsentSuccessorResolution(
		storage, record, snapshot, activeDataCoordinates,
	); absentErr != nil {
		return candidate, false, absentErr
	} else if ok {
		return absent, true, nil
	}
	seen := map[string]struct{}{}
	identities := make([]exactEvidenceIdentity, 0, len(record.Transitions))
	var certifiedBytes uint64
	var oldestProvedAt uint64
	for _, transition := range record.Transitions {
		coordinate, ok := exactMutationSuccessorCoordinate(transition, record.MutationType)
		if !ok {
			return candidate, false, nil
		}
		if _, duplicate := seen[coordinate]; duplicate {
			continue
		}
		seen[coordinate] = struct{}{}
		entry, found := entries[coordinate]
		if !found || !entry.Identity.Active || entry.Identity.RegisteredAt == 0 {
			return candidate, false, nil
		}
		certification := entry.Certification
		if !certification.Exists || certification.ProvedAt < entry.Identity.RegisteredAt ||
			certification.CertifiedExpirySlot <= snapshot.CurrentCertificationSlot ||
			certification.CertifiedKind != entry.Identity.Kind ||
			certification.CertifiedBytes != entry.Identity.CommittedBytes ||
			!strings.EqualFold(certification.VK, entry.Identity.VK) ||
			!strings.EqualFold(certification.CertifiedIdentityHash, entry.CanonicalIdentityHash) {
			return candidate, false, nil
		}
		if certifiedBytes > math.MaxUint64-certification.CertifiedBytes {
			return candidate, false, fmt.Errorf("exact mutation certified bytes overflow")
		}
		certifiedBytes += certification.CertifiedBytes
		if oldestProvedAt == 0 || certification.ProvedAt < oldestProvedAt {
			oldestProvedAt = certification.ProvedAt
		}
		identities = append(identities, exactEvidenceIdentity{
			Coordinate: coordinate, IdentityHash: strings.ToLower(entry.CanonicalIdentityHash),
			RegisteredAt: entry.Identity.RegisteredAt, ProvedAt: certification.ProvedAt,
			CertifiedBytes: certification.CertifiedBytes,
		})
	}
	if len(identities) == 0 || len(identities) > math.MaxUint32 || certifiedBytes == 0 {
		return candidate, false, nil
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Coordinate < identities[j].Coordinate })
	identitySetHash, err := hashCanonicalJSON(identities)
	if err != nil {
		return candidate, false, err
	}
	return exactMutationResolutionCandidate{
		record: record, reason: capacityExactMutationResolutionReason,
		coordinates: seen, identities: identities,
		identitySetHash: identitySetHash, certifiedBytes: certifiedBytes,
		oldestProvedAt: oldestProvedAt,
	}, true, nil
}

// evaluateAbsentSuccessorResolution builds terminal evidence for a record whose successor is
// ABSENCE on every transition — the emptying-deletion case.
//
// Every one of these must hold, per transition:
//
//  1. the successor state is non-existence (`New.Exists == false`);
//  2. LOCAL truth agrees — the sector is gone from disk, or present with status "deleted"
//     (`capacityMutationSectorStateMatches`, the same predicate the crash-recovery path uses);
//  3. the coordinate has no live local partition in this scan's manifest;
//  4. CHAIN truth agrees — the coordinate is not in the authoritative active-data-partition
//     set. This is the oracle `syncDataPartitionAfterDelete` uses before deactivating, and it
//     is deliberately independent of the local manifest: our own absence is belief, not
//     evidence.
//
// Restricted to DATA coordinates. A capacity coordinate going absent belongs to
// `normalizeMixedCapacitySectors` / `retireExtraCapacitySectors` and to the aggregate resolver;
// nothing here speculates about it.
func evaluateAbsentSuccessorResolution(
	storage string,
	record capacityMutationJournalRecord,
	snapshot CapacityIncrementalSelectionSnapshot,
	activeDataCoordinates map[string]struct{},
) (exactMutationResolutionCandidate, bool, error) {
	var candidate exactMutationResolutionCandidate
	if activeDataCoordinates == nil {
		return candidate, false, nil
	}
	seen := map[string]struct{}{}
	absences := make([]absentEvidenceCoordinate, 0, len(record.Transitions))
	for _, transition := range record.Transitions {
		// 1. name the coordinate. Two shapes are terminal-by-absence:
		//
		//   (a) the successor IS absence — an emptying deletion. Old names the coordinate.
		//   (b) the successor was a LIVE sector that a LATER deletion has since removed —
		//       a store superseded by a delete on the same coordinate. New names it.
		//
		// Shape (b) is the 10-VK failure (run d3v10w, 2026-08-17). VK3/VK5/VK9 each held
		// store+delete PAIRS on one coordinate: data:36:0 and data:1:0. The delete records
		// could retire via (a), but the store records could not retire at all — their
		// successor coordinate was gone from the manifest so the certification route had no
		// identity to check, and (a) rejected them because New.Exists is true. Four records
		// per VK sat unowned, aged to 2714 s against the 1800 s hard lag, and
		// `[capacity-liveness]` reported `unowned_pending_deadline_work ... detail="proved
		// manifest current; no exact selected work"` forever. The bytes they describe are
		// already gone from disk and from the chain; there is no proof that could ever be
		// produced for them.
		var named capacityMutationSectorState
		switch {
		case !transition.New.Exists && transition.Old.Exists:
			named = transition.Old // (a) emptying deletion
		case transition.New.Exists:
			named = transition.New // (b) candidate supersession — verified below
		default:
			return candidate, false, nil
		}
		if named.PartitionKind != PartitionKindData ||
			named.DeadlineIndex < 0 || named.PartitionIndex < 0 {
			return candidate, false, nil
		}
		// 2. LOCAL truth: whatever this transition claims to have created must be gone now.
		//    For (a) that is `capacityMutationSectorStateMatches` on the absent successor.
		//    For (b) the successor sector must be absent or status="deleted" — exactly the
		//    same predicate, asked of a non-existence we construct from the same sector id.
		//    A store whose sector is still present is NOT superseded and must not retire here.
		gone := capacityMutationSectorState{SectorID: named.SectorID, Exists: false}
		matches, matchErr := capacityMutationSectorStateMatches(storage, gone)
		if matchErr != nil {
			return candidate, false, matchErr
		}
		if !matches {
			return candidate, false, nil
		}
		coordinate := strings.ToLower(epochPartitionKey(
			PartitionKindData, named.DeadlineIndex, named.PartitionIndex))
		// 3. no live local successor at that coordinate. If one exists the record is an
		//    ordinary proof obligation and route A owns it.
		if _, live := snapshotEntryCoordinates(snapshot)[coordinate]; live {
			return candidate, false, nil
		}
		// 4. chain truth: the coordinate carries no active identity.
		if _, active := activeDataCoordinates[coordinate]; active {
			return candidate, false, nil
		}
		if _, duplicate := seen[coordinate]; duplicate {
			continue
		}
		seen[coordinate] = struct{}{}
		absences = append(absences, absentEvidenceCoordinate{
			Coordinate: coordinate, SectorID: named.SectorID,
			LocallyAbsent: true, ChainInactive: true, ObservationBloc: snapshot.BlockNumber,
		})
	}
	if len(absences) == 0 || len(absences) > math.MaxUint32 {
		return candidate, false, nil
	}
	sort.Slice(absences, func(i, j int) bool { return absences[i].Coordinate < absences[j].Coordinate })
	setHash, err := hashCanonicalJSON(absences)
	if err != nil {
		return candidate, false, err
	}
	return exactMutationResolutionCandidate{
		record: record, reason: capacityAbsentSuccessorResolutionReason,
		coordinates: seen, absences: absences, identitySetHash: setHash,
	}, true, nil
}

// snapshotEntryCoordinates is the set of coordinates the pinned scan still sees as identities.
func snapshotEntryCoordinates(
	snapshot CapacityIncrementalSelectionSnapshot,
) map[string]struct{} {
	coordinates := make(map[string]struct{}, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		coordinates[strings.ToLower(entry.Identity.PartitionKey)] = struct{}{}
	}
	return coordinates
}

// tryResolveFreshExactMutation repairs the journal-loss case where an exact current successor
// was genuinely certified on chain but no campaign ever sealed its record. Selection correctly
// returns zero proof members because the current identity is fresh; without terminal
// reconciliation the applied mutation would nevertheless remain pending forever, age past the
// hard mutation lag and close admission. This path never fabricates proof inclusion: it records
// block-pinned terminal evidence with status=resolved.
//
// SMOKE 10. This used to require `len(pending) == 1`. That count was never a safety property —
// the real safety property is that a resolved record must not hide an UNRESOLVED obligation on
// a coordinate its own evidence depends on. Cardinality is a crude proxy for that, and it is
// wrong in the ordinary case: two stores landing in the SAME partition produce two pending
// records whose single successor coordinate is one exact-current-certified identity. On VK2 of
// smoke 10 exactly that happened (sequences 7 and 8, both data:30:0, both already certified,
// divergenceBytes 0). Selection reported candidates=1 selected=0 forever, this resolver refused
// on the count alone, and the two mutations aged from 0 to 1798 s and breached the 1800 s hard
// lag with no proof work possible and no owner able to retire them. VK1 reached the SAME branch
// at 18:42:11 with exactly one pending record and resolved it; VK3 had none. The cardinality
// guard was the whole difference between converging and wedging.
//
// The guard is now the exact dependency closure it was standing in for:
//   - a record is resolvable only when every one of its successor coordinates is the exact
//     current identity with a fresh certification ordered after its registration;
//   - a resolvable record is DROPPED when any record that is NOT resolvable touches any of its
//     coordinates (an aggregate capacity-rebuild parent blocks every capacity coordinate);
//   - dropping propagates to a fixpoint, so a coordinate-connected group is resolved wholly or
//     not at all.
//
// This can only ever resolve records whose obligation is already discharged on chain. It never
// resolves more than the old code in the single-record case.
func tryResolveFreshExactMutation(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	certified CertifiedCapacityAdmissionStatus,
) (bool, error) {
	// SMOKE 11: per-coordinate ownership, not a global bail. A frozen plan owns the coordinates
	// it will prove and nothing else, so records it has no bearing on still converge.
	globalHold, holdReason, ownedCoordinates, err := capacityTerminalResolutionOwnership(storage)
	if err != nil {
		return false, err
	}
	// CATCH-UP IS NOT AN OWNER OF THESE RECORDS — it is what waits on them.
	//
	// Third site of the same deadlock. tryResolveFreshCapacityAggregate got this
	// exemption first, then quiescentDivergenceRecoveryRequired on 2026-09-22 for
	// vk_5; this function kept a blanket `if globalHold { return }` and discarded
	// the reason, so it stopped dead the moment a catch-up marker existed — and
	// silently, because that exit logs nothing.
	//
	// The marker clears only once the keeper converges, and it cannot converge
	// while an applied delete stays pending: that record keeps the hard mutation
	// lag breached, which keeps admission shut, which stops the traffic that would
	// converge it.
	//
	// Live on 2026-09-29: vk_10 carried capacity-proof-catchup.pending in phase
	// awaiting_proof from 13:02, and journal record 57 — an applied delete whose
	// sector is gone locally and whose coordinate data:7:0 is absent from both the
	// derived manifest and the chain's active set — never retired. Replaying the
	// real evaluation against that keeper's own files returned WOULD RETIRE = true
	// on every condition, so nothing but this gate was refusing. Its last terminal
	// resolution was 13:08; 64 MiB of free capacity stayed unproved and admission
	// stayed closed for seven hours, and a restart could not help because the
	// marker is on disk.
	//
	// A genuine owner still wins, and ownedCoordinates below still blocks anything
	// a live plan or journal holds — that set is populated even while catch-up is
	// pending, which is what makes passing through here safe.
	if globalHold && holdReason != capacityCatchupOwnershipReason {
		return false, nil
	}
	var pending []capacityMutationJournalRecord
	var highWatermark uint64
	err = withCapacityCoordinationLock(storage, func() error {
		var readErr error
		pending, readErr = listPendingCapacityMutationJournalRecordsUnlocked(storage)
		if readErr != nil {
			return readErr
		}
		highWatermark, readErr = capacityMutationHighWatermarkUnlocked(storage)
		return readErr
	})
	if err != nil || len(pending) == 0 {
		return false, err
	}
	snapshot, err := readCapacityIncrementalSelectionSnapshot(
		cfg.ChainProofCmd, partitions, certified.ObservationBlock)
	if err != nil {
		return false, err
	}
	if snapshot.BlockNumber != certified.ObservationBlock {
		return false, fmt.Errorf("exact mutation resolution observation blocks disagree: g5=%d g2=%d",
			certified.ObservationBlock, snapshot.BlockNumber)
	}
	if _, err := newPinnedCapacitySelectionView(snapshot, partitions, cfg); err != nil {
		return false, err
	}
	entries := make(map[string]CapacitySelectionSnapshotEntry, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		entries[strings.ToLower(entry.Identity.PartitionKey)] = entry
	}
	// The authoritative active-data set costs one chain read, so it is taken ONLY when some
	// pending record actually has an absent successor. In the ordinary case nothing here
	// touches the chain beyond the pinned snapshot already read above.
	//
	// An unreadable set is NOT an error for this function: absence is the only conclusion that
	// depends on it, and `evaluateAbsentSuccessorResolution` treats a nil set as "cannot
	// conclude absence". Certification-route resolutions must keep working — they have their
	// own block-pinned evidence and never consult this set. Failing the whole resolver on a
	// transient RPC error would convert a read blip into a stalled journal.
	var activeDataCoordinates map[string]struct{}
	if anyPendingAbsentSuccessor(pending) {
		activeDataCoordinates, err = activeDataPartitionCoordinatesOnChain(cfg.ChainProofCmd)
		if err != nil {
			log.Printf("[capacity-batch] absent-successor resolution deferred; "+
				"authoritative active-data set unreadable: %v", err)
			activeDataCoordinates = nil
		}
	}

	// Classify every pending record. Anything not provably terminal is a BLOCKER and keeps its
	// coordinates reserved.
	candidates := make([]exactMutationResolutionCandidate, 0, len(pending))
	// Coordinates a live plan or campaign owns are blockers from the start, so the closure
	// treats "a plan will prove this" exactly like "an unresolved peer holds this".
	blocked := map[string]struct{}{}
	for key := range ownedCoordinates {
		blocked[key] = struct{}{}
	}
	blockedAggregate := false
	for _, record := range pending {
		candidate, ok, evalErr := evaluateExactMutationResolution(
			storage, record, snapshot, entries, activeDataCoordinates)
		if evalErr != nil {
			return false, evalErr
		}
		if ok {
			candidates = append(candidates, candidate)
			continue
		}
		touched, aggregate := pendingMutationTouchedCoordinates(record)
		blockedAggregate = blockedAggregate || aggregate
		for key := range touched {
			blocked[key] = struct{}{}
		}
	}

	// Dependency closure to a fixpoint: a dropped candidate becomes a blocker for anything
	// sharing its coordinates, so a coordinate-connected group resolves wholly or not at all.
	for {
		kept := candidates[:0:0]
		dropped := false
		for _, candidate := range candidates {
			if coordinateSetsIntersect(candidate.coordinates, blocked) ||
				(blockedAggregate && containsCapacityCoordinate(candidate.coordinates)) {
				for key := range candidate.coordinates {
					blocked[key] = struct{}{}
				}
				dropped = true
				continue
			}
			kept = append(kept, candidate)
		}
		candidates = kept
		if !dropped {
			break
		}
	}
	if len(candidates) == 0 {
		return false, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].record.Sequence < candidates[j].record.Sequence
	})

	resolvedSequences := make([]uint64, 0, len(candidates))
	err = withCapacityCoordinationLock(storage, func() error {
		currentHighWatermark, readErr := capacityMutationHighWatermarkUnlocked(storage)
		if readErr != nil {
			return readErr
		}
		current, readErr := listPendingCapacityMutationJournalRecordsUnlocked(storage)
		if readErr != nil {
			return readErr
		}
		// The pending set must be bit-identical to the one the evidence was computed over.
		// Anything else means new work landed and the closure has to be recomputed.
		if currentHighWatermark != highWatermark || len(current) != len(pending) {
			return nil
		}
		currentStatus := make(map[uint64]string, len(current))
		for _, record := range current {
			currentStatus[record.Sequence] = record.Status
		}
		for _, record := range pending {
			if status, found := currentStatus[record.Sequence]; !found || status != record.Status {
				return nil
			}
		}
		for _, candidate := range candidates {
			record := candidate.record
			record.Status = capacityMutationStatusResolved
			record.ResolutionReason = candidate.reason
			record.ResolutionObservationBlock = snapshot.BlockNumber
			record.ResolutionIdentitySetHash = candidate.identitySetHash
			record.ResolutionPartitionCount = uint32(candidate.evidenceCount())
			// An absence carries zero certified bytes and zero proved-at, and
			// validateCapacityMutationJournalRecord asserts that positively, so the two
			// evidence shapes can never borrow each other's numbers.
			record.ResolutionCertifiedBytes = candidate.certifiedBytes
			record.ResolutionOldestProvedAt = candidate.oldestProvedAt
			if writeErr := writeCapacityMutationJournalRecord(storage, record); writeErr != nil {
				return writeErr
			}
			resolvedSequences = append(resolvedSequences, record.Sequence)
		}
		return nil
	})
	if err != nil || len(resolvedSequences) == 0 {
		return false, err
	}
	for _, candidate := range candidates {
		log.Printf("[capacity-batch] terminally resolved exact mutation sequence=%d block=%d partitions=%d bytes=%d reason=%s",
			candidate.record.Sequence, snapshot.BlockNumber, candidate.evidenceCount(),
			candidate.certifiedBytes, candidate.reason)
	}
	return true, nil
}

// evidenceCount is the number of coordinates this candidate's terminal evidence covers, on
// whichever route it took.
func (c exactMutationResolutionCandidate) evidenceCount() int {
	if c.reason == capacityAbsentSuccessorResolutionReason {
		return len(c.absences)
	}
	return len(c.identities)
}

// anyPendingAbsentSuccessor reports whether at least one pending record could take the absence
// route, so the authoritative active-data chain read is taken only when it can matter.
func anyPendingAbsentSuccessor(pending []capacityMutationJournalRecord) bool {
	for _, record := range pending {
		if record.Status != capacityMutationStatusApplied ||
			record.MutationType == "capacity_rebuild" || len(record.Transitions) == 0 {
			continue
		}
		absent := true
		for _, transition := range record.Transitions {
			if transition.New.Exists || !transition.Old.Exists ||
				transition.Old.PartitionKind != PartitionKindData {
				absent = false
				break
			}
		}
		if absent {
			return true
		}
	}
	return false
}
