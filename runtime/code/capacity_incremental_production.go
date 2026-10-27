package main

// Production G.2 selection wiring.
//
// The scheduler previously knew how to consume a frozen incremental plan but had no production
// caller that created one. This file joins the existing durable mutation/expiry candidate sources
// to the frozen G.2 selector through one block-pinned, read-only chain snapshot. It never creates
// a full-sweep reason and never replaces an existing plan.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

var errCapacityIncrementalPlanState = errors.New("capacity incremental durable plan state unavailable")

var capacityIncrementalSelectionSnapshotReaderForTest func(
	string, []PartitionMeta, uint64,
) (CapacityIncrementalSelectionSnapshot, error)

func readCapacityIncrementalSelectionSnapshot(
	chainCmd string, partitions []PartitionMeta, blockNumber uint64,
) (CapacityIncrementalSelectionSnapshot, error) {
	if capacityIncrementalSelectionSnapshotReaderForTest != nil {
		return capacityIncrementalSelectionSnapshotReaderForTest(chainCmd, partitions, blockNumber)
	}
	return capacityIncrementalSelectionSnapshotOnChain(chainCmd, partitions, blockNumber)
}

type pinnedCapacitySelectionView struct {
	slot           uint64
	identities     map[string]PartitionIdentity
	certifications map[string]PartitionCertificationRecord
	hashes         map[string]string
	activeKeys     []string
}

func (v *pinnedCapacitySelectionView) CurrentIdentity(
	ctx context.Context, partitionKey string,
) (PartitionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return PartitionIdentity{}, err
	}
	key := strings.ToLower(strings.TrimSpace(partitionKey))
	identity, ok := v.identities[key]
	if !ok {
		return PartitionIdentity{}, fmt.Errorf("partition %s is absent from the pinned identity snapshot", key)
	}
	return identity, nil
}

func (v *pinnedCapacitySelectionView) CertificationIdentityHash(
	ctx context.Context, identity PartitionIdentity,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := strings.ToLower(strings.TrimSpace(identity.PartitionKey))
	current, ok := v.identities[key]
	if !ok || current != identity {
		return "", fmt.Errorf("identity %s differs from the pinned current identity", key)
	}
	hash, ok := v.hashes[key]
	if !ok {
		return "", fmt.Errorf("identity %s has no canonical contract hash", key)
	}
	return hash, nil
}

func (v *pinnedCapacitySelectionView) Certification(
	ctx context.Context, partitionKey string,
) (PartitionCertificationRecord, error) {
	if err := ctx.Err(); err != nil {
		return PartitionCertificationRecord{}, err
	}
	key := strings.ToLower(strings.TrimSpace(partitionKey))
	record, ok := v.certifications[key]
	if !ok {
		return PartitionCertificationRecord{}, fmt.Errorf("partition %s has no pinned certification record", key)
	}
	return record, nil
}

func (v *pinnedCapacitySelectionView) CurrentCertificationSlot(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if v.slot == 0 {
		return 0, fmt.Errorf("pinned certification slot is zero")
	}
	return v.slot, nil
}

func (v *pinnedCapacitySelectionView) ActivePartitionKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]string(nil), v.activeKeys...), nil
}

func expectedPartitionKind(partition PartitionMeta) string {
	if partition.PartitionIndex >= CapacityPartitionIndexOffset {
		return PartitionKindCapacity
	}
	return PartitionKindData
}

func newPinnedCapacitySelectionView(
	snapshot CapacityIncrementalSelectionSnapshot,
	partitions []PartitionMeta,
	cfg ServerConfig,
) (*pinnedCapacitySelectionView, error) {
	if snapshot.BlockNumber == 0 || snapshot.CurrentCertificationSlot == 0 {
		return nil, fmt.Errorf("incremental selection snapshot is not block/slot pinned")
	}
	if len(snapshot.Entries) != len(partitions) {
		return nil, fmt.Errorf("incremental selection snapshot returned %d entries for %d partitions",
			len(snapshot.Entries), len(partitions))
	}
	expected := make(map[string]PartitionMeta, len(partitions))
	for _, partition := range partitions {
		key := strings.ToLower(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex))
		if key == "" {
			return nil, fmt.Errorf("local partition has no stable coordinate")
		}
		if _, duplicate := expected[key]; duplicate {
			return nil, fmt.Errorf("local partition coordinate %s is duplicated", key)
		}
		expected[key] = partition
	}
	view := &pinnedCapacitySelectionView{
		slot:           snapshot.CurrentCertificationSlot,
		identities:     make(map[string]PartitionIdentity, len(partitions)),
		certifications: make(map[string]PartitionCertificationRecord, len(partitions)),
		hashes:         make(map[string]string, len(partitions)),
	}
	for _, entry := range snapshot.Entries {
		identity := entry.Identity
		key := strings.ToLower(strings.TrimSpace(identity.PartitionKey))
		partition, ok := expected[key]
		if !ok {
			return nil, fmt.Errorf("chain snapshot returned unexpected partition coordinate %q", key)
		}
		if _, duplicate := view.identities[key]; duplicate {
			return nil, fmt.Errorf("chain snapshot duplicated partition coordinate %s", key)
		}
		if !strings.EqualFold(identity.VK, cfg.VKAddress) {
			return nil, fmt.Errorf("partition %s belongs to VK %s, want %s", key, identity.VK, cfg.VKAddress)
		}
		if identity.Kind != expectedPartitionKind(partition) || !identity.Active ||
			identity.ContentVersion == 0 || identity.CommittedBytes == 0 {
			return nil, fmt.Errorf("partition %s returned an invalid current registered identity", key)
		}
		if partition.CommittedBytes < 0 || identity.CommittedBytes != uint64(partition.CommittedBytes) {
			return nil, fmt.Errorf("partition %s committed bytes disagree: chain=%d local=%d",
				key, identity.CommittedBytes, partition.CommittedBytes)
		}
		if _, err := strictPartitionBytes32(entry.ChainPartitionKey, "chain partition key"); err != nil {
			return nil, fmt.Errorf("partition %s: %w", key, err)
		}
		if _, err := strictPartitionBytes32(identity.ContentHash, "chain content hash"); err != nil {
			return nil, fmt.Errorf("partition %s: %w", key, err)
		}
		if _, err := strictPartitionBytes32(entry.CanonicalIdentityHash, "canonical identity hash"); err != nil {
			return nil, fmt.Errorf("partition %s: %w", key, err)
		}
		if entry.ChallengeCount == 0 {
			return nil, fmt.Errorf("partition %s returned zero challenge count", key)
		}
		wantContentHash, err := partitionChainContentHash(partition, entry.ChallengeCount)
		if err != nil || !sameRoot(wantContentHash, identity.ContentHash) {
			return nil, fmt.Errorf("partition %s local content does not match pinned chain identity", key)
		}
		record := entry.Certification
		if record.Exists {
			if record.CertifiedExpirySlot == 0 || strings.TrimSpace(record.VK) == "" {
				return nil, fmt.Errorf("partition %s returned an incomplete certification record", key)
			}
			if _, err := strictPartitionBytes32(record.CertifiedIdentityHash, "certified identity hash"); err != nil {
				return nil, fmt.Errorf("partition %s: %w", key, err)
			}
		}
		view.identities[key] = identity
		view.certifications[key] = record
		view.hashes[key] = entry.CanonicalIdentityHash
		view.activeKeys = append(view.activeKeys, key)
	}
	sort.Strings(view.activeKeys)
	return view, nil
}

func pendingCapacityBatchCandidates(
	storage string, partitions []PartitionMeta, includeAll bool, chainTimestamp int64,
) ([]BatchCandidate, error) {
	// The chain timestamp pins certification and deadline reads, but mutation-journal
	// CreatedAt values are host-clock timestamps. Never compare the two clock domains:
	// governance tests (and some private chains) legitimately advance chain time.
	_ = chainTimestamp
	hostNow := time.Now()
	current := make(map[string]struct{}, len(partitions))
	currentCapacity := make([]string, 0, len(partitions))
	for _, partition := range partitions {
		key := strings.ToLower(strings.TrimSpace(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)))
		if key != "" {
			current[key] = struct{}{}
			if expectedPartitionKind(partition) == PartitionKindCapacity {
				currentCapacity = append(currentCapacity, key)
			}
		}
	}
	sort.Strings(currentCapacity)
	// A DATA PARTITION WITH AN IN-FLIGHT DELETION MUST NEVER BE SELECTED.
	//
	// Run 14 VK5: batch 4611686018427387960 was opened ON CHAIN selecting data:1:0 while a
	// deletion for that partition was already in flight. The deletion then proved and
	// DEACTIVATED the partition, so the batch's only member ceased to exist and the batch
	// became unsatisfiable by construction — no adoption and no chunk reconstruction could
	// ever produce a journal for it. The vault keeper sat wedged for 95 minutes.
	//
	// The deletion lifecycle journal already records these coordinates, and the expired-GC
	// and lifecycle-reconcile paths already refuse to act on them. Capacity selection was the
	// one consumer that did not, which is how the race reached the chain. Bounded recovery
	// still exists as the safety net, but a batch that can never be satisfied must not be
	// opened in the first place.
	deletionPending, err := pendingDeletionPartitionKeys(storage)
	if err != nil {
		// An ABSENT lifecycle/sector tree means there are no deletions to seal against — that
		// is a legitimate empty state, not a failure. Any other error is real and must not be
		// swallowed: proceeding blind would reopen exactly the race this seal closes.
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read pending deletion coordinates for capacity selection: %w", err)
		}
		deletionPending = nil
	}
	deletionSealed := make(map[string]struct{}, len(deletionPending))
	for coordinate, pending := range deletionPending {
		if !pending {
			continue
		}
		deletionSealed[strings.ToLower(strings.TrimSpace(epochPartitionKey(
			coordinate.kind, coordinate.deadlineIndex, coordinate.partitionIndex)))] = struct{}{}
	}

	// A FROZEN RECORD OWNED BY DELETION OUTLIVES THE JOURNAL ENTRY THAT CREATED IT.
	//
	// The seal above is driven by the deletion lifecycle JOURNAL. But what actually refuses a
	// capacity freeze is the local snapshot queue's FROZEN RECORD: freezing a partition whose
	// frozen record belongs to another authority returns ErrPartitionFreezeCrossAuthority and
	// always rejects (proof_snapshot.go:1012-1028, the rebind removal). Those are two different
	// facts, and the record can still be there after the journal entry is gone.
	//
	// In that window capacity selects the partition, opens the batch ON CHAIN, then cannot
	// freeze that member. The cutoff never resolves, and after five minutes the WHOLE batch is
	// abandoned -- costing a chain transaction and all the batch's progress -- only to select
	// the same conflict again on the next pass.
	//
	// Live on 2026-10-05, keeper 0xcd3B766C (vk_1), data dl=25 pt=1: six abandoned batches and
	// six cross-authority deferrals in one morning. Capacity made no progress while that
	// record stood, the oldest uncertified change aged past its 1800 s bound, and admission
	// closed on oldest_dirty_hard_lag for 65 minutes.
	//
	// Sealing here is SELECTION-TIME ONLY. It never drops a member from an already-opened
	// batch -- that membership is immutable and is what the proof certifies. The partition is
	// simply not chosen this pass and is picked up on a later one, once the record is advanced.
	// Nothing is proved that was not frozen, no stored piece is touched, and the hard-lag bound
	// still guards against a partition waiting too long.
	if queues, queueErr := listPartitionProofSnapshotQueues(storage); queueErr != nil {
		// Unreadable queue state must not be read as "no conflicts": selecting blind is what
		// opens an unsatisfiable batch.
		return nil, fmt.Errorf(
			"read frozen snapshot records for capacity selection: %w", queueErr)
	} else {
		for _, queue := range queues {
			if queue.Frozen == nil || queue.Frozen.ProofEpochID == 0 {
				continue
			}
			if queue.Frozen.ProofEpochID&standaloneDeletionProofFlag == 0 {
				continue
			}
			deletionSealed[strings.ToLower(strings.TrimSpace(epochPartitionKey(
				queue.Frozen.Partition.PartitionKind,
				queue.Frozen.Partition.DeadlineIndex,
				queue.Frozen.Partition.PartitionIndex)))] = struct{}{}
		}
	}
	candidates := map[string]BatchCandidate{}
	add := func(key string, age time.Duration) {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return
		}
		if _, sealed := deletionSealed[key]; sealed {
			// Sealed against selection until the deletion reaches a terminal state. It will
			// be selected on a later pass if it still exists, or legitimately disappear.
			return
		}
		// A mutation journal transition contains both the old and new coordinates. When the
		// last sector leaves an old coordinate, that identity is intentionally inactive and
		// absent from the block-pinned registration snapshot. Incremental proof selection is
		// defined over current active identities only; empty-transition completion is handled
		// by the G.4 release path, not by inventing a proof for an absent identity.
		if _, active := current[key]; !active {
			return
		}
		candidate := candidates[key]
		candidate.PartitionKey = key
		if age > candidate.MutationAge {
			candidate.MutationAge = age
		}
		candidates[key] = candidate
	}
	if includeAll {
		for _, partition := range partitions {
			add(epochPartitionKey(partition.PartitionKind,
				partition.DeadlineIndex, partition.PartitionIndex), 0)
		}
	}
	records, err := listPendingCapacityMutationJournalRecordsUnlocked(storage)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		age := time.Duration(0)
		if created := parseSnapshotTime(record.CreatedAt); !created.IsZero() && hostNow.After(created) {
			age = hostNow.Sub(created)
		}
		for _, transition := range record.Transitions {
			for _, state := range []capacityMutationSectorState{transition.Old, transition.New} {
				if !state.Exists {
					continue
				}
				// Capacity rebuilds journal an exact aggregate successor rather than one
				// transition per backing sector. The aggregate itself is not a chain
				// partition, so expand it to every current active capacity partition.
				// Their frozen snapshots are what the mutation reconciler later sums and
				// compares with this aggregate. Retired old-only coordinates remain ignored.
				if state.SectorID == "" && state.PartitionKind == PartitionKindCapacity &&
					state.DeadlineIndex < 0 && state.PartitionIndex < 0 {
					for _, key := range currentCapacity {
						add(key, age)
					}
					continue
				}
				add(epochPartitionKey(state.PartitionKind,
					state.DeadlineIndex, state.PartitionIndex), age)
			}
		}
	}
	out := make([]BatchCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PartitionKey < out[j].PartitionKey })
	return out, nil
}

// ensureCapacityIncrementalPlan creates the missing production G.2 cutoff when expiry or a
// durable mutation supplies candidates. Chain truth excludes fresh identities. No candidate or
// an all-fresh selection creates no file and opens no campaign.
func ensureCapacityIncrementalPlan(
	storage string, cfg ServerConfig, partitions []PartitionMeta,
) (bool, error) {
	// Stale-member retirement is now performed by capacityProofEpochStartReadyWithConfig
	// BEFORE every gate, so it still runs when a deletion owns the partition. Calling
	// it again here would be harmless but redundant.
	if _, found, err := readCapacityBatchChunkPlan(storage); err != nil || found {
		if err != nil {
			return false, fmt.Errorf("%w: %v", errCapacityIncrementalPlanState, err)
		}
		return false, nil
	}
	plan, selection, certified, ok, err := computeCapacityIncrementalPlan(storage, cfg, partitions)
	if err != nil {
		return false, err
	}
	// A prior unreadable pinned selection creates an explicit recovery owner. Once this exact
	// production read succeeds, consume only that empty retryable chain-read marker; durable
	// members, successors and every other ambiguity remain fail-closed.
	if cleared, clearErr := clearRevalidatedEmptyChainReadRecovery(storage); clearErr != nil {
		return false, fmt.Errorf("clear revalidated incremental chain-read recovery: %w", clearErr)
	} else if cleared {
		log.Printf("[capacity-batch] cleared revalidated empty chain-read recovery")
	}
	if !ok {
		// SMOKE-10 AUDIT FOLLOW-UP. This used to require `CandidateCount > 0`, which silently
		// excluded the one state that needs terminal reconciliation most: a mutation whose
		// coordinates are ALL absent from the registered manifest produces no candidate at all,
		// so `CandidateCount` is 0 and neither resolver was ever reached. An emptying deletion
		// creates exactly that, and it was proven end-to-end to stay `applied` across quiescent
		// passes and restarts until it breached the hard lag.
		//
		// `SelectedPartitionCount == 0` is the real precondition — it already says "no proof
		// work was selected". Zero candidates is a strictly weaker state than zero selected,
		// never a stronger one. Both resolvers read the pending journal FIRST and return before
		// any chain call when nothing is pending, so admitting this case costs nothing on the
		// ordinary scan.
		if selection.SelectedPartitionCount == 0 {
			_, resolveErr := tryResolveFreshCapacityAggregate(storage, cfg, partitions, certified)
			if resolveErr != nil {
				return false, fmt.Errorf("resolve zero-work capacity aggregate: %w", resolveErr)
			}
		}
		if _, exactErr := tryResolveFreshExactMutation(storage, cfg, partitions, certified); exactErr != nil {
			return false, fmt.Errorf("resolve zero-work exact mutation: %w", exactErr)
		}
		return false, nil
	}
	// G.4B-LV2 stage-A barrier. Everything above this line has already run normally: candidate
	// discovery, the block-pinned selection snapshot, the G.2/G.5 observation-block agreement
	// check and the selection itself. Only the durable freeze is withheld, so the scheduler sees
	// exactly the state it sees when no candidates exist. Requires BOTH explicit test mode and
	// the LV2 hold flag; inert in production.
	if lv2IncrementalPlanCreationHeld() {
		logLV2PlanCreationHeld(selection, certified.ObservationBlock)
		return false, nil
	}
	created, err := freezeCapacityBatchChunkPlanIfAbsent(storage, plan)
	if err != nil {
		return false, err
	}
	if created {
		logCapacitySelection(selection, plan, certified.ObservationBlock)
	}
	// Aggregate rebuild parents cover capacity coordinates only. A data-only frozen
	// plan must not postpone their block-pinned terminal reconciliation; capacity-owned
	// coordinates still fail closed inside the resolver.
	if _, aggregateErr := tryResolveFreshCapacityAggregate(storage, cfg, partitions, certified); aggregateErr != nil {
		return created, fmt.Errorf("resolve terminal capacity aggregate: %w", aggregateErr)
	}
	// SMOKE 11. Terminal reconciliation must run on EVERY pass, not only on a pass where
	// nothing was selected. Selecting one coordinate says nothing about the others: VK1 held 25
	// pending mutations over 8 coordinates while a one-member plan on data:14:0 was frozen, and
	// because this function returned here, the other seven — five of them no longer in the
	// registered manifest at all — got no terminal reconciliation for the entire run and aged
	// out against the 1800 s hard lag.
	//
	// It runs AFTER the freeze so the plan's own coordinates are already owned, and ownership is
	// per-coordinate, so a record the plan will prove is blocked while unrelated records still
	// converge. This is the outer half of the gate; the inner half was relaxed earlier this
	// session and was unreachable without this.
	if _, exactErr := tryResolveFreshExactMutation(storage, cfg, partitions, certified); exactErr != nil {
		return created, fmt.Errorf("resolve terminal exact mutation: %w", exactErr)
	}
	return created, nil
}

// computeCapacityIncrementalPlan performs the complete READ-ONLY G.2 production cutoff: block-pinned
// certification aggregate, durable candidate discovery, pinned selection snapshot, G.2/G.5
// observation-block agreement, membership selection and bounded chunk planning. It persists
// nothing.
//
// G.4B-LV3 split this out of `ensureCapacityIncrementalPlan` so the scheduler can cost the normal
// plan before deciding whether it — or an exact one-member urgency plan — should be the plan that
// actually freezes. Both callers share this one implementation, so candidate discovery, sentinel
// expansion, current-identity filtering, retired-coordinate filtering and deterministic ordering
// cannot diverge between the two paths.
func computeCapacityIncrementalPlan(
	storage string, cfg ServerConfig, partitions []PartitionMeta,
) (capacityBatchChunkPlan, CapacityBatchSelection, CertifiedCapacityAdmissionStatus, bool, error) {
	var (
		emptyPlan      capacityBatchChunkPlan
		emptySelection CapacityBatchSelection
	)
	certified, err := readCertifiedCapacityForAdmission(cfg)
	if err != nil {
		return emptyPlan, emptySelection, certified, false,
			fmt.Errorf("read pinned certification aggregate: %w", err)
	}
	candidates, err := pendingCapacityBatchCandidates(
		storage, partitions, certified.ExpiredCertifiedBytes > 0, certified.ChainTimestamp)
	if err != nil {
		return emptyPlan, emptySelection, certified, false,
			fmt.Errorf("read durable incremental candidates: %w", err)
	}
	if len(candidates) == 0 {
		return emptyPlan, emptySelection, certified, false, nil
	}
	snapshot, err := readCapacityIncrementalSelectionSnapshot(
		cfg.ChainProofCmd, partitions, certified.ObservationBlock)
	if err != nil {
		return emptyPlan, emptySelection, certified, false,
			fmt.Errorf("read pinned incremental selection snapshot: %w", err)
	}
	if snapshot.BlockNumber != certified.ObservationBlock {
		return emptyPlan, emptySelection, certified, false,
			fmt.Errorf("certification and selection observation blocks disagree: certification=%d selection=%d",
				certified.ObservationBlock, snapshot.BlockNumber)
	}
	view, err := newPinnedCapacitySelectionView(snapshot, partitions, cfg)
	if err != nil {
		return emptyPlan, emptySelection, certified, false, err
	}
	selection, err := SelectCapacityBatchMembership(context.Background(), view,
		CapacityBatchSelectionInput{Mode: BatchModeIncremental, Candidates: candidates})
	if err != nil {
		return emptyPlan, emptySelection, certified, false, err
	}
	if !selection.ShouldOpenBatch() {
		return emptyPlan, selection, certified, false, nil
	}
	plan, err := planCapacityBatchChunks(selection, MaxIncrementalBatchMembers)
	if err != nil {
		return emptyPlan, selection, certified, false, err
	}
	return plan, selection, certified, true, nil
}

func logCapacitySelection(selection CapacityBatchSelection, plan capacityBatchChunkPlan, block uint64) {
	// Aggregate-only: no content hashes, requester identity, demand id or file linkage.
	log.Printf("[capacity-batch] froze incremental selection block=%d candidates=%d selected=%d bytes=%d expired=%d recovery=%d audit=%d chunks=%d",
		block, selection.CandidateCount, selection.SelectedPartitionCount, selection.SelectedBytes,
		selection.ExpiredSelectedCount, selection.RecoverySelectedCount,
		selection.AuditSelectedCount, len(plan.Chunks))
}
