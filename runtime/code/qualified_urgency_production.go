package main

// G.4B-LV1 — production urgency-evaluator integration.
//
// Before LV1 the blocked-demand WRITE path was connected (`quote_reservation.go` records a
// demand when a request is refused for certified insufficiency) but nothing ever READ those
// demands. `EvaluateQualifiedLifecycleUrgency` and every supporting function had zero non-test
// callers, so `TriggerQualifiedLifecycleUrgency` could never reach the scheduler and no campaign
// could be labelled `qualified_lifecycle_urgency`.
//
// This file is that missing read/evaluate/route path. Per scheduler decision cycle:
//
//	load live blocked demands
//	  -> drop expired / cancelled / consumed / abandoned
//	  -> read the exact block-pinned G.5 admission observation
//	  -> read eligible unresolved G.4 release obligations
//	  -> construct QualifiedUrgencyInput
//	  -> call EvaluateQualifiedLifecycleUrgency
//	  -> route the result into campaign-mode selection
//
// Every chain-dependent value used for one decision comes from ONE observation, or the whole
// evaluation fails closed with no urgency. Nothing here invents a deadline or trusts a locally
// claimed release byte count: the lifecycle deadline is `declaredAt + graceSeconds` from
// `FileRegistrationSC.deletionRecords`, and the release bytes are
// `predecessorCommittedBytes - successorCommittedBytes` from `DeletionReleaseSC.getRevision`
// for the exact current revision.
//
// Failing closed here means "no urgency". It never escalates to a full sweep.

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// ReleaseRoute values, mirroring DeletionReleaseSC.ReleaseRoute
// { None, ActiveSnapshot, EmptyTransition }.
const (
	deletionReleaseRouteNone            uint8 = 0
	deletionReleaseRouteActiveSuccessor uint8 = 1
	deletionReleaseRouteEmptyTransition uint8 = 2
)

var (
	deletionRecordsSelector = ethcrypto.Keccak256(
		[]byte("deletionRecords(bytes32)"),
	)[:4]
	deletionReleaseRevisionSelector = ethcrypto.Keccak256(
		[]byte("getRevision(bytes32,uint64)"),
	)[:4]
)

// ─── authoritative chain reads ─────────────────────────────────────────────────────────

// deletionLifecycleDeadlineOnChain returns the authoritative finite lifecycle deadline for one
// deletion: `declaredAt + graceSeconds` from the on-chain DeletionRecord. A record that was never
// declared has no deadline, and G.4B never invents one.
func deletionLifecycleDeadlineOnChain(
	ctx context.Context, cfg ServerConfig, commitmentHash, blockTag string,
) (time.Time, bool, error) {
	if !common.IsHexAddress(cfg.FileRegistrationContract) {
		return time.Time{}, false, fmt.Errorf("file registration contract is not configured")
	}
	call := append(append([]byte{}, deletionRecordsSelector...), hexToBytes32(commitmentHash)...)
	result, err := rpcCallCtx(ctx, cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.FileRegistrationContract).Hex(),
			"data": "0x" + hex.EncodeToString(call),
		}, blockTag,
	})
	if err != nil {
		return time.Time{}, false, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("decode deletion record: %w", err)
	}
	// (uint64 declaredAt, uint64 graceSeconds, uint64 confirmedAt, bool confirmed, bool authorized)
	if len(raw) < 5*32 {
		return time.Time{}, false, fmt.Errorf("deletion record returned %d bytes", len(raw))
	}
	declaredAt, err := decodeUint64ABIWord(raw[0:32], "declaredAt")
	if err != nil {
		return time.Time{}, false, err
	}
	graceSeconds, err := decodeUint64ABIWord(raw[32:64], "graceSeconds")
	if err != nil {
		return time.Time{}, false, err
	}
	if declaredAt == 0 {
		// Not declared on chain: no authoritative deadline exists yet.
		return time.Time{}, false, nil
	}
	if graceSeconds > math.MaxInt64-declaredAt {
		return time.Time{}, false, fmt.Errorf("deletion record deadline overflows")
	}
	return time.Unix(int64(declaredAt+graceSeconds), 0).UTC(), true, nil
}

// successorRevisionRecord mirrors DeletionReleaseSC.SuccessorRevision for reading only.
type successorRevisionRecord struct {
	Revision                  uint64
	Route                     uint8
	PredecessorCommittedBytes uint64
	SuccessorKind             uint8
	SuccessorActive           bool
	SuccessorContentVersion   uint64
	SuccessorContentHash      string
	SuccessorCommittedBytes   uint64
}

// authoritativeReleaseBytes is derived on chain, never from a caller claim. A successor that
// somehow grew relative to its predecessor releases nothing.
func (r successorRevisionRecord) authoritativeReleaseBytes() uint64 {
	if r.SuccessorCommittedBytes >= r.PredecessorCommittedBytes {
		return 0
	}
	return r.PredecessorCommittedBytes - r.SuccessorCommittedBytes
}

func successorRevisionOnChain(
	ctx context.Context, cfg ServerConfig, operationID string, revision uint64, blockTag string,
) (successorRevisionRecord, error) {
	var record successorRevisionRecord
	if !common.IsHexAddress(cfg.DeletionReleaseContract) {
		return record, fmt.Errorf("deletion release contract is not configured")
	}
	call := append(append([]byte{}, deletionReleaseRevisionSelector...), hexToBytes32(operationID)...)
	call = append(call, encodeUint256ABIWord(revision)...)
	result, err := rpcCallCtx(ctx, cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.DeletionReleaseContract).Hex(),
			"data": "0x" + hex.EncodeToString(call),
		}, blockTag,
	})
	if err != nil {
		return record, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil {
		return record, fmt.Errorf("decode successor revision: %w", err)
	}
	// SuccessorRevision is an all-static tuple of 17 words.
	if len(raw) < 17*32 {
		return record, fmt.Errorf("successor revision returned %d bytes", len(raw))
	}
	word := func(index int) []byte { return raw[index*32 : (index+1)*32] }
	if record.Revision, err = decodeUint64ABIWord(word(0), "revision"); err != nil {
		return successorRevisionRecord{}, err
	}
	route, err := decodeUint64ABIWord(word(1), "route")
	if err != nil || route > 255 {
		return successorRevisionRecord{}, fmt.Errorf("invalid successor revision route")
	}
	record.Route = uint8(route)
	if record.PredecessorCommittedBytes, err = decodeUint64ABIWord(
		word(6), "predecessorCommittedBytes"); err != nil {
		return successorRevisionRecord{}, err
	}
	successorKind, err := decodeUint64ABIWord(word(9), "successorKind")
	if err != nil || successorKind > 255 {
		return successorRevisionRecord{}, fmt.Errorf("invalid successor kind")
	}
	record.SuccessorKind = uint8(successorKind)
	active, err := decodeUint64ABIWord(word(10), "successorActive")
	if err != nil {
		return successorRevisionRecord{}, err
	}
	record.SuccessorActive = active != 0
	if record.SuccessorContentVersion, err = decodeUint64ABIWord(
		word(11), "successorContentVersion"); err != nil {
		return successorRevisionRecord{}, err
	}
	record.SuccessorContentHash = "0x" + hex.EncodeToString(word(12))
	if record.SuccessorCommittedBytes, err = decodeUint64ABIWord(
		word(13), "successorCommittedBytes"); err != nil {
		return successorRevisionRecord{}, err
	}
	return record, nil
}

// encodeUint256ABIWord renders a uint64 as one right-aligned ABI word.
func encodeUint256ABIWord(value uint64) []byte {
	word := make([]byte, 32)
	for i := 0; i < 8; i++ {
		word[31-i] = byte(value >> (8 * i))
	}
	return word
}

// ─── obligation collection ─────────────────────────────────────────────────────────────

// releaseObligationSource is swapped in tests so the production caller graph is exercised
// without a chain.
var releaseObligationSourceForTest func(storage string, cfg ServerConfig) ([]ReleaseObligation, error)

// collectReleaseObligations reads every locally tracked deletion and resolves each against chain
// state. An operation whose chain state cannot be read is SKIPPED rather than guessed — it simply
// does not become an eligible obligation, so it can never manufacture urgency.
// chainPartitionKeyOf mirrors StorageProofSC.partitionKeyOf exactly:
//
//	keccak256(abi.encodePacked(vk, uint8 deadlineIndex, uint8 partitionIndex))
//
// It is `pure` on chain, so deriving it locally needs no chain read and cannot drift.
func chainPartitionKeyOf(vk string, deadlineIndex, partitionIndex int) (string, error) {
	if !common.IsHexAddress(vk) {
		return "", fmt.Errorf("vk address is not a valid hex address")
	}
	if deadlineIndex < 0 || deadlineIndex > 255 || partitionIndex < 0 || partitionIndex > 255 {
		return "", fmt.Errorf("partition coordinates exceed uint8")
	}
	packed := append(common.HexToAddress(vk).Bytes(),
		byte(uint8(deadlineIndex)), byte(uint8(partitionIndex)))
	return "0x" + hex.EncodeToString(ethcrypto.Keccak256(packed)), nil
}

// localIdentityForChainPartitionKey inverts that derivation over the CURRENT registered manifest.
//
// The invariant is documented on the chain status types: `Identity.PartitionKey` is the stable
// local `kind:deadline:partition` coordinate used by durable plans, while the bytes32 contract
// value is a separate chain identity. `DeletionReleaseSC` addresses a successor by the chain
// identity, so an obligation built from chain MUST be translated back into the local coordinate
// domain before it is compared with anything plan-shaped. Deriving each registered partition's
// chain key and matching is exact — it is the contract's own formula, not a string convention.
//
// Returns the local coordinate and the exact partition, or ok=false when the chain key does not
// resolve to exactly one current registered identity (fail closed; never guess).
func localIdentityForChainPartitionKey(
	vk string, partitions []PartitionMeta, chainPartitionKey string,
) (string, PartitionMeta, bool) {
	want := strings.ToLower(strings.TrimSpace(chainPartitionKey))
	if want == "" {
		return "", PartitionMeta{}, false
	}
	var found PartitionMeta
	coordinate := ""
	matches := 0
	for _, partition := range partitions {
		derived, err := chainPartitionKeyOf(vk, partition.DeadlineIndex, partition.PartitionIndex)
		if err != nil || derived != want {
			continue
		}
		matches++
		found = partition
		coordinate = strings.ToLower(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex))
	}
	if matches != 1 || coordinate == "" {
		return "", PartitionMeta{}, false
	}
	return coordinate, found, true
}

func collectReleaseObligations(
	storage string, cfg ServerConfig, observationBlock uint64, partitions []PartitionMeta,
) ([]ReleaseObligation, error) {
	if releaseObligationSourceForTest != nil {
		return releaseObligationSourceForTest(storage, cfg)
	}
	if observationBlock == 0 {
		return nil, fmt.Errorf("release obligation observation block is not pinned")
	}
	blockTag := fmt.Sprintf("0x%x", observationBlock)
	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return nil, fmt.Errorf("list deletion lifecycle operations: %w", err)
	}
	if len(operations) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	obligations := make([]ReleaseObligation, 0, len(operations))
	for _, operation := range operations {
		commitment := strings.TrimSpace(operation.CommitmentHash)
		if commitment == "" {
			continue
		}
		status, statusErr := deletionReleaseStatusOnChainAtBlock(ctx, cfg, commitment, blockTag)
		if statusErr != nil {
			// Unreadable obligation state is ambiguous. Skip it.
			continue
		}
		obligation := ReleaseObligation{
			OperationID:      status.OperationID,
			Revision:         status.Revision,
			State:            status.State,
			RecoveryRequired: status.RecoveryRequired,
			// deletionReleaseRouteActiveSuccessor is the only route that needs a snapshot proof.
			RequiresActiveSuccessorProof: status.Route == deletionReleaseRouteActiveSuccessor,
			EmptyTransition:              status.Route == deletionReleaseRouteEmptyTransition,
		}
		// Cheap rejections first: never spend chain reads on an obligation that is already
		// satisfied, confirmed, quarantined, or empty-transition.
		if obligation.RecoveryRequired ||
			obligation.State == deletionReleaseSatisfied ||
			obligation.State == deletionReleaseConfirmed ||
			obligation.State == deletionReleaseAwaitingSuccessorIdentity ||
			obligation.EmptyTransition || !obligation.RequiresActiveSuccessorProof {
			obligations = append(obligations, obligation)
			continue
		}

		revision, revErr := successorRevisionOnChain(
			ctx, cfg, status.OperationID, status.Revision, blockTag)
		if revErr != nil || revision.Revision != status.Revision {
			// The exact current revision could not be resolved authoritatively.
			continue
		}
		obligation.AuthoritativeReleaseBytes = revision.authoritativeReleaseBytes()

		sourceKey, keyErr := deletionReleaseSourcePartitionKey(ctx, cfg, status.OperationID, blockTag)
		if keyErr != nil || strings.TrimSpace(sourceKey) == "" {
			continue
		}
		kind := PartitionKindData
		if revision.SuccessorKind == 2 {
			kind = PartitionKindCapacity
		}
		// `sourceKey` is the DeletionReleaseSC bytes32 identity. Everything downstream — the
		// durable plan, the G.3 selected-work estimate, the active-campaign member set — is keyed
		// by the local `kind:deadline:partition` coordinate. Translate here, once, through the
		// contract's own pure derivation, and fail closed when it does not resolve to exactly one
		// current registered identity. Leaving the chain key in `PartitionKey` made predicate 2
		// unreachable for every real obligation.
		coordinate, matched, resolved := localIdentityForChainPartitionKey(
			cfg.VKAddress, partitions, sourceKey)
		if !resolved {
			continue
		}
		if matched.PartitionKind != "" && matched.PartitionKind != kind {
			// The chain-declared successor kind must agree with the registered identity.
			continue
		}
		obligation.SuccessorChainPartitionKey = strings.ToLower(strings.TrimSpace(sourceKey))
		obligation.SuccessorIdentity = PartitionIdentity{
			PartitionKey:   coordinate,
			VK:             cfg.VKAddress,
			Kind:           kind,
			Active:         revision.SuccessorActive,
			ContentVersion: revision.SuccessorContentVersion,
			ContentHash:    revision.SuccessorContentHash,
			CommittedBytes: revision.SuccessorCommittedBytes,
		}

		deadline, authoritative, deadlineErr := deletionLifecycleDeadlineOnChain(
			ctx, cfg, commitment, blockTag)
		if deadlineErr != nil {
			continue
		}
		obligation.LifecycleDeadline = deadline
		obligation.DeadlineAuthoritative = authoritative

		obligations = append(obligations, obligation)
	}
	return obligations, nil
}

// deletionReleaseSourcePartitionKey reads word 2 of DeletionReleaseSC.getOperation, the exact
// partition key the successor proof must cover.
func deletionReleaseSourcePartitionKey(
	ctx context.Context, cfg ServerConfig, operationID, blockTag string,
) (string, error) {
	if !common.IsHexAddress(cfg.DeletionReleaseContract) {
		return "", fmt.Errorf("deletion release contract is not configured")
	}
	call := append(append([]byte{}, deletionReleaseOperationSelector...), hexToBytes32(operationID)...)
	result, err := rpcCallCtx(ctx, cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.DeletionReleaseContract).Hex(),
			"data": "0x" + hex.EncodeToString(call),
		}, blockTag,
	})
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode deletion release operation: %w", err)
	}
	if len(raw) < 3*32 {
		return "", fmt.Errorf("deletion release operation returned %d bytes", len(raw))
	}
	return "0x" + hex.EncodeToString(raw[2*32:3*32]), nil
}

// ─── the block-pinned observation ──────────────────────────────────────────────────────

// urgencyObservationForTest lets tests supply one consistent observation.
var urgencyObservationForTest func(storage string, cfg ServerConfig) (ProjectedAdmission, error)

// readQualifiedUrgencyObservation builds the G.5 observation used for the whole decision. Every
// field comes from the SAME block observation; a partial read fails closed.
func readQualifiedUrgencyObservation(
	storage string, cfg ServerConfig,
) (ProjectedAdmission, error) {
	if urgencyObservationForTest != nil {
		return urgencyObservationForTest(storage, cfg)
	}
	certified, err := readCertifiedCapacityForAdmission(cfg)
	if err != nil {
		return ProjectedAdmission{}, fmt.Errorf("certified capacity observation unavailable: %w", err)
	}
	if certified.ObservationBlock == 0 || certified.ChainTimestamp == 0 {
		return ProjectedAdmission{}, fmt.Errorf("certified capacity observation is not block-pinned")
	}
	if certified.FreshCertifiedFreeCapacity < 0 || certified.RingCertifiedFreeCapacity < 0 ||
		certified.AllocatedStoredBytes < 0 {
		return ProjectedAdmission{}, fmt.Errorf("certified capacity observation is negative")
	}
	declared := cfg.CapacityBytes
	if declared <= 0 {
		return ProjectedAdmission{}, fmt.Errorf("declared capacity is not configured")
	}
	if certified.FreshCertifiedFreeCapacity > declared {
		return ProjectedAdmission{}, fmt.Errorf(
			"certified free %d exceeds declared capacity %d",
			certified.FreshCertifiedFreeCapacity, declared)
	}

	// ledgerFree is the declared capacity minus what the ledger has already allocated. The G.5
	// identity freshCertifiedFree = min(ringFresh, ledgerFree) is asserted below rather than
	// assumed, so an inconsistent pair fails closed instead of projecting from bad inputs.
	ledgerFree := declared - certified.AllocatedStoredBytes
	if ledgerFree < 0 {
		return ProjectedAdmission{}, fmt.Errorf("allocated bytes exceed declared capacity")
	}
	ringFresh := certified.RingCertifiedFreeCapacity
	expected := ringFresh
	if ledgerFree < expected {
		expected = ledgerFree
	}
	if certified.FreshCertifiedFreeCapacity != expected {
		return ProjectedAdmission{}, fmt.Errorf(
			"certified-capacity observation inconsistent: freshCertified=%d min(ringFresh=%d, ledgerFree=%d)=%d",
			certified.FreshCertifiedFreeCapacity, ringFresh, ledgerFree, expected)
	}

	transferStateMu.Lock()
	reserved, reservationErr := reservedAdmissionCapacityBytesAtLocked(
		storage, "", "", "", certified.ChainTimestamp,
	)
	transferStateMu.Unlock()
	if reservationErr != nil {
		return ProjectedAdmission{}, fmt.Errorf("active reservations unavailable: %w", reservationErr)
	}
	if reserved < 0 {
		return ProjectedAdmission{}, fmt.Errorf("active reservations are negative")
	}
	margin := admissionMarginBytes(cfg)
	if margin < 0 {
		return ProjectedAdmission{}, fmt.Errorf("admission margin is negative")
	}
	_, safe := subtractAdmissionCapacity(certified.FreshCertifiedFreeCapacity, reserved, margin)

	return ProjectedAdmission{
		ObservationBlock:         certified.ObservationBlock,
		ObservationTimestampUnix: certified.ChainTimestamp,
		DeclaredCapacity:         uint64(declared),
		LedgerFree:               uint64(ledgerFree),
		RingFresh:                uint64(ringFresh),
		ActiveReservations:       uint64(reserved),
		AdmissionMargin:          uint64(margin),
		CurrentSafeAllocatable:   uint64(max64(safe, 0)),
	}, nil
}

// ─── the production evaluation ─────────────────────────────────────────────────────────

// ProductionUrgencyOutcome is what the scheduler consumes.
type ProductionUrgencyOutcome struct {
	Result QualifiedUrgencyResult
	// Observation is retained so the demand lifecycle can be reconciled against exactly the
	// state the decision used.
	Observation ProjectedAdmission
	// Evaluated is false when the evaluation could not run at all (fail closed). It is NOT a
	// launch reason and never escalates to a full sweep.
	Evaluated bool
	Detail    string
	// Aggregate evidence for the selected conjunction. These fields contain no requester,
	// file, commitment or capability identity.
	CompletionEstimate        SelectedWorkEstimate
	AuthoritativeReleaseBytes uint64
	RequestedBytes            uint64
	CertifiedShortfall        uint64
}

// evaluateProductionQualifiedUrgency is the single production caller of
// EvaluateQualifiedLifecycleUrgency. It runs once per scheduler decision cycle.
func evaluateProductionQualifiedUrgency(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	activeMembers map[string]struct{},
) ProductionUrgencyOutcome {
	return evaluateProductionQualifiedUrgencyWithNormalCompletion(
		storage, cfg, partitions, activeMembers)
}

// evaluateProductionQualifiedUrgencyWithNormalCompletion is the same evaluation, kept as a distinct
// entry point for the LV3 precedence path.
//
// It previously accepted a `normalRequired time.Duration` that the body never read. That parameter
// was removed rather than wired in, because predicate 2 is deliberately PER SUCCESSOR: the frozen
// G.3 estimate for the exact selected successor
// (activeCampaignRemaining + cumulativePendingDurationAhead + selectedBatchEstimatedDuration +
// selectedQueueDelay), which depends on where that identity sits in the plan. A single whole-plan
// duration is a coarser, different quantity and must not be substituted for it. The real defect was
// never the timing source — it was that the successor identity arrived in the chain bytes32 domain
// and could never match the coordinate-keyed estimate. That is fixed in collectReleaseObligations.
//
// Membership and timing therefore stay separate: `localIdentityForChainPartitionKey` proves the
// successor is exactly one current registered identity, and the per-successor estimate supplies the
// completion time.
func evaluateProductionQualifiedUrgencyWithNormalCompletion(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	activeMembers map[string]struct{},
) ProductionUrgencyOutcome {
	// (a) live blocked demands, with expired ones swept from durable storage first.
	if _, err := expireBlockedDemands(storage, time.Now()); err != nil {
		return ProductionUrgencyOutcome{Detail: "blocked demand expiry unavailable: " + err.Error()}
	}
	demands, err := listBlockedDemands(storage)
	if err != nil {
		return ProductionUrgencyOutcome{Detail: "blocked demand storage unreadable: " + err.Error()}
	}
	if len(demands) == 0 {
		return ProductionUrgencyOutcome{
			Evaluated: true,
			Result:    QualifiedUrgencyResult{Reason: "no pending blocked demand"},
		}
	}

	// (b) the exact block-pinned G.5 observation.
	observation, err := readQualifiedUrgencyObservation(storage, cfg)
	if err != nil {
		return ProductionUrgencyOutcome{Detail: "certified-capacity observation unavailable: " + err.Error()}
	}
	if observation.ObservationTimestampUnix <= 0 {
		return ProductionUrgencyOutcome{
			Observation: observation,
			Detail:      "certified-capacity observation has no block-pinned chain timestamp",
		}
	}

	// Demand lifecycle first: whenever a valid observation exists, a demand whose ACTUAL
	// capacity is now sufficient becomes ready_for_retry. This must not depend on urgency
	// qualifying — the ordinary case is that capacity recovers with no urgency at all.
	if promoted, lifecycleErr := reconcileBlockedDemandLifecycle(storage, observation); lifecycleErr != nil {
		log.Printf("[capacity-urgency] demand lifecycle reconciliation deferred: %v", lifecycleErr)
	} else if promoted > 0 {
		log.Printf("[capacity-urgency] blockedDemandReadyForRetry=%d currentSafeAllocatable=%d",
			promoted, observation.CurrentSafeAllocatable)
	}

	// (c) eligible unresolved G.4 obligations.
	obligations, err := collectReleaseObligations(
		storage, cfg, observation.ObservationBlock, partitions)
	if err != nil {
		return ProductionUrgencyOutcome{
			Observation: observation,
			Detail:      "release obligation state ambiguous: " + err.Error(),
		}
	}

	// (d) the frozen G.3 completion estimate for the exact successor identity.
	completionEstimates := productionNormalCompletionEstimate(
		storage, cfg, partitions, uint64(max64(cfg.CapacityBytes, 0)))
	resolvedEstimates := map[string]SelectedWorkEstimate{}
	normalCompletion := func(identity PartitionIdentity) (time.Duration, bool) {
		estimate, ok := completionEstimates(identity)
		if !ok {
			return 0, false
		}
		resolvedEstimates[strings.ToLower(strings.TrimSpace(identity.PartitionKey))] = estimate
		return estimate.RequiredDuration, true
	}

	result := EvaluateQualifiedLifecycleUrgency(QualifiedUrgencyInput{
		Observation:           observation,
		Obligations:           obligations,
		Demands:               demands,
		NormalCompletion:      normalCompletion,
		ActiveCampaignMembers: activeMembers,
		Now:                   time.Now(),
		LifecycleNow:          time.Unix(observation.ObservationTimestampUnix, 0).UTC(),
	})
	outcome := ProductionUrgencyOutcome{Result: result, Observation: observation, Evaluated: true}
	if result.Qualified {
		key := strings.ToLower(strings.TrimSpace(result.SelectedIdentity.PartitionKey))
		outcome.CompletionEstimate = resolvedEstimates[key]
		for _, obligation := range obligations {
			if obligation.OperationID == result.OperationID {
				outcome.AuthoritativeReleaseBytes = obligation.AuthoritativeReleaseBytes
				break
			}
		}
		if len(result.MatchedDemandIDs) > 0 {
			firstMatched := result.MatchedDemandIDs[0]
			for _, demand := range demands {
				if demand.DemandID != firstMatched {
					continue
				}
				outcome.RequestedBytes = demand.RequestedBytes
				outcome.CertifiedShortfall = demand.CertifiedShortfall
				break
			}
		}
	}
	return outcome
}

// productionNormalCompletion resolves the frozen G.3 selected-work completion estimate:
//
//	activeCampaignRemaining + cumulativePendingDurationAhead
//	  + selectedBatchEstimatedDuration + selectedQueueDelay
//
// That total is `SelectedWorkEstimate.RequiredDuration`, produced by the SAME
// `liveSelectedWorkDecision` path the scheduler uses — never a separate model and never an
// override. When the successor is not yet part of the durable plan its own conservative member
// cost is added, because it would be scheduled behind the existing backlog.
//
// LV1 supplied only the per-shape member duration here, which understated completion and made
// urgency under-trigger. LV2 corrects that to the documented four-term estimate.
func productionNormalCompletion(
	storage string, cfg ServerConfig, partitions []PartitionMeta, declaredCapacity uint64,
) func(PartitionIdentity) (time.Duration, bool) {
	estimates := productionNormalCompletionEstimate(storage, cfg, partitions, declaredCapacity)
	return func(identity PartitionIdentity) (time.Duration, bool) {
		estimate, ok := estimates(identity)
		if !ok {
			return 0, false
		}
		return estimate.RequiredDuration, true
	}
}

// productionNormalCompletionEstimate exposes the exact G.3 terms to focused tests and
// observability without creating another arithmetic path.
func productionNormalCompletionEstimate(
	storage string, cfg ServerConfig, partitions []PartitionMeta, declaredCapacity uint64,
) func(PartitionIdentity) (SelectedWorkEstimate, bool) {
	registered := map[string]struct{}{}
	for _, partition := range partitions {
		coordinate := strings.ToLower(strings.TrimSpace(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)))
		if coordinate == "" {
			continue
		}
		registered[coordinate] = struct{}{}
	}
	plan, found, planErr := readCapacityBatchChunkPlan(storage)
	// G.4B evaluates qualified urgency BEFORE the ordinary durable plan is frozen:
	// `evaluateCapacityUrgencyPrecedence` runs ahead of `ensureCapacityIncrementalPlan` in the
	// scheduler, and the LV2 barrier deliberately withholds durable plan creation entirely. Reading
	// only the durable plan therefore left this resolver with nothing during exactly the window the
	// decision is made in, and it silently degraded to costing the successor as a LONE one-member
	// plan.
	//
	// Measured live (2026-08-12): every one of the 7 selected members reported 660 s that way,
	// while the real ordinary plan puts all 7 in ONE chunk whose completion is 4260 s. Predicate 2
	// compares against a 3600 s lifecycle deadline, so the degraded value made qualified urgency
	// unreachable under HOLD no matter which member the deletion targeted.
	//
	// Cost the plan production WOULD freeze, exactly as the precedence path already does. This is
	// the same read-only computation, not a second arithmetic path, and it freezes nothing.
	if !found && planErr == nil {
		if computed, _, _, ok, computeErr := computeCapacityIncrementalPlan(
			storage, cfg, partitions); computeErr == nil && ok && len(computed.Chunks) > 0 {
			plan, found = computed, true
		}
	}

	return func(identity PartitionIdentity) (SelectedWorkEstimate, bool) {
		key := strings.ToLower(strings.TrimSpace(identity.PartitionKey))
		if _, known := registered[key]; !known {
			// The obligation's identity is not in the current registered manifest. That is a
			// recovery condition, not a licence to estimate.
			return SelectedWorkEstimate{}, false
		}
		if planErr != nil {
			return SelectedWorkEstimate{}, false
		}

		selected := capacityBatchChunk{Index: 0, Keys: []string{key}}
		workingPlan := capacityBatchChunkPlan{
			Version: capacityBatchChunkPlanVersion, Mode: string(BatchModeIncremental),
			Chunks: []capacityBatchChunk{selected},
		}
		activeRemaining := time.Duration(0)
		var pending []capacityBatchChunk

		if found && len(plan.Chunks) > 0 {
			workingPlan = plan
			selected = capacityBatchChunk{Index: len(plan.Chunks), Keys: []string{key}}
			selectedFound := false
			for _, chunk := range plan.Chunks {
				for _, member := range chunk.Keys {
					if strings.EqualFold(member, key) {
						selected = chunk
						selectedFound = true
						break
					}
				}
				if selectedFound {
					break
				}
			}
			if !selectedFound {
				workingPlan.Chunks = append(append([]capacityBatchChunk(nil), plan.Chunks...), selected)
			}

			for _, chunk := range plan.Chunks {
				if chunk.Done || chunk.Index == selected.Index {
					continue
				}
				if chunk.Opened {
					activeEstimate, err := liveSelectedWorkEstimateForChunk(
						storage, partitions, plan, chunk, 0, nil, 0, declaredCapacity, cfg)
					if err != nil || !activeEstimate.PlanValid {
						return SelectedWorkEstimate{}, false
					}
					// The campaign is already active, so it has no pre-start queue delay. Its
					// remaining proof/submission/confirmation work is the active term.
					activeRemaining = activeEstimate.SelectedBatchEstimatedDuration
					continue
				}
				pending = append(pending, chunk)
			}
		}

		estimate, err := liveSelectedWorkEstimateForChunk(
			storage, partitions, workingPlan, selected, activeRemaining, pending,
			0, declaredCapacity, cfg)
		if err != nil || !estimate.PlanValid {
			return SelectedWorkEstimate{}, false
		}
		return estimate, true
	}
}

// ─── demand lifecycle ──────────────────────────────────────────────────────────────────

// reconcileBlockedDemandLifecycle marks demands ready for retry once ACTUAL G.5 capacity — not a
// projection — is sufficient. A demand is never consumed here; consumption happens only after a
// normal reservation succeeds.
func reconcileBlockedDemandLifecycle(storage string, observation ProjectedAdmission) (int, error) {
	demands, err := listBlockedDemands(storage)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	promoted := 0
	for _, demand := range demands {
		if !DemandStillPending(demand, now) {
			continue
		}
		if demand.State != BlockedDemandPending {
			continue
		}
		if demand.RequestedBytes > observation.CurrentSafeAllocatable {
			continue
		}
		if err := markBlockedDemandReadyForRetry(storage, demand.DemandID, now); err != nil {
			return promoted, err
		}
		promoted++
	}
	return promoted, nil
}

// ─── plan integration ──────────────────────────────────────────────────────────────────

// ensureUrgencyPriorityChunk makes the exact successor identity the next incremental chunk.
//
// It never rebinds an active campaign, never duplicates an already-selected identity, never
// widens membership beyond the one identity, and respects the G.2 32-member bound. If a chunk is
// already open, the identity is persisted as the next pending chunk so priority survives restart.
func ensureUrgencyPriorityChunk(
	storage string, identity PartitionIdentity, partitions []PartitionMeta,
) (bool, error) {
	inserted := false
	err := withCapacityBatchChunkLock(storage, func() error {
		var innerErr error
		inserted, innerErr = ensureUrgencyPriorityChunkLocked(storage, identity, partitions)
		return innerErr
	})
	return inserted, err
}

// ensureUrgencyPriorityChunkLocked performs the read-modify-write while holding the same plan
// lock used by ordinary freeze-if-absent creation. Qualified and ordinary NEW-plan ownership can
// therefore never overwrite each other in a cross-process race.
func ensureUrgencyPriorityChunkLocked(
	storage string, identity PartitionIdentity, partitions []PartitionMeta,
) (bool, error) {
	key := strings.ToLower(strings.TrimSpace(identity.PartitionKey))
	if key == "" {
		return false, fmt.Errorf("urgency identity has no partition key")
	}
	// The identity must be one exact CURRENT registered partition coordinate.
	coordinate := ""
	for _, partition := range partitions {
		candidate := strings.ToLower(strings.TrimSpace(epochPartitionKey(
			partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)))
		if candidate == key {
			coordinate = candidate
			break
		}
	}
	if coordinate == "" {
		// The urgent identity is not in the current manifest — a recovery condition. Do not
		// invent a plan entry for it.
		return false, nil
	}

	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil {
		return false, err
	}
	if !found || len(plan.Chunks) == 0 {
		plan = capacityBatchChunkPlan{
			Version:     capacityBatchChunkPlanVersion,
			Mode:        string(BatchModeIncremental),
			UrgencyKeys: []string{coordinate},
			Chunks: []capacityBatchChunk{{
				Index:             0,
				Keys:              []string{coordinate},
				FreshnessDeadline: true,
			}},
		}
		if !validCapacityBatchChunkPlan(plan) {
			return false, fmt.Errorf("constructed urgency plan is invalid")
		}
		return true, writeCapacityBatchChunkPlan(storage, plan)
	}

	// Already selected: add only the qualified-urgency provenance, never duplicate membership.
	for _, chunk := range plan.Chunks {
		for _, existing := range chunk.Keys {
			if strings.EqualFold(existing, coordinate) {
				for _, urgent := range plan.UrgencyKeys {
					if strings.EqualFold(urgent, coordinate) {
						return false, nil
					}
				}
				plan.UrgencyKeys = append(plan.UrgencyKeys, coordinate)
				return true, writeCapacityBatchChunkPlan(storage, plan)
			}
		}
	}
	// An open chunk is immutable. Append a new pending chunk so the urgent identity is next.
	for index, chunk := range plan.Chunks {
		if chunk.Opened || chunk.Done {
			continue
		}
		if len(chunk.Keys) >= MaxIncrementalBatchMembers {
			continue
		}
		plan.Chunks[index].Keys = append(plan.Chunks[index].Keys, coordinate)
		plan.Chunks[index].FreshnessDeadline = true
		plan.UrgencyKeys = append(plan.UrgencyKeys, coordinate)
		if !validCapacityBatchChunkPlan(plan) {
			return false, fmt.Errorf("urgency plan mutation is invalid")
		}
		return true, writeCapacityBatchChunkPlan(storage, plan)
	}
	plan.Chunks = append(plan.Chunks, capacityBatchChunk{
		Index:             len(plan.Chunks),
		Keys:              []string{coordinate},
		FreshnessDeadline: true,
	})
	plan.UrgencyKeys = append(plan.UrgencyKeys, coordinate)
	if !validCapacityBatchChunkPlan(plan) {
		return false, fmt.Errorf("appended urgency chunk is invalid")
	}
	return true, writeCapacityBatchChunkPlan(storage, plan)
}

// ─── scheduler hooks ───────────────────────────────────────────────────────────────────

// activeCampaignMembers returns the identities frozen into the currently active campaign. A
// member already selected is never duplicated by urgency.
func activeCampaignMembers(storage string, status CapacityProofEpochStatus) map[string]struct{} {
	members := map[string]struct{}{}
	if !status.Active {
		return members
	}
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil || !found || journal.EpochID != status.ProofEpochID {
		return members
	}
	for _, member := range journal.Members {
		key := strings.ToLower(strings.TrimSpace(epochPartitionKey(
			member.PartitionKind, member.DeadlineIndex, member.PartitionIndex)))
		if key != "" {
			members[key] = struct{}{}
		}
	}
	return members
}

// qualifiedUrgencyPromotesSelection reports whether urgency justifies opening an already-selected
// incremental plan that adaptive batching would otherwise keep waiting.
//
// It promotes ONLY when the urgent identity is already inside the pending chunk, so the campaign
// membership the scheduler validated is exactly the membership that opens.
func qualifiedUrgencyPromotesSelection(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	status CapacityProofEpochStatus,
	selected SelectedWorkEstimate,
) (QualifiedUrgencyResult, bool) {
	outcome := evaluateProductionQualifiedUrgency(
		storage, cfg, partitions, activeCampaignMembers(storage, status))
	if !outcome.Evaluated || !outcome.Result.Qualified {
		logQualifiedUrgency(outcome)
		return QualifiedUrgencyResult{}, false
	}
	if status.Active {
		// Another immutable campaign owns the lock. Persist priority for the next chunk and
		// do not rebind the active campaign.
		persistUrgencyPriority(storage, outcome.Result, partitions)
		return QualifiedUrgencyResult{}, false
	}
	plan, found, err := readCapacityBatchChunkPlan(storage)
	if err != nil || !found {
		return QualifiedUrgencyResult{}, false
	}
	chunk, ok := plan.nextPendingChunk()
	if !ok {
		return QualifiedUrgencyResult{}, false
	}
	urgentKey := strings.ToLower(strings.TrimSpace(outcome.Result.SelectedIdentity.PartitionKey))
	for _, key := range chunk.Keys {
		if strings.EqualFold(key, urgentKey) {
			logQualifiedUrgency(outcome)
			return outcome.Result, true
		}
	}
	// The urgent identity is not in the chunk that would open next. Persist its priority so the
	// following chunk carries it, but do not promote an unrelated selection.
	persistUrgencyPriority(storage, outcome.Result, partitions)
	return QualifiedUrgencyResult{}, false
}

// qualifiedUrgencyOpensSelection creates an exact single-identity incremental plan when urgency
// qualifies and no durable plan exists.
func qualifiedUrgencyOpensSelection(
	storage string,
	cfg ServerConfig,
	partitions []PartitionMeta,
	status CapacityProofEpochStatus,
	chainTimestamp, proofPeriodSeconds int64,
) (QualifiedUrgencyResult, SelectedWorkEstimate, bool) {
	outcome := evaluateProductionQualifiedUrgency(
		storage, cfg, partitions, activeCampaignMembers(storage, status))
	if !outcome.Evaluated || !outcome.Result.Qualified {
		logQualifiedUrgency(outcome)
		return QualifiedUrgencyResult{}, SelectedWorkEstimate{}, false
	}
	if outcome.Result.AlreadySelected || status.Active {
		// Never rebind or duplicate. Priority is persisted for the next eligible chunk.
		persistUrgencyPriority(storage, outcome.Result, partitions)
		return QualifiedUrgencyResult{}, SelectedWorkEstimate{}, false
	}
	if !persistUrgencyPriority(storage, outcome.Result, partitions) {
		return QualifiedUrgencyResult{}, SelectedWorkEstimate{}, false
	}
	// Re-derive the selected-work estimate from the durable plan that now exists, so the opened
	// campaign is validated by exactly the same G.3 path as any other incremental campaign.
	haveIncremental, _, _, selected, err := liveSelectedWorkDecision(
		storage, partitions, chainTimestamp, status.DeclaredCapacityBytes, cfg)
	if err != nil || !haveIncremental || !selected.PlanValid {
		return QualifiedUrgencyResult{}, SelectedWorkEstimate{}, false
	}
	if repErr := selectedPlanRepresentable(selected); repErr != nil {
		return QualifiedUrgencyResult{}, SelectedWorkEstimate{}, false
	}
	logQualifiedUrgency(outcome)
	return outcome.Result, selected, true
}

// persistUrgencyPriority records the urgent identity as the next eligible incremental chunk so
// the priority survives restart. It returns whether the plan now carries the identity.
func persistUrgencyPriority(
	storage string, result QualifiedUrgencyResult, partitions []PartitionMeta,
) bool {
	// TEST SCAFFOLD ONLY. The LV2 barrier must withhold EVERY durable stage-A persistence so the
	// acceptance run can observe all four predicates qualify while no plan and no campaign exist,
	// and only then release the barrier to test the real ownership race.
	//
	// `capacity_urgency_precedence.go` already honours it, but this route did not: in the live run
	// on 2026-08-12 the ordinary plan stayed held while the URGENT plan froze and opened its
	// campaign before the barrier was released, which defeated the intended sequencing. Inert in
	// production, which never sets these variables.
	if lv2IncrementalPlanCreationHeld() {
		return false
	}
	inserted, err := ensureUrgencyPriorityChunk(storage, result.SelectedIdentity, partitions)
	if err != nil {
		log.Printf("[capacity-urgency] urgent chunk priority deferred: %v", err)
		return false
	}
	if inserted {
		return true
	}
	// Not inserted because it is already present somewhere in the plan.
	plan, found, planErr := readCapacityBatchChunkPlan(storage)
	if planErr != nil || !found {
		return false
	}
	urgentKey := strings.ToLower(strings.TrimSpace(result.SelectedIdentity.PartitionKey))
	for _, chunk := range plan.Chunks {
		for _, key := range chunk.Keys {
			if strings.EqualFold(key, urgentKey) {
				return true
			}
		}
	}
	return false
}

// logQualifiedUrgency emits the aggregate-only observability surface. It never logs a demand id,
// capability token, requester reference, file identity or commitment hash.
func logQualifiedUrgency(outcome ProductionUrgencyOutcome) {
	if !outcome.Evaluated {
		if strings.TrimSpace(outcome.Detail) != "" {
			log.Printf("[capacity-urgency] evaluation failed closed (no urgency): %s", outcome.Detail)
		}
		return
	}
	fields := outcome.Result.LogFields()
	if outcome.Result.Qualified {
		estimate := outcome.CompletionEstimate
		projection := outcome.Result.Projection
		log.Printf("[capacity-urgency] qualifiedLifecycleUrgency=true batchTriggerReason=%v "+
			"campaignMode=%v selectedPlanValid=%v fullSweepReason=%v qualifiedUrgencyCount=%v "+
			"alreadySelected=%v selectedPartitionKey=%s observationBlock=%d observationTimestampUnix=%d requestedBytes=%d certifiedShortfall=%d currentSafeAllocatable=%d "+
			"ringFresh=%d ledgerFree=%d declaredCapacity=%d activeReservations=%d admissionMargin=%d "+
			"authoritativeReleaseBytes=%d projectedLedgerFree=%d projectedFreshCertifiedFree=%d "+
			"projectedSafeAllocatable=%d lifecycleDeadlineUnix=%d "+
			"activeCampaignRemainingSeconds=%d cumulativePendingDurationAheadSeconds=%d "+
			"selectedBatchEstimatedDurationSeconds=%d selectedQueueDelaySeconds=%d requiredDurationSeconds=%d",
			fields["batchTriggerReason"], fields["campaignMode"], fields["selectedPlanValid"],
			fields["fullSweepReason"], fields["qualifiedUrgencyCount"], fields["alreadySelected"],
			outcome.Result.SelectedIdentity.PartitionKey, projection.ObservationBlock,
			projection.ObservationTimestampUnix,
			outcome.RequestedBytes, outcome.CertifiedShortfall, projection.CurrentSafeAllocatable,
			projection.RingFresh, projection.LedgerFree, projection.DeclaredCapacity,
			projection.ActiveReservations, projection.AdmissionMargin,
			outcome.AuthoritativeReleaseBytes, projection.ProjectedLedgerFree,
			projection.ProjectedFreshCertifiedFree, projection.ProjectedSafeAllocatable,
			outcome.Result.LifecycleDeadline.Unix(),
			int64(estimate.ActiveCampaignRemainingDuration/time.Second),
			int64(estimate.CumulativePendingDuration/time.Second),
			int64(estimate.SelectedBatchEstimatedDuration/time.Second),
			int64(estimate.SelectedQueueDelay/time.Second),
			int64(estimate.RequiredDuration/time.Second))
		return
	}
	log.Printf("[capacity-urgency] qualifiedLifecycleUrgency=false reason=%v",
		fields["notQualifiedReason"])
}
