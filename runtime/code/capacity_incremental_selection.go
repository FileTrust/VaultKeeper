package main

// G.2 — Incremental Batch Membership.
//
// Routine capacity batches select only partitions that genuinely need proof:
//
//	needsProof ∪ recoveryRequired ∪ explicitAudit
//
// where needsProof is an ACTIVE partition whose current registered identity is not currently
// certified on chain — including a certification that has expired.
//
// The authority for "is this identity certified" is the frozen CapacityCertificationSC
// (G.1/G.1A). This file never re-derives, mirrors or re-encodes certification state: the
// canonical identity hash is computed BY the contract and compared to the record the contract
// stores. The local mutation journal is only a candidate source; chain truth decides final
// membership.
//
// Full sweeps remain available but are never a silent fallback: if incremental selection
// cannot be resolved safely, selection fails closed with an explicit recovery state.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ─── batch modes ───────────────────────────────────────────────────────────────────────

// CapacityBatchMode is the frozen on-chain numeric mode encoding retained by G.2 contracts.
// G.3C launch decisions use CapacityCampaignMode plus the independent FullSweepReason; this
// compatibility type must not be used as a scheduling trigger.
type CapacityBatchMode string

const (
	// BatchModeIncremental proves only the selected subset. It is the only routine mode.
	BatchModeIncremental CapacityBatchMode = "incremental"
	// BatchModeInitial is the first full proof of a manifest.
	BatchModeInitial CapacityBatchMode = "initial"
	// BatchModeExplicitAudit is an operator- or policy-requested re-proof of a stated scope.
	BatchModeExplicitAudit CapacityBatchMode = "explicit_audit"
	// BatchModeMigration is a cutover/redeploy re-proof against a new stack.
	BatchModeMigration CapacityBatchMode = "migration"
	// BatchModeRecoveryUncertain is entered only when reconciliation is genuinely ambiguous.
	BatchModeRecoveryUncertain CapacityBatchMode = "recovery_uncertain"
	// BatchModeFreshnessRecovery re-proves after freshness loss that incremental selection
	// cannot repair.
	BatchModeFreshnessRecovery CapacityBatchMode = "freshness_recovery"
	// BatchModeDeclaredCapacityRebuild re-proves only after a genuine declared-capacity
	// baseline rebuild. Routine manifest/content changes are incremental.
	BatchModeDeclaredCapacityRebuild CapacityBatchMode = "declared_capacity_rebuild"
	// BatchModeCapacityChange is retained as a source-compatible name; its value and semantics
	// are the narrowed declared-capacity rebuild mode.
	BatchModeCapacityChange = BatchModeDeclaredCapacityRebuild
)

// contract BATCH_MODE_* values (CapacityProofSC). Kept in one place so the Go and Solidity
// encodings cannot drift.
var capacityBatchModeOnChain = map[CapacityBatchMode]uint8{
	BatchModeIncremental:             1,
	BatchModeInitial:                 2,
	BatchModeExplicitAudit:           3,
	BatchModeMigration:               4,
	BatchModeRecoveryUncertain:       5,
	BatchModeFreshnessRecovery:       6,
	BatchModeDeclaredCapacityRebuild: 7,
}

// IsFullSweep reports whether the mode proves the whole active manifest.
func (m CapacityBatchMode) IsFullSweep() bool {
	return m != BatchModeIncremental && m.Valid()
}

// Valid reports whether the mode is one of the seven defined modes.
func (m CapacityBatchMode) Valid() bool {
	_, ok := capacityBatchModeOnChain[m]
	return ok
}

// OnChainMode returns the CapacityProofSC BATCH_MODE_* value for this mode.
func (m CapacityBatchMode) OnChainMode() (uint8, error) {
	value, ok := capacityBatchModeOnChain[m]
	if !ok {
		return 0, fmt.Errorf("capacity batch mode %q is not a defined mode", string(m))
	}
	return value, nil
}

// ─── identity and certification ────────────────────────────────────────────────────────

// PartitionIdentity is the exact current registered identity of one physical partition.
// Every field participates in the comparison against the on-chain certificate.
type PartitionIdentity struct {
	PartitionKey   string
	VK             string
	Kind           string // PartitionKindCapacity | PartitionKindData
	Active         bool
	ContentVersion uint64
	ContentHash    string
	CommittedBytes uint64
	// RegisteredAt is the chain timestamp at which this exact content version became
	// current. It is not part of the canonical identity hash; terminal aggregate
	// reconciliation uses it only to reject a certificate that predates the version it
	// claims to certify.
	RegisteredAt uint64
}

// PartitionCertificationRecord mirrors CapacityCertificationSC.partitionCertifications for
// reading only. It is never written locally and never used to reconstruct certification.
type PartitionCertificationRecord struct {
	Exists                bool
	VK                    string
	ProvedAt              uint64
	CertifiedExpirySlot   uint64
	CertifiedBytes        uint64
	CertifiedKind         string
	CertifiedIdentityHash string
}

// CapacityChainView is the read-only chain surface incremental selection depends upon.
// Every method must return an error rather than a zero value when chain state cannot be
// read: selection fails closed on any ambiguity.
type CapacityChainView interface {
	// CurrentIdentity resolves the latest current registered identity of a partition.
	CurrentIdentity(ctx context.Context, partitionKey string) (PartitionIdentity, error)
	// CertificationIdentityHash returns the CANONICAL hash computed by
	// CapacityCertificationSC.certificationIdentityHash. It must not be reimplemented here.
	CertificationIdentityHash(ctx context.Context, id PartitionIdentity) (string, error)
	// Certification returns the on-chain certificate record for a partition key.
	Certification(ctx context.Context, partitionKey string) (PartitionCertificationRecord, error)
	// CurrentCertificationSlot returns CapacityCertificationSC.currentCertificationSlot().
	CurrentCertificationSlot(ctx context.Context) (uint64, error)
	// ActivePartitionKeys lists every active registered partition key for this VK. Used by
	// full-sweep modes and by bounded reconciliation, never per scheduler tick.
	ActivePartitionKeys(ctx context.Context) ([]string, error)
}

// ErrChainStateUnreadable marks a fail-closed selection. Callers must surface an explicit
// recovery state; they must NEVER convert it into a full sweep.
var ErrChainStateUnreadable = errors.New("capacity batch selection: chain certification state unreadable")

// ─── selection reasons ─────────────────────────────────────────────────────────────────

type capacitySelectionReason string

const (
	selectionReasonNoCertification  capacitySelectionReason = "no_certification"
	selectionReasonIdentityMismatch capacitySelectionReason = "identity_mismatch"
	selectionReasonExpired          capacitySelectionReason = "expired"
	selectionReasonRecoveryRequired capacitySelectionReason = "recovery_required"
	selectionReasonAuditRequired    capacitySelectionReason = "audit_required"
	selectionReasonFullSweep        capacitySelectionReason = "full_sweep"

	exclusionReasonFreshCurrent capacitySelectionReason = "fresh_current"
	exclusionReasonInactive     capacitySelectionReason = "inactive"
)

// SelectedPartition is one frozen member of a batch.
type SelectedPartition struct {
	Identity PartitionIdentity
	Reason   capacitySelectionReason
	// MutationAge is the age of the oldest journal candidate that produced this member.
	// Zero when the member came from expiry, recovery or audit rather than a mutation.
	MutationAge time.Duration
}

// CapacityBatchSelection is the frozen result of one selection pass, including everything
// G.2 observability requires.
type CapacityBatchSelection struct {
	Mode CapacityBatchMode
	// FullSweepReason is non-empty exactly when Mode is a full sweep.
	FullSweepReason FullSweepReason

	Selected []SelectedPartition

	CandidateCount            int
	SelectedPartitionCount    int
	ExcludedFreshCount        int
	ExcludedInactiveCount     int
	ExpiredSelectedCount      int
	RecoverySelectedCount     int
	AuditSelectedCount        int
	SelectedBytes             uint64
	OldestSelectedMutationAge time.Duration
	// OldestPendingMutationAge is the oldest age over ALL pending deadline-bearing
	// candidates, selected or not (successors included). It is the binding input to the
	// latest-safe-start decision; OldestSelectedMutationAge alone is not sufficient.
	OldestPendingMutationAge time.Duration
}

// ShouldOpenBatch reports whether there is work. An empty selection must not open a batch
// and must never escalate to a full sweep.
func (s CapacityBatchSelection) ShouldOpenBatch() bool { return len(s.Selected) > 0 }

// SelectedKeys returns the frozen membership keys in deterministic order.
func (s CapacityBatchSelection) SelectedKeys() []string {
	keys := make([]string, 0, len(s.Selected))
	for _, member := range s.Selected {
		keys = append(keys, member.Identity.PartitionKey)
	}
	return keys
}

// ─── selection input ───────────────────────────────────────────────────────────────────

// BatchCandidate is one durable candidate produced by mutation, expiry, recovery or audit
// discovery. Several candidates for the same partition key coalesce into one member built
// from the LATEST current registered identity.
type BatchCandidate struct {
	PartitionKey     string
	MutationAge      time.Duration
	RecoveryRequired bool
	AuditRequired    bool
}

// CapacityBatchSelectionInput is everything a selection pass needs.
type CapacityBatchSelectionInput struct {
	Mode CapacityBatchMode
	// FullSweepReason must be set for a full-sweep mode; selection refuses to run without it,
	// so no sweep can occur without an explicit stated reason.
	FullSweepReason FullSweepReason
	// Candidates is used by incremental mode. Full-sweep modes ignore it and read the
	// active manifest from chain, except explicit_audit which uses AuditScope when set.
	Candidates []BatchCandidate
	// AuditScope restricts an explicit audit to a stated set of partition keys. Empty means
	// the complete active manifest.
	AuditScope []string
}

// SelectCapacityBatchMembership performs the frozen ten-step selection.
//
//  1. take durable candidates (mutation, expiry, recovery, audit)
//  2. deduplicate by physical partition key
//  3. resolve the latest current registered identity from chain
//  4. exclude inactive partitions from routine proving
//  5. query current certification
//  6. exclude exact-current fresh certifications
//  7. include only the latest current identity requiring proof
//  8. the caller freezes the returned membership and reason durably
//  9. the caller never adds members after cutoff
//  10. post-cutoff mutations become successors for a later batch
func SelectCapacityBatchMembership(
	ctx context.Context,
	chain CapacityChainView,
	input CapacityBatchSelectionInput,
) (CapacityBatchSelection, error) {
	if !input.Mode.Valid() {
		return CapacityBatchSelection{}, fmt.Errorf(
			"capacity batch selection: mode %q is not a defined mode", string(input.Mode))
	}
	if chain == nil {
		return CapacityBatchSelection{}, fmt.Errorf(
			"%w: no chain view configured", ErrChainStateUnreadable)
	}
	if input.Mode.IsFullSweep() {
		if strings.TrimSpace(string(input.FullSweepReason)) == "" {
			return CapacityBatchSelection{}, fmt.Errorf(
				"capacity batch selection: full-sweep mode %q requires an explicit reason",
				string(input.Mode))
		}
		return selectFullSweep(ctx, chain, input)
	}
	if strings.TrimSpace(string(input.FullSweepReason)) != "" {
		return CapacityBatchSelection{}, fmt.Errorf(
			"capacity batch selection: incremental mode must not carry a full-sweep reason")
	}
	return selectIncremental(ctx, chain, input)
}

// selectFullSweep returns the complete required manifest (or the requested audit scope).
// It is reached only through an explicitly requested full-sweep mode.
func selectFullSweep(
	ctx context.Context,
	chain CapacityChainView,
	input CapacityBatchSelectionInput,
) (CapacityBatchSelection, error) {
	keys := input.AuditScope
	if input.Mode != BatchModeExplicitAudit || len(keys) == 0 {
		listed, err := chain.ActivePartitionKeys(ctx)
		if err != nil {
			return CapacityBatchSelection{}, fmt.Errorf(
				"%w: listing active partitions: %v", ErrChainStateUnreadable, err)
		}
		keys = listed
	}
	selection := CapacityBatchSelection{
		Mode:            input.Mode,
		FullSweepReason: input.FullSweepReason,
		CandidateCount:  len(keys),
	}
	for _, key := range dedupeKeys(keys) {
		identity, err := chain.CurrentIdentity(ctx, key)
		if err != nil {
			return CapacityBatchSelection{}, fmt.Errorf(
				"%w: resolving identity for %s: %v", ErrChainStateUnreadable, key, err)
		}
		if !identity.Active {
			selection.ExcludedInactiveCount++
			continue
		}
		selection.Selected = append(selection.Selected, SelectedPartition{
			Identity: identity,
			Reason:   selectionReasonFullSweep,
		})
		selection.SelectedBytes += identity.CommittedBytes
	}
	sortSelection(selection.Selected)
	selection.SelectedPartitionCount = len(selection.Selected)
	return selection, nil
}

func selectIncremental(
	ctx context.Context,
	chain CapacityChainView,
	input CapacityBatchSelectionInput,
) (CapacityBatchSelection, error) {
	selection := CapacityBatchSelection{Mode: BatchModeIncremental}

	// 1–2. coalesce candidates by physical partition key. Several mutations to the same
	// partition collapse into one member; the oldest mutation age is retained for lag
	// reporting, and recovery/audit flags are unioned.
	coalesced := map[string]*BatchCandidate{}
	order := make([]string, 0, len(input.Candidates))
	for _, candidate := range input.Candidates {
		key := strings.ToLower(strings.TrimSpace(candidate.PartitionKey))
		if key == "" {
			continue
		}
		selection.CandidateCount++
		existing, ok := coalesced[key]
		if !ok {
			copied := candidate
			copied.PartitionKey = key
			coalesced[key] = &copied
			order = append(order, key)
			continue
		}
		if candidate.MutationAge > existing.MutationAge {
			existing.MutationAge = candidate.MutationAge
		}
		existing.RecoveryRequired = existing.RecoveryRequired || candidate.RecoveryRequired
		existing.AuditRequired = existing.AuditRequired || candidate.AuditRequired
	}

	currentSlot, err := chain.CurrentCertificationSlot(ctx)
	if err != nil {
		return CapacityBatchSelection{}, fmt.Errorf(
			"%w: reading current certification slot: %v", ErrChainStateUnreadable, err)
	}

	for _, key := range order {
		candidate := coalesced[key]

		// DEADLINE DOMINANCE (smoke9). Every pending deadline-bearing mutation mustinfluence
		// the scheduling decision on its own progress path, INCLUDING one this pass does
		// not select. A mutation that arrives after a plan freezes becomes a SUCCESSOR: it
		// is correctly excluded from the frozen membership, but its 1800 s hard-lag clock
		// is already running. Recording only the oldest SELECTED age let the scheduler
		// believe it had ~14m30s of slack while a successor was already at ~15m49s, and
		// the successors aged out (smoke9 VK1 2 stores, VK2 4 stores, both > 1800 s).
		//
		// This is observation only — it does NOT select the candidate and does NOT alter
		// frozen membership. It just makes the oldest pending age visible to the
		// latest-safe-start calculation so batching can never outlive a real deadline.
		if candidate.MutationAge > selection.OldestPendingMutationAge {
			selection.OldestPendingMutationAge = candidate.MutationAge
		}

		// 3. latest current registered identity — chain truth, not the journal's copy.
		identity, err := chain.CurrentIdentity(ctx, key)
		if err != nil {
			return CapacityBatchSelection{}, fmt.Errorf(
				"%w: resolving identity for %s: %v", ErrChainStateUnreadable, key, err)
		}

		// 4. an inactive partition is never selected for a routine proof.
		if !identity.Active {
			selection.ExcludedInactiveCount++
			continue
		}

		// 5. current certification, and the CANONICAL identity hash computed by the contract.
		record, err := chain.Certification(ctx, key)
		if err != nil {
			return CapacityBatchSelection{}, fmt.Errorf(
				"%w: reading certification for %s: %v", ErrChainStateUnreadable, key, err)
		}
		wantHash, err := chain.CertificationIdentityHash(ctx, identity)
		if err != nil {
			return CapacityBatchSelection{}, fmt.Errorf(
				"%w: computing canonical identity hash for %s: %v", ErrChainStateUnreadable, key, err)
		}

		reason, selected := incrementalSelectionReason(identity, record, wantHash, currentSlot, candidate)
		if !selected {
			selection.ExcludedFreshCount++
			continue
		}

		// 6–7. include the LATEST current identity requiring proof.
		selection.Selected = append(selection.Selected, SelectedPartition{
			Identity:    identity,
			Reason:      reason,
			MutationAge: candidate.MutationAge,
		})
		selection.SelectedBytes += identity.CommittedBytes
		switch reason {
		case selectionReasonExpired:
			selection.ExpiredSelectedCount++
		case selectionReasonRecoveryRequired:
			selection.RecoverySelectedCount++
		case selectionReasonAuditRequired:
			selection.AuditSelectedCount++
		}
		if candidate.MutationAge > selection.OldestSelectedMutationAge {
			selection.OldestSelectedMutationAge = candidate.MutationAge
		}
	}

	sortSelection(selection.Selected)
	selection.SelectedPartitionCount = len(selection.Selected)
	return selection, nil
}

// incrementalSelectionReason applies the frozen predicate to one candidate.
//
// Recovery and audit flags win over freshness — an explicitly flagged partition is proved
// even if its certificate still looks current — but they never override inactivity, which
// the caller has already filtered.
func incrementalSelectionReason(
	identity PartitionIdentity,
	record PartitionCertificationRecord,
	canonicalHash string,
	currentSlot uint64,
	candidate *BatchCandidate,
) (capacitySelectionReason, bool) {
	if candidate.RecoveryRequired {
		return selectionReasonRecoveryRequired, true
	}
	if candidate.AuditRequired {
		return selectionReasonAuditRequired, true
	}
	if !record.Exists || record.CertifiedExpirySlot == 0 {
		return selectionReasonNoCertification, true
	}
	// The certified identity must bind the partition key, VK, kind, active state, content
	// version, content hash and committed bytes. Six of those are inside the contract's
	// canonical hash; the VK is a separate field of the same on-chain record.
	if !strings.EqualFold(record.CertifiedIdentityHash, canonicalHash) ||
		!strings.EqualFold(record.VK, identity.VK) {
		return selectionReasonIdentityMismatch, true
	}
	if record.CertifiedExpirySlot <= currentSlot {
		return selectionReasonExpired, true
	}
	return exclusionReasonFreshCurrent, false
}

func dedupeKeys(keys []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func sortSelection(selected []SelectedPartition) {
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].Identity.PartitionKey < selected[j].Identity.PartitionKey
	})
}

// ─── observability ─────────────────────────────────────────────────────────────────────

// LogFields renders every field G.2 requires to be observable. A full sweep always carries
// its explicit reason.
func (s CapacityBatchSelection) LogFields() map[string]any {
	fields := map[string]any{
		"batchMode":                        string(s.Mode),
		"candidateCount":                   s.CandidateCount,
		"selectedPartitionCount":           s.SelectedPartitionCount,
		"excludedFreshCount":               s.ExcludedFreshCount,
		"excludedInactiveCount":            s.ExcludedInactiveCount,
		"expiredSelectedCount":             s.ExpiredSelectedCount,
		"recoverySelectedCount":            s.RecoverySelectedCount,
		"auditSelectedCount":               s.AuditSelectedCount,
		"selectedBytes":                    s.SelectedBytes,
		"oldestSelectedMutationAgeSeconds": int64(s.OldestSelectedMutationAge / time.Second),
	}
	if s.Mode.IsFullSweep() {
		fields["fullSweepReason"] = string(s.FullSweepReason)
	}
	return fields
}
