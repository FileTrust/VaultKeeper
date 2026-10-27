package main

// G.3 — selected-work duration estimation and bounded batching.
//
// The defect this replaces, measured in D.1 and still present in
// `capacityBatchThresholdReached`:
//
//	estimate := capacityEpochProofEstimate(partitions, ...)   // sums the WHOLE manifest
//	signals.AverageProofTime = estimate                       // a total, named as an average
//	required := AverageProofTime + queueDelay + SubmissionSafety
//	if OldestMutationAge + required >= MaxOldestMutationAge { launch }
//
// With 13 partitions and one mutated, `required` is thirteen partitions of work, so the hard-lag
// gate fires at mutation age ≈ 1 s and a 2 MiB write starts a full proof campaign immediately.
//
// G.3 estimates ONLY the frozen selected identities from G.2, so a small mutation waits for a
// real reason. Nothing here touches membership, certification, admission or any contract: this
// is off-chain VK scheduling and estimation only.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ─── named metrics ─────────────────────────────────────────────────────────────────────
//
// An average and a total never share a field. Every duration below is a TOTAL over the
// selected members unless its name says otherwise.

// SelectedWorkEstimate is the complete costing of one incremental chunk plus the backlog
// ahead of it. Every field is exposed for observability.
type SelectedWorkEstimate struct {
	BatchPlanID  string
	CampaignMode CapacityBatchMode

	CandidateCount         int
	SelectedPartitionCount int
	SelectedBytes          uint64
	ExcludedFresh          int
	ExcludedInactive       int

	// SelectedProofGenerationDuration is Σ conservativeMemberEstimate over the selected
	// members — never over the manifest.
	SelectedProofGenerationDuration time.Duration
	SelectedSubmissionDuration      time.Duration
	SelectedConfirmationMargin      time.Duration
	SelectedQueueDelay              time.Duration
	SelectedBatchEstimatedDuration  time.Duration

	ActiveCampaignRemainingDuration time.Duration
	CumulativePendingDuration       time.Duration
	RequiredDuration                time.Duration

	OldestSelectedMutationAge time.Duration
	// OldestPendingMutationAge is the oldest age over ALL pending deadline-bearing
	// mutations, including SUCCESSORS this pass did not select. It is the binding input to
	// LatestSafeStartIn; see the deadline-dominance note at the calculation below.
	OldestPendingMutationAge time.Duration
	// ProjectedCertificationDuration is the COMPLETE time still required to certify the
	// oldest pending mutation: work ahead PLUS that mutation own campaign when it is not a
	// member of the selected batch. Zero until RebindLatestSafeStart runs.
	ProjectedCertificationDuration    time.Duration
	EarliestSelectedCertificateExpiry time.Duration
	LatestSafeStartIn                 time.Duration

	EffectiveMaxPendingBytes uint64
	BatchTriggerReason       BatchTriggerReason

	// PlanValid is true only when every selected identity was resolved. A partially known
	// plan must never launch a campaign (G.3B).
	PlanValid bool
}

// ─── per-member estimation ─────────────────────────────────────────────────────────────

// SelectedWorkPolicy carries everything the estimate needs that is not part of the selection.
type SelectedWorkPolicy struct {
	// ColdStartMemberDuration is the conservative per-SELECTED-MEMBER estimate used until
	// enough observations exist. It is per member, never a manifest-derived division.
	ColdStartMemberDuration time.Duration
	// MinimumMemberDuration floors every member estimate, so no member ever costs zero.
	MinimumMemberDuration time.Duration
	SubmissionDuration    time.Duration
	ConfirmationMargin    time.Duration
	// PerQueuedJobDelay multiplies the prover queue depth.
	PerQueuedJobDelay time.Duration
	ProofQueueDepth   int

	HardMutationLagLimit time.Duration
	Debounce             time.Duration
	MaxBatchAge          time.Duration
	MaxPendingMutations  int
	MaxTouchedPartitions int
	MaxBacklogDuration   time.Duration

	PendingBytes     RelativePendingBytesPolicy
	DeclaredCapacity uint64
}

// ProofShapeKey identifies HOW LONG a proof is expected to take. It deliberately binds only
// the factors that materially affect prover work — partition kind and sector count, matching
// the durable key the prover already writes (`<kind>-final-n<sectors>`) — and deliberately
// excludes content version, content hash and certification identity.
//
// The two concepts are separate and must stay separate:
//   - the exact selected identity (G.2) decides WHAT must be proved;
//   - the proof-shape key (here) decides HOW LONG proving it is expected to take.
//
// A newly mutated partition has a brand-new certification identity but the SAME proof shape,
// so it can reuse a real measurement. Keying the estimator by identity would make every
// mutation cold by construction, which is exactly the inconsistency this closes.
type ProofShapeKey string

// proofShapeKeyFor mirrors proof_scheduler.go's class construction byte for byte, so the read
// and write sides of the durable estimator cannot drift apart.
func proofShapeKeyFor(partitionKind string, sectorCount int) ProofShapeKey {
	return ProofShapeKey(fmt.Sprintf("%s-final-n%d", partitionKind, sectorCount))
}

// memberDurationLookup returns a durable observed generation estimate for one proof SHAPE, and
// whether a valid one exists. Missing, zero, negative or corrupt observations must report
// false so the caller falls back conservatively.
type memberDurationLookup func(shape ProofShapeKey) (time.Duration, bool)

// conservativeMemberEstimate costs one selected member.
//
// Fails conservative in every direction: a missing, zero, negative or absurd observation
// becomes the configured cold-start bound, and every result is floored so no member is free.
func conservativeMemberEstimate(
	shape ProofShapeKey,
	lookup memberDurationLookup,
	policy SelectedWorkPolicy,
) time.Duration {
	coldStart := policy.ColdStartMemberDuration
	if coldStart <= 0 {
		coldStart = defaultColdStartMemberDuration
	}
	minimum := policy.MinimumMemberDuration
	if minimum <= 0 {
		minimum = defaultMinimumMemberDuration
	}
	estimate := coldStart
	if lookup != nil {
		if observed, ok := lookup(shape); ok && observed > 0 {
			estimate = observed
		}
	}
	if estimate < minimum {
		estimate = minimum
	}
	return estimate
}

// maxDuration marks a saturated duration sum.
const maxDuration = time.Duration(math.MaxInt64)

const (
	// A single 16-sector partition proof measured ~45 s in D.1; 10 minutes is a deliberately
	// pessimistic cold start, so an unmeasured VK over-reserves rather than under-reserves.
	defaultColdStartMemberDuration = 10 * time.Minute
	defaultMinimumMemberDuration   = 30 * time.Second
)

// addDurationSaturating adds without overflowing.
func addDurationSaturating(a, b time.Duration) time.Duration {
	if a < 0 {
		a = 0
	}
	if b < 0 {
		b = 0
	}
	if a > math.MaxInt64-b {
		return time.Duration(math.MaxInt64)
	}
	return a + b
}

func multiplyDurationSaturating(count int, duration time.Duration) time.Duration {
	if count <= 0 || duration <= 0 {
		return 0
	}
	if int64(count) > math.MaxInt64/int64(duration) {
		return maxDuration
	}
	return time.Duration(count) * duration
}

// ─── relative pending-byte threshold ───────────────────────────────────────────────────

// RelativePendingBytesPolicy replaces the accidental absolute-only default. The threshold
// scales with declared capacity, clamped so a small VK does not use its whole capacity as the
// trigger and a large VK is not forced to launch on an insignificant fraction.
type RelativePendingBytesPolicy struct {
	Fraction float64
	Floor    uint64
	Ceiling  uint64
}

// Defaults chosen from the representative sizes required by G.3 (see the plan for the table):
//
//	capacity   fraction×capacity   effective (clamped)
//	200 MiB          10 MiB            64 MiB   ← floor
//	  1 GiB          51.2 MiB          64 MiB   ← floor
//	 10 GiB         512 MiB           512 MiB
//	100 GiB           5 GiB              4 GiB  ← ceiling
//
// A ~2 MiB routine mutation is 3.1% of the 64 MiB floor, so it never trips the threshold at any
// size; a genuine backlog still crosses it; and the initial full-capacity build is an explicit
// `initial` campaign that does not consult this threshold at all.
var defaultRelativePendingBytesPolicy = RelativePendingBytesPolicy{
	Fraction: 0.05,
	Floor:    64 << 20, // 64 MiB
	Ceiling:  4 << 30,  // 4 GiB
}

// EffectiveMaxPendingBytes = clamp(ceil(capacity × fraction), floor, ceiling).
func (p RelativePendingBytesPolicy) EffectiveMaxPendingBytes(declaredCapacity uint64) uint64 {
	policy := p
	if policy.Fraction <= 0 {
		policy.Fraction = defaultRelativePendingBytesPolicy.Fraction
	}
	if policy.Floor == 0 {
		policy.Floor = defaultRelativePendingBytesPolicy.Floor
	}
	if policy.Ceiling == 0 || policy.Ceiling < policy.Floor {
		policy.Ceiling = defaultRelativePendingBytesPolicy.Ceiling
	}
	scaled := uint64(math.Ceil(float64(declaredCapacity) * policy.Fraction))
	if scaled < policy.Floor {
		scaled = policy.Floor
	}
	if scaled > policy.Ceiling {
		scaled = policy.Ceiling
	}
	return scaled
}

// ─── cumulative backlog ────────────────────────────────────────────────────────────────

// PendingChunkCost is one durable chunk's remaining estimated work.
type PendingChunkCost struct {
	Index     int
	Remaining time.Duration
	Done      bool
	// Reconstructed is false when the chunk could not be rebuilt from durable state; the
	// estimate then fails conservative by charging the cold-start bound for a full chunk.
	Reconstructed bool
	MemberCount   int
}

// CumulativePendingDuration sums the ordered pending chunks ahead of the one being evaluated.
// ActiveCampaignRemainingDuration is a separate RequiredDuration term; keeping it out of this
// sum makes the frozen four-term equation independently observable without double counting.
// Completed chunks contribute zero; a chunk that cannot be reconstructed is charged
// conservatively rather than skipped.
func CumulativePendingDuration(
	chunks []PendingChunkCost,
	policy SelectedWorkPolicy,
) time.Duration {
	coldStart := policy.ColdStartMemberDuration
	if coldStart <= 0 {
		coldStart = defaultColdStartMemberDuration
	}
	total := time.Duration(0)
	seen := map[int]struct{}{}
	for _, chunk := range chunks {
		if _, duplicate := seen[chunk.Index]; duplicate {
			continue // each pending chunk counts exactly once
		}
		seen[chunk.Index] = struct{}{}
		if chunk.Done {
			continue // completed chunks have zero remaining
		}
		remaining := chunk.Remaining
		if !chunk.Reconstructed {
			members := chunk.MemberCount
			if members <= 0 {
				members = MaxIncrementalBatchMembers
			}
			remaining = multiplyDurationSaturating(members, coldStart)
		}
		total = addDurationSaturating(total, remaining)
	}
	return total
}

// ─── the estimate ──────────────────────────────────────────────────────────────────────

// EstimateSelectedWork costs exactly the frozen selected identities, never the manifest.
// shapeResolver maps a selected identity to its proof shape. The live scheduler supplies the
// registered PartitionMeta; a nil resolver falls back to the configured cold start.
type shapeResolver func(identity PartitionIdentity) (ProofShapeKey, bool)

func EstimateSelectedWork(
	selection CapacityBatchSelection,
	shapes shapeResolver,
	lookup memberDurationLookup,
	activeCampaignRemaining time.Duration,
	pendingAhead []PendingChunkCost,
	policy SelectedWorkPolicy,
) SelectedWorkEstimate {
	estimate := SelectedWorkEstimate{
		CampaignMode:              selection.Mode,
		CandidateCount:            selection.CandidateCount,
		SelectedPartitionCount:    selection.SelectedPartitionCount,
		SelectedBytes:             selection.SelectedBytes,
		ExcludedFresh:             selection.ExcludedFreshCount,
		ExcludedInactive:          selection.ExcludedInactiveCount,
		OldestSelectedMutationAge: selection.OldestSelectedMutationAge,
		OldestPendingMutationAge:  selection.OldestPendingMutationAge,
	}

	// Σ over the SELECTED members only. Fresh-excluded, inactive and unselected partitions
	// contribute nothing, and a partition mutated several times contributes once — the
	// selection already coalesced it to its latest identity.
	for _, member := range selection.Selected {
		var shape ProofShapeKey
		if shapes != nil {
			if resolved, ok := shapes(member.Identity); ok {
				shape = resolved
			}
		}
		effective := lookup
		if shape == "" {
			effective = nil // unknown shape ⇒ conservative cold start, never a guess
		}
		estimate.SelectedProofGenerationDuration = addDurationSaturating(
			estimate.SelectedProofGenerationDuration,
			conservativeMemberEstimate(shape, effective, policy),
		)
	}

	estimate.SelectedSubmissionDuration = policy.SubmissionDuration
	estimate.SelectedConfirmationMargin = policy.ConfirmationMargin
	if policy.ProofQueueDepth > 0 && policy.PerQueuedJobDelay > 0 {
		estimate.SelectedQueueDelay = multiplyDurationSaturating(
			policy.ProofQueueDepth, policy.PerQueuedJobDelay)
	}

	estimate.SelectedBatchEstimatedDuration = addDurationSaturating(
		addDurationSaturating(
			estimate.SelectedProofGenerationDuration, estimate.SelectedSubmissionDuration),
		estimate.SelectedConfirmationMargin)

	estimate.ActiveCampaignRemainingDuration = activeCampaignRemaining
	estimate.CumulativePendingDuration =
		CumulativePendingDuration(pendingAhead, policy)

	estimate.RequiredDuration = addDurationSaturating(
		addDurationSaturating(
			addDurationSaturating(estimate.ActiveCampaignRemainingDuration,
				estimate.CumulativePendingDuration),
			estimate.SelectedBatchEstimatedDuration),
		estimate.SelectedQueueDelay)

	estimate.EffectiveMaxPendingBytes =
		policy.PendingBytes.EffectiveMaxPendingBytes(policy.DeclaredCapacity)

	estimate.PlanValid = true
	// DEADLINE DOMINANCE (smoke9 VK1/VK2). The binding deadline is the MOST RESTRICTIVE
	// over every pending deadline-bearing mutation whose certification depends on this
	// scheduling decision — not merely the ones this pass selected.
	//
	// Successors (mutations that arrived after a plan froze) are correctly excluded from
	// frozen membership, but their 1800 s hard-lag clock is already running and only a
	// future campaign can certify them. Using OldestSelectedMutationAge alone let the
	// scheduler defer on the selected plan's budget while a successor was already past its
	// own deadline: live evidence showed latestSafeStartIn=14m30s while oldestAge=15m49s,
	// and VK1/VK2 finished with 2 and 4 uncertified stores at >1800 s.
	//
	// Taking the max preserves batching: with genuine slack the value is unchanged and the
	// debounce still applies. It only prevents waiting past a deadline that already exists.
	bindingAge := estimate.OldestSelectedMutationAge
	if estimate.OldestPendingMutationAge > bindingAge {
		bindingAge = estimate.OldestPendingMutationAge
	}
	estimate.LatestSafeStartIn = latestSafeStartIn(
		policy.HardMutationLagLimit, estimate.RequiredDuration, bindingAge)
	return estimate
}

// latestSafeStartAge = hardLimit - requiredDuration, saturating at zero.
func latestSafeStartAge(hardLimit, required time.Duration) time.Duration {
	if hardLimit <= 0 {
		return 0
	}
	if required >= hardLimit {
		return 0
	}
	return hardLimit - required
}

// latestSafeStartIn is how long the batch may still wait: latestSafeStartAge - currentAge,
// saturating at zero (meaning "start now").
func latestSafeStartIn(hardLimit, required, oldestAge time.Duration) time.Duration {
	safeAge := latestSafeStartAge(hardLimit, required)
	if oldestAge >= safeAge {
		return 0
	}
	return safeAge - oldestAge
}

// ─── trigger precedence ────────────────────────────────────────────────────────────────

// BatchTriggerReason is the single primary reason a batch launched, or why it did not.
type BatchTriggerReason string

const (
	TriggerRecoveryEmergency    BatchTriggerReason = "recovery_emergency"
	TriggerSelectedFreshness    BatchTriggerReason = "selected_freshness_deadline"
	TriggerSelectedWorkOverload BatchTriggerReason = "selected_work_overload"
	TriggerHardLagLatestStart   BatchTriggerReason = "hard_lag_latest_start"
	TriggerMaxBatchAge          BatchTriggerReason = "max_batch_age"
	TriggerPendingByteThreshold BatchTriggerReason = "pending_byte_threshold"
	TriggerDirtyPartitionCount  BatchTriggerReason = "dirty_partition_threshold"
	TriggerMutationCount        BatchTriggerReason = "mutation_count_threshold"
	TriggerBacklogDuration      BatchTriggerReason = "backlog_duration_threshold"
	TriggerDebounceElapsed      BatchTriggerReason = "normal_debounce_elapsed"
	TriggerNotDue               BatchTriggerReason = "not_due"
	TriggerNoSelectedWork       BatchTriggerReason = "no_selected_work"
)

// BatchTriggerInputs are the observations the precedence ladder consults. Every field that
// used to be an unconditional bypass is now an ordinary input with a default of false.
type BatchTriggerInputs struct {
	RecoveryEmergency bool
	// QualifiedLifecycleUrgency is the G.4 hook. It defaults false: empty-deletion state alone
	// is NOT urgency, and its qualification and release dependency belong to G.4.
	QualifiedLifecycleUrgency bool
	// RegisteredManifestChanged is candidate discovery only — never a batching bypass.
	RegisteredManifestChanged bool
	// EmptyDeletionPending is observed, never acted on here.
	EmptyDeletionPending bool
	// CatchupPending is unrelated to admission closure and is not a batching emergency.
	CatchupPending bool

	PendingBytes      uint64
	PendingMutations  int
	TouchedPartitions int
	BatchAge          time.Duration
}

// EvaluateBatchTrigger applies the deterministic precedence ladder and returns exactly one
// primary reason.
func EvaluateBatchTrigger(
	estimate SelectedWorkEstimate,
	inputs BatchTriggerInputs,
	policy SelectedWorkPolicy,
) (bool, BatchTriggerReason) {
	// An empty selection never launches and never escalates to a full sweep.
	if estimate.SelectedPartitionCount == 0 {
		return false, TriggerNoSelectedWork
	}
	switch {
	case inputs.RecoveryEmergency:
		return true, TriggerRecoveryEmergency

	case estimate.EarliestSelectedCertificateExpiry > 0 &&
		estimate.EarliestSelectedCertificateExpiry <= estimate.SelectedBatchEstimatedDuration:
		return true, TriggerSelectedFreshness

	// The selected work alone cannot fit inside the hard limit. Surfaced distinctly and never
	// silently converted into a full sweep.
	case policy.HardMutationLagLimit > 0 &&
		estimate.SelectedBatchEstimatedDuration >= policy.HardMutationLagLimit:
		return true, TriggerSelectedWorkOverload

	// Start early enough to FINISH inside the hard limit — not because the manifest is large.
	case policy.HardMutationLagLimit > 0 && estimate.OldestSelectedMutationAge > 0 &&
		estimate.OldestSelectedMutationAge >=
			latestSafeStartAge(policy.HardMutationLagLimit, estimate.RequiredDuration):
		return true, TriggerHardLagLatestStart

	case policy.MaxBatchAge > 0 && inputs.BatchAge >= policy.MaxBatchAge:
		return true, TriggerMaxBatchAge

	case estimate.EffectiveMaxPendingBytes > 0 &&
		inputs.PendingBytes >= estimate.EffectiveMaxPendingBytes:
		return true, TriggerPendingByteThreshold

	case policy.MaxTouchedPartitions > 0 &&
		inputs.TouchedPartitions >= policy.MaxTouchedPartitions:
		return true, TriggerDirtyPartitionCount

	case policy.MaxPendingMutations > 0 &&
		inputs.PendingMutations >= policy.MaxPendingMutations:
		return true, TriggerMutationCount

	case policy.MaxBacklogDuration > 0 &&
		estimate.CumulativePendingDuration >= policy.MaxBacklogDuration:
		return true, TriggerBacklogDuration

	case policy.Debounce > 0 && estimate.OldestSelectedMutationAge >= policy.Debounce:
		return true, TriggerDebounceElapsed
	}
	return false, TriggerNotDue
}

// ─── urgency ordering ──────────────────────────────────────────────────────────────────

// PendingWorkItem is one candidate awaiting a launch decision.
type PendingWorkItem struct {
	PartitionKey     string
	RecoveryRequired bool
	// CertificateExpiresIn is zero when the partition holds no live certificate, which sorts
	// as maximum urgency.
	CertificateExpiresIn time.Duration
	MutationAge          time.Duration
}

// OrderPendingWork applies the G.3 urgency order, ending in the partition-key tie-breaker
// frozen in G.2.
//
//	recovery urgency → certificate-expiry urgency → oldest mutation age → partition key
//
// The partition-key comparison is ONLY the final deterministic tie-breaker; it is not a
// scheduling priority.
func OrderPendingWork(items []PendingWorkItem) []PendingWorkItem {
	ordered := append([]PendingWorkItem(nil), items...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.RecoveryRequired != b.RecoveryRequired {
			return a.RecoveryRequired
		}
		if a.CertificateExpiresIn != b.CertificateExpiresIn {
			return a.CertificateExpiresIn < b.CertificateExpiresIn
		}
		if a.MutationAge != b.MutationAge {
			return a.MutationAge > b.MutationAge
		}
		return a.PartitionKey < b.PartitionKey
	})
	return ordered
}

// ─── observability ─────────────────────────────────────────────────────────────────────

// LogFields renders every G.3 metric. No whole-manifest value is ever printed under a
// selected-work label.
func (e SelectedWorkEstimate) LogFields() map[string]any {
	seconds := func(d time.Duration) int64 { return int64(d / time.Second) }
	return map[string]any{
		"batchPlanId":                       e.BatchPlanID,
		"campaignMode":                      string(e.CampaignMode),
		"candidateCount":                    e.CandidateCount,
		"selectedPartitionCount":            e.SelectedPartitionCount,
		"selectedBytes":                     e.SelectedBytes,
		"excludedFresh":                     e.ExcludedFresh,
		"excludedInactive":                  e.ExcludedInactive,
		"activeCampaignRemainingDuration":   seconds(e.ActiveCampaignRemainingDuration),
		"cumulativePendingDuration":         seconds(e.CumulativePendingDuration),
		"selectedProofGenerationDuration":   seconds(e.SelectedProofGenerationDuration),
		"selectedSubmissionDuration":        seconds(e.SelectedSubmissionDuration),
		"selectedConfirmationMargin":        seconds(e.SelectedConfirmationMargin),
		"selectedQueueDelay":                seconds(e.SelectedQueueDelay),
		"selectedBatchEstimatedDuration":    seconds(e.SelectedBatchEstimatedDuration),
		"requiredDuration":                  seconds(e.RequiredDuration),
		"oldestSelectedMutationAge":         seconds(e.OldestSelectedMutationAge),
		"oldestPendingMutationAge":          seconds(e.OldestPendingMutationAge),
		"earliestSelectedCertificateExpiry": seconds(e.EarliestSelectedCertificateExpiry),
		"latestSafeStartIn":                 seconds(e.LatestSafeStartIn),
		"effectiveMaxPendingBytes":          e.EffectiveMaxPendingBytes,
		"batchTriggerReason":                string(e.BatchTriggerReason),
	}
}

// String renders a one-line summary for human logs.
func (e SelectedWorkEstimate) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "selected=%d/%d bytes=%d excludedFresh=%d selectedWork=%s required=%s "+
		"oldestAge=%s latestSafeStartIn=%s reason=%s",
		e.SelectedPartitionCount, e.CandidateCount, e.SelectedBytes, e.ExcludedFresh,
		e.SelectedBatchEstimatedDuration.Round(time.Second),
		e.RequiredDuration.Round(time.Second),
		e.OldestSelectedMutationAge.Round(time.Second),
		e.LatestSafeStartIn.Round(time.Second),
		string(e.BatchTriggerReason))
	return b.String()
}

// RebindLatestSafeStart recomputes LatestSafeStartIn for a TRUE oldest pending mutation age
// that the caller learned after EstimateSelectedWork returned.
//
// TWO DEFECTS THIS CLOSES (both proven by smoke9, run d3vk-s9-20260816T1457Z)
//
//  1. STALE DERIVED VALUE. capacity_epoch_batch.go overwrote
//     estimate.OldestSelectedMutationAge with the authoritative oldest pending age from the
//     capacity-proof-lag snapshot, but LatestSafeStartIn had ALREADY been derived from the
//     selection's own (selected-only) age and was never recomputed. The live log shows the
//     two bases side by side: oldestAge=15m49s latestSafeStartIn=14m30s.
//
//  2. INCOMPLETE SERVICE TIME. The invariant is not
//     "age + RequiredDuration(current work) <= limit" but
//     "age + work ahead + THAT MUTATION'S OWN campaign/proof/submission/confirmation
//     <= limit". A mutation older than every selected member is by definition NOT a member
//     of the frozen batch, so it needs a FURTHER campaign after the current work drains.
//     Counting only the current RequiredDuration understates its projected certification:
//     age 15m + current 8m            = 23m  -> looks safe
//     age 15m + current 8m + own 10m  = 33m  -> actually impossible under 30m
//     ownServiceDuration below is that missing term.
//
// It never lengthens a wait: it can only reduce LatestSafeStartIn (start earlier), and with
// genuine slack the value is unchanged, so batching/debounce behaviour is preserved.
func (e SelectedWorkEstimate) RebindLatestSafeStart(
	oldestPendingAge time.Duration, hardLimit time.Duration,
) SelectedWorkEstimate {
	if oldestPendingAge <= 0 {
		return e
	}
	e.OldestPendingMutationAge = oldestPendingAge
	required := e.RequiredDuration
	// A mutation older than every selected member is not in this batch: charge one further
	// campaign of its own before it can certify.
	if oldestPendingAge > e.OldestSelectedMutationAge {
		required = addDurationSaturating(required, e.ownServiceDuration())
	}
	e.ProjectedCertificationDuration = required
	rebound := latestSafeStartIn(hardLimit, required, oldestPendingAge)
	if rebound < e.LatestSafeStartIn {
		e.LatestSafeStartIn = rebound
	}
	return e
}

// ownServiceDuration is the cost of the additional campaign an unselected/successor mutation
// still needs. The selected batch's own estimated duration is the best available
// representative of one campaign's proof+submission+confirmation cost; the cold-start floor
// prevents a zero estimate from erasing the term entirely.
func (e SelectedWorkEstimate) ownServiceDuration() time.Duration {
	own := e.SelectedBatchEstimatedDuration
	if own < defaultColdStartMemberDuration {
		own = defaultColdStartMemberDuration
	}
	return own
}
