package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// C.1 storage-proof guaranteed floor + cumulative earliest-deadline-first admission.
//
// The protected resource is the single non-preemptible prover lane. Once a lower-priority job
// (capacity, deletion, recovery, routine, maintenance) starts it cannot be pre-empted, so the
// decision to start it must already guarantee that every protected storage-proof deadline can
// still be met.
//
// A single-job or single-horizon check is not sufficient: several storage proofs can share one
// window, so feasibility must hold at EVERY deadline prefix. For protected jobs sorted by
// ascending deadline, for every prefix ending at deadline d:
//
//	candidate conservative duration
//	  + Σ conservative durations of protected jobs due by d
//	  <= (d - now) - submission safety margin
//
// If that already fails with the candidate excluded, storage work alone is infeasible and the
// scheduler enters an explicit OVERLOAD state: lower-priority proving is blocked, the condition
// is exposed operationally, and the upload self-close/admission response is triggered.

// proofLaneSubmissionMargin reserves time for proof submission and chain inclusion after the
// prover finishes. It is deliberately conservative.
var proofLaneSubmissionMargin = 90 * time.Second

// edfJob is one unit of prover-lane work as the feasibility test sees it.
type edfJob struct {
	ID       string
	Class    string
	Deadline time.Time
	// Duration MUST be a conservative estimate (see conservativeProofDuration), never a raw mean.
	Duration time.Duration
}

// protectedProofClass reports whether a class holds the guaranteed storage-deadline floor.
func protectedProofClass(class string) bool { return class == proofClassDeadline }

// edfDecision is the outcome of one admission evaluation, including everything an operator needs.
type edfDecision struct {
	Admit    bool
	Overload bool
	Reason   string
	// The first deadline prefix that failed, with the numbers that made it fail.
	DeadlineUnix      int64
	RequiredSeconds   int64
	AvailableSeconds  int64
	ProtectedJobCount int
}

// orderProtectedByDeadline returns protected jobs in earliest-effective-deadline order. Ties are
// broken by ID so dispatch order is deterministic.
func orderProtectedByDeadline(jobs []edfJob) []edfJob {
	protected := make([]edfJob, 0, len(jobs))
	for _, job := range jobs {
		if protectedProofClass(job.Class) {
			protected = append(protected, job)
		}
	}
	sort.Slice(protected, func(i, j int) bool {
		if !protected[i].Deadline.Equal(protected[j].Deadline) {
			return protected[i].Deadline.Before(protected[j].Deadline)
		}
		return protected[i].ID < protected[j].ID
	})
	return protected
}

// evaluateProofLaneAdmission is pure. It decides whether `candidate` may occupy the
// non-preemptible prover lane given the pending protected storage work.
//
//   - A protected candidate is never blocked by this test: that is its guaranteed floor.
//   - A lower-priority candidate is admitted only when EVERY deadline prefix stays feasible —
//     so unused storage capacity remains borrowable, but never at the cost of a protected
//     deadline.
//   - When storage work alone already violates a prefix, the result is OVERLOAD.
func evaluateProofLaneAdmission(
	candidate edfJob, pending []edfJob, now time.Time, margin time.Duration,
) edfDecision {
	protected := orderProtectedByDeadline(pending)
	decision := edfDecision{ProtectedJobCount: len(protected)}

	// Storage-only feasibility first: this determines the overload state independently of any
	// lower-priority candidate.
	var cumulative time.Duration
	for _, job := range protected {
		cumulative += job.Duration
		available := job.Deadline.Sub(now) - margin
		if cumulative > available {
			decision.Overload = true
			decision.Admit = false
			decision.DeadlineUnix = job.Deadline.Unix()
			decision.RequiredSeconds = int64(cumulative.Seconds())
			decision.AvailableSeconds = int64(available.Seconds())
			decision.Reason = fmt.Sprintf(
				"storage proof work alone is infeasible by deadline %s: requires %s, %s available",
				job.Deadline.UTC().Format(time.RFC3339), cumulative.Round(time.Second), available.Round(time.Second),
			)
			return decision
		}
	}

	// The protected class keeps its floor: it is dispatched regardless of lower-priority load.
	if protectedProofClass(candidate.Class) {
		decision.Admit = true
		return decision
	}

	// A non-preemptible lower-priority job must fit inside EVERY prefix.
	cumulative = 0
	for _, job := range protected {
		cumulative += job.Duration
		available := job.Deadline.Sub(now) - margin
		if candidate.Duration+cumulative > available {
			decision.Admit = false
			decision.DeadlineUnix = job.Deadline.Unix()
			decision.RequiredSeconds = int64((candidate.Duration + cumulative).Seconds())
			decision.AvailableSeconds = int64(available.Seconds())
			decision.Reason = fmt.Sprintf(
				"%s job would endanger the storage deadline at %s: needs %s of %s available",
				candidate.Class, job.Deadline.UTC().Format(time.RFC3339),
				(candidate.Duration + cumulative).Round(time.Second), available.Round(time.Second),
			)
			return decision
		}
	}
	decision.Admit = true
	return decision
}

// ── Conservative duration estimation ──────────────────────────────────────────────────────────

// proofDurationPaddingFactor and proofDurationSigmas make the estimate conservative: an
// unpadded arithmetic mean would admit a long job that then overruns a deadline.
var (
	proofDurationPaddingFactor = 1.25
	proofDurationSigmas        = 3.0
	proofDurationFloor         = 30 * time.Second
)

// proofClassConservativeBound is the CONFIGURED restart-safe cold bound and the conservative anchor
// for progressive calibration. It is deliberately generous: with no durable history admission
// uses it in full, preventing an optimistic cold start from overrunning a protected deadline.
var proofClassConservativeBound = map[string]time.Duration{
	proofClassDeadline: 30 * time.Minute,
	proofClassCapacity: 45 * time.Minute,
	// C.1 cold starts. Derived from the frozen capacity bound rather than invented: a single
	// member cannot exceed the whole-campaign bound, a batch is bounded by it, and an audit
	// covers the entire manifest so it is deliberately the most pessimistic.
	proofClassCapacitySingle: 45 * time.Minute,
	proofClassCapacityBatch:  45 * time.Minute,
	proofClassCapacityAudit:  90 * time.Minute,
	proofClassDeletion:       20 * time.Minute,
	proofClassRoutine:        30 * time.Minute,
	proofClassMaintenance:    20 * time.Minute,
}

// proofClassDefaultBound applies to any class without an explicit entry.
var proofClassDefaultBound = 45 * time.Minute

// proofDurationCalibrationObservations is the number of durable same-class completions required
// before admission relies fully on the padded statistical estimate. Calibration is progressive:
// sample one still uses the complete configured bound, samples two through seven blend that bound
// down toward measured behavior, and sample eight reaches the statistical estimate. This avoids
// the unsafe alternatives of trusting one fast proof and treating seven consistent proofs as if
// there were no evidence at all.
const proofDurationCalibrationObservations = 8

// proofDurationSampleTTL makes stale estimator data fail conservatively.
var proofDurationSampleTTL = 30 * 24 * time.Hour

func conservativeBoundForClass(class string) time.Duration {
	if bound, ok := proofClassConservativeBound[class]; ok {
		return bound
	}
	return proofClassDefaultBound
}

// setProofDeadlineConservativeBound overrides the cold bound for protected storage-deadline
// proofs from configuration. It is called once during startup, before any prover or admission
// goroutine exists, but takes proofDurationMu anyway because that is the lock every production
// reader of the map already holds via conservativeProofDurationForClass.
//
// A non-positive value leaves the compiled default in place: an operator who omits the setting,
// or writes a zero, must not silently get an unbounded-optimistic cold start.
func setProofDeadlineConservativeBound(seconds int) {
	if seconds <= 0 {
		return
	}
	proofDurationMu.Lock()
	defer proofDurationMu.Unlock()
	proofClassConservativeBound[proofClassDeadline] = time.Duration(seconds) * time.Second
}

// conservativeProofDuration returns an estimate that is never below the largest observed sample,
// and is padded beyond mean + kσ. With no samples it returns a conservative floor. Callers that
// admit work must use conservativeProofDurationForClass, which additionally applies the
// restart-safe configured bound.
func conservativeProofDuration(samples []time.Duration) time.Duration {
	if len(samples) == 0 {
		return proofDurationFloor
	}
	var sum float64
	observedMax := time.Duration(0)
	for _, sample := range samples {
		if sample < 0 {
			sample = 0
		}
		sum += float64(sample)
		if sample > observedMax {
			observedMax = sample
		}
	}
	mean := sum / float64(len(samples))
	variance := 0.0
	for _, sample := range samples {
		diff := float64(sample) - mean
		variance += diff * diff
	}
	variance /= float64(len(samples))
	estimate := mean + proofDurationSigmas*math.Sqrt(variance)
	if float64(observedMax) > estimate {
		estimate = float64(observedMax)
	}
	padded := time.Duration(estimate * proofDurationPaddingFactor)
	if padded < proofDurationFloor {
		padded = proofDurationFloor
	}
	return padded
}

// ── Overload state: durable and operationally visible ─────────────────────────────────────────

const proofLaneOverloadVersion = 1

type proofLaneOverloadState struct {
	Version          int    `json:"version"`
	Active           bool   `json:"active"`
	Reason           string `json:"reason,omitempty"`
	DeadlineUnix     int64  `json:"deadlineUnix,omitempty"`
	RequiredSeconds  int64  `json:"requiredSeconds,omitempty"`
	AvailableSeconds int64  `json:"availableSeconds,omitempty"`
	ProtectedJobs    int    `json:"protectedJobs,omitempty"`
	EnteredAt        string `json:"enteredAt,omitempty"`
	ClearedAt        string `json:"clearedAt,omitempty"`
	UpdatedAt        string `json:"updatedAt"`

	// Stale is set by the reader (never persisted) when an active record's feasibility window has
	// already elapsed, so callers can report "expired cached overload" distinctly from "no overload".
	Stale bool `json:"-"`
}

func proofLaneOverloadPath(storage string) string {
	return filepath.Join(storage, "proof-lane-overload.json")
}

func readProofLaneOverload(storage string) (proofLaneOverloadState, bool, error) {
	payload, err := os.ReadFile(proofLaneOverloadPath(storage))
	if os.IsNotExist(err) {
		return proofLaneOverloadState{}, false, nil
	}
	if err != nil {
		return proofLaneOverloadState{}, false, err
	}
	var state proofLaneOverloadState
	if json.Unmarshal(payload, &state) != nil || state.Version != proofLaneOverloadVersion {
		return proofLaneOverloadState{}, false, nil
	}
	return state, true, nil
}

// recordProofLaneOverload persists an overload transition. Entering and clearing are both
// recorded so recovery from overload is observable, not just the failure.
func recordProofLaneOverload(storage string, decision edfDecision, now time.Time) error {
	previous, found, err := readProofLaneOverload(storage)
	if err != nil {
		return err
	}
	state := proofLaneOverloadState{
		Version: proofLaneOverloadVersion, Active: decision.Overload,
		UpdatedAt: now.UTC().Format(time.RFC3339Nano),
	}
	if decision.Overload {
		state.Reason = decision.Reason
		state.DeadlineUnix = decision.DeadlineUnix
		state.RequiredSeconds = decision.RequiredSeconds
		state.AvailableSeconds = decision.AvailableSeconds
		state.ProtectedJobs = decision.ProtectedJobCount
		state.EnteredAt = state.UpdatedAt
		if found && previous.Active && previous.EnteredAt != "" {
			state.EnteredAt = previous.EnteredAt // preserve when the overload began
		}
	} else {
		if found && previous.Active {
			state.ClearedAt = state.UpdatedAt
			state.EnteredAt = previous.EnteredAt
		} else if found {
			state.ClearedAt = previous.ClearedAt
			state.EnteredAt = previous.EnteredAt
		}
		if !found && !decision.Overload {
			// Nothing to record: no overload has ever been observed.
			return nil
		}
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(proofLaneOverloadPath(storage), payload, 0600)
}

// proofLaneOverloadActive reports the persisted overload state for admission and health. An
// unreadable state is treated as overloaded: it must never silently permit lower-priority work.
func proofLaneOverloadActive(storage string) (proofLaneOverloadState, bool) {
	return proofLaneOverloadActiveAt(storage, time.Now())
}

// proofLaneOverloadActiveAt is proofLaneOverloadActive with an injectable clock.
//
// SELF-LOCKING CACHED STATE (live 2026-08-23, VK9). The overload record is written from exactly one
// place — the prover-lane job-selection path (zk_prover.go) — so it is only ever recomputed when a
// proof job is dispatched. But an active record CLOSES admission, and closed admission means no new
// uploads, which means no new storage-proof work, which means no dispatch, which means the record is
// never recomputed. VK9 sat CLOSED for 3h49m on a record whose deadline had already passed 3h20m
// earlier: set on event A, cleared only on event B, while A itself prevents B.
//
// An overload decision is a statement about ONE feasibility window: "the protected storage work due
// by <deadline> cannot fit in the time remaining". Once that deadline has passed, the record is a
// description of a window that no longer exists — it is evidence about the past, never about current
// feasibility. Continuing to enforce it is unsound, so an expired record is reported as STALE (not
// active) and the next dispatch re-records the true current decision within one scan.
//
// This does NOT weaken the gate:
//   - A genuinely missed storage deadline is caught independently, and earlier, by
//     activeProofHealthFailure (certified_capacity_admission.go) — which closes admission with the
//     same reason from durable proof-health, not from this cache.
//   - A still-real overload is re-recorded by the very next dispatch, and protected storage work is
//     never gated by this filter in the first place.
//   - Fail-closed is preserved everywhere the truth cannot be established: an unreadable record, and
//     an active record carrying no authoritative deadline (DeadlineUnix <= 0), both stay ACTIVE.
func proofLaneOverloadActiveAt(storage string, now time.Time) (proofLaneOverloadState, bool) {
	state, found, err := readProofLaneOverload(storage)
	if err != nil {
		return proofLaneOverloadState{
			Active: true, Reason: "proof lane overload state unreadable: " + err.Error(),
		}, true
	}
	if !found {
		return proofLaneOverloadState{}, false
	}
	if !state.Active {
		return state, false
	}
	// Fail closed when the record carries no authoritative deadline: staleness is undecidable.
	if state.DeadlineUnix <= 0 {
		return state, true
	}
	if now.Unix() > state.DeadlineUnix {
		state.Stale = true
		return state, false
	}
	return state, true
}

// ── Dispatch filter ───────────────────────────────────────────────────────────────────────────

// admissibleProofJobs applies the C.1 gate to a dispatch candidate set. Protected storage jobs
// always survive; lower-priority jobs survive only while every deadline prefix stays feasible.
// It returns the filtered set plus the storage-only decision (for overload recording).
func admissibleProofJobs(jobs []ProofJob, durationFor func(ProofJob) time.Duration, now time.Time) ([]ProofJob, edfDecision) {
	// C.1 fail-closed: without a configured storage root the overload state cannot be persisted,
	// so admission and health would never see it. Admit protected storage work only.
	if !proofLaneConfigured() {
		protectedOnly := make([]ProofJob, 0, len(jobs))
		for _, job := range jobs {
			if protectedProofClass(job.Class) {
				protectedOnly = append(protectedOnly, job)
			}
		}
		return protectedOnly, edfDecision{
			Admit:  false,
			Reason: "proof resource controller is not configured; lower-priority proving is closed",
		}
	}
	pending := make([]edfJob, 0, len(jobs))
	for _, job := range jobs {
		if !protectedProofClass(job.Class) || job.DueUnixNano <= 0 {
			continue
		}
		pending = append(pending, edfJob{
			ID: job.ID, Class: job.Class,
			Deadline: time.Unix(0, job.DueUnixNano), Duration: durationFor(job),
		})
	}
	// Storage-only feasibility decides the overload state, independent of any candidate.
	storageOnly := evaluateProofLaneAdmission(
		edfJob{Class: proofClassDeadline}, pending, now, proofLaneSubmissionMargin,
	)
	admissible := make([]ProofJob, 0, len(jobs))
	for _, job := range jobs {
		if protectedProofClass(job.Class) {
			admissible = append(admissible, job) // guaranteed floor
			continue
		}
		if storageOnly.Overload {
			continue // overload blocks all lower-priority proving
		}
		candidate := edfJob{
			ID: job.ID, Class: job.Class, Duration: durationFor(job),
		}
		if job.DueUnixNano > 0 {
			candidate.Deadline = time.Unix(0, job.DueUnixNano)
		}
		if evaluateProofLaneAdmission(candidate, pending, now, proofLaneSubmissionMargin).Admit {
			admissible = append(admissible, job)
		}
	}
	return admissible, storageOnly
}

// ── Durable, restart-safe per-class duration estimator ────────────────────────────────────────
//
// The estimator summary is persisted atomically and reloaded before dispatch. Missing, unreadable,
// corrupt or stale data fails conservatively: the class falls back to its configured bound rather
// than to an optimistic floor.

const proofDurationEstimatorVersion = 1

type proofClassDurationSummary struct {
	Observations int     `json:"observations"`
	MaxNanos     int64   `json:"maxNanos"`
	SumNanos     int64   `json:"sumNanos"`
	SumSqNanos   float64 `json:"sumSqNanos"`
	UpdatedAt    string  `json:"updatedAt"`
}

type proofDurationEstimator struct {
	Version int                                  `json:"version"`
	Classes map[string]proofClassDurationSummary `json:"classes"`
}

var (
	proofDurationMu      sync.Mutex
	proofDurationLoaded  bool
	proofDurationState   = proofDurationEstimator{Version: proofDurationEstimatorVersion, Classes: map[string]proofClassDurationSummary{}}
	proofLaneStorageRoot string
)

func proofDurationEstimatorPath(storage string) string {
	return filepath.Join(storage, "proof-duration-estimator.json")
}

// loadProofDurationEstimatorLocked reloads the durable summary. Any failure leaves the state
// EMPTY, which makes every class fall back to its configured conservative bound.
func loadProofDurationEstimatorLocked(storage string) {
	proofDurationState = proofDurationEstimator{
		Version: proofDurationEstimatorVersion, Classes: map[string]proofClassDurationSummary{},
	}
	proofDurationLoaded = true
	if strings.TrimSpace(storage) == "" {
		return
	}
	payload, err := os.ReadFile(proofDurationEstimatorPath(storage))
	if err != nil {
		return // missing or unreadable → conservative bound
	}
	var loaded proofDurationEstimator
	if json.Unmarshal(payload, &loaded) != nil || loaded.Version != proofDurationEstimatorVersion || loaded.Classes == nil {
		return // corrupt → conservative bound
	}
	now := time.Now()
	for class, summary := range loaded.Classes {
		if updated, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(summary.UpdatedAt)); parseErr != nil ||
			now.Sub(updated) > proofDurationSampleTTL {
			continue // stale or undatable → conservative bound for that class
		}
		proofDurationState.Classes[class] = summary
	}
}

func persistProofDurationEstimatorLocked(storage string) {
	if strings.TrimSpace(storage) == "" {
		return
	}
	payload, err := json.MarshalIndent(proofDurationState, "", "  ")
	if err != nil {
		return
	}
	if err := durableAtomicWriteFile(proofDurationEstimatorPath(storage), payload, 0600); err != nil {
		log.Printf("[proof-lane] persist duration estimator: %v", err)
	}
}

// recordProofJobDuration folds one observed run into the durable per-class summary.
func recordProofJobDuration(class string, elapsed time.Duration) {
	if class == "" || elapsed <= 0 {
		return
	}
	proofDurationMu.Lock()
	defer proofDurationMu.Unlock()
	storage := proofLaneStorageRoot
	if !proofDurationLoaded {
		loadProofDurationEstimatorLocked(storage)
	}
	summary := proofDurationState.Classes[class]
	summary.Observations++
	summary.SumNanos += int64(elapsed)
	summary.SumSqNanos += float64(elapsed) * float64(elapsed)
	if int64(elapsed) > summary.MaxNanos {
		summary.MaxNanos = int64(elapsed)
	}
	summary.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	proofDurationState.Classes[class] = summary
	persistProofDurationEstimatorLocked(storage)
}

// calibratedProofDuration combines the padded observed distribution with the configured cold
// bound. The statistical side remains max-observation aware (mean + 3 sigma, then 25% padding).
// While evidence is accumulating, a linear calibration weight moves from 100% configured bound at
// sample one to 100% statistical estimate at sample eight. Observed runtimes above the configured
// bound are honored immediately; malformed summaries are rejected so callers can use the bound.
func calibratedProofDuration(bound time.Duration, summary proofClassDurationSummary) (time.Duration, bool) {
	if summary.Observations <= 0 || summary.MaxNanos <= 0 || summary.SumNanos < summary.MaxNanos ||
		summary.SumSqNanos <= 0 {
		return 0, false
	}
	minimumSumSq := float64(summary.SumNanos) * float64(summary.SumNanos) / float64(summary.Observations)
	minimumMaxSq := float64(summary.MaxNanos) * float64(summary.MaxNanos)
	squareTolerance := math.Max(minimumSumSq, minimumMaxSq) * 1e-9
	if summary.SumSqNanos+squareTolerance < minimumSumSq ||
		summary.SumSqNanos+squareTolerance < minimumMaxSq {
		return 0, false
	}
	mean := float64(summary.SumNanos) / float64(summary.Observations)
	variance := summary.SumSqNanos/float64(summary.Observations) - mean*mean
	if variance < 0 {
		// Small negative values are possible from floating-point cancellation. A materially invalid
		// summary still fails below when the resulting estimate is non-finite/non-positive.
		variance = 0
	}
	estimate := mean + proofDurationSigmas*math.Sqrt(variance)
	if float64(summary.MaxNanos) > estimate {
		estimate = float64(summary.MaxNanos)
	}
	paddedFloat := estimate * proofDurationPaddingFactor
	const maxDuration = time.Duration(1<<63 - 1)
	if math.IsNaN(paddedFloat) || math.IsInf(paddedFloat, 0) || paddedFloat <= 0 ||
		paddedFloat > float64(maxDuration) {
		return 0, false
	}
	padded := time.Duration(paddedFloat)
	if padded < proofDurationFloor {
		padded = proofDurationFloor
	}
	// Refining UP is always immediate. Full downward calibration still requires the original
	// eight observations; only the previous seven-sample cliff is removed.
	if padded >= bound || summary.Observations >= proofDurationCalibrationObservations {
		return padded, true
	}
	if summary.Observations == 1 {
		return bound, true
	}
	progress := float64(summary.Observations-1) / float64(proofDurationCalibrationObservations-1)
	calibrated := float64(bound) + (float64(padded)-float64(bound))*progress
	if calibrated < float64(padded) {
		calibrated = float64(padded)
	}
	return time.Duration(calibrated), true
}

// conservativeProofDurationForClass is the value admission uses. Missing, stale, unreadable, or
// malformed evidence uses the full configured restart-safe bound. Durable evidence progressively
// calibrates downward without a 7→8 all-or-nothing transition.
func conservativeProofDurationForClass(class string) time.Duration {
	proofDurationMu.Lock()
	defer proofDurationMu.Unlock()
	if !proofDurationLoaded {
		loadProofDurationEstimatorLocked(proofLaneStorageRoot)
	}
	bound := conservativeBoundForClass(class)
	summary, ok := proofDurationState.Classes[class]
	if !ok {
		return bound // missing / unreadable / corrupt / stale → configured bound
	}
	calibrated, valid := calibratedProofDuration(bound, summary)
	if !valid {
		return bound
	}
	return calibrated
}

// conservativeProofJobDuration is the estimate the EDF test uses for one job.
func conservativeProofJobDuration(job ProofJob) time.Duration {
	return conservativeProofDurationForClass(job.Class)
}

// setProofLaneStorageRoot configures the prover lane. Until this is called with a non-empty root
// the lane is UNCONFIGURED and dispatch fails closed (see admissibleProofJobs).
func setProofLaneStorageRoot(storage string) {
	proofDurationMu.Lock()
	defer proofDurationMu.Unlock()
	proofLaneStorageRoot = strings.TrimSpace(storage)
	// Reload the durable estimator immediately so the FIRST post-restart admission decision
	// already uses restored history rather than an empty window.
	loadProofDurationEstimatorLocked(proofLaneStorageRoot)
}

func currentProofLaneStorageRoot() string {
	proofDurationMu.Lock()
	defer proofDurationMu.Unlock()
	return proofLaneStorageRoot
}

// proofLaneConfigured reports whether the resource controller has supplied a storage root. Until
// it has, overload cannot be persisted, so lower-priority dispatch must not proceed.
func proofLaneConfigured() bool { return currentProofLaneStorageRoot() != "" }
