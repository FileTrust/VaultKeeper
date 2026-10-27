package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	proofJobQueued  = "queued"
	proofJobRunning = "running"
	proofJobFailed  = "failed"

	proofClassDeletion = "deletion"
	proofClassCapacity = "capacity"
	// C.1 (G.6): capacity work is split into three INDEPENDENT duration classes so a fast
	// one-partition refresh never teaches the scheduler that a full audit is fast, and a slow
	// audit never makes a single refresh look impossibly slow. Scheduling weight/priority/wait
	// are deliberately IDENTICAL to proofClassCapacity — only the duration history differs.
	// Classification is by WORK TYPE (campaign mode + selected member count), never by observed
	// duration. `proofClassCapacity` itself remains only as the legacy/compat label.
	proofClassCapacitySingle = "capacity_single"
	proofClassCapacityBatch  = "capacity_batch"
	proofClassCapacityAudit  = "capacity_audit"
	proofClassDeadline       = "storage_deadline"
	proofClassRoutine        = "storage_routine"
	proofClassMaintenance    = "maintenance"
)

var (
	ErrProofJobBackoff   = errors.New("proof job is in retry backoff")
	ErrProofJobExhausted = errors.New("proof job retry limit reached")
	ErrProofJobCancelled = errors.New("proof job was cancelled or superseded")
)

type proofJobJournal struct {
	Version                 int                 `json:"version"`
	Jobs                    map[string]ProofJob `json:"jobs"`
	AuthoritativeGeneration map[string]string   `json:"authoritativeGeneration"`
	DispatchedByClass       map[string]uint64   `json:"dispatchedByClass"`
	ClassCredit             map[string]int64    `json:"classCredit"`
}

func proofJobJournalPath(lockPath string) string     { return lockPath + ".jobs.json" }
func proofJobJournalLockPath(lockPath string) string { return lockPath + ".jobs.lock" }

func normalizeProofJobIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func proofJobID(vkIdentity, class, work, generation string) string {
	identity := strings.Join([]string{
		normalizeProofJobIdentity(vkIdentity),
		normalizeProofJobIdentity(class),
		strings.TrimSpace(work),
		strings.TrimSpace(generation),
	}, "\x00")
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:16])
}

func proofJobAuthorityKey(vkIdentity, scope string) string {
	identity := normalizeProofJobIdentity(vkIdentity)
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:8]) + "|" + strings.TrimSpace(scope)
}

func currentProofJobVKIdentity() (string, error) {
	identity := normalizeProofJobIdentity(os.Getenv(proofJobVKIdentityEnv))
	if identity == "" {
		return "", fmt.Errorf("%s is required for host-wide proof scheduling", proofJobVKIdentityEnv)
	}
	return identity, nil
}

func canonicalProofClass(class string, due, now time.Time) string {
	class = strings.ToLower(strings.TrimSpace(class))
	switch {
	case strings.HasPrefix(class, "deletion"):
		return proofClassDeletion
	case class == proofClassCapacitySingle:
		return proofClassCapacitySingle
	case class == proofClassCapacityBatch:
		return proofClassCapacityBatch
	case class == proofClassCapacityAudit:
		return proofClassCapacityAudit
	case strings.HasPrefix(class, "capacity"):
		return proofClassCapacity
	case class == "background" || strings.HasPrefix(class, "maintenance"):
		return proofClassMaintenance
	case strings.HasPrefix(class, "data") || strings.HasPrefix(class, "storage"):
		if !due.IsZero() && due.Sub(now) <= 30*time.Minute {
			return proofClassDeadline
		}
		return proofClassRoutine
	default:
		return proofClassRoutine
	}
}

// isCapacityProofClass reports whether a class is any capacity duration class. Scheduling
// treats them identically; only their durable duration histories are separate.
func isCapacityProofClass(class string) bool {
	switch class {
	case proofClassCapacity, proofClassCapacitySingle, proofClassCapacityBatch, proofClassCapacityAudit:
		return true
	}
	return false
}

// capacityProofDurationClass maps WORK TYPE to a C.1 duration class. A full sweep is always an
// audit regardless of its FullSweepReason; otherwise one selected member is single work and more
// than one is batch work. It never inspects how long anything took.
func capacityProofDurationClass(fullSweep bool, selectedMembers int) string {
	if fullSweep {
		return proofClassCapacityAudit
	}
	if selectedMembers <= 1 {
		return proofClassCapacitySingle
	}
	return proofClassCapacityBatch
}

func proofClassWeight(class string) int64 {
	switch class {
	case proofClassDeletion:
		return 8
	case proofClassCapacity, proofClassCapacitySingle, proofClassCapacityBatch, proofClassCapacityAudit:
		return 6
	case proofClassDeadline:
		return 4
	case proofClassRoutine:
		return 2
	default:
		return 1
	}
}

func proofClassPriority(class string) int64 {
	switch class {
	case proofClassDeletion:
		return 50
	case proofClassCapacity, proofClassCapacitySingle, proofClassCapacityBatch, proofClassCapacityAudit:
		return 40
	case proofClassDeadline:
		return 35
	case proofClassRoutine:
		return 15
	default:
		return 5
	}
}

func proofClassMaxWait(class string) time.Duration {
	switch class {
	case proofClassDeletion:
		return 2 * time.Minute
	case proofClassCapacity, proofClassCapacitySingle, proofClassCapacityBatch, proofClassCapacityAudit:
		return 5 * time.Minute
	case proofClassDeadline:
		return 10 * time.Minute
	case proofClassRoutine:
		return 30 * time.Minute
	default:
		return time.Hour
	}
}

func proofRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		return 0
	}
	delay := time.Second << min(attempt-1, 8)
	if delay > 5*time.Minute {
		return 5 * time.Minute
	}
	return delay
}

func readProofJobJournal(path string) (proofJobJournal, error) {
	journal := proofJobJournal{Version: 2, Jobs: map[string]ProofJob{}, AuthoritativeGeneration: map[string]string{}, DispatchedByClass: map[string]uint64{}, ClassCredit: map[string]int64{}}
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return journal, nil
	}
	if err != nil {
		return journal, err
	}
	if err := json.Unmarshal(payload, &journal); err != nil {
		return journal, fmt.Errorf("decode proof job journal: %w", err)
	}
	if journal.Jobs == nil {
		journal.Jobs = map[string]ProofJob{}
	}
	if journal.AuthoritativeGeneration == nil {
		journal.AuthoritativeGeneration = map[string]string{}
	}
	if journal.DispatchedByClass == nil {
		journal.DispatchedByClass = map[string]uint64{}
	}
	if journal.ClassCredit == nil {
		journal.ClassCredit = map[string]int64{}
	}
	if journal.Version < 2 {
		// Version 1 used only generation/work labels, so a record could not be
		// attributed safely to one VK after restart. The underlying immutable
		// snapshot journals reconstruct this work; discard only the ambiguous
		// scheduling envelopes and rebuild scoped authority on re-enqueue.
		for id, job := range journal.Jobs {
			if normalizeProofJobIdentity(job.VKIdentity) == "" {
				delete(journal.Jobs, id)
			}
		}
		journal.AuthoritativeGeneration = map[string]string{}
		journal.Version = 2
	}
	return journal, nil
}

func withProofJobJournal(lockPath string, write bool, fn func(*proofJobJournal) error) error {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(proofJobJournalLockPath(lockPath), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	journal, err := readProofJobJournal(proofJobJournalPath(lockPath))
	if err != nil {
		return err
	}
	if err := fn(&journal); err != nil {
		return err
	}
	if !write {
		return nil
	}
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(proofJobJournalPath(lockPath), payload, 0600)
}

func recoverAbandonedProofJobs(journal *proofJobJournal, now time.Time) {
	for id, job := range journal.Jobs {
		if job.State != proofJobRunning {
			continue
		}
		alive := job.OwnerPID > 0 && syscall.Kill(job.OwnerPID, 0) != syscall.ESRCH
		if alive && job.OwnerStart != "" {
			alive = linuxProcessStartToken(job.OwnerPID) == job.OwnerStart
		}
		if alive {
			continue
		}
		job.State = proofJobQueued
		job.OwnerPID = 0
		job.OwnerStart = ""
		job.UpdatedUnixNano = now.UnixNano()
		job.NextAttemptNano = now.UnixNano()
		job.LastError = "proof worker exited before completion"
		journal.Jobs[id] = job
	}
}

func enqueueProofJob(lockPath, vkIdentity, generation, scope, work, class, resource string, due, now time.Time) (ProofJob, error) {
	vkIdentity = normalizeProofJobIdentity(vkIdentity)
	identityClass := normalizeProofJobIdentity(class)
	if vkIdentity == "" || identityClass == "" || strings.TrimSpace(work) == "" || strings.TrimSpace(generation) == "" {
		return ProofJob{}, fmt.Errorf("proof job identity requires VK, class, work, and generation")
	}
	id := proofJobID(vkIdentity, identityClass, work, generation)
	authorityKey := proofJobAuthorityKey(vkIdentity, scope)
	var result ProofJob
	err := withProofJobJournal(lockPath, true, func(journal *proofJobJournal) error {
		recoverAbandonedProofJobs(journal, now)
		for otherID, other := range journal.Jobs {
			if otherID != id && normalizeProofJobIdentity(other.VKIdentity) == vkIdentity && other.Scope == scope && other.Resource == resource && other.State != proofJobRunning {
				delete(journal.Jobs, otherID) // the new immutable generation supersedes it
			}
		}
		journal.AuthoritativeGeneration[authorityKey] = generation
		if existing, ok := journal.Jobs[id]; ok {
			if existing.State == proofJobFailed {
				result = existing
				return fmt.Errorf("%w after %d attempts: %s", ErrProofJobExhausted, existing.Attempts, existing.LastError)
			}
			if due.UnixNano() > 0 && (existing.DueUnixNano == 0 || due.UnixNano() < existing.DueUnixNano) {
				existing.DueUnixNano = due.UnixNano()
			}
			existing.UpdatedUnixNano = now.UnixNano()
			journal.Jobs[id] = existing
			result = existing
			if existing.NextAttemptNano > now.UnixNano() {
				return fmt.Errorf("%w until %s", ErrProofJobBackoff, time.Unix(0, existing.NextAttemptNano).Format(time.RFC3339Nano))
			}
			return nil
		}
		result = ProofJob{
			ID: id, VKIdentity: vkIdentity, IdentityClass: identityClass,
			Generation: generation, Scope: scope, Work: work,
			Class: canonicalProofClass(class, due, now), Resource: resource,
			State: proofJobQueued, CreatedUnixNano: now.UnixNano(), UpdatedUnixNano: now.UnixNano(),
			DueUnixNano: due.UnixNano(), MaxAttempts: 5,
		}
		journal.Jobs[id] = result
		if _, ok := journal.ClassCredit[result.Class]; !ok {
			journal.ClassCredit[result.Class] = 0
		}
		return nil
	})
	return result, err
}

func proofJobGenerationAuthoritativeForVK(lockPath, vkIdentity, scope, generation string) (bool, error) {
	authoritative := false
	err := withProofJobJournal(lockPath, false, func(journal *proofJobJournal) error {
		authoritative = journal.AuthoritativeGeneration[proofJobAuthorityKey(vkIdentity, scope)] == generation
		return nil
	})
	return authoritative, err
}

func proofJobGenerationAuthoritative(lockPath, scope, generation string) (bool, error) {
	vkIdentity, err := currentProofJobVKIdentity()
	if err != nil {
		return false, err
	}
	return proofJobGenerationAuthoritativeForVK(lockPath, vkIdentity, scope, generation)
}

func proofJobScopeAuthorityForVK(lockPath, vkIdentity, scope string) (string, bool, error) {
	var generation string
	err := withProofJobJournal(lockPath, false, func(journal *proofJobJournal) error {
		generation = journal.AuthoritativeGeneration[proofJobAuthorityKey(vkIdentity, scope)]
		return nil
	})
	return generation, generation != "", err
}

func proofJobScopeAuthority(lockPath, scope string) (string, bool, error) {
	vkIdentity, err := currentProofJobVKIdentity()
	if err != nil {
		return "", false, err
	}
	return proofJobScopeAuthorityForVK(lockPath, vkIdentity, scope)
}

func proofJobQueuedOrRunning(lockPath, id string) bool {
	found := false
	_ = withProofJobJournal(lockPath, false, func(journal *proofJobJournal) error {
		job, ok := journal.Jobs[id]
		found = ok && (job.State == proofJobQueued || job.State == proofJobRunning)
		return nil
	})
	return found
}

func activeProofJobs(lockPath, resource string, activeIDs map[string]bool, now time.Time) ([]ProofJob, error) {
	var jobs []ProofJob
	err := withProofJobJournal(lockPath, false, func(journal *proofJobJournal) error {
		for _, job := range journal.Jobs {
			if job.Resource == resource && job.State == proofJobQueued && activeIDs[job.ID] && job.NextAttemptNano <= now.UnixNano() {
				jobs = append(jobs, job)
			}
		}
		return nil
	})
	return jobs, err
}

func selectProofJob(jobs []ProofJob, dispatched map[string]uint64, credit map[string]int64, now time.Time) (ProofJob, bool) {
	if len(jobs) == 0 {
		return ProofJob{}, false
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].ID < jobs[j].ID })
	best := jobs[0]
	bestBounded, bestScore := false, int64(-1<<62)
	for _, job := range jobs {
		age := now.Sub(time.Unix(0, job.CreatedUnixNano))
		if age < 0 {
			age = 0
		}
		bounded := age >= proofClassMaxWait(job.Class)
		// Smooth weighted round-robin credit is the primary fairness signal;
		// class priority decides the initial/equal-credit dispatch and deadlines
		// can still overtake the share order as their lag grows.
		score := credit[job.Class]*100 + proofClassPriority(job.Class)
		score += int64(age / (10 * time.Second))
		if job.DueUnixNano > 0 && now.UnixNano() > job.DueUnixNano {
			lag := now.Sub(time.Unix(0, job.DueUnixNano))
			multiplier := int64(1)
			if isCapacityProofClass(job.Class) {
				multiplier = 2
			}
			score += multiplier * int64(lag/time.Second)
		}
		if bounded {
			score = int64(age/proofClassMaxWait(job.Class))*1_000_000 + int64(age/time.Second)
		}
		if bounded && !bestBounded || bounded == bestBounded && (score > bestScore || score == bestScore && job.ID < best.ID) {
			best, bestBounded, bestScore = job, bounded, score
		}
	}
	_ = dispatched // retained in the journal as an explicit externally visible share metric
	return best, true
}

func startProofJob(lockPath, id string, now time.Time) error {
	return withProofJobJournal(lockPath, true, func(journal *proofJobJournal) error {
		job, ok := journal.Jobs[id]
		if !ok || job.State != proofJobQueued {
			return fmt.Errorf("proof job %s is no longer queued", id)
		}
		job.State = proofJobRunning
		job.Attempts++
		job.OwnerPID = os.Getpid()
		job.OwnerStart = linuxProcessStartToken(os.Getpid())
		job.UpdatedUnixNano = now.UnixNano()
		journal.Jobs[id] = job
		journal.DispatchedByClass[job.Class]++
		totalWeight := int64(0)
		for class := range journal.ClassCredit {
			journal.ClassCredit[class] += proofClassWeight(class)
			totalWeight += proofClassWeight(class)
		}
		if _, ok := journal.ClassCredit[job.Class]; !ok {
			journal.ClassCredit[job.Class] = proofClassWeight(job.Class)
			totalWeight += proofClassWeight(job.Class)
		}
		journal.ClassCredit[job.Class] -= totalWeight
		return nil
	})
}

func finishProofJob(lockPath, id string, runErr error, now time.Time) error {
	return withProofJobJournal(lockPath, true, func(journal *proofJobJournal) error {
		// C.1: feed the observed run time into the conservative duration estimator.
		if job, ok := journal.Jobs[id]; ok && job.UpdatedUnixNano > 0 {
			recordProofJobDuration(job.Class, now.Sub(time.Unix(0, job.UpdatedUnixNano)))
		}
		job, ok := journal.Jobs[id]
		if !ok {
			return nil
		}
		if runErr == nil {
			delete(journal.Jobs, id)
			return nil
		}
		for otherID, other := range journal.Jobs {
			if otherID != id && normalizeProofJobIdentity(other.VKIdentity) == normalizeProofJobIdentity(job.VKIdentity) && other.Scope == job.Scope && other.Resource == job.Resource {
				// A newer immutable generation exists. Never retry this stale one.
				delete(journal.Jobs, id)
				return nil
			}
		}
		job.OwnerPID, job.OwnerStart = 0, ""
		job.UpdatedUnixNano = now.UnixNano()
		job.LastError = runErr.Error()
		if job.Attempts >= job.MaxAttempts {
			job.State = proofJobFailed
			job.NextAttemptNano = 0
		} else {
			job.State = proofJobQueued
			job.NextAttemptNano = now.Add(proofRetryDelay(job.Attempts)).UnixNano()
		}
		journal.Jobs[id] = job
		return nil
	})
}

func cancelProofJob(lockPath, id string) error {
	return withProofJobJournal(lockPath, true, func(journal *proofJobJournal) error {
		if job, ok := journal.Jobs[id]; ok && job.State == proofJobRunning {
			return fmt.Errorf("cannot cancel indivisible running proof job %s", id)
		}
		if job, ok := journal.Jobs[id]; ok {
			authorityKey := proofJobAuthorityKey(job.VKIdentity, job.Scope)
			if journal.AuthoritativeGeneration[authorityKey] == job.Generation {
				delete(journal.AuthoritativeGeneration, authorityKey)
			}
			delete(journal.Jobs, id)
		}
		return nil
	})
}

func dataPartitionCoordinatesFromProofScope(scope string) (int, int, bool) {
	var deadlineIndex, partitionIndex int
	for _, format := range []string{
		"partition-data-dl%d-pt%d",
		"snapshot-data-dl%d-pt%d",
	} {
		if _, err := fmt.Sscanf(scope, format, &deadlineIndex, &partitionIndex); err != nil {
			continue
		}
		expected := fmt.Sprintf(format, deadlineIndex, partitionIndex)
		if expected == scope && deadlineIndex >= 0 && partitionIndex >= 0 {
			return deadlineIndex, partitionIndex, true
		}
	}
	return 0, 0, false
}

// retireProofJobsForDeadDataPartitions removes scheduler envelopes which can
// never acquire another waiter because their local data partition has become
// terminal. A running proof remains indivisible and is deliberately untouched.
//
// The job journal is host-wide, so cleanup is restricted to this VK identity.
// A coordinate is dead when the durable sector catalog holds NO live sector for it.
//
// Live 2026-08-23 (fresh9, VK6 dl7-pt0 + VK10 dl38-pt0): the earlier rule also required the
// coordinate to still be "known" in the catalog, i.e. a sector record present but marked deleted.
// That only covers the MIDDLE of a deletion. When a deletion fully completes the sector files are
// removed, so `known` became false, the job was skipped, and it stayed queued forever — the more
// completely the deletion succeeded, the more permanently its proof job was stranded. Drain then
// never reaches zero. Absence of any live sector is the terminal condition, so absence of the
// record entirely must retire the job too.
//
// Safety: an empty/unreadable catalog must not mass-retire. listSectors errors already return
// above, and we additionally refuse to treat "no sectors at all" as evidence that every coordinate
// is dead.
func retireProofJobsForDeadDataPartitions(storage string) (int, error) {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return 0, nil
	}
	vkIdentity, err := currentProofJobVKIdentity()
	if err != nil {
		return 0, err
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return 0, err
	}
	type coordinate struct{ deadline, partition int }
	assigned := 0
	live := map[coordinate]bool{}
	for _, sector := range sectors {
		if !sector.PartitionAssigned {
			continue
		}
		assigned++
		key := coordinate{sector.DeadlineIndex, sector.PartitionIndex}
		if sector.Status != "deleted" {
			live[key] = true
		}
	}
	// Fail closed: with no partition-assigned sector at all the catalog carries no evidence about
	// any coordinate, so retiring on it would be guessing.
	if assigned == 0 {
		return 0, nil
	}
	retired := 0
	err = withProofJobJournal(lockPath, true, func(journal *proofJobJournal) error {
		for id, job := range journal.Jobs {
			if normalizeProofJobIdentity(job.VKIdentity) != vkIdentity || job.State == proofJobRunning {
				continue
			}
			deadlineIndex, partitionIndex, ok := dataPartitionCoordinatesFromProofScope(job.Scope)
			if !ok {
				continue
			}
			key := coordinate{deadlineIndex, partitionIndex}
			if live[key] {
				continue
			}
			authorityKey := proofJobAuthorityKey(job.VKIdentity, job.Scope)
			if journal.AuthoritativeGeneration[authorityKey] == job.Generation {
				delete(journal.AuthoritativeGeneration, authorityKey)
			}
			delete(journal.Jobs, id)
			retired++
		}
		return nil
	})
	return retired, err
}

// proofJobWaiterlessGrace is how long a queued job may hold the journal with no live waiter before
// it is treated as abandoned. It must exceed the longest legitimate gap between a job being
// enqueued and its owner registering the waiter, plus one scheduler interval.
const proofJobWaiterlessGrace = 15 * time.Minute

// retireWaiterlessProofJobs removes queued scheduler envelopes that can never be dispatched again.
//
// THE STRUCTURAL DEFECT (live 2026-08-23, fresh9: VK6 dl27-pt1 + dl7-pt0, VK10 dl38-pt0).
// Dispatch eligibility requires a LIVE waiter: activeProofJobs() only returns jobs whose ID appears
// in activeIDs, and activeIDs is rebuilt each pass from the on-disk waiter markers of processes that
// are still alive. But the job journal is DURABLE and host-wide while a waiter is EPHEMERAL. Any
// path that abandons a proof attempt without deleting its job — an attempt skipped because a
// deletion was in progress, content changing mid-flight, a daemon restart — leaves a queued record
// with no waiter. It is then permanently undispatchable, nothing sweeps it, and because the drain
// contract requires queuedProofJobs and recoveryQueueDepth to reach zero, the whole run can never
// certify. Three such orphans held fresh9 at a non-zero drain for over two hours.
//
// Retiring them is safe and self-correcting: the job carries no state that its owner cannot rebuild.
// If the work is still owed, the owning VK enqueues a fresh job on its next scheduling pass (and
// registerProofJob already supersedes any older non-running record for the same scope). If the work
// is no longer owed, the record was pure garbage. Running jobs are never touched — a proof in flight
// remains indivisible — and the grace window keeps a job that is merely between enqueue and waiter
// registration.
func retireWaiterlessProofJobs(storage string, now time.Time) (int, error) {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return 0, nil
	}
	vkIdentity, err := currentProofJobVKIdentity()
	if err != nil {
		return 0, err
	}
	live, err := liveProofWaiterJobIDs(lockPath)
	if err != nil {
		return 0, err
	}
	retired := 0
	err = withProofJobJournal(lockPath, true, func(journal *proofJobJournal) error {
		for id, job := range journal.Jobs {
			// Only this VK's own records; a running proof is indivisible.
			if normalizeProofJobIdentity(job.VKIdentity) != vkIdentity || job.State == proofJobRunning {
				continue
			}
			if job.State != proofJobQueued || live[id] {
				continue
			}
			updated := job.UpdatedUnixNano
			if updated == 0 {
				updated = job.CreatedUnixNano
			}
			if updated <= 0 || now.Sub(time.Unix(0, updated)) < proofJobWaiterlessGrace {
				continue
			}
			authorityKey := proofJobAuthorityKey(job.VKIdentity, job.Scope)
			if journal.AuthoritativeGeneration[authorityKey] == job.Generation {
				delete(journal.AuthoritativeGeneration, authorityKey)
			}
			delete(journal.Jobs, id)
			retired++
		}
		return nil
	})
	return retired, err
}

// liveProofWaiterJobIDs reports the job IDs that currently have a waiter marker owned by a live
// process — the same evidence the dispatcher uses to decide what it may run.
func liveProofWaiterJobIDs(lockPath string) (map[string]bool, error) {
	dir := filepath.Dir(lockPath)
	prefix := filepath.Base(lockPath) + ".wait-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			continue
		}
		var waiter proofWorkWaiter
		if json.Unmarshal(payload, &waiter) != nil || !proofWaiterAlive(waiter) {
			continue
		}
		if waiter.JobID != "" {
			out[waiter.JobID] = true
		}
	}
	return out, nil
}

func proofSchedulerMetrics(lockPath string, now time.Time) (ProofSchedulerMetrics, error) {
	metrics := ProofSchedulerMetrics{
		QueuedByClass: map[string]int{}, FailedByClass: map[string]int{},
		DispatchedByClass: map[string]uint64{}, OldestWaitNanos: map[string]int64{},
	}
	err := withProofJobJournal(lockPath, false, func(journal *proofJobJournal) error {
		for class, count := range journal.DispatchedByClass {
			metrics.DispatchedByClass[class] = count
		}
		for _, job := range journal.Jobs {
			if job.State == proofJobFailed {
				metrics.FailedByClass[job.Class]++
				continue
			}
			metrics.QueuedByClass[job.Class]++
			wait := now.UnixNano() - job.CreatedUnixNano
			if wait > metrics.OldestWaitNanos[job.Class] {
				metrics.OldestWaitNanos[job.Class] = wait
			}
			if job.NextAttemptNano > now.UnixNano() {
				metrics.Retrying++
			}
		}
		return nil
	})
	return metrics, err
}
