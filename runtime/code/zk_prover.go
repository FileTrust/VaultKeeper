package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	proofHostLockPathEnv  = "FILETRUST_PROOF_HOST_LOCK_PATH"
	proofJobVKIdentityEnv = "FILETRUST_PROOF_JOB_VK_IDENTITY"
)

type proofWorkWaiter struct {
	PID          int    `json:"pid"`
	ProcessStart string `json:"processStart,omitempty"`
	Sequence     uint64 `json:"sequence"`
	Work         string `json:"work"`
	Class        string `json:"class"`
	QueuedUnix   int64  `json:"queuedUnixNano"`
	DueUnix      int64  `json:"dueUnixNano"`
	Estimate     int64  `json:"estimatedDurationNano,omitempty"`
	JobID        string `json:"jobId,omitempty"`
}

type proofWorkStats struct {
	AverageNanos       map[string]int64 `json:"averageNanos"`
	ObservedSinceNanos int64            `json:"observedSinceUnixNano,omitempty"`
	TotalActiveNanos   int64            `json:"totalActiveNanos,omitempty"`
	CompletedWork      uint64           `json:"completedWork,omitempty"`
}

var proofWaitSequence atomic.Uint64

func proofWaitMarkerPath(lockPath string, pid int, sequence uint64) string {
	return fmt.Sprintf("%s.wait-%d-%d", lockPath, pid, sequence)
}

func proofWaiterAlive(waiter proofWorkWaiter) bool {
	if waiter.PID <= 0 || syscall.Kill(waiter.PID, 0) == syscall.ESRCH {
		return false
	}
	if waiter.ProcessStart != "" && linuxProcessStartToken(waiter.PID) != waiter.ProcessStart {
		return false
	}
	return true
}

func proofStatsPath(lockPath string) string { return lockPath + ".stats.json" }

func proofEstimateKeys(class string) []string {
	keys := []string{class}
	if idx := strings.LastIndex(class, "-n"); idx > 0 && idx+2 < len(class) {
		family := class[:idx] + "-any"
		if family != class {
			keys = append(keys, family)
		}
		if family != "partition-final-any" {
			keys = append(keys, "partition-final-any")
		}
	}
	return keys
}

func readProofWorkEstimate(lockPath, class string) int64 {
	payload, err := os.ReadFile(proofStatsPath(lockPath))
	if err != nil {
		return 0
	}
	var stats proofWorkStats
	if json.Unmarshal(payload, &stats) != nil {
		return 0
	}
	for _, key := range proofEstimateKeys(class) {
		if estimate := stats.AverageNanos[key]; estimate > 0 {
			return estimate
		}
	}
	return 0
}

func recordProofWorkDuration(lockPath, class string, elapsed time.Duration) {
	path := proofStatsPath(lockPath)
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	stats := proofWorkStats{AverageNanos: map[string]int64{}}
	if payload, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(payload, &stats)
	}
	if stats.AverageNanos == nil {
		stats.AverageNanos = map[string]int64{}
	}
	if stats.ObservedSinceNanos == 0 {
		stats.ObservedSinceNanos = time.Now().Add(-elapsed).UnixNano()
	}
	if elapsed > 0 {
		stats.TotalActiveNanos += elapsed.Nanoseconds()
	}
	stats.CompletedWork++
	for _, key := range proofEstimateKeys(class) {
		measured := elapsed.Nanoseconds()
		if previous := stats.AverageNanos[key]; previous > 0 {
			// A rolling hardware-specific estimate: recent work matters, while one
			// unusually slow proof cannot destabilize the scheduler.
			measured = (previous*3 + measured) / 4
		}
		stats.AverageNanos[key] = measured
	}
	payload, err := json.Marshal(stats)
	if err != nil {
		return
	}
	_ = durableAtomicWriteFile(path, payload, 0600)
}

func proofLatestStart(waiter proofWorkWaiter) int64 {
	return waiter.DueUnix - waiter.Estimate
}

// selectedProofWaiter implements earliest-deadline-first scheduling across all
// VK processes sharing a prover. Queue time breaks ties, so no proof class can
// starve merely because new work of another class keeps arriving.
func selectedProofWaiter(lockPath string) (string, proofWorkWaiter, bool) {
	dir := filepath.Dir(lockPath)
	prefix := filepath.Base(lockPath) + ".wait-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", proofWorkWaiter{}, false
	}
	bestPath := ""
	best := proofWorkWaiter{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var waiter proofWorkWaiter
		if json.Unmarshal(payload, &waiter) != nil || !proofWaiterAlive(waiter) {
			_ = os.Remove(path)
			continue
		}
		waiterStart, bestStart := proofLatestStart(waiter), proofLatestStart(best)
		if bestPath == "" || waiterStart < bestStart ||
			(waiterStart == bestStart && waiter.QueuedUnix < best.QueuedUnix) ||
			(waiterStart == bestStart && waiter.QueuedUnix == best.QueuedUnix && path < bestPath) {
			bestPath, best = path, waiter
		}
	}
	return bestPath, best, bestPath != ""
}

func proofQueueHasOverdueCapacity(lockPath string, now time.Time) (bool, time.Duration) {
	dir := filepath.Dir(lockPath)
	prefix := filepath.Base(lockPath) + ".wait-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, 0
	}
	var oldest time.Duration
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var waiter proofWorkWaiter
		if json.Unmarshal(payload, &waiter) != nil || !proofWaiterAlive(waiter) {
			_ = os.Remove(path)
			continue
		}
		if !strings.HasPrefix(waiter.Class, "capacity") || waiter.DueUnix > now.UnixNano() {
			continue
		}
		age := now.Sub(time.Unix(0, waiter.QueuedUnix))
		if age > oldest {
			oldest = age
		}
	}
	return oldest > 0, oldest
}

func hostProofQueueOverdueCapacity() (bool, time.Duration) {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return false, 0
	}
	return proofQueueHasOverdueCapacity(lockPath, time.Now())
}

func proofWorkMarkerPath(lockPath string, pid int) string {
	return fmt.Sprintf("%s.active-%d", lockPath, pid)
}

type proofActiveRecord struct {
	PID          int    `json:"pid"`
	ProcessStart string `json:"processStart,omitempty"`
	Work         string `json:"work"`
}

func proofWorkActive() bool {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return false
	}
	dir := filepath.Dir(lockPath)
	prefix := filepath.Base(lockPath) + ".active-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), prefix))
		if err != nil || pid <= 0 {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
			continue
		}
		path := filepath.Join(dir, entry.Name())
		processStart := ""
		if payload, readErr := os.ReadFile(path); readErr == nil {
			var record proofActiveRecord
			if json.Unmarshal(payload, &record) == nil && record.PID > 0 {
				pid = record.PID
				processStart = record.ProcessStart
			}
		}
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH ||
			(processStart != "" && linuxProcessStartToken(pid) != processStart) {
			_ = os.Remove(path)
			continue
		}
		return true
	}
	return false
}

func selectedPersistedProofWaiter(lockPath, resource string, now time.Time) (string, ProofJob, bool) {
	return selectedPersistedProofWaiterAt(lockPath, lockPath, resource, now)
}

// activePersistedProofWaiters returns the live ephemeral waiters for one host lane. Keeping this
// scan separate from dispatch also lets the completion path recompute proof-lane overload after a
// protected job leaves the durable journal. The completion path uses strict=true so an unreadable
// or corrupt marker cannot be mistaken for an empty lane and accidentally clear admission. Normal
// dispatch retains its existing cleanup behavior with strict=false.
func activePersistedProofWaiters(waiterLockPath string, strict bool) (map[string]bool, map[string]string, error) {
	dir := filepath.Dir(waiterLockPath)
	prefix := filepath.Base(waiterLockPath) + ".wait-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	activeIDs := map[string]bool{}
	paths := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			if strict {
				return nil, nil, fmt.Errorf("read proof waiter %s: %w", path, readErr)
			}
			continue
		}
		var waiter proofWorkWaiter
		if decodeErr := json.Unmarshal(payload, &waiter); decodeErr != nil {
			if strict {
				return nil, nil, fmt.Errorf("decode proof waiter %s: %w", path, decodeErr)
			}
			_ = os.Remove(path)
			continue
		}
		if !proofWaiterAlive(waiter) {
			_ = os.Remove(path)
			continue
		}
		if waiter.JobID == "" {
			continue
		}
		activeIDs[waiter.JobID] = true
		if previous := paths[waiter.JobID]; previous == "" || path < previous {
			paths[waiter.JobID] = path
		}
	}
	return activeIDs, paths, nil
}

// reconcileProofLaneOverloadAfterProtectedCompletion refreshes the cached overload decision from
// the authoritative durable jobs which still have live waiters. It runs only after a successful
// protected job has been removed from the journal. Errors leave the previous record untouched,
// preserving fail-closed admission.
func reconcileProofLaneOverloadAfterProtectedCompletion(
	journalLockPath, waiterLockPath, resource, storageRoot string, now time.Time,
) error {
	activeIDs, _, err := activePersistedProofWaiters(waiterLockPath, true)
	if err != nil {
		return fmt.Errorf("scan remaining proof waiters: %w", err)
	}
	jobs, err := activeProofJobs(journalLockPath, resource, activeIDs, now)
	if err != nil {
		return fmt.Errorf("read remaining proof jobs: %w", err)
	}
	_, laneDecision := admissibleProofJobs(jobs, conservativeProofJobDuration, now)
	if err := recordProofLaneOverload(storageRoot, laneDecision, now); err != nil {
		return fmt.Errorf("record completed-job overload reconciliation: %w", err)
	}
	return nil
}

func selectedPersistedProofWaiterAt(journalLockPath, waiterLockPath, resource string, now time.Time) (string, ProofJob, bool) {
	activeIDs, paths, err := activePersistedProofWaiters(waiterLockPath, false)
	if err != nil {
		return "", ProofJob{}, false
	}
	jobs, err := activeProofJobs(journalLockPath, resource, activeIDs, now)
	if err != nil {
		return "", ProofJob{}, false
	}
	dispatched := map[string]uint64{}
	credit := map[string]int64{}
	_ = withProofJobJournal(journalLockPath, false, func(journal *proofJobJournal) error {
		for class, value := range journal.DispatchedByClass {
			dispatched[class] = value
		}
		for class, value := range journal.ClassCredit {
			credit[class] = value
		}
		return nil
	})
	// C.1: the prover lane is non-preemptible. Before any lower-priority job may take it, every
	// pending storage-deadline prefix must remain feasible; protected storage work keeps its
	// guaranteed floor regardless of load.
	jobs, laneDecision := admissibleProofJobs(jobs, conservativeProofJobDuration, now)
	if storageRoot := currentProofLaneStorageRoot(); storageRoot != "" {
		if err := recordProofLaneOverload(storageRoot, laneDecision, now); err != nil {
			log.Printf("[proof-lane] record overload state: %v", err)
		}
	}
	// Logged through a throttle: this check runs several times a second, and an
	// unthrottled verdict buried a successful completion under ~150 identical
	// lines. See proof_lane_overload_log.go.
	reportProofLaneOverload(laneDecision.Overload, laneDecision.Reason, now)
	job, ok := selectProofJob(jobs, dispatched, credit, now)
	if !ok {
		return "", ProofJob{}, false
	}
	return paths[job.ID], job, true
}

// withHostProofWorkLockDeadline serializes memory/IO-heavy proof work across
// all VK processes on one host. Waiters are selected by their real work
// deadline, then FIFO. flock itself is released if a process exits.
func withHostProofWorkLockDeadline(work, class string, due time.Time, fn func() error) error {
	return withHostPersistedProofJobDeadline(class+"|"+work, work, work, class, due, fn)
}

func withHostPersistedProofJobDeadline(generation, scope, work, class string, due time.Time, fn func() error) error {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return fn()
	}
	vkIdentity, err := currentProofJobVKIdentity()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return fmt.Errorf("create proof host lock directory: %w", err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open proof host lock: %w", err)
	}
	defer lockFile.Close()
	if due.IsZero() {
		due = time.Now().Add(24 * time.Hour)
	}
	job, err := enqueueProofJob(lockPath, vkIdentity, generation, scope, work, class, "prover", due, time.Now())
	if err != nil {
		return err
	}
	sequence := proofWaitSequence.Add(1)
	waiter := proofWorkWaiter{
		PID: os.Getpid(), ProcessStart: linuxProcessStartToken(os.Getpid()),
		Sequence: sequence, Work: work, Class: class,
		QueuedUnix: time.Now().UnixNano(), DueUnix: due.UnixNano(),
		Estimate: readProofWorkEstimate(lockPath, class),
		JobID:    job.ID,
	}
	waitMarker := proofWaitMarkerPath(lockPath, waiter.PID, waiter.Sequence)
	payload, err := json.Marshal(waiter)
	if err != nil {
		return fmt.Errorf("encode proof waiter: %w", err)
	}
	if err := atomicWriteFile(waitMarker, payload, 0600); err != nil {
		return fmt.Errorf("create proof wait marker: %w", err)
	}
	defer os.Remove(waitMarker)

	waitStarted := time.Now()
	log.Printf("[proof-lock] waiting work=%s class=%s due=%s path=%s", work, class, due.Format(time.RFC3339), lockPath)
	for {
		if !proofJobQueuedOrRunning(lockPath, job.ID) {
			return fmt.Errorf("%w: %s", ErrProofJobCancelled, job.ID)
		}
		selectedPath, _, ok := selectedPersistedProofWaiter(lockPath, "prover", time.Now())
		if ok && selectedPath != waitMarker {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			time.Sleep(250 * time.Millisecond)
			continue
		} else if err != nil {
			return fmt.Errorf("acquire proof host lock: %w", err)
		}
		selectedPath, _, ok = selectedPersistedProofWaiter(lockPath, "prover", time.Now())
		if ok && selectedPath != waitMarker {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		break
	}
	if err := startProofJob(lockPath, job.ID, time.Now()); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		return err
	}
	defer func() {
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
			log.Printf("[proof-lock] release warning work=%s: %v", work, err)
		}
	}()
	_ = os.Remove(waitMarker)
	log.Printf("[proof-lock] acquired work=%s class=%s wait=%s", work, class, time.Since(waitStarted).Round(time.Millisecond))
	activeMarker := proofWorkMarkerPath(lockPath, os.Getpid())
	activePayload, marshalErr := json.Marshal(proofActiveRecord{
		PID: os.Getpid(), ProcessStart: linuxProcessStartToken(os.Getpid()), Work: work,
	})
	if marshalErr != nil {
		return fmt.Errorf("encode active proof marker: %w", marshalErr)
	}
	if err := atomicWriteFile(activeMarker, activePayload, 0600); err != nil {
		return fmt.Errorf("create active proof marker: %w", err)
	}
	defer os.Remove(activeMarker)

	workStarted := time.Now()
	err = fn()
	// G.3A: only a proof that actually COMPLETED may train the generation estimate. An
	// interrupted, cancelled or failed attempt measured an abandoned interval, not real work,
	// and training on it would make the estimator optimistic exactly when it must not be.
	if err == nil {
		recordProofWorkDuration(lockPath, class, time.Since(workStarted))
	}
	completionTime := time.Now()
	finishErr := finishProofJob(lockPath, job.ID, err, completionTime)
	if finishErr != nil {
		if err == nil {
			return fmt.Errorf("persist proof job completion: %w", finishErr)
		}
		log.Printf("[proof-scheduler] failed to persist retry state job=%s: %v", job.ID, finishErr)
	}
	// The dispatch-time overload record includes this protected job. Once it succeeds and is
	// durably removed, recompute immediately from the remaining live protected work. Without this
	// transition a future-deadline marker can keep this VK closed long after the proof completed.
	// A failed proof or failed journal update deliberately does not clear anything.
	if err == nil && finishErr == nil && protectedProofClass(job.Class) {
		if storageRoot := currentProofLaneStorageRoot(); storageRoot != "" {
			if reconcileErr := reconcileProofLaneOverloadAfterProtectedCompletion(
				lockPath, lockPath, "prover", storageRoot, completionTime,
			); reconcileErr != nil {
				log.Printf("[proof-lane] post-completion overload reconciliation: %v", reconcileErr)
			}
		}
	}
	return err
}

func withHostProofWorkLock(work string, fn func() error) error {
	return withHostProofWorkLockDeadline(work, "capacity", time.Now(), fn)
}

func withHostDataProofWorkLock(work string, fn func() error) error {
	return withHostProofWorkLockDeadline(work, "data", time.Now().Add(24*time.Hour), fn)
}

func equalPublicInputs(expected, actual []string) bool {
	if len(expected) != len(actual) {
		return false
	}
	for i := range expected {
		a, okA := new(big.Int).SetString(strings.TrimSpace(expected[i]), 10)
		b, okB := new(big.Int).SetString(strings.TrimSpace(actual[i]), 10)
		if !okA || !okB || a.Cmp(b) != 0 {
			return false
		}
	}
	return true
}

func validatePartitionProofResponse(req ZKPartitionProofRequest, out ZKProofResult) error {
	if out.Round != req.Challenge.Round {
		return fmt.Errorf("partition prover response round mismatch: got %d expected %d", out.Round, req.Challenge.Round)
	}
	if !sameRoot(out.SectorRoot, req.Challenge.ChallengeSeed) {
		return fmt.Errorf("partition prover response challenge seed mismatch")
	}
	proofHex := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(out.Proof), "0x"), "0X")
	if proofHex == "" {
		return fmt.Errorf("partition prover returned an empty proof")
	}
	if _, err := hex.DecodeString(proofHex); err != nil {
		return fmt.Errorf("partition prover returned malformed proof hex: %w", err)
	}
	if len(req.PublicInputs) > 0 && !equalPublicInputs(req.PublicInputs, out.PublicInputs) {
		return fmt.Errorf("partition prover response public inputs do not match the chain challenge")
	}
	return nil
}

func persistPartitionProofSubmissionFailure(
	storage string,
	partition PartitionMeta,
	challenge PartitionChallenge,
	proof ZKProofResult,
	deterministic bool,
	submitErr error,
) error {
	return persistPartitionProofFailureRecord(
		storage, partition, challenge, proof, deterministic, submitErr,
	)
}

// runExternalZKPartitionProverUnlocked invokes the prover without taking the
// host-heavy-work lock. Callers coordinating partition lifecycle state use it
// after acquiring the host lock and the exact partition lock in that order.
func runExternalZKPartitionProverUnlocked(proverCmd string, req ZKPartitionProofRequest) (ZKProofResult, error) {
	if proverCmd == "" {
		return ZKProofResult{}, fmt.Errorf("partition zk prover command is not configured; refusing to create fake proofs")
	}
	// B.1: proving must never run under the short allocator lock.
	noteLockConfinedWork("zk-prover")
	payload, err := json.Marshal(req)
	if err != nil {
		return ZKProofResult{}, err
	}
	cmd := exec.Command(proverCmd)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return ZKProofResult{}, fmt.Errorf("partition zk prover failed: %w: %s", err, stderr.String())
	}
	var out ZKProofResult
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return ZKProofResult{}, fmt.Errorf("partition zk prover returned invalid json: %w", err)
	}
	if !out.OK {
		return out, fmt.Errorf("partition zk prover returned error: %s", out.Err)
	}
	if err := validatePartitionProofResponse(req, out); err != nil {
		return out, err
	}
	out.GeneratedAt = time.Now().Format(time.RFC3339)
	return out, nil
}

// runExternalZKPartitionProver is retained for standalone callers. The full
// chain proof path performs finer host/partition lock ordering itself.
func runExternalZKPartitionProver(proverCmd string, req ZKPartitionProofRequest) (ZKProofResult, error) {
	work := fmt.Sprintf("partition-%s-dl%d-pt%d", req.Partition.PartitionKind, req.Partition.DeadlineIndex, req.Partition.PartitionIndex)
	runWithLock := withHostProofWorkLock
	if req.Partition.PartitionKind == PartitionKindData {
		runWithLock = withHostDataProofWorkLock
	}
	var result ZKProofResult
	err := runWithLock(work, func() error {
		var runErr error
		result, runErr = runExternalZKPartitionProverUnlocked(proverCmd, req)
		return runErr
	})
	return result, err
}

func runExternalZKProver(proverCmd string, req ZKProofRequest) (ZKProofResult, error) {
	if proverCmd == "" {
		return ZKProofResult{}, fmt.Errorf("zk prover command is not configured; refusing to create fake proofs")
	}
	// B.1: proving must never run under the short allocator lock.
	noteLockConfinedWork("zk-prover")
	payload, err := json.Marshal(req)
	if err != nil {
		return ZKProofResult{}, err
	}
	cmd := exec.Command(proverCmd)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := withHostDataProofWorkLock("sector-proof", cmd.Run); err != nil {
		return ZKProofResult{}, fmt.Errorf("zk prover failed: %w: %s", err, stderr.String())
	}
	var out ZKProofResult
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return ZKProofResult{}, fmt.Errorf("zk prover returned invalid json: %w", err)
	}
	if !out.OK {
		return out, fmt.Errorf("zk prover returned error: %s", out.Err)
	}
	out.GeneratedAt = time.Now().Format(time.RFC3339)
	return out, nil
}

func runSectorProof(storage, sectorID string, round uint64, challengeCount int, seed, proverCmd string) {
	ensureStorageForCLI(storage)
	sector, err := readSector(storage, sectorID)
	if err != nil {
		fatalJSON(err)
	}
	challenge, err := buildSectorChallenge(sector, round, challengeCount, seed)
	if err != nil {
		fatalJSON(err)
	}
	result, err := runExternalZKProver(proverCmd, ZKProofRequest{Sector: sector, Challenge: challenge, StorageDir: storage})
	if err != nil {
		fatalJSON(err)
	}
	writePrettyJSON(os.Stdout, result)
}
