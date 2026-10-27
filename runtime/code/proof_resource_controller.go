package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Proof preparation and final proof generation have deliberately different
// resource policies. Merkle/cache preparation is divisible and can yield after
// every durable batch. A Groth16 proof is indivisible and is instead started
// early and executed by the low-priority external prover.
type proofResourceSettings struct {
	minWorkers     int
	maxWorkers     int
	busyCPUPercent int
}

var proofResources = struct {
	sync.Mutex
	settings    proofResourceSettings
	idleWorkers int
}{
	settings: proofResourceSettings{
		minWorkers:     DefaultProofBackgroundMinWorkers,
		maxWorkers:     DefaultProofBackgroundMaxWorkers,
		busyCPUPercent: DefaultProofBackgroundBusyCPUPercent,
	},
	idleWorkers: DefaultProofBackgroundMinWorkers,
}

func validateProofResourceConfig(cfg ServerConfig) error {
	minWorkers := cfg.ProofBackgroundMinWorkers
	if minWorkers == 0 {
		minWorkers = DefaultProofBackgroundMinWorkers
	}
	maxWorkers := cfg.ProofBackgroundMaxWorkers
	busyCPUPercent := cfg.ProofBackgroundBusyCPUPercent
	if busyCPUPercent == 0 {
		busyCPUPercent = DefaultProofBackgroundBusyCPUPercent
	}
	if minWorkers < 1 {
		return fmt.Errorf("proof background minimum workers must be at least 1")
	}
	if maxWorkers < 0 || (maxWorkers > 0 && maxWorkers < minWorkers) {
		return fmt.Errorf("proof background maximum workers must be 0 (auto) or at least the minimum")
	}
	if busyCPUPercent < 1 || busyCPUPercent > 100 {
		return fmt.Errorf("proof background busy CPU percent must be in [1,100]")
	}
	return nil
}

func configureProofResourceController(cfg ServerConfig) error {
	// C.1: the prover-lane admission gate persists its overload state under this storage root.
	setProofLaneStorageRoot(cfg.Storage)
	if err := validateProofResourceConfig(cfg); err != nil {
		return err
	}
	settings := proofResourceSettings{
		minWorkers:     cfg.ProofBackgroundMinWorkers,
		maxWorkers:     cfg.ProofBackgroundMaxWorkers,
		busyCPUPercent: cfg.ProofBackgroundBusyCPUPercent,
	}
	if settings.minWorkers == 0 {
		settings.minWorkers = DefaultProofBackgroundMinWorkers
	}
	if settings.busyCPUPercent == 0 {
		settings.busyCPUPercent = DefaultProofBackgroundBusyCPUPercent
	}
	proofResources.Lock()
	proofResources.settings = settings
	proofResources.idleWorkers = settings.minWorkers
	proofResources.Unlock()
	return nil
}

func resolvedProofBackgroundMaxWorkers(settings proofResourceSettings) int {
	maximum := settings.maxWorkers
	if maximum == 0 {
		maximum = runtime.GOMAXPROCS(0)
		if maximum <= 0 {
			maximum = runtime.NumCPU()
		}
	}
	if maximum < settings.minWorkers {
		maximum = settings.minWorkers
	}
	return maximum
}

// proofBuildWorkerCount is called at each cache batch, so a change between
// foreground-busy and idle state takes effect without cancelling the batch.
func proofBuildWorkerCount(background bool, items int) int {
	if items <= 0 {
		return 0
	}
	if !background {
		workers := runtime.GOMAXPROCS(0)
		if workers <= 0 {
			workers = runtime.NumCPU()
		}
		if workers < 1 {
			workers = 1
		}
		if workers > items {
			workers = items
		}
		return workers
	}

	busy := hostForegroundActivityActive() || proofWorkActive()
	proofResources.Lock()
	settings := proofResources.settings
	maximum := resolvedProofBackgroundMaxWorkers(settings)
	if busy {
		proofResources.idleWorkers = settings.minWorkers
	} else if proofResources.idleWorkers < maximum {
		// Ramp up one worker per durable batch. This avoids an abrupt CPU spike
		// immediately after the last foreground request finishes.
		proofResources.idleWorkers++
	}
	workers := proofResources.idleWorkers
	proofResources.Unlock()
	if workers > maximum {
		workers = maximum
	}
	if workers > items {
		workers = items
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// proofBuildBatchComplete enforces an average CPU share only while the host is
// busy. The pause is derived from measured batch time rather than a fixed sleep,
// so it behaves consistently on slow and fast production hardware.
func proofBuildBatchComplete(background bool, elapsed time.Duration) {
	if !background || elapsed <= 0 || (!hostForegroundActivityActive() && !proofWorkActive()) {
		return
	}
	proofResources.Lock()
	percent := proofResources.settings.busyCPUPercent
	proofResources.Unlock()
	if percent <= 0 {
		percent = DefaultProofBackgroundBusyCPUPercent
	}
	if percent >= 100 {
		runtime.Gosched()
		return
	}
	pause := elapsed * time.Duration(100-percent) / time.Duration(percent)
	// A bounded batch should normally make this much smaller. The cap keeps
	// shutdown/deadline responsiveness even if a machine experiences a long
	// scheduling pause inside one batch.
	if pause > 2*time.Second {
		pause = 2 * time.Second
	}
	if pause > 0 {
		time.Sleep(pause)
	}
}

type foregroundActivityRecord struct {
	PID          int    `json:"pid"`
	ProcessStart string `json:"processStart,omitempty"`
	Sequence     uint64 `json:"sequence"`
	Kind         string `json:"kind"`
	StartedAt    string `json:"startedAt"`
}

type foregroundActivityLease struct {
	path string
	once sync.Once
}

var foregroundActivitySequence atomic.Uint64

func foregroundActivityPrefix(lockPath string) string {
	return filepath.Base(lockPath) + ".foreground-"
}

func foregroundActivityPath(lockPath string, pid int, sequence uint64) string {
	return fmt.Sprintf("%s.foreground-%d-%d", lockPath, pid, sequence)
}

// beginForegroundActivity is best-effort by design: inability to publish a
// scheduling hint must never reject a valid upload, download, or deletion.
func beginForegroundActivity(kind string) *foregroundActivityLease {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return &foregroundActivityLease{}
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		log.Printf("[proof-resource] cannot create foreground marker directory: %v", err)
		return &foregroundActivityLease{}
	}
	sequence := foregroundActivitySequence.Add(1)
	record := foregroundActivityRecord{
		PID: os.Getpid(), ProcessStart: linuxProcessStartToken(os.Getpid()),
		Sequence: sequence, Kind: kind, StartedAt: nowRFC3339(),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return &foregroundActivityLease{}
	}
	path := foregroundActivityPath(lockPath, record.PID, sequence)
	if err := atomicWriteFile(path, payload, 0600); err != nil {
		log.Printf("[proof-resource] cannot publish %s activity: %v", kind, err)
		return &foregroundActivityLease{}
	}
	return &foregroundActivityLease{path: path}
}

func (lease *foregroundActivityLease) Release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		if lease.path != "" {
			if err := os.Remove(lease.path); err != nil && !os.IsNotExist(err) {
				log.Printf("[proof-resource] foreground marker cleanup warning: %v", err)
			}
		}
	})
}

func markerPIDFromName(name, prefix string) int {
	raw := strings.TrimPrefix(name, prefix)
	pidText, _, _ := strings.Cut(raw, "-")
	pid, _ := strconv.Atoi(pidText)
	return pid
}

func hostForegroundActivityActive() bool {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return false
	}
	dir := filepath.Dir(lockPath)
	prefix := foregroundActivityPrefix(lockPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		pid := markerPIDFromName(entry.Name(), prefix)
		processStart := ""
		if payload, readErr := os.ReadFile(path); readErr == nil {
			var record foregroundActivityRecord
			if json.Unmarshal(payload, &record) == nil && record.PID > 0 {
				pid = record.PID
				processStart = record.ProcessStart
			}
		}
		if pid <= 0 || syscall.Kill(pid, 0) == syscall.ESRCH ||
			(processStart != "" && linuxProcessStartToken(pid) != processStart) {
			_ = os.Remove(path)
			continue
		}
		return true
	}
	return false
}

// Capacity cache construction is serialized separately from final proofs. It
// therefore cannot hold the final-prover lock for minutes, while ten VKs on one
// host still cannot launch ten background cache builds at once.
func withHostBackgroundBuildLock(work, generation string, fn func() error) error {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return fn()
	}
	vkIdentity, err := currentProofJobVKIdentity()
	if err != nil {
		return err
	}
	path := lockPath + ".background"
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create background proof lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open background proof lock: %w", err)
	}
	defer f.Close()

	// Queue every bounded background quantum explicitly. A plain blocking flock
	// lets the process that just released it immediately reacquire it and can
	// starve the other VKs on a shared host. FIFO markers make a completed batch
	// rejoin at the tail, so all VKs continue to advance.
	sequence := proofWaitSequence.Add(1)
	queuedAt := time.Now()
	waiter := proofWorkWaiter{
		PID: os.Getpid(), ProcessStart: linuxProcessStartToken(os.Getpid()),
		Sequence: sequence, Work: work, Class: "background",
		QueuedUnix: queuedAt.UnixNano(), DueUnix: queuedAt.UnixNano(),
	}
	job, err := enqueueProofJob(lockPath, vkIdentity, generation, work, work, "maintenance", "background", queuedAt, queuedAt)
	if err != nil {
		return err
	}
	waiter.JobID = job.ID
	waitMarker := proofWaitMarkerPath(path, waiter.PID, waiter.Sequence)
	payload, err := json.Marshal(waiter)
	if err != nil {
		return fmt.Errorf("encode background proof waiter: %w", err)
	}
	if err := atomicWriteFile(waitMarker, payload, 0600); err != nil {
		return fmt.Errorf("create background proof waiter: %w", err)
	}
	defer os.Remove(waitMarker)

	waitStarted := time.Now()
	log.Printf("[proof-background] waiting work=%s path=%s", work, path)
	for {
		if !proofJobQueuedOrRunning(lockPath, job.ID) {
			return fmt.Errorf("%w: %s", ErrProofJobCancelled, job.ID)
		}
		selectedPath, _, ok := selectedPersistedProofWaiterAt(lockPath, path, "background", time.Now())
		if ok && selectedPath != waitMarker {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			time.Sleep(50 * time.Millisecond)
			continue
		} else if err != nil {
			return fmt.Errorf("acquire background proof lock: %w", err)
		}
		selectedPath, _, ok = selectedPersistedProofWaiterAt(lockPath, path, "background", time.Now())
		if ok && selectedPath != waitMarker {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		break
	}
	if err := startProofJob(lockPath, job.ID, time.Now()); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return err
	}
	_ = os.Remove(waitMarker)
	defer func() {
		if unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); unlockErr != nil {
			log.Printf("[proof-background] release warning work=%s: %v", work, unlockErr)
		}
	}()
	log.Printf("[proof-background] acquired work=%s wait=%s", work, time.Since(waitStarted).Round(time.Millisecond))
	runErr := fn()
	if finishErr := finishProofJob(lockPath, job.ID, runErr, time.Now()); finishErr != nil {
		if runErr == nil {
			return fmt.Errorf("persist maintenance proof job completion: %w", finishErr)
		}
		log.Printf("[proof-scheduler] failed to persist maintenance retry job=%s: %v", job.ID, finishErr)
	}
	return runErr
}
