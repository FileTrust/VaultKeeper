package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const vkOperationalMetricsVersion = 1

type lifecycleOperationalMetrics struct {
	Pending             int            `json:"pending"`
	WithError           int            `json:"withError"`
	OldestPendingUnix   int64          `json:"oldestPendingUnix,omitempty"`
	ByPhase             map[string]int `json:"byPhase"`
	AllocationFailures  int            `json:"allocationFailures,omitempty"`
	RegistrationWaiting int            `json:"registrationWaiting,omitempty"`
	ProofWaiting        int            `json:"proofWaiting,omitempty"`
	ReleaseWaiting      int            `json:"releaseWaiting,omitempty"`
}

type snapshotOperationalMetrics struct {
	Queues        int   `json:"queues"`
	Frozen        int   `json:"frozen"`
	Successors    int   `json:"successors"`
	RetainedBytes int64 `json:"retainedBytes"`
}

type recoveryOperationalMetrics struct {
	Healthy        bool     `json:"healthy"`
	QueueDepth     int      `json:"queueDepth"`
	Quarantined    int      `json:"quarantined,omitempty"`
	PendingReasons []string `json:"pendingReasons,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

type capacityOperationalMetrics struct {
	ActiveCutoffSequence        uint64 `json:"activeCutoffSequence,omitempty"`
	ExcludedSnapshots           uint32 `json:"excludedSnapshots,omitempty"`
	ExcludedBytes               uint64 `json:"excludedBytes,omitempty"`
	ConsecutiveFailedEpochs     int    `json:"consecutiveFailedEpochs,omitempty"`
	LastSuccessfulCapacityProof string `json:"lastSuccessfulCapacityProofAt,omitempty"`
}

// vkOperationalMetrics is a local, durable projection. The source journals
// remain authoritative; consumers must check Recovery.Healthy before treating
// a zero as an observed zero.
type vkOperationalMetrics struct {
	Version                 int                         `json:"version"`
	ObservedAt              string                      `json:"observedAt"`
	Transfers               transferMetrics             `json:"transfers"`
	Uploads                 lifecycleOperationalMetrics `json:"uploads"`
	Deletions               lifecycleOperationalMetrics `json:"deletions"`
	ProofJobs               ProofSchedulerMetrics       `json:"proofJobs"`
	ProofActive             bool                        `json:"proofActive"`
	ProofAverage            map[string]int64            `json:"proofAverageNanos,omitempty"`
	ProofCompleted          uint64                      `json:"proofCompletedWork,omitempty"`
	ProofActiveNanos        int64                       `json:"proofActiveNanos,omitempty"`
	ProofLockUtilizationPPM int64                       `json:"proofLockUtilizationPpm,omitempty"`
	Snapshots               snapshotOperationalMetrics  `json:"snapshots"`
	CapacityLag             *capacityProofLagSnapshot   `json:"capacityLag,omitempty"`
	ActiveEpoch             *capacityEpochJournal       `json:"activeEpoch,omitempty"`
	Capacity                capacityOperationalMetrics  `json:"capacity"`
	Recovery                recoveryOperationalMetrics  `json:"recovery"`
	// FreezeQuiesce is the observable drain-before-cutover state (A.0 migration):
	// quiesced + the count of locally frozen snapshots still awaiting resolution.
	FreezeQuiesce freezeQuiesceStatus `json:"freezeQuiesce"`
}

func vkOperationalMetricsPath(storage string) string {
	return filepath.Join(storage, "metrics", "vk-operational.json")
}

func recordOperationalError(metrics *vkOperationalMetrics, component string, err error) {
	metrics.Recovery.Healthy = false
	metrics.Recovery.Errors = append(metrics.Recovery.Errors, component+": "+err.Error())
}

func countQuarantinedDeletionJournals(storage string) (int, error) {
	entries, err := os.ReadDir(filepath.Join(deletionLifecycleDir(storage), "quarantine"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.Contains(entry.Name(), ".invalid-") && !strings.HasSuffix(entry.Name(), ".reason") {
			count++
		}
	}
	return count, nil
}

func lifecycleOldestUnix(created string) int64 {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(created))
	if err != nil {
		return 0
	}
	return parsed.Unix()
}

func updateOldest(current *int64, candidate int64) {
	if candidate > 0 && (*current == 0 || candidate < *current) {
		*current = candidate
	}
}

// physicalFileKey identifies one PHYSICAL file: the device number is part of the key so equal
// inode numbers on different filesystems never collide.
type physicalFileKey struct {
	device uint64
	inode  uint64
}

// snapshotRetainedBytes reports the bytes physically retained by frozen/successor proof
// artifacts.
//
// C.2: deduplication is by (device, inode) rather than by directory path. Artifacts are
// hard-linked between authority directories — a deletion successor, a capacity member and a
// storage snapshot can all reference the SAME physical file — so path-based deduplication
// counted one physical file several times and overstated retained bytes. Two distinct files
// still count twice even when their size and contents are identical, because their inodes
// differ. Symlink and artifact-root traversal policy is unchanged: WalkDir does not follow
// symlinks, and only regular files contribute.
func snapshotRetainedBytes(queues []partitionProofSnapshotQueue) (int64, error) {
	seenRoots := make(map[string]struct{})
	seenFiles := make(map[physicalFileKey]struct{})
	var total int64
	for _, queue := range queues {
		for _, snapshot := range []*partitionProofSnapshot{queue.Frozen, queue.Successor} {
			if snapshot == nil || strings.TrimSpace(snapshot.ArtifactDir) == "" {
				continue
			}
			root := filepath.Clean(snapshot.ArtifactDir)
			if _, ok := seenRoots[root]; ok {
				continue
			}
			seenRoots[root] = struct{}{}
			err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !entry.Type().IsRegular() {
					return nil
				}
				info, infoErr := entry.Info()
				if infoErr != nil {
					return infoErr
				}
				key, ok := physicalFileIdentity(info)
				if ok {
					if _, counted := seenFiles[key]; counted {
						return nil // another hard link to a file already counted
					}
					seenFiles[key] = struct{}{}
				}
				total += info.Size()
				return nil
			})
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

// physicalFileIdentity extracts (device, inode) from a FileInfo. When the platform does not
// expose it, the caller counts the file rather than silently dropping its bytes.
func physicalFileIdentity(info os.FileInfo) (physicalFileKey, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return physicalFileKey{}, false
	}
	return physicalFileKey{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, true
}

func collectVKOperationalMetrics(storage string) vkOperationalMetrics {
	metrics := vkOperationalMetrics{
		Version: vkOperationalMetricsVersion, ObservedAt: nowRFC3339(),
		Uploads:      lifecycleOperationalMetrics{ByPhase: map[string]int{}},
		Deletions:    lifecycleOperationalMetrics{ByPhase: map[string]int{}},
		ProofJobs:    ProofSchedulerMetrics{QueuedByClass: map[string]int{}, FailedByClass: map[string]int{}, DispatchedByClass: map[string]uint64{}, OldestWaitNanos: map[string]int64{}},
		ProofAverage: map[string]int64{}, Recovery: recoveryOperationalMetrics{Healthy: true},
	}
	metrics.FreezeQuiesce = collectFreezeQuiesceStatus(storage)

	transferAdmissionMu.Lock()
	if transferAdmission != nil && filepath.Clean(transferAdmission.storage) == filepath.Clean(storage) {
		metrics.Transfers = transferAdmission.snapshot()
	}
	transferAdmissionMu.Unlock()

	stores, err := listStoreLifecycleOperations(storage)
	if err != nil {
		recordOperationalError(&metrics, "store lifecycle", err)
	} else {
		for _, operation := range stores {
			metrics.Uploads.Pending++
			metrics.Uploads.ByPhase[operation.Phase]++
			updateOldest(&metrics.Uploads.OldestPendingUnix, lifecycleOldestUnix(operation.CreatedAt))
			if operation.LastError != "" {
				metrics.Uploads.WithError++
				if operation.Phase != "sector_committed" && operation.Phase != "partition_registered" && operation.Phase != "file_registered" {
					metrics.Uploads.AllocationFailures++
				}
			}
			if operation.Phase == "sector_committed" || operation.Phase == "partition_registered" {
				metrics.Uploads.RegistrationWaiting++
			}
		}
	}

	deletions, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		recordOperationalError(&metrics, "deletion lifecycle", err)
	} else {
		for _, operation := range deletions {
			metrics.Deletions.Pending++
			metrics.Deletions.ByPhase[operation.Phase]++
			updateOldest(&metrics.Deletions.OldestPendingUnix, lifecycleOldestUnix(operation.CreatedAt))
			if operation.LastError != "" {
				metrics.Deletions.WithError++
			}
			if operation.Phase == "partition_synced" || operation.Phase == "declared" {
				metrics.Deletions.ProofWaiting++
			}
			if operation.Phase == "partition_proven" || operation.Phase == "confirmed" {
				metrics.Deletions.ReleaseWaiting++
			}
		}
	}
	if quarantined, quarantineErr := countQuarantinedDeletionJournals(storage); quarantineErr != nil {
		recordOperationalError(&metrics, "deletion quarantine", quarantineErr)
	} else {
		metrics.Recovery.Quarantined = quarantined
	}

	if lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv)); lockPath != "" {
		if scheduler, schedulerErr := proofSchedulerMetrics(lockPath, time.Now()); schedulerErr != nil {
			recordOperationalError(&metrics, "proof scheduler", schedulerErr)
		} else {
			metrics.ProofJobs = scheduler
			for _, count := range scheduler.QueuedByClass {
				metrics.Recovery.QueueDepth += count
			}
			for _, count := range scheduler.FailedByClass {
				metrics.Recovery.QueueDepth += count
			}
		}
		if payload, readErr := os.ReadFile(proofStatsPath(lockPath)); readErr == nil {
			var stats proofWorkStats
			if json.Unmarshal(payload, &stats) != nil {
				recordOperationalError(&metrics, "proof duration stats", fmt.Errorf("invalid JSON"))
			} else {
				metrics.ProofAverage = stats.AverageNanos
				metrics.ProofCompleted = stats.CompletedWork
				metrics.ProofActiveNanos = stats.TotalActiveNanos
				window := time.Now().UnixNano() - stats.ObservedSinceNanos
				if window > 0 && stats.TotalActiveNanos > 0 {
					utilization := int64(float64(stats.TotalActiveNanos) / float64(window) * 1_000_000)
					if utilization > 1_000_000 {
						utilization = 1_000_000
					}
					metrics.ProofLockUtilizationPPM = utilization
				}
			}
		} else if !os.IsNotExist(readErr) {
			recordOperationalError(&metrics, "proof duration stats", readErr)
		}
	}
	metrics.ProofActive = proofWorkActive()

	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		recordOperationalError(&metrics, "snapshot queues", err)
	} else {
		metrics.Snapshots.Queues = len(queues)
		for _, queue := range queues {
			if queue.Frozen != nil {
				metrics.Snapshots.Frozen++
			}
			if queue.Successor != nil {
				metrics.Snapshots.Successors++
			}
		}
		if retained, retainedErr := snapshotRetainedBytes(queues); retainedErr != nil {
			recordOperationalError(&metrics, "snapshot retained bytes", retainedErr)
		} else {
			metrics.Snapshots.RetainedBytes = retained
		}
	}

	if lag, found, lagErr := readCapacityProofLagSnapshot(storage); lagErr != nil {
		recordOperationalError(&metrics, "capacity lag", lagErr)
	} else if found {
		metrics.CapacityLag = &lag
		metrics.Capacity.ConsecutiveFailedEpochs = lag.ConsecutiveFailedEpochs
	}
	if epoch, found, epochErr := readCapacityEpochJournal(storage); epochErr != nil {
		recordOperationalError(&metrics, "capacity epoch", epochErr)
	} else if found {
		metrics.Capacity.ActiveCutoffSequence = epoch.MutationCutoffSequence
		metrics.Capacity.ExcludedSnapshots = epoch.ExcludedPartitions
		metrics.Capacity.ExcludedBytes = epoch.ExcludedBytes
		if epoch.State == capacityEpochStateCompleted {
			metrics.Capacity.LastSuccessfulCapacityProof = epoch.UpdatedAt
		} else if epoch.State != capacityEpochStateAbandoned {
			metrics.ActiveEpoch = &epoch
			metrics.Recovery.QueueDepth++
		}
	}
	mutationPending := 0
	if records, mutationErr := listCapacityMutationJournalRecordsUnlocked(storage); mutationErr != nil {
		recordOperationalError(&metrics, "capacity mutations", mutationErr)
	} else {
		for _, record := range records {
			if record.Status != capacityMutationStatusIncluded &&
				record.Status != capacityMutationStatusAbandoned &&
				record.Status != capacityMutationStatusResolved {
				mutationPending++
			}
		}
		metrics.Recovery.QueueDepth += mutationPending
	}
	metrics.Recovery.QueueDepth += metrics.Uploads.Pending + metrics.Deletions.Pending + metrics.Snapshots.Frozen + metrics.Snapshots.Successors
	if metrics.Uploads.Pending > 0 {
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "store lifecycle operations")
	}
	if metrics.Deletions.Pending > 0 {
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "deletion lifecycle operations")
	}
	if metrics.Recovery.Quarantined > 0 {
		metrics.Recovery.QueueDepth += metrics.Recovery.Quarantined
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "quarantined deletion journals")
	}
	proofPending := 0
	for _, count := range metrics.ProofJobs.QueuedByClass {
		proofPending += count
	}
	for _, count := range metrics.ProofJobs.FailedByClass {
		proofPending += count
	}
	if proofPending > 0 {
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "proof jobs")
	}
	if metrics.Snapshots.Frozen+metrics.Snapshots.Successors > 0 {
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "retained proof snapshots")
	}
	if metrics.ActiveEpoch != nil {
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "capacity epoch recovery")
	}
	if mutationPending > 0 {
		metrics.Recovery.PendingReasons = append(metrics.Recovery.PendingReasons, "capacity mutation journals")
	}
	if metrics.Recovery.QueueDepth > 0 || metrics.Recovery.Quarantined > 0 {
		metrics.Recovery.Healthy = false
	}
	return metrics
}

func writeVKOperationalMetrics(storage string) error {
	metrics := collectVKOperationalMetrics(storage)
	payload, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(vkOperationalMetricsPath(storage), payload, 0600)
}

func runVKOperationalMetricsPublisher(stop <-chan struct{}, storage string) {
	write := func() {
		if err := writeVKOperationalMetrics(storage); err != nil {
			log.Printf("[metrics] VK operational export failed: %v", err)
		}
	}
	write()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			write()
			return
		case <-ticker.C:
			write()
		}
	}
}
