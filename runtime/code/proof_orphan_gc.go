package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A.4 continuous owner-safe runtime orphan-artifact GC (deferred from A.2).
//
// Runs at a bounded interval. For each artifact directory it: attributes the directory through
// its OWN valid manifest, takes the owning partition lock, verifies no live queue record, no
// active broadcast_pending freeze claim, and no pending recovery record references it, and only
// then removes it through the A.2 ownership-verified path (removeSupersededPartitionArtifactDir,
// which itself refuses symlinked / unattributable / cross-authority / still-referenced dirs).
// Everything it does not conclusively own is PRESERVED and counted as retained.

const orphanArtifactGCMetricsVersion = 1

type orphanArtifactGCMetrics struct {
	Version                  int    `json:"version"`
	LastRunAt                string `json:"lastRunAt"`
	Removed                  int    `json:"removed"`
	RetainedOrphans          int    `json:"retainedOrphans"`
	OldestRetainedAgeSeconds int64  `json:"oldestRetainedAgeSeconds"`
	LastError                string `json:"lastError,omitempty"`
}

func orphanArtifactGCMetricsPath(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "orphan-artifact-gc.json")
}

func readOrphanArtifactGCMetrics(storage string) (orphanArtifactGCMetrics, bool, error) {
	payload, err := os.ReadFile(orphanArtifactGCMetricsPath(storage))
	if os.IsNotExist(err) {
		return orphanArtifactGCMetrics{}, false, nil
	}
	if err != nil {
		return orphanArtifactGCMetrics{}, false, err
	}
	var m orphanArtifactGCMetrics
	if json.Unmarshal(payload, &m) != nil || m.Version != orphanArtifactGCMetricsVersion {
		return orphanArtifactGCMetrics{}, false, nil
	}
	return m, true, nil
}

func writeOrphanArtifactGCMetrics(storage string, m orphanArtifactGCMetrics) error {
	m.Version = orphanArtifactGCMetricsVersion
	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(orphanArtifactGCMetricsPath(storage), payload, 0600)
}

// countPresentOrphanArtifactDirs returns how many artifact directories physically exist under the
// artifact root right now (excluding in-progress .tmp- staging dirs, exactly as the sweep does).
// It is the physical ceiling on how many orphans can be "retained": you cannot retain more than
// exist.
func countPresentOrphanArtifactDirs(storage string) (int, error) {
	root := partitionProofSnapshotArtifactRoot(storage)
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	present := 0
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".tmp-") {
			present++
		}
	}
	return present, nil
}

// readReconciledOrphanArtifactGCMetrics reads the last-written GC metrics and corrects a STALE
// retained-orphan count against physical reality. The metrics file is written once per sweep, so
// after an artifact is removed — by a later sweep or another owner-safe path — while no fresh sweep
// runs (e.g. the scheduler idles once the fleet drains), the cached RetainedOrphans lags above the
// truth. This is the Run-17 accounting lag: the artifact files were gone yet the count stuck at 1.
//
// A retained orphan is by definition a directory that still physically exists, so the count can
// never exceed the directories present now: when the artifact root is empty the count is 0. The
// correction is downward-only — it never fabricates a higher count, and it never weakens the drain
// gate, because a genuinely retained orphan keeps its directory on disk and so keeps the count > 0.
// When physical reality cannot be read, the cached value is kept (never fabricate 0 on doubt).
func readReconciledOrphanArtifactGCMetrics(storage string) (orphanArtifactGCMetrics, bool, error) {
	metrics, ok, err := readOrphanArtifactGCMetrics(storage)
	if err != nil || !ok || metrics.RetainedOrphans <= 0 {
		return metrics, ok, err
	}
	present, presentErr := countPresentOrphanArtifactDirs(storage)
	if presentErr != nil {
		return metrics, ok, nil
	}
	if present < metrics.RetainedOrphans {
		metrics.RetainedOrphans = present
		if present == 0 {
			metrics.OldestRetainedAgeSeconds = 0
		}
	}
	return metrics, ok, nil
}

// artifactDirReferencedByLiveWork reports whether any LIVE reference to the artifact directory
// exists beyond the queue reference the A.2 remover already checks. The caller MUST hold the
// partition snapshot lock, so this final re-check is atomic with the removal — a concurrently
// created claim or recovery record cannot race with deletion. A directory is protected while:
//   - a broadcast_pending freeze attempt references its generation;
//   - an UNEXPIRED pre-broadcast freeze claim owns the partition (about to proceed);
//   - ANY recovery record — pending OR terminal — references its content identity (a terminal
//     record deliberately preserves the artifact as diagnostic evidence until operator action).
// Resolved claims (confirmed/failed) and expired pre-broadcast reservations do not protect it.
func artifactDirReferencedByLiveWork(storage string, manifest partitionProofSnapshot, now time.Time) (bool, error) {
	kind := manifest.Partition.PartitionKind
	dl, pt := manifest.Partition.DeadlineIndex, manifest.Partition.PartitionIndex
	if claim, found, err := readFreezeClaimUnlocked(storage, kind, dl, pt); err != nil {
		return false, err
	} else if found {
		switch claim.AttemptState {
		case freezeAttemptBroadcastPending:
			// A broadcast_pending attempt protects the exact generation it is broadcasting.
			if claim.AttemptGeneration == manifest.Generation {
				return true, nil
			}
		case freezeAttemptConfirmed, freezeAttemptFailed:
			// Conclusively resolved: does not protect.
		default:
			// A pre-broadcast reservation (no attempt yet): protects the partition while it is
			// still unexpired and may proceed. Expired reservations do not protect.
			if now.Unix() < claim.ExpiresAtUnix {
				return true, nil
			}
		}
	}
	// Any recovery record — pending OR terminal — referencing this content identity protects it.
	if entry, found, err := proofRecoveryEntry(storage, manifest.Partition); err != nil {
		return false, err
	} else if found && sameRoot(entry.ContentHash, manifest.ContentHash) {
		return true, nil
	}
	return false, nil
}

// runOrphanArtifactGCOnce performs one bounded sweep and persists observability metrics.
func runOrphanArtifactGCOnce(storage string, now time.Time) (orphanArtifactGCMetrics, error) {
	metrics := orphanArtifactGCMetrics{LastRunAt: now.UTC().Format(time.RFC3339Nano)}
	root := partitionProofSnapshotArtifactRoot(storage)
	entries, readErr := os.ReadDir(root)
	if os.IsNotExist(readErr) {
		return metrics, writeOrphanArtifactGCMetrics(storage, metrics)
	}
	if readErr != nil {
		metrics.LastError = readErr.Error()
		_ = writeOrphanArtifactGCMetrics(storage, metrics)
		return metrics, readErr
	}
	var firstErr error
	retainDir := func(dirPath string) {
		metrics.RetainedOrphans++
		if info, err := os.Stat(dirPath); err == nil {
			if age := int64(now.Sub(info.ModTime()).Seconds()); age > metrics.OldestRetainedAgeSeconds {
				metrics.OldestRetainedAgeSeconds = age
			}
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		dirPath := filepath.Join(root, entry.Name())
		payload, manErr := os.ReadFile(filepath.Join(dirPath, "snapshot.json"))
		if manErr != nil {
			retainDir(dirPath) // unattributable → preserve
			continue
		}
		var manifest partitionProofSnapshot
		if json.Unmarshal(payload, &manifest) != nil || strings.TrimSpace(manifest.Partition.PartitionKind) == "" {
			retainDir(dirPath) // malformed → preserve
			continue
		}
		kind := manifest.Partition.PartitionKind
		dl, pt := manifest.Partition.DeadlineIndex, manifest.Partition.PartitionIndex
		removedHere := false
		lockErr := withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
			referenced, refErr := artifactDirReferencedByLiveWork(storage, manifest, now)
			if refErr != nil {
				return refErr
			}
			if referenced {
				return nil // live claim/recovery references it → preserve (counted below)
			}
			// A.2 ownership-verified removal (queue-reference + attribution + symlink checks).
			didRemove, rmErr := removeSupersededPartitionArtifactDir(storage, kind, dl, pt, dirPath)
			if rmErr != nil {
				return nil // refused (still-referenced / ambiguous) → preserve
			}
			removedHere = didRemove
			return nil
		})
		if lockErr != nil {
			if firstErr == nil {
				firstErr = lockErr
			}
			retainDir(dirPath)
			continue
		}
		if removedHere {
			metrics.Removed++
		} else {
			retainDir(dirPath)
		}
	}
	if firstErr != nil {
		metrics.LastError = firstErr.Error()
	}
	return metrics, writeOrphanArtifactGCMetrics(storage, metrics)
}
