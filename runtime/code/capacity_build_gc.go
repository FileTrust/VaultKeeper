package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// CapacityBuildArtifactGCResult makes maintenance observable without requiring
// the collector to write logs itself.
type CapacityBuildArtifactGCResult struct {
	BuildDirectoriesRemoved int
	IndexesRemoved          int
	BusyBuildsSkipped       int
	ReferencedBuildsSkipped int
	YoungBuildsSkipped      int
	InvalidNamesSkipped     int
	GlobalBuildBusy         bool
}

// cleanupStaleCapacityBuildArtifacts removes abandoned capacity-piece
// checkpoints and their auxiliary indexes after retention has elapsed.
//
// It is safe to call from periodic maintenance. A zero/negative retention is
// rejected rather than interpreted as "delete immediately".
func cleanupStaleCapacityBuildArtifacts(storage string, cfg ServerConfig, retention time.Duration) (CapacityBuildArtifactGCResult, error) {
	return cleanupStaleCapacityBuildArtifactsAt(storage, cfg, retention, time.Now().UTC())
}

func tryCapacityArtifactLock(path string) (*os.File, bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, false, err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return lock, true, nil
}

func releaseCapacityArtifactLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func validCapacityArtifactBuildID(buildID string) bool {
	if len(buildID) != 64 || strings.ToLower(buildID) != buildID {
		return false
	}
	decoded, err := hex.DecodeString(buildID)
	return err == nil && len(decoded) == 32
}

func capacityArtifactIDs(storage string) (map[string]bool, int, error) {
	ids := map[string]bool{}
	invalid := 0
	buildEntries, err := os.ReadDir(capacityPieceBuildRoot(storage))
	if err != nil && !os.IsNotExist(err) {
		return nil, 0, err
	}
	for _, entry := range buildEntries {
		name := entry.Name()
		if !validCapacityArtifactBuildID(name) {
			invalid++
			continue
		}
		ids[name] = true
	}
	indexDir := filepath.Join(capacityDir(storage), "piece-index")
	indexEntries, err := os.ReadDir(indexDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, 0, err
	}
	for _, entry := range indexEntries {
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			invalid++
			continue
		}
		buildID := strings.TrimSuffix(name, ".json")
		if !validCapacityArtifactBuildID(buildID) {
			invalid++
			continue
		}
		ids[buildID] = true
	}
	return ids, invalid, nil
}

func currentCapacityArtifactBuildIDs(storage string, cfg ServerConfig) (map[string]bool, error) {
	current := map[string]bool{}
	if cfg.CapacityBytes <= 0 {
		return current, nil
	}
	accounting, err := computeCapacityAccounting(storage, cfg.CapacityBytes)
	if err != nil {
		return nil, fmt.Errorf("capacity artifact accounting: %w", err)
	}
	if accounting.UsedBytes > cfg.CapacityBytes {
		return nil, fmt.Errorf("capacity artifact accounting: used bytes %d exceed declared %d", accounting.UsedBytes, cfg.CapacityBytes)
	}
	targetFree := committedFreeCapacityTarget(cfg.CapacityBytes-accounting.UsedBytes, cfg.ZKBlockSize)
	plan, _, err := capacitySlotPlanForFree(cfg, targetFree)
	if err != nil {
		return nil, fmt.Errorf("capacity artifact slot plan: %w", err)
	}
	blockSize := cfg.PieceBlockSize
	if blockSize <= 0 {
		blockSize = DefaultPieceBlockSize
	}
	for _, slot := range plan {
		generation, found, err := readCapacitySlotGeneration(storage, slot.Index)
		if err != nil {
			return nil, fmt.Errorf("read capacity slot generation %d: %w", slot.Index, err)
		}
		if !found {
			continue
		}
		if generation.Version != capacitySlotGenerationVersion || generation.TargetSize != slot.Size ||
			generation.BlockSize != blockSize || !validCapacityArtifactBuildID(generation.BuildID) {
			continue
		}
		current[generation.BuildID] = true
	}
	return current, nil
}

func referencedCapacityPieceRoots(storage string) (map[string]bool, error) {
	referenced := map[string]bool{}
	sectors, err := listSectors(storage)
	if err != nil {
		return nil, err
	}
	for _, sector := range sectors {
		// Do not apply host-time expiration here. Until lifecycle processing has
		// durably retired a sector, its piece is still a local reference.
		if sector.Status == "deleted" || !sector.IsCapacity {
			continue
		}
		for _, root := range sector.PieceRoots {
			referenced[normalizeRoot(root)] = true
		}
	}
	return referenced, nil
}

func capacityArtifactPieceRoots(storage, buildID string) []string {
	seen := map[string]bool{}
	var roots []string
	add := func(root string) {
		if validateRoot(root) != nil {
			return
		}
		root = normalizeRoot(root)
		if seen[root] {
			return
		}
		seen[root] = true
		roots = append(roots, root)
	}

	indexPath := capacityPieceBuildIndexPath(storage, buildID)
	if info, err := os.Lstat(indexPath); err == nil && info.Mode().IsRegular() {
		if payload, err := os.ReadFile(indexPath); err == nil {
			var index capacityPieceBuildIndex
			if json.Unmarshal(payload, &index) == nil && index.Version == capacityPieceBuildVersion && index.BuildID == buildID {
				add(index.PieceRoot)
			}
		}
	}
	buildDir := capacityPieceBuildDir(storage, buildID)
	if buildInfo, err := os.Lstat(buildDir); err == nil && buildInfo.IsDir() && buildInfo.Mode()&os.ModeSymlink == 0 {
		manifestPath := capacityPieceBuildManifestPath(buildDir)
		if info, err := os.Lstat(manifestPath); err == nil && info.Mode().IsRegular() {
			if payload, err := os.ReadFile(manifestPath); err == nil {
				var manifest capacityPieceBuildManifest
				if json.Unmarshal(payload, &manifest) == nil && manifest.Version == capacityPieceBuildVersion && manifest.BuildID == buildID {
					add(manifest.PieceRoot)
				}
			}
		}
	}
	return roots
}

func newestCapacityArtifactTime(path string) (time.Time, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	newest := info.ModTime()
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return newest, true, nil
	}
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.ModTime().After(newest) {
			newest = entryInfo.ModTime()
		}
		// WalkDir never follows a directory symlink. Explicitly retaining that
		// property documents that collection cannot escape the artifact root.
		if entryInfo.Mode()&os.ModeSymlink != 0 && entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return time.Time{}, false, err
	}
	return newest, true, nil
}

func capacityArtifactLastActivity(storage, buildID string) (time.Time, bool, error) {
	paths := []string{
		capacityPieceBuildDir(storage, buildID),
		capacityPieceBuildIndexPath(storage, buildID),
	}
	var newest time.Time
	found := false
	for _, path := range paths {
		modified, exists, err := newestCapacityArtifactTime(path)
		if err != nil {
			return time.Time{}, false, err
		}
		if !exists {
			continue
		}
		found = true
		if modified.After(newest) {
			newest = modified
		}
	}

	// A durable manifest timestamp advances only after checkpoint data is synced.
	// Consider it in addition to filesystem mtimes and preserve future timestamps.
	buildDir := capacityPieceBuildDir(storage, buildID)
	if buildInfo, err := os.Lstat(buildDir); err == nil && buildInfo.IsDir() && buildInfo.Mode()&os.ModeSymlink == 0 {
		manifestPath := capacityPieceBuildManifestPath(buildDir)
		if info, err := os.Lstat(manifestPath); err == nil && info.Mode().IsRegular() {
			if payload, err := os.ReadFile(manifestPath); err == nil {
				var manifest capacityPieceBuildManifest
				if json.Unmarshal(payload, &manifest) == nil {
					if updated, err := time.Parse(time.RFC3339Nano, manifest.UpdatedAt); err == nil && updated.After(newest) {
						newest = updated
					}
				}
			}
		}
	}
	return newest, found, nil
}

func syncCapacityArtifactParent(path string) error {
	dir, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeCapacityArtifactGroup(storage, buildID string) (buildRemoved, indexRemoved bool, err error) {
	buildDir := capacityPieceBuildDir(storage, buildID)
	if _, statErr := os.Lstat(buildDir); statErr == nil {
		if err := os.RemoveAll(buildDir); err != nil {
			return false, false, err
		}
		buildRemoved = true
		if err := syncCapacityArtifactParent(capacityPieceBuildRoot(storage)); err != nil {
			return buildRemoved, false, err
		}
	} else if !os.IsNotExist(statErr) {
		return false, false, statErr
	}
	indexPath := capacityPieceBuildIndexPath(storage, buildID)
	if err := os.Remove(indexPath); err == nil {
		indexRemoved = true
		if err := syncCapacityArtifactParent(filepath.Dir(indexPath)); err != nil {
			return buildRemoved, indexRemoved, err
		}
	} else if !os.IsNotExist(err) {
		return buildRemoved, false, err
	}
	return buildRemoved, indexRemoved, nil
}

func cleanupStaleCapacityBuildArtifactsAt(storage string, cfg ServerConfig, retention time.Duration, now time.Time) (CapacityBuildArtifactGCResult, error) {
	var result CapacityBuildArtifactGCResult
	if strings.TrimSpace(storage) == "" {
		return result, fmt.Errorf("capacity artifact collection requires storage")
	}
	if retention <= 0 {
		return result, fmt.Errorf("capacity artifact retention must be positive")
	}
	if now.IsZero() {
		return result, fmt.Errorf("capacity artifact collection requires current time")
	}

	// A rebalance may create several related build IDs. If it is active, skip the
	// whole collection immediately instead of waiting or observing a mixed plan.
	globalLock, acquired, err := tryCapacityArtifactLock(capacityBuildLockPath(storage))
	if err != nil {
		return result, fmt.Errorf("capacity artifact global build lock: %w", err)
	}
	if !acquired {
		result.GlobalBuildBusy = true
		return result, nil
	}
	defer releaseCapacityArtifactLock(globalLock)

	ids, invalid, err := capacityArtifactIDs(storage)
	if err != nil {
		return result, err
	}
	result.InvalidNamesSkipped = invalid
	if len(ids) == 0 {
		return result, nil
	}
	current, err := currentCapacityArtifactBuildIDs(storage, cfg)
	if err != nil {
		// An uncertain current plan is a preserve-all condition.
		return result, err
	}
	referencedRoots, err := referencedCapacityPieceRoots(storage)
	if err != nil {
		return result, err
	}
	buildIDs := make([]string, 0, len(ids))
	for buildID := range ids {
		buildIDs = append(buildIDs, buildID)
	}
	sort.Strings(buildIDs)
	cutoff := now.Add(-retention)

	for _, buildID := range buildIDs {
		lock, acquired, err := tryCapacityArtifactLock(capacityPieceBuildLockPath(storage, buildID))
		if err != nil {
			return result, fmt.Errorf("capacity artifact lock %s: %w", buildID[:16], err)
		}
		if !acquired {
			result.BusyBuildsSkipped++
			continue
		}

		func() {
			defer releaseCapacityArtifactLock(lock)
			if current[buildID] {
				result.ReferencedBuildsSkipped++
				return
			}
			for _, root := range capacityArtifactPieceRoots(storage, buildID) {
				if referencedRoots[root] {
					result.ReferencedBuildsSkipped++
					return
				}
			}
			lastActivity, exists, activityErr := capacityArtifactLastActivity(storage, buildID)
			if activityErr != nil {
				err = activityErr
				return
			}
			if !exists {
				return
			}
			if !lastActivity.Before(cutoff) {
				result.YoungBuildsSkipped++
				return
			}
			buildRemoved, indexRemoved, removeErr := removeCapacityArtifactGroup(storage, buildID)
			if removeErr != nil {
				err = removeErr
				return
			}
			if buildRemoved {
				result.BuildDirectoriesRemoved++
			}
			if indexRemoved {
				result.IndexesRemoved++
			}
		}()
		if err != nil {
			return result, fmt.Errorf("collect capacity artifact %s: %w", buildID[:16], err)
		}
	}
	return result, nil
}
