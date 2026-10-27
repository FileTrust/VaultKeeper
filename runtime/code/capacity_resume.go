package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateZKSectorCache(storage, sectorRoot string, pieceRoots []string, zkBlockSize int64, depth int) error {
	sectorRoot = normalizeRoot(sectorRoot)
	if sectorRoot == "" {
		return fmt.Errorf("empty sector root")
	}
	cacheDir := zkSectorCacheDir(storage, sectorRoot)
	metaPath := filepath.Join(cacheDir, "meta.json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read cache meta: %w", err)
	}
	var meta ZKSectorCacheMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return fmt.Errorf("parse cache meta: %w", err)
	}
	if meta.Version != ZKSectorCacheVersion {
		return fmt.Errorf("cache version %q != %q", meta.Version, ZKSectorCacheVersion)
	}
	if meta.RootAlg != RootAlgZKMiMCBN254 {
		return fmt.Errorf("cache root alg %q != %q", meta.RootAlg, RootAlgZKMiMCBN254)
	}
	if !strings.EqualFold(normalizeRoot(meta.SectorRoot), sectorRoot) {
		return fmt.Errorf("cache sector root mismatch")
	}
	if meta.ZKBlockSize != zkBlockSize {
		return fmt.Errorf("cache zk block size %d != %d", meta.ZKBlockSize, zkBlockSize)
	}
	if meta.ZKTreeDepth != depth {
		return fmt.Errorf("cache zk tree depth %d != %d", meta.ZKTreeDepth, depth)
	}
	if len(meta.PieceRoots) != len(pieceRoots) {
		return fmt.Errorf("cache piece root count mismatch")
	}
	for i := range pieceRoots {
		if normalizeRoot(meta.PieceRoots[i]) != normalizeRoot(pieceRoots[i]) {
			return fmt.Errorf("cache piece root mismatch at %d", i)
		}
	}
	if len(meta.LevelFiles) == 0 || len(meta.LevelNodeCounts) != len(meta.LevelFiles) {
		return fmt.Errorf("cache level metadata incomplete")
	}
	for i, name := range meta.LevelFiles {
		path := filepath.Join(cacheDir, name)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("cache level file %s: %w", name, err)
		}
		wantNodes := meta.LevelNodeCounts[i]
		if wantNodes <= 0 {
			return fmt.Errorf("cache level %s has invalid node count", name)
		}
		wantSize := int64(wantNodes * 32)
		if info.Size() < wantSize {
			return fmt.Errorf("cache level %s truncated: got %d want >= %d", name, info.Size(), wantSize)
		}
	}
	finalLevel := fmt.Sprintf("level_%02d.bin", depth)
	rootBytes, err := os.ReadFile(filepath.Join(cacheDir, finalLevel))
	if err != nil {
		return fmt.Errorf("read cache root level: %w", err)
	}
	if len(rootBytes) < 32 {
		return fmt.Errorf("cache root level empty")
	}
	rootFromFile := fieldHexFromBytes(rootBytes[:32])
	if !strings.EqualFold(normalizeRoot(rootFromFile), sectorRoot) {
		return fmt.Errorf("cache root bytes mismatch")
	}
	return nil
}

func pieceRootsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normalizeRoot(a[i]) != normalizeRoot(b[i]) {
			return false
		}
	}
	return true
}

func tryReuseZKSectorCache(storage string, pieceRoots []string, zkBlockSize int64, depth int, forceRebuild bool) (root string, blockCount int, zkPC string, ok bool) {
	if forceRebuild || len(pieceRoots) == 0 {
		return "", 0, "", false
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return "", 0, "", false
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || sector.SectorRoot == "" || !pieceRootsMatch(sector.PieceRoots, pieceRoots) {
			continue
		}
		if err := validateZKSectorCache(storage, sector.SectorRoot, pieceRoots, zkBlockSize, depth); err != nil {
			continue
		}
		return sector.SectorRoot, sector.SectorBlockCount, sector.ZKPieceCommitment, true
	}
	return "", 0, "", false
}

func validateCapacitySectorIntegrity(storage string, cfg ServerConfig, targetFree int64) (bool, string) {
	if targetFree <= 0 {
		return false, "no target free space"
	}
	if cfg.ZKBlockSize <= 0 {
		cfg.ZKBlockSize = DefaultZKBlockSize
	}
	if cfg.ZKTreeDepth <= 0 {
		cfg.ZKTreeDepth = DefaultZKTreeDepth
	}
	targetFree = committedFreeCapacityTarget(targetFree, cfg.ZKBlockSize)
	plan, _, err := capacitySlotPlanForFree(cfg, targetFree)
	if err != nil {
		return false, err.Error()
	}
	expected := map[string]capacitySlotPlan{}
	for _, slot := range plan {
		expected[slot.SectorID] = slot
	}

	sectors, err := listSectors(storage)
	if err != nil {
		return false, fmt.Sprintf("list sectors: %v", err)
	}
	seen := map[string]bool{}
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.IsCapacity {
			continue
		}
		slot, ok := expected[sector.SectorID]
		if !ok {
			return false, fmt.Sprintf("unexpected capacity sector %s", sector.SectorID)
		}
		seen[sector.SectorID] = true
		if sector.Status != "sealed" {
			return false, fmt.Sprintf("capacity sector %s not sealed", sector.SectorID)
		}
		if sectorHasRealPiece(storage, sector) {
			return false, fmt.Sprintf("mixed capacity sector %s", sector.SectorID)
		}
		if len(sector.PieceRoots) != 1 {
			return false, fmt.Sprintf("capacity sector %s expected one piece, got %d", sector.SectorID, len(sector.PieceRoots))
		}
		committed := committedSectorBytes(sector)
		if committed != slot.Size {
			return false, fmt.Sprintf("capacity slot %d committed %d != target %d", slot.Index, committed, slot.Size)
		}

		root := sector.PieceRoots[0]
		meta, err := readMeta(storage, root)
		if err != nil {
			return false, fmt.Sprintf("read capacity piece meta: %v", err)
		}
		if meta.Name != "capacity" {
			return false, fmt.Sprintf("piece %s is not capacity dummy", root)
		}
		if _, err := os.Stat(piecePath(storage, root)); err != nil {
			return false, fmt.Sprintf("capacity piece file missing: %v", err)
		}
		var pieceOK bool
		pieceOK, _, err = verifyStoredPiece(storage, root)
		if err != nil {
			return false, fmt.Sprintf("capacity piece verify error: %v", err)
		}
		if !pieceOK {
			return false, "capacity piece hash mismatch"
		}
		if sector.SectorRoot == "" || sector.ZKPieceCommitment == "" {
			return false, fmt.Sprintf("capacity sector %s root/commitment missing", sector.SectorID)
		}
		if err := validateZKSectorCache(storage, sector.SectorRoot, sector.PieceRoots, cfg.ZKBlockSize, cfg.ZKTreeDepth); err != nil {
			return false, fmt.Sprintf("zk cache sector=%s: %v", sector.SectorID, err)
		}
		if sector.SectorBlockCount <= 0 {
			return false, fmt.Sprintf("capacity sector %s block count missing", sector.SectorID)
		}
	}
	for _, slot := range plan {
		if !seen[slot.SectorID] {
			return false, fmt.Sprintf("capacity slot %d sector %s missing", slot.Index, slot.SectorID)
		}
	}
	return true, fmt.Sprintf("slots=%d target=%d", len(plan), targetFree)
}
