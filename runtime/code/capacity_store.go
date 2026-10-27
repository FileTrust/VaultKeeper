package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Serialize capacity rebalance operations per VK process.
// Store requests can arrive concurrently; without this lock, overlapping
// rebalances can race on capacity sector state and temp files.
var capacityRebalanceMu sync.Mutex

const stableCapacitySectorID = "capacity-sector-v1"
const capacitySlotSectorPrefix = "capacity-sector-v1-slot-"

const capacityPieceBuildVersion = "capacity-piece-build-v2-random"
const capacitySlotGenerationVersion = "capacity-slot-generation-v2-random"
const capacityEntropyMode = "crypto-random-file"

const (
	autoCapacityMinSlotBytes = int64(64 * 1024 * 1024)
	autoCapacityTargetSlots  = int64(128)
)

type capacityPieceBuildManifest struct {
	Version             string  `json:"version"`
	BuildID             string  `json:"buildId"`
	EntropyMode         string  `json:"entropyMode"`
	SlotIndex           int     `json:"slotIndex"`
	TargetSize          int64   `json:"targetSize"`
	BlockSize           int64   `json:"blockSize"`
	Stage               string  `json:"stage"`
	WrittenBytes        int64   `json:"writtenBytes"`
	BlockCount          int64   `json:"blockCount"`
	WholeHashState      []byte  `json:"wholeHashState,omitempty"`
	WholeHash           string  `json:"wholeHash,omitempty"`
	CurrentLevel        int     `json:"currentLevel,omitempty"`
	CurrentLevelWritten int64   `json:"currentLevelWritten,omitempty"`
	LevelNodeCounts     []int64 `json:"levelNodeCounts,omitempty"`
	PieceRoot           string  `json:"pieceRoot,omitempty"`
	UpdatedAt           string  `json:"updatedAt"`
}

// capacitySlotGeneration is a public, non-secret durable pointer to the random
// bytes currently backing one fixed slot. BuildID is only an opaque identifier;
// it cannot regenerate any filler byte. Removing this record retires the
// generation, and a later regrowth creates fresh randomness and a fresh root.
type capacitySlotGeneration struct {
	Version    string `json:"version"`
	SlotIndex  int    `json:"slotIndex"`
	TargetSize int64  `json:"targetSize"`
	BlockSize  int64  `json:"blockSize"`
	BuildID    string `json:"buildId"`
	PieceRoot  string `json:"pieceRoot,omitempty"`
	UpdatedAt  string `json:"updatedAt"`
}

type capacityPieceBuildIndex struct {
	Version    string `json:"version"`
	BuildID    string `json:"buildId"`
	PieceRoot  string `json:"pieceRoot"`
	PieceHash  string `json:"pieceHash"`
	BlockSize  int64  `json:"blockSize"`
	BlockCount int64  `json:"blockCount"`
	Size       int64  `json:"size"`
}

// Tests replace this hook to emulate a process dying after staged bytes and
// Merkle nodes reached disk but before the durable manifest advanced.
var capacityBuildAfterFileSyncHook = func(stage string) error { return nil }

type capacitySlotPlan struct {
	Index    int
	SectorID string
	Size     int64
}

func capacitySlotSectorID(index int) string {
	if index <= 0 {
		return stableCapacitySectorID
	}
	return fmt.Sprintf("%s%06d", capacitySlotSectorPrefix, index)
}

func parseCapacitySlotIndex(sector SectorMeta) (int, bool) {
	if sector.SectorID == stableCapacitySectorID {
		return 0, true
	}
	if strings.HasPrefix(sector.SectorID, capacitySlotSectorPrefix) {
		raw := strings.TrimPrefix(sector.SectorID, capacitySlotSectorPrefix)
		idx, err := strconv.Atoi(raw)
		return idx, err == nil && idx > 0
	}
	if sector.CapacitySlotIndex > 0 {
		return sector.CapacitySlotIndex, true
	}
	return 0, false
}

func maxCapacitySlotPayloadBytes(cfg ServerConfig) int64 {
	zkBlockSize := cfg.ZKBlockSize
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	depth := cfg.ZKTreeDepth
	if depth <= 0 {
		depth = DefaultZKTreeDepth
	}
	if depth >= 62 {
		return 0
	}
	// One leaf is reserved for the sector commitment block.
	maxLeaves := (int64(1) << depth) - 1
	if maxLeaves <= 0 {
		return 0
	}
	return maxLeaves * zkBlockSize
}

func resolvedCapacitySlotSize(cfg ServerConfig) (int64, error) {
	zkBlockSize := cfg.ZKBlockSize
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	maxSlot := maxCapacitySlotPayloadBytes(cfg)
	if maxSlot <= 0 {
		return 0, fmt.Errorf("capacity slot max is zero for zk depth=%d blockSize=%d", cfg.ZKTreeDepth, zkBlockSize)
	}
	slotSize := cfg.CapacitySlotSizeBytes
	if slotSize <= 0 {
		// Auto mode bounds proof/partition count without making test-sized or
		// modest VKs retain one enormous filler beside incoming data. Operators can
		// still request an explicit slot size. The circuit payload is the hard cap.
		declared := cfg.CapacityBytes
		if declared < 0 {
			declared = 0
		}
		desired := autoCapacityMinSlotBytes
		if declared > 0 {
			perSlot := declared / autoCapacityTargetSlots
			if declared%autoCapacityTargetSlots != 0 {
				perSlot++
			}
			if perSlot > desired {
				desired = perSlot
			}
		}
		if desired > maxSlot {
			desired = maxSlot
		}
		// Round up: auto chunks must cover the requested boundary, while the
		// explicit path below remains conservatively rounded down for compatibility.
		if rem := desired % zkBlockSize; rem != 0 {
			desired += zkBlockSize - rem
		}
		if desired > maxSlot {
			desired = maxSlot
		}
		slotSize = desired
	}
	slotSize = committedFreeCapacityTarget(slotSize, zkBlockSize)
	if slotSize <= 0 {
		return 0, fmt.Errorf("capacity slot size must be at least one zk block (%d bytes)", zkBlockSize)
	}
	if slotSize > maxSlot {
		return 0, fmt.Errorf("capacity slot size %d exceeds max sector payload %d for zk depth=%d blockSize=%d",
			slotSize, maxSlot, cfg.ZKTreeDepth, zkBlockSize)
	}
	return slotSize, nil
}

func capacitySlotPlanForFree(cfg ServerConfig, targetFree int64) ([]capacitySlotPlan, int64, error) {
	if targetFree <= 0 {
		return nil, 0, nil
	}
	zkBlockSize := cfg.ZKBlockSize
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	targetFree = committedFreeCapacityTarget(targetFree, zkBlockSize)
	declared := committedFreeCapacityTarget(cfg.CapacityBytes, zkBlockSize)
	if declared <= 0 || targetFree <= 0 {
		return nil, 0, nil
	}
	if targetFree > declared {
		targetFree = declared
	}
	slotSize, err := resolvedCapacitySlotSize(cfg)
	if err != nil {
		return nil, 0, err
	}
	// Slot sizes are derived once from the declared capacity, not from the
	// constantly changing free-byte tail. This makes every slot immutable: small
	// uploads reuse the existing commitment/cache and only a chunk-boundary
	// crossing retires a slot. The selected prefix is the smallest fixed plan
	// whose backing covers targetFree, so temporary proof overhead is always less
	// than one configured slot.
	var declaredPlan []capacitySlotPlan
	remaining := declared
	idx := 0
	// Put the one residual chunk first. The remaining chunks are uniform, so as
	// used bytes rise the tail retires exactly at full-slot boundaries instead of
	// retiring a tiny residual after the first small upload burst.
	if residual := declared % slotSize; residual != 0 {
		declaredPlan = append(declaredPlan, capacitySlotPlan{
			Index: 0, SectorID: capacitySlotSectorID(0), Size: residual,
		})
		remaining -= residual
		idx++
	}
	for remaining > 0 {
		declaredPlan = append(declaredPlan, capacitySlotPlan{
			Index: idx, SectorID: capacitySlotSectorID(idx), Size: slotSize,
		})
		remaining -= slotSize
		idx++
	}
	var out []capacitySlotPlan
	var covered int64
	for _, slot := range declaredPlan {
		out = append(out, slot)
		covered += slot.Size
		if covered >= targetFree {
			break
		}
	}
	return out, slotSize, nil
}

func capacitySlotPlanBytes(plan []capacitySlotPlan) int64 {
	var total int64
	for _, slot := range plan {
		total += slot.Size
	}
	return total
}

func committedFreeCapacityTarget(targetFree, zkBlockSize int64) int64 {
	if targetFree <= 0 {
		return 0
	}
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	return (targetFree / zkBlockSize) * zkBlockSize
}

func capacityDir(storage string) string {
	return filepath.Join(storage, "capacity")
}

func legacyCapacitySeedPath(storage string) string {
	return filepath.Join(capacityDir(storage), "seed.bin")
}

func removeLegacyCapacitySeed(storage string) error {
	err := os.Remove(legacyCapacitySeedPath(storage))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove insecure legacy capacity seed: %w", err)
	}
	log.Printf("[capacity] removed insecure legacy deterministic filler seed")
	return nil
}

// writeRandomCapacityFile is used only by legacy mixed-sector recovery. Normal
// capacity builds use the checkpointed materializer below. Random bytes are
// written once and retained; no compact regeneration secret exists.
func writeRandomCapacityFile(path string, targetSize int64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 1024*1024)
	var written int64
	for written < targetSize {
		n := int64(len(buf))
		if rem := targetSize - written; rem < n {
			n = rem
		}
		if _, err := io.ReadFull(rand.Reader, buf[:int(n)]); err != nil {
			return fmt.Errorf("read operating-system randomness: %w", err)
		}
		if _, err := f.Write(buf[:int(n)]); err != nil {
			return err
		}
		written += n
	}
	return f.Sync()
}

func capacityPieceBuildRoot(storage string) string {
	return filepath.Join(capacityDir(storage), "piece-builds")
}

func capacityPieceBuildDir(storage, buildID string) string {
	return filepath.Join(capacityPieceBuildRoot(storage), buildID)
}

func capacityPieceBuildManifestPath(buildDir string) string {
	return filepath.Join(buildDir, "manifest.json")
}

func capacityPieceBuildDataPath(buildDir string) string {
	return filepath.Join(buildDir, "capacity.piece")
}

func capacityPieceBuildIndexPath(storage, buildID string) string {
	return filepath.Join(capacityDir(storage), "piece-index", buildID+".json")
}

func capacityPieceBuildLockPath(storage, buildID string) string {
	return filepath.Join(capacityDir(storage), "piece-build-locks", buildID+".lock")
}

func capacitySlotGenerationPath(storage string, slotIndex int) string {
	return filepath.Join(capacityDir(storage), "slot-generations", fmt.Sprintf("slot-%06d.json", slotIndex))
}

func capacitySlotGenerationLockPath(storage string, slotIndex int) string {
	return filepath.Join(capacityDir(storage), "slot-generation-locks", fmt.Sprintf("slot-%06d.lock", slotIndex))
}

func acquireCapacitySlotGenerationLock(storage string, slotIndex int) (*os.File, error) {
	path := capacitySlotGenerationLockPath(storage, slotIndex)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

func readCapacitySlotGeneration(storage string, slotIndex int) (capacitySlotGeneration, bool, error) {
	payload, err := os.ReadFile(capacitySlotGenerationPath(storage, slotIndex))
	if os.IsNotExist(err) {
		return capacitySlotGeneration{}, false, nil
	}
	if err != nil {
		return capacitySlotGeneration{}, false, err
	}
	var generation capacitySlotGeneration
	if err := json.Unmarshal(payload, &generation); err != nil {
		return capacitySlotGeneration{}, true, err
	}
	return generation, true, nil
}

func writeCapacitySlotGeneration(storage string, generation capacitySlotGeneration) error {
	generation.Version = capacitySlotGenerationVersion
	generation.UpdatedAt = nowRFC3339()
	payload, err := json.MarshalIndent(generation, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(capacitySlotGenerationPath(storage, generation.SlotIndex), payload, 0600)
}

func randomCapacityBuildID() (string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", fmt.Errorf("create capacity generation identifier: %w", err)
	}
	return hex.EncodeToString(random), nil
}

func loadOrCreateCapacitySlotGeneration(storage string, slotIndex int, targetSize, blockSize int64) (capacitySlotGeneration, error) {
	generation, found, err := readCapacitySlotGeneration(storage, slotIndex)
	if err == nil && found && generation.Version == capacitySlotGenerationVersion &&
		generation.SlotIndex == slotIndex && generation.TargetSize == targetSize &&
		generation.BlockSize == blockSize && validCapacityArtifactBuildID(generation.BuildID) {
		return generation, nil
	}
	if err != nil || found {
		log.Printf("[capacity] replacing invalid/legacy slot generation slot=%d", slotIndex)
	}
	buildID, err := randomCapacityBuildID()
	if err != nil {
		return capacitySlotGeneration{}, err
	}
	generation = capacitySlotGeneration{
		Version: capacitySlotGenerationVersion, SlotIndex: slotIndex,
		TargetSize: targetSize, BlockSize: blockSize, BuildID: buildID,
	}
	if err := writeCapacitySlotGeneration(storage, generation); err != nil {
		return capacitySlotGeneration{}, err
	}
	return generation, nil
}

func acquireCapacityPieceBuildLock(storage, buildID string) (*os.File, error) {
	path := capacityPieceBuildLockPath(storage, buildID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, err
	}
	return lock, nil
}

func releaseCapacityPieceBuildLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = lock.Close()
}

func marshalCapacityWholeHashState(h interface{ Sum([]byte) []byte }) ([]byte, error) {
	marshaler, ok := h.(interface{ MarshalBinary() ([]byte, error) })
	if !ok {
		return nil, fmt.Errorf("SHA-256 implementation does not support durable state")
	}
	return marshaler.MarshalBinary()
}

func restoreCapacityWholeHash(state []byte) (interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}, error) {
	h := sha256.New()
	unmarshaler, ok := h.(interface{ UnmarshalBinary([]byte) error })
	if !ok {
		return nil, fmt.Errorf("SHA-256 implementation does not support durable state")
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil, err
	}
	return h, nil
}

func initialCapacityWholeHashState() ([]byte, error) {
	return marshalCapacityWholeHashState(sha256.New())
}

func capacityPieceBatchBlocks(blockSize int64) int {
	const targetBatchBytes = int64(8 * 1024 * 1024)
	count := int(targetBatchBytes / blockSize)
	if count < 1 {
		return 1
	}
	if count > 4096 {
		return 4096
	}
	return count
}

func expectedCapacityPieceBlocks(size, blockSize int64) int64 {
	if size <= 0 {
		return 0
	}
	// Avoid overflowing size+blockSize for very large declared capacities.
	return 1 + (size-1)/blockSize
}

func validateCapacityPieceBuildManifest(manifest capacityPieceBuildManifest, buildID string, slotIndex int, targetSize, blockSize int64) error {
	if manifest.Version != capacityPieceBuildVersion || manifest.BuildID != buildID || manifest.EntropyMode != capacityEntropyMode ||
		manifest.SlotIndex != slotIndex || manifest.TargetSize != targetSize || manifest.BlockSize != blockSize {
		return fmt.Errorf("capacity piece manifest does not match immutable build specification")
	}
	if manifest.WrittenBytes < 0 || manifest.WrittenBytes > targetSize || manifest.BlockCount < 0 {
		return fmt.Errorf("capacity piece manifest cursor is out of range")
	}
	if manifest.BlockCount != expectedCapacityPieceBlocks(manifest.WrittenBytes, blockSize) {
		return fmt.Errorf("capacity piece manifest byte/block cursor mismatch")
	}
	switch manifest.Stage {
	case "materialize":
		if manifest.WrittenBytes >= targetSize || len(manifest.WholeHashState) == 0 || manifest.WholeHash != "" ||
			manifest.CurrentLevel != 0 || manifest.CurrentLevelWritten != 0 || len(manifest.LevelNodeCounts) != 0 || manifest.PieceRoot != "" {
			return fmt.Errorf("invalid capacity materialization state")
		}
	case "parents", "complete":
		if manifest.WrittenBytes != targetSize || manifest.BlockCount != expectedCapacityPieceBlocks(targetSize, blockSize) || manifest.WholeHash == "" {
			return fmt.Errorf("capacity parent state has incomplete source materialization")
		}
		if len(manifest.LevelNodeCounts) == 0 || manifest.LevelNodeCounts[0] != manifest.BlockCount {
			return fmt.Errorf("capacity piece leaf count mismatch")
		}
		for level := 1; level < len(manifest.LevelNodeCounts); level++ {
			want := (manifest.LevelNodeCounts[level-1] + 1) / 2
			if manifest.LevelNodeCounts[level] != want {
				return fmt.Errorf("capacity piece level %d count mismatch", level)
			}
		}
		if manifest.CurrentLevel != len(manifest.LevelNodeCounts) || manifest.CurrentLevelWritten < 0 {
			return fmt.Errorf("capacity piece parent cursor mismatch")
		}
		if manifest.LevelNodeCounts[len(manifest.LevelNodeCounts)-1] > 1 {
			nextCount := (manifest.LevelNodeCounts[len(manifest.LevelNodeCounts)-1] + 1) / 2
			if manifest.CurrentLevelWritten > nextCount {
				return fmt.Errorf("capacity piece parent cursor exceeds next level")
			}
		} else if manifest.CurrentLevelWritten != 0 {
			return fmt.Errorf("capacity piece completed tree retains parent cursor")
		}
		if manifest.Stage == "complete" {
			if manifest.LevelNodeCounts[len(manifest.LevelNodeCounts)-1] != 1 || manifest.PieceRoot == "" {
				return fmt.Errorf("capacity piece complete state is missing root")
			}
		} else if manifest.PieceRoot != "" {
			return fmt.Errorf("capacity piece parent state already has root")
		}
	default:
		return fmt.Errorf("unknown capacity piece build stage %q", manifest.Stage)
	}
	return nil
}

func newCapacityPieceBuildManifest(buildID string, slotIndex int, targetSize, blockSize int64) (capacityPieceBuildManifest, error) {
	state, err := initialCapacityWholeHashState()
	if err != nil {
		return capacityPieceBuildManifest{}, err
	}
	return capacityPieceBuildManifest{
		Version:        capacityPieceBuildVersion,
		BuildID:        buildID,
		EntropyMode:    capacityEntropyMode,
		SlotIndex:      slotIndex,
		TargetSize:     targetSize,
		BlockSize:      blockSize,
		Stage:          "materialize",
		WholeHashState: state,
		UpdatedAt:      nowRFC3339(),
	}, nil
}

func persistCapacityPieceBuildManifest(buildDir string, manifest *capacityPieceBuildManifest) error {
	manifest.UpdatedAt = nowRFC3339()
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(capacityPieceBuildManifestPath(buildDir), payload, 0600)
}

func loadOrCreateCapacityPieceBuild(storage, buildID string, slotIndex int, targetSize, blockSize int64) (string, capacityPieceBuildManifest, error) {
	buildDir := capacityPieceBuildDir(storage, buildID)
	payload, err := os.ReadFile(capacityPieceBuildManifestPath(buildDir))
	if err == nil {
		var manifest capacityPieceBuildManifest
		if json.Unmarshal(payload, &manifest) == nil && validateCapacityPieceBuildManifest(manifest, buildID, slotIndex, targetSize, blockSize) == nil {
			if manifest.Stage == "complete" {
				if info, statErr := os.Stat(piecePath(storage, manifest.PieceRoot)); statErr == nil && info.Size() == targetSize {
					return buildDir, manifest, nil
				}
			}
			dataInfo, dataErr := os.Stat(capacityPieceBuildDataPath(buildDir))
			leafInfo, leafErr := os.Stat(filepath.Join(buildDir, "level_00.bin"))
			if dataErr == nil && leafErr == nil && dataInfo.Size() >= manifest.WrittenBytes && leafInfo.Size() >= manifest.BlockCount*32 {
				return buildDir, manifest, nil
			}
		}
		log.Printf("[capacity] discarding invalid piece checkpoint build=%s", buildID[:16])
		if err := os.RemoveAll(buildDir); err != nil {
			return "", capacityPieceBuildManifest{}, err
		}
	} else if !os.IsNotExist(err) {
		return "", capacityPieceBuildManifest{}, err
	}
	if err := os.MkdirAll(buildDir, 0700); err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	manifest, err := newCapacityPieceBuildManifest(buildID, slotIndex, targetSize, blockSize)
	if err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	dataFile, err := os.OpenFile(capacityPieceBuildDataPath(buildDir), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	if err := dataFile.Close(); err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	leafFile, err := os.OpenFile(filepath.Join(buildDir, "level_00.bin"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	if err := leafFile.Close(); err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	if err := persistCapacityPieceBuildManifest(buildDir, &manifest); err != nil {
		return "", capacityPieceBuildManifest{}, err
	}
	return buildDir, manifest, nil
}

func openCapacityBuildFileForAppend(path string, committedSize int64) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() < committedSize {
		f.Close()
		return nil, fmt.Errorf("capacity checkpoint %s is shorter than manifest: %d < %d", path, info.Size(), committedSize)
	}
	if info.Size() > committedSize {
		if err := f.Truncate(committedSize); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
	}
	if _, err := f.Seek(committedSize, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func generateCapacityPieceBatch(blockSize, remaining int64) ([][]byte, [][]byte, error) {
	count := capacityPieceBatchBlocks(blockSize)
	if max := int(expectedCapacityPieceBlocks(remaining, blockSize)); count > max {
		count = max
	}
	blocks := make([][]byte, count)
	leaves := make([][]byte, count)
	for i := 0; i < count; i++ {
		n := blockSize
		if left := remaining - int64(i)*blockSize; left < n {
			n = left
		}
		block := make([]byte, int(n))
		if _, err := io.ReadFull(rand.Reader, block); err != nil {
			return nil, nil, fmt.Errorf("read operating-system randomness: %w", err)
		}
		blocks[i] = block
	}
	workers := proofBuildWorkerCount(true, count)
	if workers < 1 {
		workers = 1
	}
	if workers > count {
		workers = count
	}
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < count; i += workers {
				leaves[i] = hashLeaf(blocks[i])
			}
		}(worker)
	}
	wg.Wait()
	return blocks, leaves, nil
}

func advanceCapacityPieceMaterialization(buildDir string, manifest *capacityPieceBuildManifest) error {
	dataPath := capacityPieceBuildDataPath(buildDir)
	leafPath := filepath.Join(buildDir, "level_00.bin")
	for manifest.WrittenBytes < manifest.TargetSize {
		var elapsed time.Duration
		generation := fmt.Sprintf("capacity-piece|%s|materialize|%d", filepath.Base(buildDir), manifest.WrittenBytes)
		if err := withHostBackgroundBuildLock("capacity-piece-materialize", generation, func() error {
			started := time.Now()
			dataFile, err := openCapacityBuildFileForAppend(dataPath, manifest.WrittenBytes)
			if err != nil {
				return err
			}
			leafFile, err := openCapacityBuildFileForAppend(leafPath, manifest.BlockCount*32)
			if err != nil {
				dataFile.Close()
				return err
			}
			whole, err := restoreCapacityWholeHash(manifest.WholeHashState)
			if err != nil {
				dataFile.Close()
				leafFile.Close()
				return err
			}
			blocks, leaves, err := generateCapacityPieceBatch(manifest.BlockSize, manifest.TargetSize-manifest.WrittenBytes)
			if err != nil {
				dataFile.Close()
				leafFile.Close()
				return err
			}
			var consumed int64
			for i := range blocks {
				if _, err := dataFile.Write(blocks[i]); err != nil {
					dataFile.Close()
					leafFile.Close()
					return err
				}
				_, _ = whole.Write(blocks[i])
				if _, err := leafFile.Write(leaves[i]); err != nil {
					dataFile.Close()
					leafFile.Close()
					return err
				}
				consumed += int64(len(blocks[i]))
			}
			if err := dataFile.Sync(); err != nil {
				dataFile.Close()
				leafFile.Close()
				return err
			}
			if err := leafFile.Sync(); err != nil {
				dataFile.Close()
				leafFile.Close()
				return err
			}
			if err := dataFile.Close(); err != nil {
				leafFile.Close()
				return err
			}
			if err := leafFile.Close(); err != nil {
				return err
			}
			if err := capacityBuildAfterFileSyncHook("materialize"); err != nil {
				return err
			}
			state, err := marshalCapacityWholeHashState(whole)
			if err != nil {
				return err
			}
			manifest.WrittenBytes += consumed
			manifest.BlockCount += int64(len(blocks))
			manifest.WholeHashState = state
			if manifest.WrittenBytes == manifest.TargetSize {
				manifest.WholeHash = hex.EncodeToString(whole.Sum(nil))
				manifest.Stage = "parents"
				manifest.CurrentLevel = 1
				manifest.LevelNodeCounts = []int64{manifest.BlockCount}
			}
			if err := persistCapacityPieceBuildManifest(buildDir, manifest); err != nil {
				return err
			}
			elapsed = time.Since(started)
			return nil
		}); err != nil {
			return err
		}
		proofBuildBatchComplete(true, elapsed)
	}
	return nil
}

type capacityMerklePair struct {
	left  []byte
	right []byte
}

func hashCapacityMerklePairs(pairs []capacityMerklePair) [][]byte {
	out := make([][]byte, len(pairs))
	workers := proofBuildWorkerCount(true, len(pairs))
	if workers < 1 {
		workers = 1
	}
	if workers > len(pairs) {
		workers = len(pairs)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < len(pairs); i += workers {
				out[i] = hashNode(pairs[i].left, pairs[i].right)
			}
		}(worker)
	}
	wg.Wait()
	return out
}

func advanceCapacityPieceParents(buildDir string, manifest *capacityPieceBuildManifest) error {
	for manifest.Stage == "parents" && manifest.LevelNodeCounts[len(manifest.LevelNodeCounts)-1] > 1 {
		level := manifest.CurrentLevel
		prevCount := manifest.LevelNodeCounts[level-1]
		nextCount := (prevCount + 1) / 2
		remaining := nextCount - manifest.CurrentLevelWritten
		batchCount := int64(8192)
		if remaining < batchCount {
			batchCount = remaining
		}
		var elapsed time.Duration
		work := fmt.Sprintf("capacity-piece-parent-%02d", level)
		generation := fmt.Sprintf("capacity-piece|%s|parent-%02d|%d", filepath.Base(buildDir), level, manifest.CurrentLevelWritten)
		if err := withHostBackgroundBuildLock(work, generation, func() error {
			started := time.Now()
			prev, err := os.Open(filepath.Join(buildDir, fmt.Sprintf("level_%02d.bin", level-1)))
			if err != nil {
				return err
			}
			childStart := manifest.CurrentLevelWritten * 2
			if _, err := prev.Seek(childStart*32, io.SeekStart); err != nil {
				prev.Close()
				return err
			}
			pairs := make([]capacityMerklePair, 0, int(batchCount))
			for i := int64(0); i < batchCount; i++ {
				left := make([]byte, 32)
				if _, err := io.ReadFull(prev, left); err != nil {
					prev.Close()
					return err
				}
				right := left
				if childStart+i*2+1 < prevCount {
					right = make([]byte, 32)
					if _, err := io.ReadFull(prev, right); err != nil {
						prev.Close()
						return err
					}
				}
				pairs = append(pairs, capacityMerklePair{left: left, right: right})
			}
			if err := prev.Close(); err != nil {
				return err
			}
			next, err := openCapacityBuildFileForAppend(filepath.Join(buildDir, fmt.Sprintf("level_%02d.bin", level)), manifest.CurrentLevelWritten*32)
			if err != nil {
				return err
			}
			for _, node := range hashCapacityMerklePairs(pairs) {
				if _, err := next.Write(node); err != nil {
					next.Close()
					return err
				}
			}
			if err := next.Sync(); err != nil {
				next.Close()
				return err
			}
			if err := next.Close(); err != nil {
				return err
			}
			if err := capacityBuildAfterFileSyncHook("parents"); err != nil {
				return err
			}
			manifest.CurrentLevelWritten += batchCount
			if manifest.CurrentLevelWritten == nextCount {
				manifest.LevelNodeCounts = append(manifest.LevelNodeCounts, nextCount)
				manifest.CurrentLevel++
				manifest.CurrentLevelWritten = 0
			}
			if err := persistCapacityPieceBuildManifest(buildDir, manifest); err != nil {
				return err
			}
			elapsed = time.Since(started)
			return nil
		}); err != nil {
			return err
		}
		proofBuildBatchComplete(true, elapsed)
	}
	if manifest.Stage != "parents" {
		return nil
	}
	rootLevel := len(manifest.LevelNodeCounts) - 1
	rootBytes, err := os.ReadFile(filepath.Join(buildDir, fmt.Sprintf("level_%02d.bin", rootLevel)))
	if err != nil {
		return err
	}
	if len(rootBytes) != 32 {
		return fmt.Errorf("capacity piece root level has %d bytes, expected 32", len(rootBytes))
	}
	manifest.PieceRoot = bytesToRoot(rootBytes)
	manifest.Stage = "complete"
	return persistCapacityPieceBuildManifest(buildDir, manifest)
}

func capacityPieceMetaFromBuild(slotIndex int, index capacityPieceBuildIndex) PieceMeta {
	return PieceMeta{
		Name:            "capacity",
		PieceIndex:      slotIndex,
		PieceRoot:       index.PieceRoot,
		PieceID:         index.PieceRoot,
		CID:             cidV0FromSHA256Hex(index.PieceHash),
		PieceHash:       index.PieceHash,
		HashAlg:         HashAlgSha256,
		RootAlg:         RootAlgMerkleSHA256,
		PieceBlockSize:  index.BlockSize,
		PieceBlockCount: index.BlockCount,
		Size:            index.Size,
		ServiceEnd:      time.Now().UTC().Add(365 * 24 * time.Hour).Unix(),
		StoredAt:        nowRFC3339(),
		FileFormat:      fmt.Sprintf("capacity-slot-%d", slotIndex),
	}
}

func readCapacityPieceBuildIndex(storage, buildID string, slotIndex int, expectedSize, blockSize int64) (PieceMeta, bool) {
	payload, err := os.ReadFile(capacityPieceBuildIndexPath(storage, buildID))
	if err != nil {
		return PieceMeta{}, false
	}
	var index capacityPieceBuildIndex
	if json.Unmarshal(payload, &index) != nil || index.Version != capacityPieceBuildVersion || index.BuildID != buildID ||
		index.Size != expectedSize || index.BlockSize != blockSize || index.BlockCount != expectedCapacityPieceBlocks(expectedSize, blockSize) ||
		validateRoot(index.PieceRoot) != nil {
		return PieceMeta{}, false
	}
	wholeHash, err := hex.DecodeString(index.PieceHash)
	if err != nil || len(wholeHash) != sha256.Size {
		return PieceMeta{}, false
	}
	info, err := os.Stat(piecePath(storage, index.PieceRoot))
	if err != nil || info.Size() != index.Size {
		return PieceMeta{}, false
	}
	return capacityPieceMetaFromBuild(slotIndex, index), true
}

func publishCapacityPieceBuild(storage, buildDir string, manifest capacityPieceBuildManifest) (PieceMeta, bool, error) {
	if err := validateCapacityPieceBuildManifest(
		manifest, manifest.BuildID, manifest.SlotIndex, manifest.TargetSize, manifest.BlockSize,
	); err != nil {
		return PieceMeta{}, false, fmt.Errorf("validate completed capacity piece build: %w", err)
	}
	if manifest.Stage != "complete" || manifest.PieceRoot == "" {
		return PieceMeta{}, false, fmt.Errorf("cannot publish incomplete capacity piece build")
	}
	index := capacityPieceBuildIndex{
		Version: capacityPieceBuildVersion, BuildID: manifest.BuildID, PieceRoot: manifest.PieceRoot,
		PieceHash: manifest.WholeHash, BlockSize: manifest.BlockSize, BlockCount: manifest.BlockCount, Size: manifest.TargetSize,
	}
	finalPath := piecePath(storage, manifest.PieceRoot)
	created := false
	if info, err := os.Stat(finalPath); err == nil {
		if info.Size() != manifest.TargetSize {
			return PieceMeta{}, false, fmt.Errorf("existing capacity piece %s has size %d, expected %d", manifest.PieceRoot, info.Size(), manifest.TargetSize)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(pieceDir(storage), 0700); err != nil {
			return PieceMeta{}, false, err
		}
		// A hard link atomically publishes the piece while retaining the staged
		// source. If a later ZK/sector step fails and rolls back the published
		// name, the completed hundreds-GB materialization remains resumable.
		if err := os.Link(capacityPieceBuildDataPath(buildDir), finalPath); err != nil {
			return PieceMeta{}, false, fmt.Errorf("publish capacity piece: %w", err)
		}
		created = true
		dir, err := os.Open(pieceDir(storage))
		if err != nil {
			return PieceMeta{}, false, err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return PieceMeta{}, false, err
		}
	} else {
		return PieceMeta{}, false, err
	}
	payload, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return PieceMeta{}, false, err
	}
	if err := durableAtomicWriteFile(capacityPieceBuildIndexPath(storage, manifest.BuildID), payload, 0600); err != nil {
		return PieceMeta{}, false, err
	}
	return capacityPieceMetaFromBuild(manifest.SlotIndex, index), created, nil
}

func cleanupCapacityPieceBuildCheckpoint(storage string, cfg ServerConfig, targetSize int64, slotIndex int) {
	blockSize := cfg.PieceBlockSize
	if blockSize <= 0 {
		blockSize = DefaultPieceBlockSize
	}
	generation, found, err := readCapacitySlotGeneration(storage, slotIndex)
	if err != nil || !found || generation.Version != capacitySlotGenerationVersion ||
		generation.TargetSize != targetSize || generation.BlockSize != blockSize {
		if err != nil {
			log.Printf("[capacity] completed piece checkpoint cleanup warning: %v", err)
		}
		return
	}
	if err := os.RemoveAll(capacityPieceBuildDir(storage, generation.BuildID)); err != nil {
		log.Printf("[capacity] completed piece checkpoint cleanup warning build=%s: %v", generation.BuildID[:16], err)
	}
}

func retireCapacitySlotGeneration(storage string, slotIndex int) error {
	lock, err := acquireCapacitySlotGenerationLock(storage, slotIndex)
	if err != nil {
		return err
	}
	defer releaseCapacityPieceBuildLock(lock)
	generation, found, err := readCapacitySlotGeneration(storage, slotIndex)
	if err != nil {
		return err
	}
	if found && validCapacityArtifactBuildID(generation.BuildID) {
		if err := os.RemoveAll(capacityPieceBuildDir(storage, generation.BuildID)); err != nil {
			return err
		}
		if err := os.Remove(capacityPieceBuildIndexPath(storage, generation.BuildID)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Remove(capacitySlotGenerationPath(storage, slotIndex)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func copyFileTo(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-cap-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// resealCapacityPieceRoots is kept for legacy mixed capacity-sector recovery only.
// The live storage path no longer appends real user pieces to capacity sectors:
// capacity sectors prove free reserved bytes, while data sectors prove real files.
func resealCapacityPieceRoots(storage string, sector *SectorMeta, cfg ServerConfig) error {
	blockSize := cfg.PieceBlockSize
	if blockSize <= 0 {
		blockSize = DefaultPieceBlockSize
	}

	// Separate dummy piece (Name=="capacity") from real pieces.
	dummyRoot := ""
	realRoots := []string{}
	for _, root := range sector.PieceRoots {
		if m, merr := readMeta(storage, root); merr == nil && m.Name == "capacity" {
			dummyRoot = root
		} else {
			realRoots = append(realRoots, root)
		}
	}

	// Sum real piece bytes.
	var realUsedBytes int64
	for _, root := range realRoots {
		if m, merr := readMeta(storage, root); merr == nil {
			realUsedBytes += m.Size
		}
	}

	// Remove old dummy file and meta.
	if dummyRoot != "" {
		_ = os.Remove(piecePath(storage, dummyRoot))
		_ = os.Remove(metaPath(storage, dummyRoot))
	}

	newDummySize := cfg.CapacityBytes - realUsedBytes
	if newDummySize > 0 {
		tmpPath := filepath.Join(tmpDir(storage), "capacity-reseal.tmp")
		defer os.Remove(tmpPath)

		if err := writeRandomCapacityFile(tmpPath, newDummySize); err != nil {
			return fmt.Errorf("write resized dummy: %w", err)
		}
		newRoot, pieceHash, blockCount, size, err := computePieceCommitment(tmpPath, blockSize)
		if err != nil {
			return fmt.Errorf("compute resized dummy root: %w", err)
		}
		finalPath := piecePath(storage, newRoot)
		if _, statErr := os.Stat(finalPath); os.IsNotExist(statErr) {
			if err := os.Rename(tmpPath, finalPath); err != nil {
				if err2 := copyFileTo(tmpPath, finalPath); err2 != nil {
					return fmt.Errorf("move resized dummy: %v / %v", err, err2)
				}
			}
		}
		newMeta := PieceMeta{
			Name:            "capacity",
			PieceRoot:       newRoot,
			PieceID:         newRoot,
			CID:             cidV0FromSHA256Hex(pieceHash),
			PieceHash:       pieceHash,
			HashAlg:         HashAlgSha256,
			RootAlg:         RootAlgMerkleSHA256,
			PieceBlockSize:  blockSize,
			PieceBlockCount: blockCount,
			Size:            size,
			ServiceEnd:      sector.MaxServiceEnd,
			StoredAt:        nowRFC3339(),
			SectorID:        sector.SectorID,
		}
		_ = writeMeta(storage, newMeta)
		sector.PieceRoots = append([]string{newRoot}, realRoots...)
		log.Printf("[capacity] dummy shrunk to %.1f MB  realUsed=%.1f MB",
			float64(newDummySize)/1e6, float64(realUsedBytes)/1e6)
	} else {
		sector.IsCapacity = false
		sector.PieceRoots = realRoots
		log.Printf("[capacity] sector fully converted to real data  realUsed=%.1f MB", float64(realUsedBytes)/1e6)
	}
	return nil
}

func capacityPieceMeta(storage string, cfg ServerConfig, targetSize int64) (PieceMeta, error) {
	meta, _, err := capacityPieceMetaForSlotWithOwnership(storage, cfg, targetSize, 0)
	return meta, err
}

func capacityPieceMetaForSlot(storage string, cfg ServerConfig, targetSize int64, slotIndex int) (PieceMeta, error) {
	meta, _, err := capacityPieceMetaForSlotWithOwnership(storage, cfg, targetSize, slotIndex)
	return meta, err
}

// capacityPieceMetaForSlotWithOwnership reports whether this invocation
// installed the final piece file. Filler is cryptographically random and the
// random bytes themselves are the only durable source; BuildID is not a seed.
func capacityPieceMetaForSlotWithOwnership(storage string, cfg ServerConfig, targetSize int64, slotIndex int) (PieceMeta, bool, error) {
	if targetSize <= 0 {
		return PieceMeta{}, false, fmt.Errorf("capacity piece target size must be positive")
	}
	if err := removeLegacyCapacitySeed(storage); err != nil {
		return PieceMeta{}, false, err
	}

	blockSize := cfg.PieceBlockSize
	if blockSize <= 0 {
		blockSize = DefaultPieceBlockSize
	}
	if blockSize > int64(int(^uint(0)>>1)) {
		return PieceMeta{}, false, fmt.Errorf("capacity piece block size too large")
	}
	slotLock, err := acquireCapacitySlotGenerationLock(storage, slotIndex)
	if err != nil {
		return PieceMeta{}, false, fmt.Errorf("lock capacity slot generation: %w", err)
	}
	defer releaseCapacityPieceBuildLock(slotLock)

	generation, err := loadOrCreateCapacitySlotGeneration(storage, slotIndex, targetSize, blockSize)
	if err != nil {
		return PieceMeta{}, false, err
	}
	if meta, ok := readCapacityPieceBuildIndex(storage, generation.BuildID, slotIndex, targetSize, blockSize); ok {
		if generation.PieceRoot != "" && !sameRoot(generation.PieceRoot, meta.PieceRoot) {
			return PieceMeta{}, false, fmt.Errorf("capacity slot generation root mismatch")
		}
		if generation.PieceRoot == "" {
			generation.PieceRoot = meta.PieceRoot
			if err := writeCapacitySlotGeneration(storage, generation); err != nil {
				return PieceMeta{}, false, err
			}
		}
		return meta, false, nil
	}
	lock, err := acquireCapacityPieceBuildLock(storage, generation.BuildID)
	if err != nil {
		return PieceMeta{}, false, fmt.Errorf("lock capacity piece build: %w", err)
	}
	defer releaseCapacityPieceBuildLock(lock)
	if meta, ok := readCapacityPieceBuildIndex(storage, generation.BuildID, slotIndex, targetSize, blockSize); ok {
		return meta, false, nil
	}

	log.Printf("[capacity] materializing random resumable free-space commitment %.1f MB build=%s ...",
		float64(targetSize)/1e6, generation.BuildID[:16])
	buildDir, manifest, err := loadOrCreateCapacityPieceBuild(
		storage, generation.BuildID, slotIndex, targetSize, blockSize,
	)
	if err != nil {
		return PieceMeta{}, false, fmt.Errorf("load capacity piece checkpoint: %w", err)
	}
	if manifest.Stage == "materialize" {
		if err := advanceCapacityPieceMaterialization(buildDir, &manifest); err != nil {
			return PieceMeta{}, false, fmt.Errorf("materialize capacity piece: %w", err)
		}
	}
	if manifest.Stage == "parents" {
		if err := advanceCapacityPieceParents(buildDir, &manifest); err != nil {
			return PieceMeta{}, false, fmt.Errorf("commit capacity piece: %w", err)
		}
	}
	if manifest.Stage != "complete" {
		return PieceMeta{}, false, fmt.Errorf("capacity piece build stopped in unknown stage %q", manifest.Stage)
	}
	meta, created, err := publishCapacityPieceBuild(storage, buildDir, manifest)
	if err != nil {
		return PieceMeta{}, false, err
	}
	generation.PieceRoot = meta.PieceRoot
	if err := writeCapacitySlotGeneration(storage, generation); err != nil {
		return PieceMeta{}, false, err
	}
	return meta, created, nil
}

func chooseCapacitySlotSector(storage string, sectors []SectorMeta, slotIndex int) (SectorMeta, bool) {
	wantID := capacitySlotSectorID(slotIndex)
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.IsCapacity || sector.SectorID != wantID {
			continue
		}
		if sectorHasRealPiece(storage, sector) {
			continue
		}
		return sector, true
	}
	return SectorMeta{}, false
}

func retireExtraCapacitySectors(storage string, keepSectorIDs map[string]bool) error {
	sectors, err := listSectors(storage)
	if err != nil {
		return err
	}
	protectedRoots := map[string]bool{}
	for _, sector := range sectors {
		if sector.Status == "deleted" {
			continue
		}
		willRetire := sector.IsCapacity && !keepSectorIDs[sector.SectorID] && !sectorHasRealPiece(storage, sector)
		if willRetire {
			continue
		}
		for _, root := range sector.PieceRoots {
			protectedRoots[root] = true
		}
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.IsCapacity || keepSectorIDs[sector.SectorID] {
			continue
		}
		if sectorHasRealPiece(storage, sector) {
			return fmt.Errorf("refuse to retire mixed capacity sector %s", sector.SectorID)
		}
		oldRoots := append([]string(nil), sector.PieceRoots...)
		sector.Status = "deleted"
		sector.SectorBlockCount = 0
		sector.SectorRoot = strings.Repeat("0", 64)
		sector.ZKPieceCommitment = ""
		sector.PieceRoots = nil
		sector.UpdatedAt = nowRFC3339()
		if err := writeSector(storage, sector); err != nil {
			return fmt.Errorf("retire extra capacity sector %s: %w", sector.SectorID, err)
		}
		if slotIndex, ok := parseCapacitySlotIndex(sector); ok {
			if err := retireCapacitySlotGeneration(storage, slotIndex); err != nil {
				return fmt.Errorf("retire capacity slot generation %d: %w", slotIndex, err)
			}
		}
		for _, root := range oldRoots {
			if protectedRoots[root] {
				continue
			}
			if meta, err := readMeta(storage, root); err == nil && meta.Name == "capacity" {
				_ = os.Remove(piecePath(storage, root))
				_ = os.Remove(metaPath(storage, root))
			}
		}
	}
	return nil
}

func rootReferencedByOtherActiveSector(storage, root, sectorID string) bool {
	sectors, err := listSectors(storage)
	if err != nil {
		return true
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || sector.SectorID == sectorID {
			continue
		}
		for _, existing := range sector.PieceRoots {
			if existing == root {
				return true
			}
		}
	}
	return false
}

func activeCapacitySectorMap(storage string) (map[string]SectorMeta, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return nil, err
	}
	out := map[string]SectorMeta{}
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.IsCapacity {
			continue
		}
		out[sector.SectorID] = sector
	}
	return out, nil
}

func capacitySlotMetadataMatchesFromMap(storage string, cfg ServerConfig, slot capacitySlotPlan, sectors map[string]SectorMeta) (bool, string) {
	if cfg.ZKBlockSize <= 0 {
		cfg.ZKBlockSize = DefaultZKBlockSize
	}
	if cfg.ZKTreeDepth <= 0 {
		cfg.ZKTreeDepth = DefaultZKTreeDepth
	}
	sector, found := sectors[slot.SectorID]
	if !found {
		return false, fmt.Sprintf("slot %d sector missing", slot.Index)
	}
	if sector.Status != "sealed" || !sector.IsCapacity {
		return false, fmt.Sprintf("slot %d not sealed capacity", slot.Index)
	}
	if sectorHasRealPiece(storage, sector) {
		return false, fmt.Sprintf("slot %d mixed with real piece", slot.Index)
	}
	if len(sector.PieceRoots) != 1 {
		return false, fmt.Sprintf("slot %d piece count=%d", slot.Index, len(sector.PieceRoots))
	}
	if committedSectorBytes(sector) != slot.Size {
		return false, fmt.Sprintf("slot %d committed=%d target=%d", slot.Index, committedSectorBytes(sector), slot.Size)
	}
	root := sector.PieceRoots[0]
	blockSize := cfg.PieceBlockSize
	if blockSize <= 0 {
		blockSize = DefaultPieceBlockSize
	}
	generation, found, generationErr := readCapacitySlotGeneration(storage, slot.Index)
	if generationErr != nil || !found || generation.Version != capacitySlotGenerationVersion ||
		generation.TargetSize != slot.Size || generation.BlockSize != blockSize ||
		!validCapacityArtifactBuildID(generation.BuildID) || !sameRoot(generation.PieceRoot, root) {
		if generationErr != nil {
			return false, fmt.Sprintf("slot %d random generation: %v", slot.Index, generationErr)
		}
		return false, fmt.Sprintf("slot %d lacks a valid random filler generation", slot.Index)
	}
	meta, err := readMeta(storage, root)
	if err != nil {
		return false, fmt.Sprintf("slot %d meta: %v", slot.Index, err)
	}
	if meta.Name != "capacity" || meta.Size != slot.Size || meta.SectorID != sector.SectorID {
		return false, fmt.Sprintf("slot %d meta mismatch", slot.Index)
	}
	if _, err := os.Stat(piecePath(storage, root)); err != nil {
		return false, fmt.Sprintf("slot %d piece missing: %v", slot.Index, err)
	}
	if sector.SectorRoot == "" || sector.ZKPieceCommitment == "" || sector.SectorBlockCount <= 0 {
		return false, fmt.Sprintf("slot %d sector commitment missing", slot.Index)
	}
	if err := validateZKSectorCache(storage, sector.SectorRoot, sector.PieceRoots, cfg.ZKBlockSize, cfg.ZKTreeDepth); err != nil {
		return false, fmt.Sprintf("slot %d zk cache: %v", slot.Index, err)
	}
	return true, "ok"
}

func capacitySlotMetadataMatches(storage string, cfg ServerConfig, slot capacitySlotPlan) (bool, string) {
	sectors, err := activeCapacitySectorMap(storage)
	if err != nil {
		return false, fmt.Sprintf("list sectors: %v", err)
	}
	return capacitySlotMetadataMatchesFromMap(storage, cfg, slot, sectors)
}

func capacityPlanMetadataMatches(storage string, cfg ServerConfig, plan []capacitySlotPlan) (bool, string) {
	expected := map[string]bool{}
	sectors, err := activeCapacitySectorMap(storage)
	if err != nil {
		return false, fmt.Sprintf("list sectors: %v", err)
	}
	for _, slot := range plan {
		expected[slot.SectorID] = true
		if ok, detail := capacitySlotMetadataMatchesFromMap(storage, cfg, slot, sectors); !ok {
			return false, detail
		}
	}
	for sectorID := range sectors {
		if !expected[sectorID] {
			return false, fmt.Sprintf("unexpected capacity sector %s", sectorID)
		}
	}
	return true, "ok"
}

func createCapacitySector(storage string, cfg ServerConfig, targetSize int64) error {
	return upsertCapacitySlotSector(storage, cfg, 0, targetSize, targetSize)
}

func upsertCapacitySector(storage string, cfg ServerConfig, targetSize int64) error {
	return upsertCapacitySlotSector(storage, cfg, 0, targetSize, targetSize)
}

func upsertCapacitySlotSector(storage string, cfg ServerConfig, slotIndex int, targetSize, slotSize int64) error {
	if targetSize <= 0 {
		return nil
	}
	if cfg.SectorMaxPieces <= 0 {
		cfg.SectorMaxPieces = DefaultSectorMaxPieces
	}
	if cfg.SectorLifetimeDays <= 0 {
		cfg.SectorLifetimeDays = DefaultSectorLifetimeDays
	}
	if cfg.ZKBlockSize <= 0 {
		cfg.ZKBlockSize = DefaultZKBlockSize
	}
	if cfg.ZKTreeDepth <= 0 {
		cfg.ZKTreeDepth = DefaultZKTreeDepth
	}
	if cfg.DeadlineCount <= 0 {
		cfg.DeadlineCount = 0
	}
	if slotSize <= 0 {
		var err error
		slotSize, err = resolvedCapacitySlotSize(cfg)
		if err != nil {
			return err
		}
	}
	if targetSize > slotSize {
		return fmt.Errorf("capacity slot %d target %d exceeds slot size %d", slotIndex, targetSize, slotSize)
	}

	meta, createdPiece, err := capacityPieceMetaForSlotWithOwnership(storage, cfg, targetSize, slotIndex)
	if err != nil {
		return err
	}

	// Keep creation transactional: if any later step fails, clean up the newly
	// staged capacity artifacts so failed rebalances cannot accumulate orphan
	// files. Never remove a deterministic piece that predates this attempt or is
	// referenced by an active (possibly still on-chain-proven) sector.
	cleanupOnError := true
	metaWritten := false
	defer func() {
		if !cleanupOnError {
			return
		}
		if rootReferencedByOtherActiveSector(storage, meta.PieceRoot, "") {
			return
		}
		if createdPiece {
			_ = os.Remove(piecePath(storage, meta.PieceRoot))
		}
		if metaWritten {
			_ = os.Remove(metaPath(storage, meta.PieceRoot))
		}
	}()

	sectors, err := listSectors(storage)
	if err != nil {
		return fmt.Errorf("list sectors for capacity upsert: %w", err)
	}
	sector, found := chooseCapacitySlotSector(storage, sectors, slotIndex)
	oldRoots := append([]string(nil), sector.PieceRoots...)
	if !found {
		sector = newSectorWithID(cfg, meta.ServiceEnd, capacitySlotSectorID(slotIndex))
	} else if sector.CreatedAt == "" {
		sector.CreatedAt = nowRFC3339()
	}
	sector.IsCapacity = true
	sector.CapacitySlotIndex = slotIndex
	sector.CapacitySlotSizeBytes = slotSize
	sector.Status = "sealed"
	sector.PieceRoots = []string{meta.PieceRoot}
	sector.MinServiceEnd = meta.ServiceEnd
	sector.MaxServiceEnd = meta.ServiceEnd

	sectorRoot, sectorBlockCount, zkPC, err := computeBackgroundZKSectorRoot(
		storage, sector.PieceRoots, cfg.ZKBlockSize, cfg.ZKTreeDepth, cfg.ForceCapacityRebuild,
	)
	if err != nil {
		return fmt.Errorf("compute capacity ZK sector root: %w", err)
	}
	sector.SectorRoot = sectorRoot
	sector.SectorBlockCount = sectorBlockCount
	sector.ZKPieceCommitment = zkPC
	sector.RootAlg = RootAlgZKMiMCBN254
	sector.ZKBlockSize = cfg.ZKBlockSize
	sector.ZKTreeDepth = cfg.ZKTreeDepth
	sector.UpdatedAt = nowRFC3339()
	if err := assignPartitionForSector(storage, &sector, cfg, PartitionKindCapacity); err != nil {
		return err
	}

	meta.SectorID = sector.SectorID
	meta.SectorRoot = sector.SectorRoot
	meta.PiecePosition = 0
	if err := writeMeta(storage, meta); err != nil {
		return fmt.Errorf("write capacity sector linkage: %w", err)
	}
	metaWritten = true
	if err := writeSector(storage, sector); err != nil {
		return fmt.Errorf("write capacity sector: %w", err)
	}
	cleanupOnError = false
	cleanupCapacityPieceBuildCheckpoint(storage, cfg, targetSize, slotIndex)
	for _, root := range oldRoots {
		if root == "" || root == meta.PieceRoot {
			continue
		}
		if rootReferencedByOtherActiveSector(storage, root, sector.SectorID) {
			continue
		}
		if oldMeta, err := readMeta(storage, root); err == nil && oldMeta.Name == "capacity" {
			_ = os.Remove(piecePath(storage, root))
			_ = os.Remove(metaPath(storage, root))
		}
	}
	log.Printf("[capacity] committed free %.1f MB  slot=%d sectorId=%s  root=%s",
		float64(targetSize)/1e6,
		slotIndex,
		sector.SectorID[:min(20, len(sector.SectorID))],
		sector.SectorRoot[:min(18, len(sector.SectorRoot))])
	cleanupOnError = false
	return nil
}

func sectorHasRealPiece(storage string, sector SectorMeta) bool {
	for _, root := range sector.PieceRoots {
		meta, err := readMeta(storage, root)
		if err != nil || meta.Name != "capacity" {
			return true
		}
	}
	return false
}

func normalizeMixedCapacitySectors(storage string) error {
	sectors, err := listSectors(storage)
	if err != nil {
		return err
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.IsCapacity || !sectorHasRealPiece(storage, sector) {
			continue
		}
		sector.IsCapacity = false
		sector.Status = "sealed"
		sector.UpdatedAt = nowRFC3339()
		if err := writeSector(storage, sector); err != nil {
			return fmt.Errorf("preserve mixed capacity sector as data %s: %w", sector.SectorID, err)
		}
		log.Printf("[capacity] preserved legacy mixed capacity sector as data  sector=%s", sector.SectorID[:min(20, len(sector.SectorID))])
	}
	return nil
}

func deleteCapacityOnlySectors(storage string) error {
	sectors, err := listSectors(storage)
	if err != nil {
		return err
	}
	for _, sector := range sectors {
		if sector.Status == "deleted" || !sector.IsCapacity {
			continue
		}
		if sectorHasRealPiece(storage, sector) {
			return fmt.Errorf("refuse to delete mixed capacity sector %s", sector.SectorID)
		}
		sector.Status = "deleted"
		sector.SectorBlockCount = 0
		sector.SectorRoot = strings.Repeat("0", 64)
		sector.ZKPieceCommitment = ""
		oldRoots := append([]string(nil), sector.PieceRoots...)
		sector.PieceRoots = nil
		sector.UpdatedAt = nowRFC3339()
		if err := writeSector(storage, sector); err != nil {
			return fmt.Errorf("mark capacity sector deleted %s: %w", sector.SectorID, err)
		}
		if slotIndex, ok := parseCapacitySlotIndex(sector); ok {
			if err := retireCapacitySlotGeneration(storage, slotIndex); err != nil {
				return fmt.Errorf("retire capacity slot generation %d: %w", slotIndex, err)
			}
		}
		for _, root := range oldRoots {
			if meta, err := readMeta(storage, root); err == nil && meta.Name == "capacity" {
				_ = os.Remove(piecePath(storage, root))
				_ = os.Remove(metaPath(storage, root))
			}
		}
	}
	return nil
}

// rebalanceCapacitySectors maintains immutable capacity chunks whose total is
// the smallest fixed-slot backing that covers declared capacity minus committed
// data bytes. This preserves a cryptographically exact lower bound without
// rebuilding a variable tail after every upload.
func rebalanceCapacitySectors(storage string, cfg ServerConfig) (retErr error) {
	capacityRebalanceMu.Lock()
	defer capacityRebalanceMu.Unlock()

	if cfg.CapacityBytes <= 0 {
		return nil
	}
	// Only one process may alter this VK's capacity slots at a time. Publish a
	// durable mutation lease while the expensive build runs, so chain publication
	// and stale cleanup defer without blocking foreground transfers.
	buildLock, err := acquireCapacityBuildLock(storage)
	if err != nil {
		return err
	}
	defer releaseCapacityBuildLock(buildLock)
	mutationOperationID, err := markCapacityProofCatchupBuild(
		storage, "capacity snapshot build active",
	)
	if err != nil {
		return fmt.Errorf("mark capacity snapshot build: %w", err)
	}
	mutationLease, err := beginCapacityMutationOperation(
		storage, mutationOperationID, "capacity_rebuild",
	)
	if err != nil {
		return err
	}
	defer mutationLease.Release()
	beforeAccounting, err := computeCapacityAccounting(storage, cfg.CapacityBytes)
	if err != nil {
		return err
	}
	beforeState := capacityMutationSectorState{
		Exists: true, PartitionKind: PartitionKindCapacity,
		DeadlineIndex: -1, PartitionIndex: -1,
		ContentHash:    fmt.Sprintf("capacity:%d:%d", beforeAccounting.FreeBytes, beforeAccounting.CapacitySectorCount),
		CommittedBytes: beforeAccounting.FreeBytes, Status: "capacity_backing",
	}
	if err := mutationLease.PrepareSectorTransition(beforeState, beforeState); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = setCapacityProofCatchupPhase(storage, "rebuild_failed", retErr.Error())
		}
	}()

	if err := normalizeMixedCapacitySectors(storage); err != nil {
		return err
	}
	accounting, err := computeCapacityAccounting(storage, cfg.CapacityBytes)
	if err != nil {
		return err
	}
	if accounting.UsedBytes > cfg.CapacityBytes {
		return fmt.Errorf("used data bytes %d exceed declared capacity %d", accounting.UsedBytes, cfg.CapacityBytes)
	}
	targetFree := cfg.CapacityBytes - accounting.UsedBytes
	if targetFree < 0 {
		targetFree = 0
	}
	targetFree = committedFreeCapacityTarget(targetFree, cfg.ZKBlockSize)

	plan, slotSize, err := capacitySlotPlanForFree(cfg, targetFree)
	if err != nil {
		return err
	}
	backingBytes := capacitySlotPlanBytes(plan)
	// Presentation only: count verified or successfully prepared slots, never
	// infer progress from elapsed time or count these bytes as proven on-chain.
	preparedBytes := int64(0)
	reportPrepared := func() {
		log.Printf("[storage-preparation] completed_bytes=%d total_bytes=%d", preparedBytes, backingBytes)
	}
	reportPrepared()
	keep := map[string]bool{}
	for _, slot := range plan {
		keep[slot.SectorID] = true
	}
	if targetFree <= 0 {
		if err := deleteCapacityOnlySectors(storage); err != nil {
			return err
		}
	} else if !cfg.ForceCapacityRebuild {
		if ok, detail := capacityPlanMetadataMatches(storage, cfg, plan); ok {
			log.Printf("[capacity] resume: verified existing free-space slots %.1f MB (%s)",
				float64(targetFree)/1e6, detail)
			preparedBytes = backingBytes
			reportPrepared()
		} else {
			log.Printf("[capacity] slot plan changed (%s); reconciling free-space slots", detail)
			if err := retireExtraCapacitySectors(storage, keep); err != nil {
				return err
			}
			activeSlots, err := activeCapacitySectorMap(storage)
			if err != nil {
				return fmt.Errorf("list capacity slots: %w", err)
			}
			for _, slot := range plan {
				if ok, _ := capacitySlotMetadataMatchesFromMap(storage, cfg, slot, activeSlots); ok {
					preparedBytes += slot.Size
					reportPrepared()
					continue
				}
				if err := upsertCapacitySlotSector(storage, cfg, slot.Index, slot.Size, slotSize); err != nil {
					return err
				}
				preparedBytes += slot.Size
				reportPrepared()
			}
		}
	} else {
		log.Printf("[capacity] force rebuild requested")
		if err := retireExtraCapacitySectors(storage, keep); err != nil {
			return err
		}
		for _, slot := range plan {
			// Force rebuild means a fresh random generation, never reconstruction
			// from an old compact secret or reuse of the previous filler root.
			if err := retireCapacitySlotGeneration(storage, slot.Index); err != nil {
				return fmt.Errorf("reset capacity slot generation %d: %w", slot.Index, err)
			}
			if err := upsertCapacitySlotSector(storage, cfg, slot.Index, slot.Size, slotSize); err != nil {
				return err
			}
			preparedBytes += slot.Size
			reportPrepared()
		}
	}
	if len(keep) > 0 {
		if err := retireExtraCapacitySectors(storage, keep); err != nil {
			return err
		}
	}
	log.Printf("[capacity] balanced declared=%.1f MB used=%.1f MB logicalFree=%.1f MB proofBacking=%.1f MB slots=%d slotSize=%.1f MB",
		float64(cfg.CapacityBytes)/1e6, float64(accounting.UsedBytes)/1e6,
		float64(targetFree)/1e6, float64(backingBytes)/1e6, len(plan), float64(slotSize)/1e6)
	if err := setCapacityProofCatchupPhase(storage, "awaiting_registration", "exact local capacity snapshot ready"); err != nil {
		return fmt.Errorf("mark capacity snapshot ready: %w", err)
	}
	afterAccounting, err := computeCapacityAccounting(storage, cfg.CapacityBytes)
	if err != nil {
		return err
	}
	afterState := capacityMutationSectorState{
		Exists: true, PartitionKind: PartitionKindCapacity,
		DeadlineIndex: -1, PartitionIndex: -1,
		ContentHash:    fmt.Sprintf("capacity:%d:%d", afterAccounting.FreeBytes, afterAccounting.CapacitySectorCount),
		CommittedBytes: afterAccounting.FreeBytes, Status: "capacity_backing",
	}
	if err := mutationLease.FinalizePreparedTransition(afterState); err != nil {
		return err
	}
	if err := mutationLease.Complete(); err != nil {
		return err
	}
	// G.3D: publish the physical-layout generation only after the complete local
	// rebalance is durable. Ordinary same-geometry rebalances preserve the revision;
	// an explicit force rebuild records a genuine physical replacement.
	if err := recordCapacityLayoutAfterRebalance(storage, cfg, cfg.ForceCapacityRebuild); err != nil {
		return fmt.Errorf("record capacity layout provenance: %w", err)
	}
	return nil
}

func capacityNeedsRebalance(storage string, cfg ServerConfig) (bool, string, error) {
	if cfg.CapacityBytes <= 0 {
		return false, "", nil
	}
	accounting, err := computeCapacityAccounting(storage, cfg.CapacityBytes)
	if err != nil {
		return false, "", err
	}
	if accounting.UsedBytes > cfg.CapacityBytes {
		return false, "", fmt.Errorf("used data bytes %d exceed declared capacity %d", accounting.UsedBytes, cfg.CapacityBytes)
	}
	targetFree := cfg.CapacityBytes - accounting.UsedBytes
	if targetFree < 0 {
		targetFree = 0
	}
	targetFree = committedFreeCapacityTarget(targetFree, cfg.ZKBlockSize)
	plan, _, err := capacitySlotPlanForFree(cfg, targetFree)
	if err != nil {
		return false, "", err
	}
	targetBacking := capacitySlotPlanBytes(plan)
	if accounting.FreeBytes != targetBacking {
		return true, fmt.Sprintf("backing=%d targetBacking=%d logicalFree=%d used=%d slots=%d",
			accounting.FreeBytes, targetBacking, targetFree, accounting.UsedBytes, len(plan)), nil
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return false, "", fmt.Errorf("list sectors: %w", err)
	}
	active := map[string]int64{}
	for _, s := range sectors {
		if s.Status == "deleted" || !s.IsCapacity {
			continue
		}
		active[s.SectorID] = committedSectorBytes(s)
	}
	if len(active) != len(plan) {
		return true, fmt.Sprintf("backing=%d targetBacking=%d logicalFree=%d used=%d slots=%d activeSlots=%d",
			accounting.FreeBytes, targetBacking, targetFree, accounting.UsedBytes, len(plan), len(active)), nil
	}
	for _, slot := range plan {
		if active[slot.SectorID] != slot.Size {
			return true, fmt.Sprintf("backing=%d targetBacking=%d logicalFree=%d used=%d slot=%d active=%d want=%d",
				accounting.FreeBytes, targetBacking, targetFree, accounting.UsedBytes,
				slot.Index, active[slot.SectorID], slot.Size), nil
		}
	}
	// Byte totals alone are insufficient for chain publication: a crash may
	// leave sector metadata with the right size but a missing/truncated piece or
	// ZK cache. Treat that state as unfinished so it is rebuilt, never registered.
	if ok, detail := capacityPlanMetadataMatches(storage, cfg, plan); !ok {
		return true, fmt.Sprintf("backing=%d targetBacking=%d logicalFree=%d used=%d metadata=%s",
			accounting.FreeBytes, targetBacking, targetFree, accounting.UsedBytes, detail), nil
	}
	return false, fmt.Sprintf("backing=%d logicalFree=%d used=%d slots=%d",
		accounting.FreeBytes, targetFree, accounting.UsedBytes, len(plan)), nil
}

func capacityProofCatchupPath(storage string) string {
	return filepath.Join(storage, "capacity-proof-catchup.pending")
}

func capacityProofCatchupLockPath(storage string) string {
	return filepath.Join(storage, "capacity-proof-catchup.lock")
}

// The server and proof daemon are separate processes.  Catch-up state is a
// read/modify/write record (not merely a marker), so atomic rename alone does
// not prevent one process from overwriting a newer phase or the initial
// admission gate written by the other process.
func withCapacityProofCatchupLock(storage string, fn func() error) error {
	if err := os.MkdirAll(storage, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(capacityProofCatchupLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

const capacityProofCatchupStateVersion = 1

type capacityProofCatchupState struct {
	Version             int    `json:"version"`
	CreatedAt           string `json:"createdAt"`
	UpdatedAt           string `json:"updatedAt"`
	Phase               string `json:"phase"`
	Detail              string `json:"detail,omitempty"`
	AdmissionGate       bool   `json:"admissionGate,omitempty"`
	MutationOperationID string `json:"mutationOperationId,omitempty"`
}

func markCapacityProofCatchupBuild(storage, detail string) (operationID string, err error) {
	err = withCapacityProofCatchupLock(storage, func() error {
		state, found, readErr := readCapacityProofCatchupUnlocked(storage)
		if readErr != nil {
			return readErr
		}
		now := nowRFC3339()
		if !found {
			state = capacityProofCatchupState{Version: capacityProofCatchupStateVersion, CreatedAt: now}
		}
		if state.MutationOperationID == "" {
			buildID, buildErr := randomCapacityBuildID()
			if buildErr != nil {
				return buildErr
			}
			state.MutationOperationID = "capacity-build:" + buildID
		}
		state.Version = capacityProofCatchupStateVersion
		state.UpdatedAt = now
		state.Phase = "rebuilding"
		state.Detail = detail
		operationID = state.MutationOperationID
		return writeCapacityProofCatchupUnlocked(storage, state)
	})
	return operationID, err
}

func readCapacityProofCatchupUnlocked(storage string) (capacityProofCatchupState, bool, error) {
	payload, err := os.ReadFile(capacityProofCatchupPath(storage))
	if os.IsNotExist(err) {
		return capacityProofCatchupState{}, false, nil
	}
	if err != nil {
		return capacityProofCatchupState{}, false, err
	}
	var state capacityProofCatchupState
	if json.Unmarshal(payload, &state) == nil && state.Version == capacityProofCatchupStateVersion {
		return state, true, nil
	}
	// Upgrade the old two-line marker safely. Its first line was the creation
	// time, never a real chain proof deadline.
	lines := strings.SplitN(strings.TrimSpace(string(payload)), "\n", 2)
	if len(lines) > 0 {
		if _, parseErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(lines[0])); parseErr == nil {
			detail := ""
			if len(lines) == 2 {
				detail = strings.TrimSpace(lines[1])
			}
			return capacityProofCatchupState{
				Version: capacityProofCatchupStateVersion, CreatedAt: strings.TrimSpace(lines[0]),
				UpdatedAt: nowRFC3339(), Phase: "rebuilding", Detail: detail,
			}, true, nil
		}
	}
	return capacityProofCatchupState{}, true, fmt.Errorf("invalid capacity proof catch-up state")
}

func readCapacityProofCatchup(storage string) (state capacityProofCatchupState, found bool, err error) {
	err = withCapacityProofCatchupLock(storage, func() error {
		state, found, err = readCapacityProofCatchupUnlocked(storage)
		return err
	})
	return state, found, err
}

func writeCapacityProofCatchupUnlocked(storage string, state capacityProofCatchupState) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(capacityProofCatchupPath(storage), payload, 0600)
}

func setCapacityProofCatchupPhase(storage, phase, detail string) error {
	return withCapacityProofCatchupLock(storage, func() error {
		state, found, err := readCapacityProofCatchupUnlocked(storage)
		if err != nil {
			return err
		}
		now := nowRFC3339()
		if !found {
			state = capacityProofCatchupState{Version: capacityProofCatchupStateVersion, CreatedAt: now}
		}
		state.Version = capacityProofCatchupStateVersion
		state.UpdatedAt = now
		state.Phase = phase
		state.Detail = detail
		return writeCapacityProofCatchupUnlocked(storage, state)
	})
}

func markCapacityProofCatchup(storage, detail string) error {
	return setCapacityProofCatchupPhase(storage, "rebuilding", detail)
}

func markInitialCapacityProofCatchup(storage, detail string) error {
	return withCapacityProofCatchupLock(storage, func() error {
		state, found, err := readCapacityProofCatchupUnlocked(storage)
		if err != nil {
			return err
		}
		now := nowRFC3339()
		if !found {
			state = capacityProofCatchupState{Version: capacityProofCatchupStateVersion, CreatedAt: now}
		}
		state.Version = capacityProofCatchupStateVersion
		state.UpdatedAt = now
		state.Phase = "initializing"
		state.Detail = detail
		state.AdmissionGate = true
		return writeCapacityProofCatchupUnlocked(storage, state)
	})
}

func clearCapacityProofCatchup(storage string) error {
	return withCapacityProofCatchupLock(storage, func() error {
		err := os.Remove(capacityProofCatchupPath(storage))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		dir, err := os.Open(storage)
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
}

func capacityProofCatchupPending(storage string) bool {
	_, err := os.Stat(capacityProofCatchupPath(storage))
	return err == nil
}

// capacityCatchupBlocksCleanup distinguishes an in-progress/failed local
// generation from a complete generation that is merely waiting for chain
// publication or proof.  Obsolete on-chain capacity coordinates must be
// removed once the exact replacement is durable; keeping them until the proof
// marker clears makes the chain manifest differ from the local manifest and
// prevents that very proof epoch from starting.
func capacityCatchupBlocksCleanup(state capacityProofCatchupState, pending bool) bool {
	if !pending {
		return false
	}
	switch state.Phase {
	case "awaiting_registration", "awaiting_proof":
		return false
	default:
		return true
	}
}

func currentCapacityPartitionsProven(cfg ServerConfig, round uint64) (bool, error) {
	partitions, err := currentCapacityPartitions(cfg)
	if err != nil {
		return false, err
	}
	for _, partition := range partitions {
		status, statusErr := partitionVersionStatusOnChain(cfg.ChainProofCmd, partition)
		if statusErr != nil {
			return false, statusErr
		}
		if !exactPartitionVersionAlreadyProven(status, partition, round) {
			return false, nil
		}
	}
	return true, nil
}

func cleanupStaleCapacityPartitionsOnChain(storage string, cfg ServerConfig) error {
	if cfg.ChainProofCmd == "" || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return nil
	}

	// Validate local cleanup eligibility under the short filesystem lock, then
	// release it before the read-only list RPC. A slow/unavailable RPC must not
	// prevent a foreground store/delete from publishing its mutation lease.
	ready, err := capacityCleanupReady(storage, cfg)
	if err != nil {
		if errors.Is(err, ErrCapacityPublicationDeferred) {
			log.Printf("[capacity] stale partition cleanup deferred: %v", err)
			return nil
		}
		return err
	}
	if !ready {
		return nil
	}
	onChain, err := listActiveCapacityPartitionsOnChain(cfg.ChainProofCmd)
	if err != nil {
		return fmt.Errorf("capacity cleanup: list on-chain partitions: %w", err)
	}

	for _, partition := range onChain {
		if partition.PartitionKind != 2 || !partition.Active {
			continue
		}
		deactivated, tx, err := deactivateStaleCapacityPartition(cfg, partition)
		if err != nil {
			if errors.Is(err, ErrCapacityPublicationDeferred) {
				log.Printf("[capacity] stale partition cleanup deferred after chain listing: %v", err)
				return nil
			}
			return fmt.Errorf("capacity cleanup: deactivate dl%d-pt%d: %w",
				partition.DeadlineIndex, partition.PartitionIndex, err)
		}
		if deactivated {
			log.Printf("[capacity] deactivated stale on-chain capacity partition  dl=%d pt=%d tx=%s",
				partition.DeadlineIndex, partition.PartitionIndex, tx)
		}
	}
	return nil
}

// capacityCleanupReady checks the local side only. Cleanup is unsafe while a
// local generation is being built or is known broken. Once the replacement is
// durably exact (awaiting_registration/awaiting_proof), stale chain coordinates
// must be removed so the next proof epoch sees the same manifest on both sides.
func capacityCleanupReady(storage string, cfg ServerConfig) (ready bool, err error) {
	err = withCapacityCoordinationLock(storage, func() error {
		catchup, pending, catchupErr := readCapacityProofCatchup(storage)
		if catchupErr != nil {
			return fmt.Errorf("capacity cleanup: read proof catch-up state: %w", catchupErr)
		}
		if capacityCatchupBlocksCleanup(catchup, pending) {
			log.Printf("[capacity] stale partition cleanup deferred while capacity proof catch-up is pending phase=%s", catchup.Phase)
			return nil
		}
		if _, _, snapshotErr := exactCapacitySnapshotLocked(cfg); snapshotErr != nil {
			return snapshotErr
		}
		ready = true
		return nil
	})
	return ready, err
}

func capacityPartitionCoordinateExists(partitions []PartitionMeta, deadlineIndex, partitionIndex int) bool {
	for _, partition := range partitions {
		if partition.PartitionKind == PartitionKindCapacity &&
			partition.DeadlineIndex == deadlineIndex && partition.PartitionIndex == partitionIndex {
			return true
		}
	}
	return false
}

// deactivateStaleCapacityPartition revalidates one coordinate and holds the
// publication lock for one deactivation transaction only. A local mutation may
// safely run between two stale coordinates; the next coordinate is then
// revalidated from disk before any transaction is sent.
func deactivateStaleCapacityPartition(cfg ServerConfig, candidate CapacityPartitionInfo) (bool, string, error) {
	deactivated := false
	tx := ""

	// ── B.3.1 phase 1: under the coordination lock, revalidate and capture the exact identity ──
	// The captured fingerprint is the immutable call input: phase 3 refuses to complete if the
	// local capacity snapshot moved on while the lock was released for the RPC.
	skip := false
	var fingerprint string
	if err := withCapacityCoordinationLock(cfg.Storage, func() error {
		catchup, pending, err := readCapacityProofCatchup(cfg.Storage)
		if err != nil {
			return fmt.Errorf("capacity cleanup: read proof catch-up state: %w", err)
		}
		if capacityCatchupBlocksCleanup(catchup, pending) {
			return fmt.Errorf("%w: capacity proof catch-up phase=%s", ErrCapacityPublicationDeferred, catchup.Phase)
		}
		partitions, snapshotFingerprint, err := exactCapacitySnapshotLocked(cfg)
		if err != nil {
			return err
		}
		if capacityPartitionCoordinateExists(partitions, candidate.DeadlineIndex, candidate.PartitionIndex) {
			skip = true
			return nil
		}
		fingerprint = snapshotFingerprint
		return nil
	}); err != nil {
		return false, "", err
	}
	if skip {
		return false, "", nil
	}

	// ── phase 2: the chain call runs with NO coordination lock held ────────────────────────────
	tx, rpcErr := deactivatePartitionOnChain(cfg.ChainProofCmd, candidate.DeadlineIndex, candidate.PartitionIndex)

	// ── phase 3: reacquire the lock and verify the identity the call was made for ─────────────
	if err := withCapacityCoordinationLock(cfg.Storage, func() error {
		after, afterFingerprint, err := exactCapacitySnapshotStateLocked(cfg, false)
		if err != nil {
			return fmt.Errorf("%w: post-cleanup exactness check failed: %v", ErrCapacityPublicationDeferred, err)
		}
		if afterFingerprint != fingerprint ||
			capacityPartitionCoordinateExists(after, candidate.DeadlineIndex, candidate.PartitionIndex) {
			return fmt.Errorf("%w: local capacity snapshot changed during dl%d-pt%d deactivation",
				ErrCapacityPublicationDeferred, candidate.DeadlineIndex, candidate.PartitionIndex)
		}
		if rpcErr != nil {
			return rpcErr
		}
		deactivated = true
		return nil
	}); err != nil {
		return false, tx, err
	}
	return deactivated, tx, nil
}

func currentCapacityPartitionFingerprint(cfg ServerConfig) (string, error) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return "", nil
	}
	partitions, err := currentCapacityPartitions(cfg)
	if err != nil {
		return "", err
	}
	return capacityPartitionFingerprint(partitions), nil
}

func capacityPartitionFingerprint(partitions []PartitionMeta) string {
	var parts []string
	for _, p := range partitions {
		parts = append(parts, fmt.Sprintf("%d:%d:%s", p.DeadlineIndex, p.PartitionIndex, p.ContentHash))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

func currentCapacityPartitions(cfg ServerConfig) ([]PartitionMeta, error) {
	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return nil, fmt.Errorf("capacity partitions: list sectors: %w", err)
	}
	out := []PartitionMeta{}
	for _, p := range buildDeadlinePartitions(sectors, cfg.DeadlineCount, cfg.PartitionMaxSectors) {
		if p.PartitionKind != PartitionKindCapacity {
			continue
		}
		if p.ContentHash == "" {
			p.ContentHash = partitionContentHash(p)
		}
		out = append(out, p)
	}
	return out, nil
}

func capacityPartitionCoordKey(p PartitionMeta) string {
	return fmt.Sprintf("%d:%d", p.DeadlineIndex, p.PartitionIndex)
}

// capacityPartitionPublicationIntent is an immutable local generation. It lets
// a multi-partition publication release the coordination lock between chain
// transactions without ever submitting a partition from a superseded local
// snapshot.
type capacityPartitionPublicationIntent struct {
	Partition           PartitionMeta
	SnapshotFingerprint string
}

// exactCapacitySnapshotLocked returns the only snapshot that may be published.
// The caller must hold the capacity publication lock, which prevents a
// coordinated store/delete/build mutation from starting during this check.
func exactCapacitySnapshotLocked(cfg ServerConfig) ([]PartitionMeta, string, error) {
	return exactCapacitySnapshotStateLocked(cfg, true)
}

// exactCapacitySnapshotStateLocked also serves the post-transaction invariant
// check. A foreground waiter may publish its lease while the chain command is
// running, but it cannot cross the publication-lock barrier and mutate local
// state. Therefore post-checks deliberately ignore waiter leases and validate
// the unchanged disk snapshot itself.
func exactCapacitySnapshotStateLocked(cfg ServerConfig, enforceMutationGuard bool) ([]PartitionMeta, string, error) {
	if enforceMutationGuard {
		if err := capacityPublicationGuardLocked(cfg.Storage); err != nil {
			return nil, "", err
		}
	}
	if cfg.CapacityBytes > 0 {
		needsRebalance, detail, err := capacityNeedsRebalance(cfg.Storage, cfg)
		if err != nil {
			return nil, "", fmt.Errorf("%w: exactness check failed: %v", ErrCapacityPublicationDeferred, err)
		}
		if needsRebalance {
			return nil, "", fmt.Errorf("%w: local snapshot is stale (%s)", ErrCapacityPublicationDeferred, detail)
		}
	}
	partitions, err := currentCapacityPartitions(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("capacity snapshot partitions: %w", err)
	}
	return partitions, capacityPartitionFingerprint(partitions), nil
}

func captureExactCapacityPublicationIntents(cfg ServerConfig) ([]capacityPartitionPublicationIntent, error) {
	var intents []capacityPartitionPublicationIntent
	err := withCapacityCoordinationLock(cfg.Storage, func() error {
		partitions, fingerprint, err := exactCapacitySnapshotLocked(cfg)
		if err != nil {
			return err
		}
		intents = make([]capacityPartitionPublicationIntent, 0, len(partitions))
		for _, partition := range partitions {
			intents = append(intents, capacityPartitionPublicationIntent{
				Partition:           partition,
				SnapshotFingerprint: fingerprint,
			})
		}
		return nil
	})
	return intents, err
}

func matchingCapacityPartition(partitions []PartitionMeta, intended PartitionMeta) (PartitionMeta, bool) {
	for _, partition := range partitions {
		if partition.DeadlineIndex != intended.DeadlineIndex || partition.PartitionIndex != intended.PartitionIndex {
			continue
		}
		if partition.PartitionKind != PartitionKindCapacity || partition.ContentHash != intended.ContentHash {
			return PartitionMeta{}, false
		}
		return partition, true
	}
	return PartitionMeta{}, false
}

// publishExactCapacityPartition holds the publication lock for one chain
// transaction only. The complete snapshot generation and the exact coordinate
// are revalidated immediately before submission. Releasing the lock after each
// transaction lets foreground mutations interleave safely between partitions.
func publishExactCapacityPartition(
	cfg ServerConfig,
	intent capacityPartitionPublicationIntent,
	publish func(PartitionMeta) error,
) error {
	return withCapacityChainPublicationLock(cfg.Storage, func() error {
		var partition PartitionMeta
		var fingerprint string
		if err := withCapacityCoordinationLock(cfg.Storage, func() error {
			partitions, currentFingerprint, err := exactCapacitySnapshotLocked(cfg)
			if err != nil {
				return err
			}
			if currentFingerprint != intent.SnapshotFingerprint {
				return fmt.Errorf("%w: capacity snapshot generation changed before dl%d-pt%d publication",
					ErrCapacityPublicationDeferred, intent.Partition.DeadlineIndex, intent.Partition.PartitionIndex)
			}
			current, ok := matchingCapacityPartition(partitions, intent.Partition)
			if !ok {
				return fmt.Errorf("%w: capacity partition dl%d-pt%d changed before publication",
					ErrCapacityPublicationDeferred, intent.Partition.DeadlineIndex, intent.Partition.PartitionIndex)
			}
			partition, fingerprint = current, currentFingerprint
			return nil
		}); err != nil {
			return err
		}

		// The durable transaction barrier remains held, but the short coordination lock is not.
		if err := publish(partition); err != nil {
			return err
		}

		// Coordinated writers cannot enter while this transaction is in flight.
		// This post-check detects any legacy writer that did not create a mutation
		// lease; it is an invariant alarm, not permission to publish stale content.
		return withCapacityCoordinationLock(cfg.Storage, func() error {
			after, afterFingerprint, err := exactCapacitySnapshotStateLocked(cfg, false)
			if err != nil {
				return fmt.Errorf("%w: post-publication exactness check failed: %v", ErrCapacityPublicationDeferred, err)
			}
			if afterFingerprint != fingerprint {
				return fmt.Errorf("%w: local snapshot changed during dl%d-pt%d chain registration",
					ErrCapacityPublicationDeferred, partition.DeadlineIndex, partition.PartitionIndex)
			}
			if _, ok := matchingCapacityPartition(after, partition); !ok {
				return fmt.Errorf("%w: local partition dl%d-pt%d changed during chain registration",
					ErrCapacityPublicationDeferred, partition.DeadlineIndex, partition.PartitionIndex)
			}
			return nil
		})
	})
}

func registerCurrentCapacityPartitionsOnChain(cfg ServerConfig) (int, error) {
	if cfg.ChainProofCmd == "" || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return 0, nil
	}
	intents, err := captureExactCapacityPublicationIntents(cfg)
	if err != nil {
		return 0, err
	}
	registered := 0
	var errs []error
	for _, intent := range intents {
		err := publishExactCapacityPartition(cfg, intent, func(p PartitionMeta) error {
			tx, err := registerConfiguredPartitionOnChain(cfg, p)
			if err != nil {
				return fmt.Errorf("capacity partition registration dl%d-pt%d: %w",
					p.DeadlineIndex, p.PartitionIndex, err)
			}
			// NEVER treat a missing transaction as a completed registration. An empty tx is
			// ambiguous: either p's content is ALREADY the current registered identity on chain
			// (a benign no-op the adapter sends no tx for) or the change did NOT reach chain (the
			// Run-16 VK4 wedge). Classify from CHAIN TRUTH (read-back) — never advance on err==nil
			// alone. `strings.TrimSpace(tx)` stays the trigger, so an empty tx is never trusted.
			return applyCapacityRegistrationOutcome(cfg, p, tx, len(p.Sectors))
		})
		if err != nil {
			// A stale-snapshot deferral means the captured intents no longer describe local
			// state; stop and let the next reconcile re-capture. Any other error is a single
			// partition's held/retrying registration — ISOLATE it so the remaining, independent
			// partitions in this pass still make progress (Run-17 Go-2 flaw: one retrying
			// partition returned early and could block later ones).
			if errors.Is(err, ErrCapacityPublicationDeferred) {
				return registered, err
			}
			errs = append(errs, err)
			continue
		}
		registered++
	}
	if len(errs) > 0 {
		return registered, errors.Join(errs...)
	}
	return registered, nil
}

// applyCapacityRegistrationOutcome classifies a capacity registration transaction and returns nil
// only when the registration is durably reflected on chain (a real tx, or an empty tx proven to be
// an already-current no-op). It NEVER advances on an unverified empty tx: a not-current or
// unverifiable empty tx is a retryable error so the caller holds the job and does not record it as
// registered.
func applyCapacityRegistrationOutcome(cfg ServerConfig, p PartitionMeta, tx string, sectors int) error {
	outcome, rbErr := classifyMutationTx(tx, func() (bool, error) {
		return capacityPartitionRegistrationCurrentOnChain(cfg, p)
	})
	switch outcome {
	case mutationApplied:
		if strings.TrimSpace(tx) == "" {
			// A: chain read-back proves our exact content is already the current registered
			// identity. No transaction was needed; the registration is satisfied.
			log.Printf("[capacity] capacity partition already current on chain  dl=%d pt=%d (no tx needed; registration satisfied)",
				p.DeadlineIndex, p.PartitionIndex)
		} else {
			log.Printf("[capacity] registered capacity partition  dl=%d pt=%d sectors=%d tx=%s",
				p.DeadlineIndex, p.PartitionIndex, sectors, tx)
		}
		return nil
	case mutationNotApplied:
		// B: empty tx and the chain still holds different/no content — the change did not land.
		return fmt.Errorf("capacity partition registration dl%d-pt%d returned no transaction and chain does not hold this content; not applied, will retry",
			p.DeadlineIndex, p.PartitionIndex)
	default: // mutationUnverifiable
		// C: empty tx and chain truth could not be read — fail closed, never advance on doubt.
		return fmt.Errorf("capacity partition registration dl%d-pt%d returned no transaction and chain read-back unavailable (%v); not applied, will retry",
			p.DeadlineIndex, p.PartitionIndex, rbErr)
	}
}

func registerChangedCapacityPartitionsOnChain(cfg ServerConfig, lastRegistered map[string]string) (int, error) {
	if cfg.ChainProofCmd == "" || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return 0, nil
	}
	intents, err := captureExactCapacityPublicationIntents(cfg)
	if err != nil {
		return 0, err
	}
	registered := 0
	currentKeys := make(map[string]bool, len(intents))
	for _, intent := range intents {
		currentKeys[capacityPartitionCoordKey(intent.Partition)] = true
	}
	if lastRegistered != nil {
		for key := range lastRegistered {
			if !currentKeys[key] {
				delete(lastRegistered, key)
			}
		}
	}
	var errs []error
	for _, intent := range intents {
		p := intent.Partition
		key := capacityPartitionCoordKey(p)
		if lastRegistered != nil && lastRegistered[key] == p.ContentHash {
			continue
		}
		err := publishExactCapacityPartition(cfg, intent, func(current PartitionMeta) error {
			tx, err := registerConfiguredPartitionOnChain(cfg, current)
			if err != nil {
				return fmt.Errorf("capacity partition registration dl%d-pt%d: %w",
					current.DeadlineIndex, current.PartitionIndex, err)
			}
			// This path is reached for content the LOCAL dedup thinks changed — but lastRegistered
			// is in-memory and empty after a restart, so an already-current partition also lands
			// here. An empty tx is therefore ambiguous: already-current (benign no-op, e.g. after
			// a restart with the content still on chain) OR a genuine change that did NOT reach
			// chain (Run-16 VK4 wedge, which also broke the VK2 deletion successor lineage).
			// Classify from CHAIN TRUTH; lastRegistered is advanced below ONLY when this returns
			// nil (applied), never on an unverified empty tx.
			return applyCapacityRegistrationOutcome(cfg, current, tx, len(current.Sectors))
		})
		if err != nil {
			// Stale-snapshot deferral -> re-capture next reconcile. Any other error is this one
			// partition's held/retrying registration -> ISOLATE and keep going so the remaining
			// independent partitions still progress.
			if errors.Is(err, ErrCapacityPublicationDeferred) {
				return registered, err
			}
			errs = append(errs, err)
			continue
		}
		registered++
		if lastRegistered != nil {
			lastRegistered[key] = p.ContentHash
		}
	}
	if len(errs) > 0 {
		return registered, errors.Join(errs...)
	}
	return registered, nil
}

func syncCurrentCapacityPartitionsOnChain(cfg ServerConfig) error {
	if cfg.ChainProofCmd == "" || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return nil
	}
	registered, err := registerCurrentCapacityPartitionsOnChain(cfg)
	if err != nil {
		return err
	}
	if registered == 0 {
		log.Printf("[capacity] no active capacity partition to sync on-chain")
	}
	return nil
}

// initCapacitySectors ensures the proof daemon or an explicit maintenance run
// has an exact capacity-only snapshot. Network-server startup only verifies and
// queues this work, so lengthy proof construction cannot delay VK readiness.
func initCapacitySectors(storage string, cfg ServerConfig) error {
	if cfg.CapacityBytes <= 0 {
		return nil
	}
	if cfg.ResumeCapacity {
		log.Printf("[capacity] resume mode enabled; verifying existing capacity before rebuild")
	}
	log.Printf("[capacity] initializing declared capacity %.1f MB", float64(cfg.CapacityBytes)/1e6)
	return rebalanceCapacitySectors(storage, cfg)
}
