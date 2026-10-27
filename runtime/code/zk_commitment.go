package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	mimcNative "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

const (
	FieldWordBytes        = 31
	ZKBlockWords          = 5
	ZKSectorCacheVersion  = "zk-sector-cache-v2"
	ZKSectorCacheRootName = "zk_cache"
)

var bn254FrModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
var zkCommitmentSplitBase = new(big.Int).Lsh(big.NewInt(1), 128)

type ZKSectorCacheMeta struct {
	Version           string   `json:"version"`
	RootAlg           string   `json:"rootAlg"`
	SectorRoot        string   `json:"sectorRoot"`
	ZKBlockSize       int64    `json:"zkBlockSize"`
	ZKTreeDepth       int      `json:"zkTreeDepth"`
	SectorBlockCount  int      `json:"sectorBlockCount"`
	LeafCount         int      `json:"leafCount"`
	PieceRoots        []string `json:"pieceRoots"`
	PieceBlockCounts  []int    `json:"pieceBlockCounts"`
	ZKPieceCommitment string   `json:"zkPieceCommitment"`
	LevelFiles        []string `json:"levelFiles"`
	LevelNodeCounts   []int    `json:"levelNodeCounts"`
	EmptyHashes       []string `json:"emptyHashes"`
	CreatedAt         string   `json:"createdAt"`
	// SnapshotID is optional so the on-disk cache remains compatible with the
	// existing prover. It lets a restarted builder recover a fully published
	// cache when the process died before writing the separate snapshot index.
	SnapshotID string `json:"snapshotId,omitempty"`
}

const zkSectorBuildVersion = "zk-sector-build-v1"

type zkSectorSnapshotPiece struct {
	Root string `json:"root"`
	Size int64  `json:"size"`
}

type zkSectorSnapshot struct {
	ID          string                  `json:"id"`
	ZKBlockSize int64                   `json:"zkBlockSize"`
	ZKTreeDepth int                     `json:"zkTreeDepth"`
	Pieces      []zkSectorSnapshotPiece `json:"pieces"`
}

type zkSectorBuildManifest struct {
	Version             string                  `json:"version"`
	SnapshotID          string                  `json:"snapshotId"`
	ZKBlockSize         int64                   `json:"zkBlockSize"`
	ZKTreeDepth         int                     `json:"zkTreeDepth"`
	Pieces              []zkSectorSnapshotPiece `json:"pieces"`
	ZKPieceCommitment   string                  `json:"zkPieceCommitment"`
	Stage               string                  `json:"stage"`
	PieceIndex          int                     `json:"pieceIndex"`
	PieceOffset         int64                   `json:"pieceOffset"`
	DataBlockCount      int                     `json:"dataBlockCount"`
	PieceBlockCounts    []int                   `json:"pieceBlockCounts"`
	CommitmentAppended  bool                    `json:"commitmentAppended"`
	CurrentLevel        int                     `json:"currentLevel"`
	CurrentLevelWritten int                     `json:"currentLevelWritten"`
	LevelNodeCounts     []int                   `json:"levelNodeCounts"`
	ResultRoot          string                  `json:"resultRoot,omitempty"`
	UpdatedAt           string                  `json:"updatedAt"`
}

type zkSectorSnapshotIndex struct {
	Version      string `json:"version"`
	SnapshotID   string `json:"snapshotId"`
	SectorRoot   string `json:"sectorRoot"`
	BlockCount   int    `json:"blockCount"`
	ZKCommitment string `json:"zkPieceCommitment"`
}

// zkBuildAfterFileSyncHook is a no-op in production. Tests replace it to
// emulate a process dying after output reached disk but before the manifest
// advanced; the next run must truncate that uncommitted tail and resume.
var zkBuildAfterFileSyncHook = func(stage string) error { return nil }

func fieldHexFromBytes(b []byte) string {
	if len(b) >= 32 {
		return "0x" + hex.EncodeToString(b[len(b)-32:])
	}
	pad := make([]byte, 32)
	copy(pad[32-len(b):], b)
	return "0x" + hex.EncodeToString(pad)
}

func fieldBytesFromHex(root string) ([]byte, error) {
	b, err := rootBytes(root)
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(b)
	if x.Cmp(bn254FrModulus) >= 0 {
		return nil, fmt.Errorf("field root is outside BN254 scalar field")
	}
	return b, nil
}

func zkBlockWordsForSize(zkBlockSize int64) int {
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	words := int((zkBlockSize + FieldWordBytes - 1) / FieldWordBytes)
	if words < 2 {
		return 2
	}
	return words
}

func zkCircuitCapacity(zkBlockSize int64) int64 {
	return int64(zkBlockWordsForSize(zkBlockSize) * FieldWordBytes)
}

func blockWordsForSize(block []byte, zkBlockSize int64) [][]byte {
	wordCount := zkBlockWordsForSize(zkBlockSize)
	words := make([][]byte, 0, wordCount)
	for i := 0; i < wordCount; i++ {
		start := i * FieldWordBytes
		end := start + FieldWordBytes
		chunk := make([]byte, FieldWordBytes)
		if start < len(block) {
			if end > len(block) {
				end = len(block)
			}
			copy(chunk[FieldWordBytes-(end-start):], block[start:end])
		}
		words = append(words, chunk)
	}
	return words
}

func blockWords(block []byte) [][]byte {
	return blockWordsForSize(block, int64(len(block)))
}

func mimcHashPartsChecked(parts ...[]byte) ([]byte, error) {
	h := mimcNative.NewMiMC()
	for _, p := range parts {
		if _, err := h.Write(p); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func mimcHashParts(parts ...[]byte) []byte {
	h, err := mimcHashPartsChecked(parts...)
	if err != nil {
		panic(fmt.Sprintf("invalid MiMC field input: %v", err))
	}
	return h
}

func zkLeafForBlock(block []byte) []byte {
	return zkLeafForBlockWithSize(block, int64(len(block)))
}

func zkLeafForBlockWithSize(block []byte, zkBlockSize int64) []byte {
	parts := [][]byte{[]byte{0x46, 0x54, 0x2d, 0x4c, 0x45, 0x41, 0x46, 0x2d, 0x31}}
	parts = append(parts, blockWordsForSize(block, zkBlockSize)...)
	return mimcHashParts(parts...)
}

func zkHashNode(left, right []byte) []byte {
	return mimcHashParts([]byte{0x46, 0x54, 0x2d, 0x4e, 0x4f, 0x44, 0x45, 0x2d, 0x31}, left, right)
}

func zkEmptyLeaf() []byte {
	return mimcHashParts([]byte{0x46, 0x54, 0x2d, 0x45, 0x4d, 0x50, 0x54, 0x59, 0x2d, 0x31})
}

// zkMerkleRootFixed computes the MiMC Merkle root of leaves in a sparse tree
// of the given depth. Uses a parallel, level-by-level approach so it stays
// fast regardless of depth or file size:
//   - only nodes with at least one real leaf descendant are hashed
//   - all hashes at each level are computed concurrently across CPU cores
func zkMerkleRootFixed(leaves [][]byte, depth int) ([]byte, error) {
	if depth < 0 || depth > 30 {
		return nil, fmt.Errorf("ZK tree depth %d out of range [0,30]", depth)
	}
	cap64 := int64(1) << depth
	if int64(len(leaves)) > cap64 {
		return nil, fmt.Errorf("too many ZK sector leaves: %d > %d", len(leaves), cap64)
	}

	// Pre-compute empty-subtree hashes — O(depth), negligible.
	empty := make([][]byte, depth+1)
	empty[0] = zkEmptyLeaf()
	for d := 1; d <= depth; d++ {
		empty[d] = zkHashNode(empty[d-1], empty[d-1])
	}

	if len(leaves) == 0 {
		return empty[depth], nil
	}

	// Build the tree level-by-level, bottom-up.
	// currentLevel holds only the non-empty nodes at the current height.
	currentLevel := make(map[int][]byte, len(leaves))
	for i, leaf := range leaves {
		currentLevel[i] = append([]byte(nil), leaf...)
	}

	for d := 0; d < depth; d++ {
		// Collect the parent positions that have at least one real child.
		seen := make(map[int]struct{}, len(currentLevel))
		parents := make([]int, 0, len(currentLevel))
		for pos := range currentLevel {
			p := pos / 2
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				parents = append(parents, p)
			}
		}

		// Compute all parent hashes in parallel.
		// Each goroutine writes to its own slice range — no mutex needed.
		results := make([][]byte, len(parents))
		workers := runtime.NumCPU()
		if workers > len(parents) {
			workers = len(parents)
		}
		chunk := (len(parents) + workers - 1) / workers
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			lo := w * chunk
			hi := lo + chunk
			if hi > len(parents) {
				hi = len(parents)
			}
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				for i := lo; i < hi; i++ {
					p := parents[i]
					left := currentLevel[p*2]
					if left == nil {
						left = empty[d]
					}
					right := currentLevel[p*2+1]
					if right == nil {
						right = empty[d]
					}
					results[i] = zkHashNode(left, right)
				}
			}(lo, hi)
		}
		wg.Wait()

		nextLevel := make(map[int][]byte, len(parents))
		for i, p := range parents {
			nextLevel[p] = results[i]
		}
		currentLevel = nextLevel
	}

	root := currentLevel[0]
	if root == nil {
		return empty[depth], nil
	}
	return root, nil
}

// readZKLeavesForPiece reads a piece file and returns one MiMC leaf hash per
// ZK block. File I/O is sequential; leaf hashing is parallelised across all
// available CPU cores so large files (100 MB+) don't stall the server.
func readZKLeavesForPiece(path string, zkBlockSize int64) ([][]byte, error) {
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	capacity := zkCircuitCapacity(zkBlockSize)
	if zkBlockSize > capacity {
		return nil, fmt.Errorf("zk block size %d exceeds circuit capacity %d", zkBlockSize, capacity)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read all blocks sequentially (file I/O cannot be parallelised).
	var blocks [][]byte
	buf := make([]byte, int(zkBlockSize))
	for {
		n, rerr := io.ReadFull(f, buf)
		if rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			return nil, rerr
		}
		if n > 0 {
			blocks = append(blocks, append([]byte(nil), buf[:n]...))
		}
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}

	if len(blocks) == 0 {
		return [][]byte{zkLeafForBlockWithSize(nil, zkBlockSize)}, nil
	}

	// Hash each block in parallel — this is the CPU bottleneck for large files.
	leaves := make([][]byte, len(blocks))
	workers := runtime.NumCPU()
	if workers > len(blocks) {
		workers = len(blocks)
	}
	chunk := (len(blocks) + workers - 1) / workers
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		if hi > len(blocks) {
			hi = len(blocks)
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				leaves[i] = zkLeafForBlockWithSize(blocks[i], zkBlockSize)
			}
		}(lo, hi)
	}
	wg.Wait()
	return leaves, nil
}

func readZKSectorLeaves(storage string, pieceRoots []string, zkBlockSize int64) ([][]byte, error) {
	out := [][]byte{}
	for i, pieceRoot := range pieceRoots {
		path := piecePath(storage, pieceRoot)
		info, _ := os.Stat(path)
		sizeMB := 0.0
		if info != nil {
			sizeMB = float64(info.Size()) / 1e6
		}
		log.Printf("[zk] hashing piece %d/%d  %.1f MB  root=%s...", i+1, len(pieceRoots), sizeMB, pieceRoot[:min(16, len(pieceRoot))])
		leaves, err := readZKLeavesForPiece(path, zkBlockSize)
		if err != nil {
			return nil, fmt.Errorf("read ZK leaves for %s: %w", pieceRoot, err)
		}
		log.Printf("[zk] piece %d/%d: %d leaves", i+1, len(pieceRoots), len(leaves))
		out = append(out, leaves...)
	}
	return out, nil
}

func fieldElementBytes32(x *big.Int) []byte {
	out := make([]byte, 32)
	if x == nil {
		return out
	}
	xb := x.Bytes()
	copy(out[32-len(xb):], xb)
	return out
}

func splitRootForZKCommitment(root string) ([]byte, []byte, error) {
	b, err := rootBytes(root)
	if err != nil {
		return nil, nil, err
	}
	x := new(big.Int).SetBytes(b)
	hi := new(big.Int).Rsh(new(big.Int).Set(x), 128)
	lo := new(big.Int).And(x, new(big.Int).Sub(zkCommitmentSplitBase, big.NewInt(1)))
	return fieldElementBytes32(hi), fieldElementBytes32(lo), nil
}

// computeZKPieceCommitment returns MiMC("FT-COMMIT-V2", pieceRoot_1_hi,
// pieceRoot_1_lo, ...) as a 0x-prefixed BN254 field element. SHA256 piece roots
// are split into two 128-bit field elements so no root can be silently rejected
// by the BN254 MiMC implementation.
func computeZKPieceCommitment(pieceRoots []string) (string, error) {
	if len(pieceRoots) == 0 {
		return "", fmt.Errorf("computeZKPieceCommitment: no piece roots")
	}
	parts := [][]byte{[]byte("FT-COMMIT-V2")}
	for _, root := range pieceRoots {
		hi, lo, err := splitRootForZKCommitment(root)
		if err != nil {
			return "", fmt.Errorf("computeZKPieceCommitment: bad pieceRoot %s: %w", root, err)
		}
		parts = append(parts, hi, lo)
	}
	h, err := mimcHashPartsChecked(parts...)
	if err != nil {
		return "", fmt.Errorf("computeZKPieceCommitment: hash: %w", err)
	}
	return fieldHexFromBytes(h), nil
}

// buildZKCommitmentBlock builds the zkBlockSize-byte commitment block.
// The BN254 field element is split hi/lo to fit in 31-byte words:
//
//	word0 (bytes 0..30)  = zkPieceCommitment >> 128  (hi)
//	word1 (bytes 31..61) = zkPieceCommitment & mask128 (lo)
//	word2..end = zero
//
// Matches the circuit's reconstruction: commitFull = word0 * 2^128 + word1.
func buildZKCommitmentBlock(zkPieceCommitment string, zkBlockSize int64) ([]byte, error) {
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	fb, err := fieldBytesFromHex(zkPieceCommitment)
	if err != nil {
		return nil, fmt.Errorf("buildZKCommitmentBlock: %w", err)
	}
	val := new(big.Int).SetBytes(fb)
	mask128 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	hi := new(big.Int).Rsh(val, 128)
	lo := new(big.Int).And(val, mask128)

	block := make([]byte, zkBlockSize)
	if hiBytes := hi.Bytes(); len(hiBytes) > 0 {
		n := len(hiBytes)
		if n > 31 {
			n = 31
		}
		copy(block[31-n:31], hiBytes[len(hiBytes)-n:])
	}
	if loBytes := lo.Bytes(); len(loBytes) > 0 {
		n := len(loBytes)
		if n > 31 {
			n = 31
		}
		copy(block[62-n:62], loBytes[len(loBytes)-n:])
	}
	return block, nil
}

func zkSectorCacheBaseDir(storage string) string {
	return filepath.Join(storage, ZKSectorCacheRootName)
}

func zkSectorCacheDir(storage, sectorRoot string) string {
	return filepath.Join(zkSectorCacheBaseDir(storage), safeID(sectorRoot))
}

func cleanupStaleZKSectorTempDirs(base string, staleAfter time.Duration) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if staleAfter > 0 {
			info, infoErr := entry.Info()
			if infoErr == nil && time.Since(info.ModTime()) < staleAfter {
				// Skip temp dirs that are likely active for another concurrent
				// request; only purge stale leftovers from crashed/aborted runs.
				continue
			}
		}
		path := filepath.Join(base, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			log.Printf("[zk] could not remove stale temp cache %s: %v", path, err)
		} else {
			log.Printf("[zk] removed stale temp cache %s", path)
		}
	}
}

// cleanupObsoleteZKSectorCaches removes old zk_cache sector directories that are
// no longer referenced by active sectors. This keeps proof caches bounded while
// preserving caches needed for current proofs.
func cleanupObsoleteZKSectorCaches(storage string, staleAfter time.Duration) (int, error) {
	if staleAfter <= 0 {
		return 0, nil
	}
	base := zkSectorCacheBaseDir(storage)
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	sectors, err := listSectors(storage)
	if err != nil {
		return 0, err
	}
	activeRoots := make(map[string]struct{}, len(sectors))
	for _, sector := range sectors {
		if sector.Status == "deleted" {
			continue
		}
		rootID := safeID(strings.TrimSpace(sector.SectorRoot))
		if rootID == "" {
			continue
		}
		activeRoots[rootID] = struct{}{}
	}
	// Frozen proof jobs may outlive the live sector name. Their immutable piece
	// hard links are sufficient for leaf reads, but the expensive content-addressed
	// Merkle cache must also remain pinned until the exact proof is submitted or
	// abandoned. If the durable queue cannot be read, fail closed and delete no
	// caches; losing proof inputs is worse than temporarily retaining disk space.
	pinnedRoots, err := pinnedProofSnapshotSectorRootIDs(storage)
	if err != nil {
		return 0, fmt.Errorf("read frozen proof cache pins: %w", err)
	}
	for rootID := range pinnedRoots {
		activeRoots[rootID] = struct{}{}
	}
	cutoff := time.Now().Add(-staleAfter)
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// These hidden directories contain active resumable builds, their stable
		// locks/index, or foreground temp work. None is a published sector cache,
		// so reference-based cache GC must never remove it. Other hidden entries
		// (notably quarantined invalid caches) remain eligible for retention GC.
		if name == ".build" || name == ".build-locks" || name == ".snapshot-index" || strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if _, keep := activeRoots[name]; keep {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(base, name)
		if err := os.RemoveAll(path); err != nil {
			log.Printf("[zk] could not remove stale sector cache %s: %v", path, err)
			continue
		}
		removed++
	}
	return removed, nil
}

func hashHex32(b []byte) string {
	return fieldHexFromBytes(b)
}

func hashBytes32(b []byte) []byte {
	out := make([]byte, 32)
	if len(b) >= 32 {
		copy(out, b[len(b)-32:])
		return out
	}
	copy(out[32-len(b):], b)
	return out
}

func precomputeZKEmptyHashes(depth int) [][]byte {
	empty := make([][]byte, depth+1)
	empty[0] = zkEmptyLeaf()
	for d := 1; d <= depth; d++ {
		empty[d] = zkHashNode(empty[d-1], empty[d-1])
	}
	return empty
}

func writeHashNode(f *os.File, h []byte) error {
	_, err := f.Write(hashBytes32(h))
	return err
}

func readHashNode(f *os.File) ([]byte, error) {
	buf := make([]byte, 32)
	_, err := io.ReadFull(f, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func zkWorkerCount(items int) int {
	if items <= 0 {
		return 0
	}
	workers := runtime.GOMAXPROCS(0)
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > items {
		workers = items
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func zkLeafBatchSize(zkBlockSize int64) int {
	const targetBytes = 8 * 1024 * 1024
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	n := int(targetBytes / zkBlockSize)
	if n < 256 {
		return 256
	}
	if n > 8192 {
		return 8192
	}
	return n
}

func hashZKBlocksParallelMode(blocks [][]byte, zkBlockSize int64, background bool) [][]byte {
	leaves := make([][]byte, len(blocks))
	workers := proofBuildWorkerCount(background, len(blocks))
	if workers == 0 {
		return leaves
	}
	if workers > len(blocks) {
		workers = len(blocks)
	}
	if workers < 1 {
		workers = 1
	}
	chunk := (len(blocks) + workers - 1) / workers
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		if hi > len(blocks) {
			hi = len(blocks)
		}
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				leaves[i] = zkLeafForBlockWithSize(blocks[i], zkBlockSize)
			}
		}(lo, hi)
	}
	wg.Wait()
	return leaves
}

func hashZKBlocksParallel(blocks [][]byte, zkBlockSize int64) [][]byte {
	return hashZKBlocksParallelMode(blocks, zkBlockSize, false)
}

func writeZKLeafBatch(fout *os.File, blocks [][]byte, zkBlockSize int64) error {
	for _, leaf := range hashZKBlocksParallel(blocks, zkBlockSize) {
		if err := writeHashNode(fout, leaf); err != nil {
			return err
		}
	}
	return nil
}

func writeZKLeafLevel(storage string, pieceRoots []string, zkBlockSize int64, levelPath string) (int, []int, error) {
	fout, err := os.Create(levelPath)
	if err != nil {
		return 0, nil, err
	}
	defer fout.Close()

	totalBlocks := 0
	pieceCounts := make([]int, 0, len(pieceRoots))
	for i, pieceRoot := range pieceRoots {
		path := piecePath(storage, pieceRoot)
		info, _ := os.Stat(path)
		sizeMB := 0.0
		if info != nil {
			sizeMB = float64(info.Size()) / 1e6
		}
		log.Printf("[zk] cache leaf level piece %d/%d  %.1f MB  root=%s...",
			i+1, len(pieceRoots), sizeMB, pieceRoot[:min(16, len(pieceRoot))])

		fin, err := os.Open(path)
		if err != nil {
			return 0, nil, err
		}
		buf := make([]byte, int(zkBlockSize))
		batch := make([][]byte, 0, zkLeafBatchSize(zkBlockSize))
		pieceBlocks := 0
		nextProgress := time.Now().Add(10 * time.Second)
		flushBatch := func() error {
			if len(batch) == 0 {
				return nil
			}
			if err := writeZKLeafBatch(fout, batch, zkBlockSize); err != nil {
				return err
			}
			pieceBlocks += len(batch)
			totalBlocks += len(batch)
			batch = batch[:0]
			if time.Now().After(nextProgress) {
				log.Printf("[zk] cache leaf level piece %d/%d: %d leaves so far",
					i+1, len(pieceRoots), pieceBlocks)
				nextProgress = time.Now().Add(10 * time.Second)
			}
			return nil
		}
		for {
			n, rerr := io.ReadFull(fin, buf)
			if rerr == io.EOF {
				break
			}
			if rerr != nil && rerr != io.ErrUnexpectedEOF {
				fin.Close()
				return 0, nil, rerr
			}
			if n > 0 {
				block := make([]byte, n)
				copy(block, buf[:n])
				batch = append(batch, block)
				if len(batch) == cap(batch) {
					if err := flushBatch(); err != nil {
						fin.Close()
						return 0, nil, err
					}
				}
			}
			if rerr == io.ErrUnexpectedEOF {
				break
			}
		}
		if err := flushBatch(); err != nil {
			fin.Close()
			return 0, nil, err
		}
		fin.Close()
		if pieceBlocks == 0 {
			if err := writeHashNode(fout, zkLeafForBlockWithSize(nil, zkBlockSize)); err != nil {
				return 0, nil, err
			}
			pieceBlocks = 1
			totalBlocks++
		}
		pieceCounts = append(pieceCounts, pieceBlocks)
		log.Printf("[zk] cache leaf level piece %d/%d: %d leaves", i+1, len(pieceRoots), pieceBlocks)
	}
	return totalBlocks, pieceCounts, nil
}

type zkHashPair struct {
	left  []byte
	right []byte
}

func hashZKPairsParallelMode(pairs []zkHashPair, background bool) [][]byte {
	nodes := make([][]byte, len(pairs))
	workers := proofBuildWorkerCount(background, len(pairs))
	if workers == 0 {
		return nodes
	}
	if workers > len(pairs) {
		workers = len(pairs)
	}
	if workers < 1 {
		workers = 1
	}
	chunk := (len(pairs) + workers - 1) / workers
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		if hi > len(pairs) {
			hi = len(pairs)
		}
		if lo >= hi {
			continue
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				nodes[i] = zkHashNode(pairs[i].left, pairs[i].right)
			}
		}(lo, hi)
	}
	wg.Wait()
	return nodes
}

func hashZKPairsParallel(pairs []zkHashPair) [][]byte {
	return hashZKPairsParallelMode(pairs, false)
}

func writeZKParentBatch(fout *os.File, pairs []zkHashPair) error {
	for _, node := range hashZKPairsParallel(pairs) {
		if err := writeHashNode(fout, node); err != nil {
			return err
		}
	}
	return nil
}

func buildNextZKCacheLevel(prevPath, nextPath string, prevCount int, emptyAtLevel []byte) (int, error) {
	fin, err := os.Open(prevPath)
	if err != nil {
		return 0, err
	}
	defer fin.Close()
	fout, err := os.Create(nextPath)
	if err != nil {
		return 0, err
	}
	defer fout.Close()

	nextCount := (prevCount + 1) / 2
	const parentBatchSize = 8192
	pairs := make([]zkHashPair, 0, parentBatchSize)
	written := 0
	flushBatch := func() error {
		if len(pairs) == 0 {
			return nil
		}
		if err := writeZKParentBatch(fout, pairs); err != nil {
			return err
		}
		written += len(pairs)
		pairs = pairs[:0]
		return nil
	}
	for i := 0; i < prevCount; i += 2 {
		left, err := readHashNode(fin)
		if err != nil {
			return 0, err
		}
		right := emptyAtLevel
		if i+1 < prevCount {
			right, err = readHashNode(fin)
			if err != nil {
				return 0, err
			}
		}
		pairs = append(pairs, zkHashPair{left: left, right: right})
		if len(pairs) == cap(pairs) {
			if err := flushBatch(); err != nil {
				return 0, err
			}
		}
	}
	if err := flushBatch(); err != nil {
		return 0, err
	}
	if written != nextCount {
		return 0, fmt.Errorf("cache level wrote %d parent nodes, expected %d", written, nextCount)
	}
	return nextCount, nil
}

func zkSectorBuildBaseDir(storage string) string {
	return filepath.Join(zkSectorCacheBaseDir(storage), ".build")
}

func zkSectorBuildDir(storage, snapshotID string) string {
	return filepath.Join(zkSectorBuildBaseDir(storage), snapshotID)
}

func zkSectorBuildLockPath(storage, snapshotID string) string {
	return filepath.Join(zkSectorCacheBaseDir(storage), ".build-locks", snapshotID+".lock")
}

func zkSectorSnapshotIndexPath(storage, snapshotID string) string {
	return filepath.Join(zkSectorCacheBaseDir(storage), ".snapshot-index", snapshotID+".json")
}

func zkSectorBuildManifestPath(buildDir string) string {
	return filepath.Join(buildDir, "build-manifest.json")
}

func syncZKDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeZKJSONDurable(path string, value any) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".tmp-zk-json-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncZKDirectory(parent)
}

func writeSnapshotHashUint64(h io.Writer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func describeZKSectorSnapshot(storage string, pieceRoots []string, zkBlockSize int64, depth int) (zkSectorSnapshot, error) {
	snapshot := zkSectorSnapshot{ZKBlockSize: zkBlockSize, ZKTreeDepth: depth}
	h := sha256.New()
	_, _ = io.WriteString(h, "filetrust-zk-sector-snapshot-v1")
	writeSnapshotHashUint64(h, uint64(zkBlockSize))
	writeSnapshotHashUint64(h, uint64(depth))
	writeSnapshotHashUint64(h, uint64(len(pieceRoots)))
	for _, pieceRoot := range pieceRoots {
		root := normalizeRoot(pieceRoot)
		rootRaw, err := rootBytes(root)
		if err != nil {
			return zkSectorSnapshot{}, fmt.Errorf("snapshot piece root %q: %w", pieceRoot, err)
		}
		info, err := os.Stat(piecePath(storage, root))
		if err != nil {
			return zkSectorSnapshot{}, fmt.Errorf("snapshot piece %s: %w", root, err)
		}
		if !info.Mode().IsRegular() {
			return zkSectorSnapshot{}, fmt.Errorf("snapshot piece %s is not a regular file", root)
		}
		snapshot.Pieces = append(snapshot.Pieces, zkSectorSnapshotPiece{Root: root, Size: info.Size()})
		_, _ = h.Write(rootRaw)
		writeSnapshotHashUint64(h, uint64(info.Size()))
	}
	snapshot.ID = hex.EncodeToString(h.Sum(nil))
	return snapshot, nil
}

func snapshotPieceRoots(snapshot zkSectorSnapshot) []string {
	roots := make([]string, len(snapshot.Pieces))
	for i := range snapshot.Pieces {
		roots[i] = snapshot.Pieces[i].Root
	}
	return roots
}

func sameZKSectorSnapshotPieces(a, b []zkSectorSnapshotPiece) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if normalizeRoot(a[i].Root) != normalizeRoot(b[i].Root) || a[i].Size != b[i].Size {
			return false
		}
	}
	return true
}

func manifestMatchesZKSectorSnapshot(manifest zkSectorBuildManifest, snapshot zkSectorSnapshot) bool {
	return manifest.Version == zkSectorBuildVersion &&
		manifest.SnapshotID == snapshot.ID &&
		manifest.ZKBlockSize == snapshot.ZKBlockSize &&
		manifest.ZKTreeDepth == snapshot.ZKTreeDepth &&
		sameZKSectorSnapshotPieces(manifest.Pieces, snapshot.Pieces)
}

func expectedZKPieceBlocks(size, blockSize int64) int {
	if size <= 0 {
		return 1
	}
	return int((size + blockSize - 1) / blockSize)
}

func validateZKSectorBuildManifest(manifest zkSectorBuildManifest, snapshot zkSectorSnapshot) error {
	if !manifestMatchesZKSectorSnapshot(manifest, snapshot) {
		return fmt.Errorf("manifest does not match immutable snapshot")
	}
	if len(manifest.PieceBlockCounts) != len(snapshot.Pieces) {
		return fmt.Errorf("manifest piece count length mismatch")
	}
	if manifest.PieceIndex < 0 || manifest.PieceIndex > len(snapshot.Pieces) || manifest.PieceOffset < 0 {
		return fmt.Errorf("manifest piece cursor is out of range")
	}
	totalBlocks := 0
	for i, piece := range snapshot.Pieces {
		count := manifest.PieceBlockCounts[i]
		if count < 0 {
			return fmt.Errorf("manifest piece %d has negative block count", i)
		}
		expected := expectedZKPieceBlocks(piece.Size, snapshot.ZKBlockSize)
		switch {
		case i < manifest.PieceIndex:
			if count != expected {
				return fmt.Errorf("manifest completed piece %d has %d blocks, expected %d", i, count, expected)
			}
		case i == manifest.PieceIndex && manifest.PieceIndex < len(snapshot.Pieces):
			if piece.Size == 0 {
				if manifest.PieceOffset != 0 || count != 0 {
					return fmt.Errorf("manifest empty piece cursor is invalid")
				}
			} else {
				if manifest.PieceOffset >= piece.Size || manifest.PieceOffset%snapshot.ZKBlockSize != 0 {
					return fmt.Errorf("manifest piece %d offset %d is invalid", i, manifest.PieceOffset)
				}
				if count != int(manifest.PieceOffset/snapshot.ZKBlockSize) {
					return fmt.Errorf("manifest piece %d cursor/count mismatch", i)
				}
			}
		default:
			if count != 0 {
				return fmt.Errorf("manifest future piece %d already has blocks", i)
			}
		}
		totalBlocks += count
	}
	if manifest.PieceIndex == len(snapshot.Pieces) && manifest.PieceOffset != 0 {
		return fmt.Errorf("manifest completed leaf stage has a non-zero offset")
	}
	if manifest.DataBlockCount != totalBlocks || manifest.DataBlockCount < 0 {
		return fmt.Errorf("manifest data block total mismatch: %d != %d", manifest.DataBlockCount, totalBlocks)
	}
	if int64(manifest.DataBlockCount+1) > int64(1)<<snapshot.ZKTreeDepth {
		return fmt.Errorf("manifest leaf count exceeds tree capacity")
	}

	switch manifest.Stage {
	case "leaves":
		if manifest.CommitmentAppended || len(manifest.LevelNodeCounts) != 0 || manifest.CurrentLevel != 0 || manifest.CurrentLevelWritten != 0 || manifest.ResultRoot != "" {
			return fmt.Errorf("leaf-stage manifest contains parent/final state")
		}
	case "parents", "complete":
		if manifest.PieceIndex != len(snapshot.Pieces) || !manifest.CommitmentAppended {
			return fmt.Errorf("parent-stage manifest has incomplete leaves")
		}
		if len(manifest.LevelNodeCounts) == 0 || manifest.LevelNodeCounts[0] != manifest.DataBlockCount+1 {
			return fmt.Errorf("manifest leaf level count mismatch")
		}
		for level := 1; level < len(manifest.LevelNodeCounts); level++ {
			want := (manifest.LevelNodeCounts[level-1] + 1) / 2
			if manifest.LevelNodeCounts[level] != want {
				return fmt.Errorf("manifest level %d count=%d want=%d", level, manifest.LevelNodeCounts[level], want)
			}
		}
		if manifest.CurrentLevel != len(manifest.LevelNodeCounts) || manifest.CurrentLevel > snapshot.ZKTreeDepth+1 {
			return fmt.Errorf("manifest current level/count mismatch")
		}
		if manifest.CurrentLevel <= snapshot.ZKTreeDepth {
			nextCount := (manifest.LevelNodeCounts[manifest.CurrentLevel-1] + 1) / 2
			if manifest.CurrentLevelWritten < 0 || manifest.CurrentLevelWritten > nextCount {
				return fmt.Errorf("manifest current-level cursor is invalid")
			}
		} else if manifest.CurrentLevelWritten != 0 {
			return fmt.Errorf("manifest completed levels retain a write cursor")
		}
		if manifest.Stage == "complete" {
			if manifest.CurrentLevel != snapshot.ZKTreeDepth+1 || len(manifest.LevelNodeCounts) != snapshot.ZKTreeDepth+1 || manifest.ResultRoot == "" {
				return fmt.Errorf("complete manifest is missing final state")
			}
		} else if manifest.ResultRoot != "" {
			return fmt.Errorf("parent-stage manifest already has a result root")
		}
	default:
		return fmt.Errorf("unknown build stage %q", manifest.Stage)
	}
	return nil
}

func acquireZKSectorBuildLock(storage, snapshotID string) (*os.File, error) {
	path := zkSectorBuildLockPath(storage, snapshotID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func releaseZKSectorBuildLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func newZKSectorBuildManifest(snapshot zkSectorSnapshot, zkPC string) zkSectorBuildManifest {
	return zkSectorBuildManifest{
		Version:           zkSectorBuildVersion,
		SnapshotID:        snapshot.ID,
		ZKBlockSize:       snapshot.ZKBlockSize,
		ZKTreeDepth:       snapshot.ZKTreeDepth,
		Pieces:            append([]zkSectorSnapshotPiece(nil), snapshot.Pieces...),
		ZKPieceCommitment: zkPC,
		Stage:             "leaves",
		PieceBlockCounts:  make([]int, len(snapshot.Pieces)),
		UpdatedAt:         nowRFC3339(),
	}
}

func loadOrCreateZKSectorBuild(storage string, snapshot zkSectorSnapshot, zkPC string) (string, zkSectorBuildManifest, error) {
	buildDir := zkSectorBuildDir(storage, snapshot.ID)
	manifestPath := zkSectorBuildManifestPath(buildDir)
	payload, err := os.ReadFile(manifestPath)
	if err == nil {
		var manifest zkSectorBuildManifest
		if json.Unmarshal(payload, &manifest) == nil && strings.EqualFold(manifest.ZKPieceCommitment, zkPC) &&
			validateZKSectorBuildManifest(manifest, snapshot) == nil {
			return buildDir, manifest, nil
		}
		log.Printf("[zk] discarding invalid resumable build snapshot=%s", snapshot.ID[:16])
		if err := os.RemoveAll(buildDir); err != nil {
			return "", zkSectorBuildManifest{}, err
		}
	} else if !os.IsNotExist(err) {
		return "", zkSectorBuildManifest{}, err
	}
	if err := os.MkdirAll(buildDir, 0700); err != nil {
		return "", zkSectorBuildManifest{}, err
	}
	manifest := newZKSectorBuildManifest(snapshot, zkPC)
	if err := writeZKJSONDurable(manifestPath, manifest); err != nil {
		return "", zkSectorBuildManifest{}, err
	}
	return buildDir, manifest, nil
}

func persistZKSectorBuildManifest(buildDir string, manifest *zkSectorBuildManifest) error {
	manifest.UpdatedAt = nowRFC3339()
	return writeZKJSONDurable(zkSectorBuildManifestPath(buildDir), manifest)
}

func openZKBuildLevelForAppend(path string, committedNodes int) (*os.File, error) {
	if committedNodes < 0 {
		return nil, fmt.Errorf("negative committed node count %d", committedNodes)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	wantSize := int64(committedNodes) * 32
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Size() < wantSize {
		file.Close()
		return nil, fmt.Errorf("checkpoint output %s is shorter than manifest: got %d want %d", path, info.Size(), wantSize)
	}
	if info.Size() > wantSize {
		if err := file.Truncate(wantSize); err != nil {
			file.Close()
			return nil, err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return nil, err
		}
	}
	if _, err := file.Seek(wantSize, io.SeekStart); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func writeZKLeafBatchMode(fout *os.File, blocks [][]byte, zkBlockSize int64, background bool) error {
	for _, leaf := range hashZKBlocksParallelMode(blocks, zkBlockSize, background) {
		if err := writeHashNode(fout, leaf); err != nil {
			return err
		}
	}
	return nil
}

func writeZKParentBatchMode(fout *os.File, pairs []zkHashPair, background bool) error {
	for _, node := range hashZKPairsParallelMode(pairs, background) {
		if err := writeHashNode(fout, node); err != nil {
			return err
		}
	}
	return nil
}

func advanceBackgroundZKLeafLevel(storage, buildDir string, snapshot zkSectorSnapshot, manifest *zkSectorBuildManifest) error {
	levelPath := filepath.Join(buildDir, "level_00.bin")
	for manifest.PieceIndex < len(snapshot.Pieces) {
		piece := snapshot.Pieces[manifest.PieceIndex]
		if manifest.PieceOffset < 0 || manifest.PieceOffset > piece.Size {
			return fmt.Errorf("invalid leaf checkpoint offset %d for piece size %d", manifest.PieceOffset, piece.Size)
		}
		info, err := os.Stat(piecePath(storage, piece.Root))
		if err != nil {
			return err
		}
		if info.Size() != piece.Size {
			return fmt.Errorf("snapshot piece %s size changed: got %d want %d", piece.Root, info.Size(), piece.Size)
		}

		if piece.Size == 0 {
			if manifest.PieceOffset != 0 || manifest.PieceBlockCounts[manifest.PieceIndex] != 0 {
				return fmt.Errorf("invalid empty-piece leaf checkpoint")
			}
			var batchElapsed time.Duration
			generation := fmt.Sprintf("zk-sector|%s|leaf-empty|%d|%d", filepath.Base(buildDir), manifest.PieceIndex, manifest.PieceOffset)
			if err := withHostBackgroundBuildLock("zk-leaf-empty", generation, func() error {
				started := time.Now()
				fout, err := openZKBuildLevelForAppend(levelPath, manifest.DataBlockCount)
				if err != nil {
					return err
				}
				err = writeHashNode(fout, zkLeafForBlockWithSize(nil, snapshot.ZKBlockSize))
				if err == nil {
					err = fout.Sync()
				}
				closeErr := fout.Close()
				if err == nil {
					err = closeErr
				}
				if err != nil {
					return err
				}
				if err := zkBuildAfterFileSyncHook("leaves"); err != nil {
					return err
				}
				manifest.PieceBlockCounts[manifest.PieceIndex] = 1
				manifest.DataBlockCount++
				manifest.PieceIndex++
				manifest.PieceOffset = 0
				if err := persistZKSectorBuildManifest(buildDir, manifest); err != nil {
					return err
				}
				batchElapsed = time.Since(started)
				return nil
			}); err != nil {
				return err
			}
			proofBuildBatchComplete(true, batchElapsed)
			continue
		}

		fin, err := os.Open(piecePath(storage, piece.Root))
		if err != nil {
			return err
		}
		if _, err := fin.Seek(manifest.PieceOffset, io.SeekStart); err != nil {
			fin.Close()
			return err
		}
		remaining := piece.Size - manifest.PieceOffset
		maxBlocks := zkLeafBatchSize(snapshot.ZKBlockSize)
		blocks := make([][]byte, 0, maxBlocks)
		var consumed int64
		for len(blocks) < maxBlocks && consumed < remaining {
			n := snapshot.ZKBlockSize
			if left := remaining - consumed; left < n {
				n = left
			}
			block := make([]byte, int(n))
			if _, err := io.ReadFull(fin, block); err != nil {
				fin.Close()
				return err
			}
			blocks = append(blocks, block)
			consumed += n
		}
		if err := fin.Close(); err != nil {
			return err
		}
		if len(blocks) == 0 {
			return fmt.Errorf("leaf builder made no progress for non-empty piece")
		}
		var batchElapsed time.Duration
		generation := fmt.Sprintf("zk-sector|%s|leaf-batch|%d|%d", filepath.Base(buildDir), manifest.PieceIndex, manifest.PieceOffset)
		if err := withHostBackgroundBuildLock("zk-leaf-batch", generation, func() error {
			started := time.Now()
			fout, err := openZKBuildLevelForAppend(levelPath, manifest.DataBlockCount)
			if err != nil {
				return err
			}
			err = writeZKLeafBatchMode(fout, blocks, snapshot.ZKBlockSize, true)
			if err == nil {
				err = fout.Sync()
			}
			closeErr := fout.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			if err := zkBuildAfterFileSyncHook("leaves"); err != nil {
				return err
			}
			manifest.PieceOffset += consumed
			manifest.DataBlockCount += len(blocks)
			manifest.PieceBlockCounts[manifest.PieceIndex] += len(blocks)
			if manifest.PieceOffset == piece.Size {
				manifest.PieceIndex++
				manifest.PieceOffset = 0
			}
			if err := persistZKSectorBuildManifest(buildDir, manifest); err != nil {
				return err
			}
			batchElapsed = time.Since(started)
			return nil
		}); err != nil {
			return err
		}
		proofBuildBatchComplete(true, batchElapsed)
	}

	if manifest.CommitmentAppended {
		return nil
	}
	if int64(manifest.DataBlockCount+1) > int64(1)<<snapshot.ZKTreeDepth {
		return fmt.Errorf("too many ZK sector leaves with commitment: %d > %d", manifest.DataBlockCount+1, int64(1)<<snapshot.ZKTreeDepth)
	}
	commitBlock, err := buildZKCommitmentBlock(manifest.ZKPieceCommitment, snapshot.ZKBlockSize)
	if err != nil {
		return err
	}
	var batchElapsed time.Duration
	generation := fmt.Sprintf("zk-sector|%s|commitment|%d", filepath.Base(buildDir), manifest.DataBlockCount)
	if err := withHostBackgroundBuildLock("zk-commitment-leaf", generation, func() error {
		started := time.Now()
		fout, err := openZKBuildLevelForAppend(levelPath, manifest.DataBlockCount)
		if err != nil {
			return err
		}
		err = writeHashNode(fout, zkLeafForBlockWithSize(commitBlock, snapshot.ZKBlockSize))
		if err == nil {
			err = fout.Sync()
		}
		closeErr := fout.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err := zkBuildAfterFileSyncHook("commitment"); err != nil {
			return err
		}
		manifest.CommitmentAppended = true
		manifest.Stage = "parents"
		manifest.CurrentLevel = 1
		manifest.CurrentLevelWritten = 0
		manifest.LevelNodeCounts = []int{manifest.DataBlockCount + 1}
		if err := persistZKSectorBuildManifest(buildDir, manifest); err != nil {
			return err
		}
		batchElapsed = time.Since(started)
		return nil
	}); err != nil {
		return err
	}
	proofBuildBatchComplete(true, batchElapsed)
	return nil
}

func advanceBackgroundZKParentLevels(buildDir string, snapshot zkSectorSnapshot, manifest *zkSectorBuildManifest) error {
	if !manifest.CommitmentAppended || len(manifest.LevelNodeCounts) == 0 {
		return fmt.Errorf("parent build started before leaf level completed")
	}
	empty := precomputeZKEmptyHashes(snapshot.ZKTreeDepth)
	for manifest.CurrentLevel <= snapshot.ZKTreeDepth {
		level := manifest.CurrentLevel
		if len(manifest.LevelNodeCounts) != level {
			return fmt.Errorf("parent checkpoint has %d completed levels, expected %d", len(manifest.LevelNodeCounts), level)
		}
		prevCount := manifest.LevelNodeCounts[level-1]
		nextCount := (prevCount + 1) / 2
		if manifest.CurrentLevelWritten < 0 || manifest.CurrentLevelWritten > nextCount {
			return fmt.Errorf("invalid parent checkpoint count %d/%d", manifest.CurrentLevelWritten, nextCount)
		}
		remaining := nextCount - manifest.CurrentLevelWritten
		if remaining == 0 {
			manifest.LevelNodeCounts = append(manifest.LevelNodeCounts, nextCount)
			manifest.CurrentLevel++
			manifest.CurrentLevelWritten = 0
			if err := persistZKSectorBuildManifest(buildDir, manifest); err != nil {
				return err
			}
			continue
		}
		batchSize := 8192
		if remaining < batchSize {
			batchSize = remaining
		}
		prevPath := filepath.Join(buildDir, fmt.Sprintf("level_%02d.bin", level-1))
		fin, err := os.Open(prevPath)
		if err != nil {
			return err
		}
		childStart := manifest.CurrentLevelWritten * 2
		if _, err := fin.Seek(int64(childStart)*32, io.SeekStart); err != nil {
			fin.Close()
			return err
		}
		pairs := make([]zkHashPair, 0, batchSize)
		for i := 0; i < batchSize; i++ {
			childIndex := childStart + i*2
			left, err := readHashNode(fin)
			if err != nil {
				fin.Close()
				return err
			}
			right := empty[level-1]
			if childIndex+1 < prevCount {
				right, err = readHashNode(fin)
				if err != nil {
					fin.Close()
					return err
				}
			}
			pairs = append(pairs, zkHashPair{left: left, right: right})
		}
		if err := fin.Close(); err != nil {
			return err
		}
		var batchElapsed time.Duration
		work := fmt.Sprintf("zk-parent-level-%02d", level)
		generation := fmt.Sprintf("zk-sector|%s|parent-%02d|%d", filepath.Base(buildDir), level, manifest.CurrentLevelWritten)
		if err := withHostBackgroundBuildLock(work, generation, func() error {
			started := time.Now()
			nextPath := filepath.Join(buildDir, fmt.Sprintf("level_%02d.bin", level))
			fout, err := openZKBuildLevelForAppend(nextPath, manifest.CurrentLevelWritten)
			if err != nil {
				return err
			}
			err = writeZKParentBatchMode(fout, pairs, true)
			if err == nil {
				err = fout.Sync()
			}
			closeErr := fout.Close()
			if err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			if err := zkBuildAfterFileSyncHook("parents"); err != nil {
				return err
			}
			manifest.CurrentLevelWritten += len(pairs)
			if manifest.CurrentLevelWritten == nextCount {
				manifest.LevelNodeCounts = append(manifest.LevelNodeCounts, nextCount)
				manifest.CurrentLevel++
				manifest.CurrentLevelWritten = 0
			}
			if err := persistZKSectorBuildManifest(buildDir, manifest); err != nil {
				return err
			}
			batchElapsed = time.Since(started)
			return nil
		}); err != nil {
			return err
		}
		proofBuildBatchComplete(true, batchElapsed)
	}
	rootBytes, err := os.ReadFile(filepath.Join(buildDir, fmt.Sprintf("level_%02d.bin", snapshot.ZKTreeDepth)))
	if err != nil {
		return err
	}
	if len(rootBytes) != 32 {
		return fmt.Errorf("final ZK cache level has %d bytes, expected 32", len(rootBytes))
	}
	manifest.ResultRoot = fieldHexFromBytes(rootBytes)
	manifest.Stage = "complete"
	return persistZKSectorBuildManifest(buildDir, manifest)
}

func writeZKSectorSnapshotIndex(storage string, index zkSectorSnapshotIndex) error {
	return writeZKJSONDurable(zkSectorSnapshotIndexPath(storage, index.SnapshotID), index)
}

func cachedBackgroundSnapshotResult(storage string, snapshot zkSectorSnapshot) (string, int, string, bool) {
	readIndex := func(path string) (zkSectorSnapshotIndex, bool) {
		payload, err := os.ReadFile(path)
		if err != nil {
			return zkSectorSnapshotIndex{}, false
		}
		var index zkSectorSnapshotIndex
		if json.Unmarshal(payload, &index) != nil || index.Version != zkSectorBuildVersion || index.SnapshotID != snapshot.ID {
			return zkSectorSnapshotIndex{}, false
		}
		return index, true
	}
	if index, ok := readIndex(zkSectorSnapshotIndexPath(storage, snapshot.ID)); ok {
		if err := validateZKSectorCache(storage, index.SectorRoot, snapshotPieceRoots(snapshot), snapshot.ZKBlockSize, snapshot.ZKTreeDepth); err == nil {
			return index.SectorRoot, index.BlockCount, index.ZKCommitment, true
		}
	}

	// Recover the narrow crash window where the complete directory was renamed
	// into place but the small index file was not written yet.
	entries, err := os.ReadDir(zkSectorCacheBaseDir(storage))
	if err != nil {
		return "", 0, "", false
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(zkSectorCacheBaseDir(storage), entry.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var meta ZKSectorCacheMeta
		if json.Unmarshal(payload, &meta) != nil || meta.SnapshotID != snapshot.ID {
			continue
		}
		if err := validateZKSectorCache(storage, meta.SectorRoot, snapshotPieceRoots(snapshot), snapshot.ZKBlockSize, snapshot.ZKTreeDepth); err != nil {
			continue
		}
		index := zkSectorSnapshotIndex{
			Version:      zkSectorBuildVersion,
			SnapshotID:   snapshot.ID,
			SectorRoot:   meta.SectorRoot,
			BlockCount:   meta.SectorBlockCount,
			ZKCommitment: meta.ZKPieceCommitment,
		}
		_ = writeZKSectorSnapshotIndex(storage, index)
		return index.SectorRoot, index.BlockCount, index.ZKCommitment, true
	}
	return "", 0, "", false
}

func publishBackgroundZKSectorCache(storage, buildDir string, snapshot zkSectorSnapshot, manifest zkSectorBuildManifest) (string, int, string, error) {
	if err := validateZKSectorBuildManifest(manifest, snapshot); err != nil {
		return "", 0, "", fmt.Errorf("validate completed ZK cache build: %w", err)
	}
	if manifest.Stage != "complete" || manifest.ResultRoot == "" || len(manifest.LevelNodeCounts) != snapshot.ZKTreeDepth+1 {
		return "", 0, "", fmt.Errorf("cannot publish incomplete ZK cache build")
	}
	levelFiles := make([]string, snapshot.ZKTreeDepth+1)
	for level := range levelFiles {
		levelFiles[level] = fmt.Sprintf("level_%02d.bin", level)
		info, err := os.Stat(filepath.Join(buildDir, levelFiles[level]))
		if err != nil {
			return "", 0, "", err
		}
		wantSize := int64(manifest.LevelNodeCounts[level]) * 32
		if info.Size() != wantSize {
			return "", 0, "", fmt.Errorf("cache level %d size=%d want=%d", level, info.Size(), wantSize)
		}
	}
	empty := precomputeZKEmptyHashes(snapshot.ZKTreeDepth)
	emptyHex := make([]string, len(empty))
	for i := range empty {
		emptyHex[i] = hashHex32(empty[i])
	}
	meta := ZKSectorCacheMeta{
		Version:           ZKSectorCacheVersion,
		RootAlg:           RootAlgZKMiMCBN254,
		SectorRoot:        manifest.ResultRoot,
		ZKBlockSize:       snapshot.ZKBlockSize,
		ZKTreeDepth:       snapshot.ZKTreeDepth,
		SectorBlockCount:  manifest.DataBlockCount,
		LeafCount:         manifest.DataBlockCount + 1,
		PieceRoots:        snapshotPieceRoots(snapshot),
		PieceBlockCounts:  append([]int(nil), manifest.PieceBlockCounts...),
		ZKPieceCommitment: manifest.ZKPieceCommitment,
		LevelFiles:        levelFiles,
		LevelNodeCounts:   append([]int(nil), manifest.LevelNodeCounts...),
		EmptyHashes:       emptyHex,
		CreatedAt:         nowRFC3339(),
		SnapshotID:        snapshot.ID,
	}
	if err := writeZKJSONDurable(filepath.Join(buildDir, "meta.json"), meta); err != nil {
		return "", 0, "", err
	}

	base := zkSectorCacheBaseDir(storage)
	finalDir := zkSectorCacheDir(storage, manifest.ResultRoot)
	if _, err := os.Stat(finalDir); err == nil {
		if err := validateZKSectorCache(storage, manifest.ResultRoot, meta.PieceRoots, snapshot.ZKBlockSize, snapshot.ZKTreeDepth); err == nil {
			if err := os.RemoveAll(buildDir); err != nil {
				return "", 0, "", err
			}
		} else {
			quarantine := filepath.Join(base, fmt.Sprintf(".invalid-%s-%d", safeID(manifest.ResultRoot), time.Now().UnixNano()))
			if err := os.Rename(finalDir, quarantine); err != nil {
				return "", 0, "", fmt.Errorf("quarantine invalid cache: %w", err)
			}
			if err := os.Rename(buildDir, finalDir); err != nil {
				_ = os.Rename(quarantine, finalDir)
				return "", 0, "", err
			}
		}
	} else if os.IsNotExist(err) {
		if err := os.Rename(buildDir, finalDir); err != nil {
			return "", 0, "", err
		}
	} else {
		return "", 0, "", err
	}
	if err := syncZKDirectory(base); err != nil {
		return "", 0, "", err
	}
	_ = os.Remove(filepath.Join(finalDir, "build-manifest.json"))
	index := zkSectorSnapshotIndex{
		Version:      zkSectorBuildVersion,
		SnapshotID:   snapshot.ID,
		SectorRoot:   manifest.ResultRoot,
		BlockCount:   manifest.DataBlockCount,
		ZKCommitment: manifest.ZKPieceCommitment,
	}
	if err := writeZKSectorSnapshotIndex(storage, index); err != nil {
		// The final cache is already atomically published and carries SnapshotID
		// in meta.json, so a later call can repair this auxiliary index by scan.
		// Returning failure here would make callers roll back the source piece
		// underneath a valid published cache.
		log.Printf("[zk] snapshot index write warning snapshot=%s: %v", snapshot.ID[:16], err)
	}
	log.Printf("[zk] background sector cache ready root=%s levels=%d blocks=%d dir=%s",
		manifest.ResultRoot[:min(18, len(manifest.ResultRoot))], len(levelFiles), manifest.DataBlockCount, finalDir)
	return manifest.ResultRoot, manifest.DataBlockCount, manifest.ZKPieceCommitment, nil
}

// computeBackgroundZKSectorRoot builds the same cache as computeZKSectorRoot,
// but checkpoints every bounded leaf/parent batch and consults the adaptive
// proof resource controller between batches. A process restart resumes the
// deterministic snapshot work directory instead of rehashing completed work.
func computeBackgroundZKSectorRoot(storage string, pieceRoots []string, zkBlockSize int64, depth int, forceRebuild bool) (root string, blockCount int, zkPC string, err error) {
	if len(pieceRoots) == 0 {
		return "", 0, "", fmt.Errorf("computeBackgroundZKSectorRoot: no piece roots")
	}
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	if zkBlockSize > zkCircuitCapacity(zkBlockSize) {
		return "", 0, "", fmt.Errorf("zk block size %d exceeds circuit capacity %d", zkBlockSize, zkCircuitCapacity(zkBlockSize))
	}
	if depth < 0 || depth > 30 {
		return "", 0, "", fmt.Errorf("ZK tree depth %d out of range [0,30]", depth)
	}
	if !forceRebuild {
		if cachedRoot, cachedBlocks, cachedZKPC, ok := tryReuseZKSectorCache(storage, pieceRoots, zkBlockSize, depth, false); ok {
			return cachedRoot, cachedBlocks, cachedZKPC, nil
		}
	}
	snapshot, err := describeZKSectorSnapshot(storage, pieceRoots, zkBlockSize, depth)
	if err != nil {
		return "", 0, "", err
	}
	if !forceRebuild {
		if cachedRoot, cachedBlocks, cachedZKPC, ok := cachedBackgroundSnapshotResult(storage, snapshot); ok {
			return cachedRoot, cachedBlocks, cachedZKPC, nil
		}
	}
	lock, err := acquireZKSectorBuildLock(storage, snapshot.ID)
	if err != nil {
		return "", 0, "", err
	}
	defer releaseZKSectorBuildLock(lock)
	if !forceRebuild {
		if cachedRoot, cachedBlocks, cachedZKPC, ok := cachedBackgroundSnapshotResult(storage, snapshot); ok {
			return cachedRoot, cachedBlocks, cachedZKPC, nil
		}
	} else if err := os.RemoveAll(zkSectorBuildDir(storage, snapshot.ID)); err != nil {
		return "", 0, "", err
	}
	zkPC, err = computeZKPieceCommitment(snapshotPieceRoots(snapshot))
	if err != nil {
		return "", 0, "", err
	}
	buildDir, manifest, err := loadOrCreateZKSectorBuild(storage, snapshot, zkPC)
	if err != nil {
		return "", 0, "", err
	}
	if manifest.Stage == "leaves" {
		if err := advanceBackgroundZKLeafLevel(storage, buildDir, snapshot, &manifest); err != nil {
			return "", 0, "", err
		}
	}
	if manifest.Stage == "parents" {
		if err := advanceBackgroundZKParentLevels(buildDir, snapshot, &manifest); err != nil {
			return "", 0, "", err
		}
	}
	if manifest.Stage != "complete" {
		return "", 0, "", fmt.Errorf("background ZK cache stopped in unknown stage %q", manifest.Stage)
	}
	return publishBackgroundZKSectorCache(storage, buildDir, snapshot, manifest)
}

func buildZKSectorRootAndCache(storage string, pieceRoots []string, zkBlockSize int64, depth int, forceRebuild bool) (string, int, string, error) {
	if len(pieceRoots) == 0 {
		return "", 0, "", fmt.Errorf("computeZKSectorRoot: no piece roots")
	}
	cacheBuildStarted := time.Now()
	if cachedRoot, cachedBlocks, cachedZKPC, ok := tryReuseZKSectorCache(storage, pieceRoots, zkBlockSize, depth, forceRebuild); ok {
		log.Printf("[zk] reusing verified sector cache root=%s blocks=%d",
			cachedRoot[:min(18, len(cachedRoot))], cachedBlocks)
		return cachedRoot, cachedBlocks, cachedZKPC, nil
	}
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	capacity := zkCircuitCapacity(zkBlockSize)
	if zkBlockSize > capacity {
		return "", 0, "", fmt.Errorf("zk block size %d exceeds circuit capacity %d", zkBlockSize, capacity)
	}
	if depth < 0 || depth > 30 {
		return "", 0, "", fmt.Errorf("ZK tree depth %d out of range [0,30]", depth)
	}

	zkPC, err := computeZKPieceCommitment(pieceRoots)
	if err != nil {
		return "", 0, "", err
	}
	empty := precomputeZKEmptyHashes(depth)

	base := zkSectorCacheBaseDir(storage)
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", 0, "", err
	}
	cleanupStaleZKSectorTempDirs(base, 30*time.Minute)
	tmpDir := filepath.Join(base, fmt.Sprintf(".tmp-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return "", 0, "", err
	}
	defer os.RemoveAll(tmpDir)

	levelFiles := make([]string, 0, depth+1)
	levelCounts := make([]int, 0, depth+1)
	level0 := "level_00.bin"
	blockCount, pieceCounts, err := writeZKLeafLevel(storage, pieceRoots, zkBlockSize, filepath.Join(tmpDir, level0))
	if err != nil {
		return "", 0, "", err
	}

	commitBlock, err := buildZKCommitmentBlock(zkPC, zkBlockSize)
	if err != nil {
		return "", 0, "", err
	}
	f0, err := os.OpenFile(filepath.Join(tmpDir, level0), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "", 0, "", err
	}
	if err := writeHashNode(f0, zkLeafForBlockWithSize(commitBlock, zkBlockSize)); err != nil {
		f0.Close()
		return "", 0, "", err
	}
	if err := f0.Close(); err != nil {
		return "", 0, "", err
	}

	nodeCount := blockCount + 1
	cap64 := int64(1) << depth
	if int64(nodeCount) > cap64 {
		return "", 0, "", fmt.Errorf("too many ZK sector leaves with commitment: %d > %d", nodeCount, cap64)
	}
	levelFiles = append(levelFiles, level0)
	levelCounts = append(levelCounts, nodeCount)

	for level := 1; level <= depth; level++ {
		prev := filepath.Join(tmpDir, fmt.Sprintf("level_%02d.bin", level-1))
		nextName := fmt.Sprintf("level_%02d.bin", level)
		next := filepath.Join(tmpDir, nextName)
		started := time.Now()
		nodeCount, err = buildNextZKCacheLevel(prev, next, nodeCount, empty[level-1])
		if err != nil {
			return "", 0, "", err
		}
		// One line per level meant 26 lines per sector, 14 of them reporting a
		// single node in 0.0s -- enough to bury the events around it. The whole
		// build is summarised below; individual levels are only interesting when
		// one of them is slow, so report just those.
		if elapsed := time.Since(started); elapsed >= zkCacheLevelReportThreshold {
			log.Printf("[zk] cache level %02d took %.1fs (%d nodes)",
				level, elapsed.Seconds(), nodeCount)
		}
		levelFiles = append(levelFiles, nextName)
		levelCounts = append(levelCounts, nodeCount)
	}

	rootBytes, err := os.ReadFile(filepath.Join(tmpDir, fmt.Sprintf("level_%02d.bin", depth)))
	if err != nil {
		return "", 0, "", err
	}
	if len(rootBytes) < 32 {
		return "", 0, "", fmt.Errorf("empty ZK root")
	}
	root := fieldHexFromBytes(rootBytes[:32])

	emptyHex := make([]string, len(empty))
	for i := range empty {
		emptyHex[i] = hashHex32(empty[i])
	}
	meta := ZKSectorCacheMeta{
		Version:           ZKSectorCacheVersion,
		RootAlg:           RootAlgZKMiMCBN254,
		SectorRoot:        root,
		ZKBlockSize:       zkBlockSize,
		ZKTreeDepth:       depth,
		SectorBlockCount:  blockCount,
		LeafCount:         blockCount + 1,
		PieceRoots:        append([]string(nil), pieceRoots...),
		PieceBlockCounts:  pieceCounts,
		ZKPieceCommitment: zkPC,
		LevelFiles:        levelFiles,
		LevelNodeCounts:   levelCounts,
		EmptyHashes:       emptyHex,
		CreatedAt:         nowRFC3339(),
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", 0, "", err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "meta.json"), metaBytes, 0600); err != nil {
		return "", 0, "", err
	}

	finalDir := zkSectorCacheDir(storage, root)
	if err := os.RemoveAll(finalDir); err != nil {
		return "", 0, "", err
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return "", 0, "", err
	}
	log.Printf("[zk] sector cache ready root=%s levels=%d blocks=%d in %.1fs",
		root[:min(18, len(root))], len(levelFiles), blockCount,
		time.Since(cacheBuildStarted).Seconds())
	return root, blockCount, zkPC, nil
}

// computeZKSectorRoot builds the ZK MiMC Merkle root for a sector.
// Returns (sectorRoot hex, dataBlockCount, zkPieceCommitment hex, error).
// The sector tree includes a commitment block appended after the data blocks:
//
//	leaves[0..blockCount-1] = ZK leaves for piece data blocks
//	leaves[blockCount]      = commitment block leaf  (MiMC("FT-COMMIT-V2", ...))
//
// sectorBlockCount equals len(dataLeaves) only; the commitment block is transparent.
func computeZKSectorRoot(storage string, pieceRoots []string, zkBlockSize int64, depth int, forceRebuild bool) (root string, blockCount int, zkPC string, err error) {
	return buildZKSectorRootAndCache(storage, pieceRoots, zkBlockSize, depth, forceRebuild)
}

func computeZKSectorRootInMemory(storage string, pieceRoots []string, zkBlockSize int64, depth int) (root string, blockCount int, zkPC string, err error) {
	// B.1: artifact/root construction must never run under the short allocator lock.
	noteLockConfinedWork("zk-sector-root-construction")
	leaves, lerr := readZKSectorLeaves(storage, pieceRoots, zkBlockSize)
	if lerr != nil {
		return "", 0, "", lerr
	}
	blockCount = len(leaves)

	zkPC, err = computeZKPieceCommitment(pieceRoots)
	if err != nil {
		return "", 0, "", err
	}

	// Append commitment block leaf.
	commitBlock, err := buildZKCommitmentBlock(zkPC, zkBlockSize)
	if err != nil {
		return "", 0, "", err
	}
	commitLeaf := zkLeafForBlockWithSize(commitBlock, zkBlockSize)
	leaves = append(leaves, commitLeaf)

	r, rerr := zkMerkleRootFixed(leaves, depth)
	if rerr != nil {
		return "", 0, "", rerr
	}
	if bytes.Equal(r, nil) {
		return "", 0, "", fmt.Errorf("empty ZK root")
	}
	return fieldHexFromBytes(r), blockCount, zkPC, nil
}
