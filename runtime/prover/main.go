package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	frBN254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	backendWitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	mimcCircuit "github.com/consensys/gnark/std/hash/mimc"
	"golang.org/x/crypto/sha3"
)

const (
	FieldWordBytes     = 31
	MinZKBlockSize     = 2 * FieldWordBytes
	MaxZKBlockSize     = 16 * 1024
	DefaultTreeDepth   = 28
	DefaultChallenges  = 4
	DefaultZKBlockSize = 128
	ParamsFileName     = "storageproof.params.json"
	RootAlgZKMiMCBN254 = "mimc-bn254-sector-blocks-v2"
	ZKSectorCacheName  = "zk_cache"
	ZKSectorCacheV1    = "zk-sector-cache-v2"
)

var (
	two128    = new(big.Int).Lsh(big.NewInt(1), 128)
	leafTag   = new(big.Int).SetBytes([]byte("FT-LEAF-1"))
	nodeTag   = new(big.Int).SetBytes([]byte("FT-NODE-1"))
	commitTag = new(big.Int).SetBytes([]byte("FT-COMMIT-V2"))
)

type partitionStageLogger struct {
	start time.Time
	last  time.Time
}

func validatePartitionPublicWitness(publicWitness backendWitness.Witness, publicInputs []string) error {
	vector, ok := publicWitness.Vector().(frBN254.Vector)
	if !ok {
		return fmt.Errorf("partition public witness has unexpected BN254 vector type")
	}
	if len(vector) != len(publicInputs) {
		return fmt.Errorf("partition public witness length=%d response public inputs=%d", len(vector), len(publicInputs))
	}
	modulus := frBN254.Modulus()
	for i := range vector {
		expected, ok := new(big.Int).SetString(strings.TrimSpace(publicInputs[i]), 10)
		if !ok || expected.Sign() < 0 || expected.Cmp(modulus) >= 0 {
			return fmt.Errorf("partition public input[%d] is not a canonical BN254 field element", i)
		}
		var actual big.Int
		vector[i].BigInt(&actual)
		if actual.Cmp(expected) != 0 {
			return fmt.Errorf("partition public witness mismatch at index %d: witness=%s response=%s", i, actual.String(), expected.String())
		}
	}
	return nil
}

func newPartitionStageLogger() *partitionStageLogger {
	now := time.Now()
	return &partitionStageLogger{start: now, last: now}
}

func (l *partitionStageLogger) Log(format string, args ...any) {
	if l == nil {
		return
	}
	now := time.Now()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(
		os.Stderr,
		"%s [partition-prover] elapsed=%.3fs delta=%.3fs %s\n",
		now.UTC().Format(time.RFC3339),
		now.Sub(l.start).Seconds(),
		now.Sub(l.last).Seconds(),
		msg,
	)
	l.last = now
}

type ProverParams struct {
	ZKBlockSize   int64 `json:"zk_block_size"`
	ZKTreeDepth   int   `json:"zk_tree_depth"`
	MaxChallenges int   `json:"storageproof_max_challenges"`
}

func defaultParams() ProverParams {
	return ProverParams{ZKBlockSize: DefaultZKBlockSize, ZKTreeDepth: DefaultTreeDepth, MaxChallenges: DefaultChallenges}
}

func (p ProverParams) validate() error {
	if p.ZKBlockSize <= 0 {
		return fmt.Errorf("zk_block_size must be > 0")
	}
	if p.ZKBlockSize < MinZKBlockSize {
		return fmt.Errorf("zk_block_size %d is too small; need at least %d bytes for commitment words", p.ZKBlockSize, MinZKBlockSize)
	}
	if p.ZKBlockSize > MaxZKBlockSize {
		return fmt.Errorf("zk_block_size %d exceeds configured safety limit %d", p.ZKBlockSize, MaxZKBlockSize)
	}
	if p.ZKTreeDepth <= 0 || p.ZKTreeDepth > 30 {
		return fmt.Errorf("zk_tree_depth must be in range 1..30")
	}
	if p.MaxChallenges <= 0 || p.MaxChallenges > 64 {
		return fmt.Errorf("storageproof_max_challenges must be in range 1..64")
	}
	return nil
}

func (p ProverParams) equal(q ProverParams) bool {
	return p.ZKBlockSize == q.ZKBlockSize && p.ZKTreeDepth == q.ZKTreeDepth && p.MaxChallenges == q.MaxChallenges
}

func blockWordCountForSize(zkBlockSize int64) int {
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	return int((zkBlockSize + FieldWordBytes - 1) / FieldWordBytes)
}

func (p ProverParams) blockWordCount() int {
	return blockWordCountForSize(p.ZKBlockSize)
}

// SectorProofCircuit proves knowledge of random sector blocks and Merkle paths.
// Public input layout is exactly the StorageProofSC layout:
// [0] sectorRoot high 128 bits
// [1] sectorRoot low 128 bits
// [2] challengeSeed high 128 bits
// [3] challengeSeed low 128 bits
// [4] round
// [5] sectorBlockCount
// [6] challengeCount
// [7..] challengeIndexes, count = storageproof_max_challenges from VK config.
// Private witness: block data, Merkle sibling paths, and direction bits.
type SectorProofCircuit struct {
	RootHi           frontend.Variable   `gnark:",public"`
	RootLo           frontend.Variable   `gnark:",public"`
	SeedHi           frontend.Variable   `gnark:",public"`
	SeedLo           frontend.Variable   `gnark:",public"`
	Round            frontend.Variable   `gnark:",public"`
	SectorBlockCount frontend.Variable   `gnark:",public"`
	ChallengeCount   frontend.Variable   `gnark:",public"`
	Indexes          []frontend.Variable `gnark:",public"`

	BlockWords [][]frontend.Variable
	Path       [][]frontend.Variable
	PathBits   [][]frontend.Variable
}

func newCircuit(params ProverParams) *SectorProofCircuit {
	wordCount := params.blockWordCount()
	c := &SectorProofCircuit{
		Indexes:    make([]frontend.Variable, params.MaxChallenges),
		BlockWords: make([][]frontend.Variable, params.MaxChallenges),
		Path:       make([][]frontend.Variable, params.MaxChallenges),
		PathBits:   make([][]frontend.Variable, params.MaxChallenges),
	}
	for i := 0; i < params.MaxChallenges; i++ {
		c.BlockWords[i] = make([]frontend.Variable, wordCount)
		c.Path[i] = make([]frontend.Variable, params.ZKTreeDepth)
		c.PathBits[i] = make([]frontend.Variable, params.ZKTreeDepth)
	}
	return c
}

func mimcHash(api frontend.API, parts ...frontend.Variable) frontend.Variable {
	h, err := mimcCircuit.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	h.Write(parts...)
	return h.Sum()
}

func (c *SectorProofCircuit) Define(api frontend.API) error {
	root := api.Add(api.Mul(c.RootHi, two128), c.RootLo)
	api.AssertIsEqual(c.ChallengeCount, len(c.Indexes))

	for i := 0; i < len(c.Indexes); i++ {
		leafInputs := []frontend.Variable{leafTag}
		for j := 0; j < len(c.BlockWords[i]); j++ {
			leafInputs = append(leafInputs, c.BlockWords[i][j])
		}
		cur := mimcHash(api, leafInputs...)

		reconstructedIndex := frontend.Variable(0)
		pow := frontend.Variable(1)
		for level := 0; level < len(c.Path[i]); level++ {
			bit := c.PathBits[i][level]
			api.AssertIsBoolean(bit)
			reconstructedIndex = api.Add(reconstructedIndex, api.Mul(bit, pow))
			pow = api.Mul(pow, 2)

			left := api.Select(bit, c.Path[i][level], cur)
			right := api.Select(bit, cur, c.Path[i][level])
			cur = mimcHash(api, nodeTag, left, right)
		}
		api.AssertIsEqual(reconstructedIndex, c.Indexes[i])
		api.AssertIsEqual(cur, root)
	}
	return nil
}

type SectorMeta struct {
	SectorID         string   `json:"sectorId"`
	SectorRoot       string   `json:"sectorRoot"`
	RootAlg          string   `json:"rootAlg"`
	PieceRoots       []string `json:"pieceRoots"`
	SectorBlockCount int      `json:"sectorBlockCount"`
	ZKBlockSize      int64    `json:"zkBlockSize"`
	ZKTreeDepth      int      `json:"zkTreeDepth"`
}

type SectorChallenge struct {
	SectorRoot       string   `json:"sectorRoot"`
	Round            uint64   `json:"round"`
	ChallengeSeed    string   `json:"challengeSeed"`
	ChallengeIndexes []uint64 `json:"challengeIndexes"`
}

type ProverRequest struct {
	Sector       SectorMeta      `json:"sector"`
	Challenge    SectorChallenge `json:"challenge"`
	StorageDir   string          `json:"storageDir"`
	PublicInputs []string        `json:"publicInputs,omitempty"`
}

type ProverResponse struct {
	OK           bool     `json:"ok"`
	Err          string   `json:"err,omitempty"`
	SectorRoot   string   `json:"sectorRoot,omitempty"`
	Round        uint64   `json:"round,omitempty"`
	Proof        string   `json:"proof,omitempty"`
	PublicInputs []string `json:"publicInputs,omitempty"`
}

func failJSON(err error) {
	b, _ := json.Marshal(ProverResponse{OK: false, Err: err.Error()})
	fmt.Println(string(b))
	os.Exit(1)
}

func cleanHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	return s
}

func bytes32FromHex(s string) ([]byte, error) {
	clean := cleanHex(s)
	if len(clean) != 64 {
		return nil, fmt.Errorf("expected bytes32 hex, got length %d", len(clean))
	}
	return hex.DecodeString(clean)
}

func splitHiLoFromRoot(root string) (*big.Int, *big.Int, error) {
	b, err := bytes32FromHex(root)
	if err != nil {
		return nil, nil, err
	}
	x := new(big.Int).SetBytes(b)
	hi := new(big.Int).Rsh(new(big.Int).Set(x), 128)
	lo := new(big.Int).And(x, new(big.Int).Sub(two128, big.NewInt(1)))
	return hi, lo, nil
}

func failIfBadReqParams(req ProverRequest, params ProverParams) error {
	if req.Sector.RootAlg != "" && req.Sector.RootAlg != RootAlgZKMiMCBN254 {
		return fmt.Errorf("unsupported sector rootAlg %q, expected %q", req.Sector.RootAlg, RootAlgZKMiMCBN254)
	}
	if req.Sector.ZKBlockSize > 0 && req.Sector.ZKBlockSize != params.ZKBlockSize {
		return fmt.Errorf("sector zkBlockSize=%d but prover keys/config use zk_block_size=%d", req.Sector.ZKBlockSize, params.ZKBlockSize)
	}
	if req.Sector.ZKTreeDepth > 0 && req.Sector.ZKTreeDepth != params.ZKTreeDepth {
		return fmt.Errorf("sector zkTreeDepth=%d but prover keys/config use zk_tree_depth=%d", req.Sector.ZKTreeDepth, params.ZKTreeDepth)
	}
	if len(req.Challenge.ChallengeIndexes) > params.MaxChallenges {
		return fmt.Errorf("too many challenge indexes: %d > %d", len(req.Challenge.ChallengeIndexes), params.MaxChallenges)
	}
	return nil
}

func blockWords(block []byte, wordCount int) []*big.Int {
	out := make([]*big.Int, wordCount)
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
		out[i] = new(big.Int).SetBytes(chunk)
	}
	return out
}

func mimcHashNativeChecked(parts ...[]byte) ([]byte, error) {
	h := mimcNative.NewMiMC()
	for _, p := range parts {
		if _, err := h.Write(p); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func mimcHashNative(parts ...[]byte) []byte {
	h, err := mimcHashNativeChecked(parts...)
	if err != nil {
		panic(fmt.Sprintf("invalid MiMC field input: %v", err))
	}
	return h
}

func bigTo32(x *big.Int) []byte {
	out := make([]byte, 32)
	xb := x.Bytes()
	copy(out[32-len(xb):], xb)
	return out
}

func leafForBlock(block []byte, wordCount int) ([]byte, []*big.Int) {
	words := blockWords(block, wordCount)
	parts := [][]byte{[]byte("FT-LEAF-1")}
	for _, w := range words {
		parts = append(parts, bigTo32(w))
	}
	return mimcHashNative(parts...), words
}

func hashNode(left, right []byte) []byte {
	return mimcHashNative([]byte("FT-NODE-1"), left, right)
}

func emptyLeaf() []byte {
	return mimcHashNative([]byte("FT-EMPTY-1"))
}

func piecePath(storageDir, pieceRoot string) string {
	clean := cleanHex(pieceRoot)
	return filepath.Join(storageDir, "pieces", clean+".piece")
}

type blockReadProgressFunc func(blocks int, bytesRead int64)

func readBlocks(path string, zkBlockSize int64) ([][]byte, error) {
	return readBlocksWithProgress(path, zkBlockSize, nil)
}

func readBlocksWithProgress(path string, zkBlockSize int64, progress blockReadProgressFunc) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := [][]byte{}
	buf := make([]byte, int(zkBlockSize))
	var bytesRead int64
	lastProgress := time.Now()
	for {
		n, rerr := io.ReadFull(f, buf)
		if rerr == io.EOF {
			break
		}
		if rerr == io.ErrUnexpectedEOF {
			// final short block
		} else if rerr != nil {
			return nil, rerr
		}
		if n > 0 {
			out = append(out, append([]byte(nil), buf[:n]...))
			bytesRead += int64(n)
			if progress != nil && (len(out)%100000 == 0 || time.Since(lastProgress) >= 10*time.Second) {
				progress(len(out), bytesRead)
				lastProgress = time.Now()
			}
		}
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	if len(out) == 0 {
		out = append(out, nil)
	}
	if progress != nil {
		progress(len(out), bytesRead)
	}
	return out, nil
}

type leafInfo struct {
	block []byte
	leaf  []byte
	words []*big.Int
}

func sectorLeaves(req ProverRequest, params ProverParams) ([]leafInfo, error) {
	out := []leafInfo{}
	wordCount := params.blockWordCount()
	for _, root := range req.Sector.PieceRoots {
		blocks, err := readBlocks(piecePath(req.StorageDir, root), params.ZKBlockSize)
		if err != nil {
			return nil, err
		}
		for _, b := range blocks {
			leaf, words := leafForBlock(b, wordCount)
			out = append(out, leafInfo{block: b, leaf: leaf, words: words})
		}
	}
	return out, nil
}

// sparseTree is a sparse Merkle tree that only materialises nodes that lie on
// the path from an actual leaf to the root.  Empty subtrees are represented by
// a precomputed hash so the tree never needs more than O(K*D) memory regardless
// of the declared depth – critical for depth=28 (2^28 leaves = 8 GB if dense).
type sparseTree struct {
	depth  int
	leaves [][]byte          // leaves[i].leaf for i < len; emptyLeaf() beyond
	empty  [][]byte          // empty[d] = hash of a full subtree of empty leaves at level d
	memo   map[[2]int][]byte // memoised node hashes
}

func newSparseTree(leaves []leafInfo, depth int) (*sparseTree, error) {
	cap64 := int64(1) << depth
	if int64(len(leaves)) > cap64 {
		return nil, fmt.Errorf("too many leaves %d > 2^%d", len(leaves), depth)
	}
	lh := make([][]byte, len(leaves))
	for i, lf := range leaves {
		lh[i] = append([]byte(nil), lf.leaf...)
	}
	emp := make([][]byte, depth+1)
	emp[0] = emptyLeaf()
	for d := 1; d <= depth; d++ {
		emp[d] = hashNode(emp[d-1], emp[d-1])
	}
	return &sparseTree{depth: depth, leaves: lh, empty: emp, memo: make(map[[2]int][]byte)}, nil
}

func (t *sparseTree) nodeHash(level, pos int) []byte {
	if level == 0 {
		if pos < len(t.leaves) {
			return t.leaves[pos]
		}
		return t.empty[0]
	}
	key := [2]int{level, pos}
	if v, ok := t.memo[key]; ok {
		return v
	}
	// Early-exit: all leaves covered by this subtree are empty.
	// The leftmost leaf index under (level, pos) is pos << level.
	leftmost := pos << level
	if leftmost >= len(t.leaves) {
		t.memo[key] = t.empty[level]
		return t.empty[level]
	}
	left := t.nodeHash(level-1, pos*2)
	right := t.nodeHash(level-1, pos*2+1)
	result := hashNode(left, right)
	t.memo[key] = result
	return result
}

func (t *sparseTree) root() []byte {
	return t.nodeHash(t.depth, 0)
}

// siblingPath returns the sibling hashes and direction bits for the Merkle path
// of the leaf at leafIdx, from level 0 (leaf) up to level depth-1.
func (t *sparseTree) siblingPath(leafIdx int) ([]*big.Int, []int) {
	siblings := make([]*big.Int, t.depth)
	bits := make([]int, t.depth)
	pos := leafIdx
	for lvl := 0; lvl < t.depth; lvl++ {
		sibPos := pos ^ 1
		sib := t.nodeHash(lvl, sibPos)
		siblings[lvl] = new(big.Int).SetBytes(sib)
		bits[lvl] = pos & 1
		pos >>= 1
	}
	return siblings, bits
}

// buildFixedTree is kept for depths where full materialisation is acceptable
// (depth ≤ 20).  For depth > 20 use newSparseTree instead.
func buildFixedTree(leaves []leafInfo, params ProverParams) ([][][]byte, error) {
	if params.ZKTreeDepth > 20 {
		return nil, fmt.Errorf("use newSparseTree for depth > 20 (requested depth=%d)", params.ZKTreeDepth)
	}
	capacity64 := int64(1) << params.ZKTreeDepth
	if capacity64 > int64(math.MaxInt) {
		return nil, fmt.Errorf("zk_tree_depth too large for this platform")
	}
	capacity := int(capacity64)
	if len(leaves) > capacity {
		return nil, fmt.Errorf("too many leaves %d > %d", len(leaves), capacity)
	}
	level := make([][]byte, capacity)
	empty := emptyLeaf()
	for i := 0; i < capacity; i++ {
		if i < len(leaves) {
			level[i] = append([]byte(nil), leaves[i].leaf...)
		} else {
			level[i] = append([]byte(nil), empty...)
		}
	}
	tree := [][][]byte{level}
	for len(level) > 1 {
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, hashNode(level[i], level[i+1]))
		}
		level = next
		tree = append(tree, level)
	}
	return tree, nil
}

func fieldHex(b []byte) string {
	if len(b) >= 32 {
		return "0x" + hex.EncodeToString(b[len(b)-32:])
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return "0x" + hex.EncodeToString(out)
}

func publicInputs(req ProverRequest, params ProverParams) ([]string, error) {
	rootHi, rootLo, err := splitHiLoFromRoot(req.Sector.SectorRoot)
	if err != nil {
		return nil, err
	}
	seedHi, seedLo, err := splitHiLoFromRoot(req.Challenge.ChallengeSeed)
	if err != nil {
		return nil, err
	}
	out := []string{
		rootHi.String(), rootLo.String(), seedHi.String(), seedLo.String(),
		strconv.FormatUint(req.Challenge.Round, 10),
		strconv.FormatInt(int64(req.Sector.SectorBlockCount), 10),
		strconv.Itoa(params.MaxChallenges),
	}
	for i := 0; i < params.MaxChallenges; i++ {
		v := uint64(0)
		if i < len(req.Challenge.ChallengeIndexes) {
			v = req.Challenge.ChallengeIndexes[i]
		}
		out = append(out, strconv.FormatUint(v, 10))
	}
	return out, nil
}

func buildAssignment(req ProverRequest, params ProverParams) (*SectorProofCircuit, []string, error) {
	if err := failIfBadReqParams(req, params); err != nil {
		return nil, nil, err
	}
	leaves, err := sectorLeaves(req, params)
	if err != nil {
		return nil, nil, err
	}
	if len(leaves) != req.Sector.SectorBlockCount {
		return nil, nil, fmt.Errorf("sectorBlockCount mismatch: metadata=%d local=%d", req.Sector.SectorBlockCount, len(leaves))
	}
	st, err := newSparseTree(leaves, params.ZKTreeDepth)
	if err != nil {
		return nil, nil, err
	}
	gotRoot := fieldHex(st.root())
	if !strings.EqualFold(gotRoot, req.Sector.SectorRoot) {
		return nil, nil, fmt.Errorf("local ZK sector root mismatch: local=%s metadata=%s", gotRoot, req.Sector.SectorRoot)
	}

	rootHi, rootLo, _ := splitHiLoFromRoot(req.Sector.SectorRoot)
	seedHi, seedLo, _ := splitHiLoFromRoot(req.Challenge.ChallengeSeed)
	assignment := newCircuit(params)
	assignment.RootHi = rootHi
	assignment.RootLo = rootLo
	assignment.SeedHi = seedHi
	assignment.SeedLo = seedLo
	assignment.Round = req.Challenge.Round
	assignment.SectorBlockCount = req.Sector.SectorBlockCount
	assignment.ChallengeCount = params.MaxChallenges

	for i := 0; i < params.MaxChallenges; i++ {
		idx := uint64(0)
		if i < len(req.Challenge.ChallengeIndexes) {
			idx = req.Challenge.ChallengeIndexes[i]
		}
		if idx >= uint64(len(leaves)) {
			return nil, nil, fmt.Errorf("challenge index %d out of range", idx)
		}
		assignment.Indexes[i] = idx
		for w := 0; w < len(assignment.BlockWords[i]); w++ {
			assignment.BlockWords[i][w] = leaves[idx].words[w]
		}
		siblings, bits := st.siblingPath(int(idx))
		for level := 0; level < params.ZKTreeDepth; level++ {
			assignment.Path[i][level] = siblings[level]
			assignment.PathBits[i][level] = bits[level]
		}
	}
	inputs, err := publicInputs(req, params)
	return assignment, inputs, err
}

func getInt(cfg map[string]interface{}, names ...string) (int64, bool) {
	for _, name := range names {
		if v, ok := cfg[name]; ok {
			switch x := v.(type) {
			case float64:
				return int64(x), true
			case int:
				return int64(x), true
			case int64:
				return x, true
			case string:
				if x == "" {
					continue
				}
				parsed, err := strconv.ParseInt(x, 10, 64)
				if err == nil {
					return parsed, true
				}
			}
		}
	}
	return 0, false
}

func discoverConfigPath(cli string) string {
	if cli != "" {
		return cli
	}
	for _, env := range []string{"FILETRUST_VK_CONFIG", "VK_CONFIG", "STORAGEPROOF_CONFIG"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(cwd, "config.json"),
		filepath.Join(cwd, "..", "config.json"),
		filepath.Join(cwd, "..", "..", "config.json"),
		filepath.Join(cwd, "..", "..", "..", "config.json"),
		filepath.Join(exeDir, "config.json"),
		filepath.Join(exeDir, "..", "config.json"),
		filepath.Join(exeDir, "..", "..", "config.json"),
		filepath.Join(exeDir, "..", "..", "..", "config.json"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return ""
}

func loadConfigParams(path string) (ProverParams, bool, error) {
	params := defaultParams()
	if path == "" {
		return params, false, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return params, false, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return params, false, err
	}
	if v, ok := getInt(cfg, "zk_block_size", "ZK_BLOCK_SIZE", "zkBlockSize"); ok {
		params.ZKBlockSize = v
	}
	if v, ok := getInt(cfg, "zk_tree_depth", "ZK_TREE_DEPTH", "zkTreeDepth"); ok {
		params.ZKTreeDepth = int(v)
	}
	if v, ok := getInt(cfg, "storageproof_max_challenges", "STORAGEPROOF_MAX_CHALLENGES", "challengeCount", "maxChallenges"); ok {
		params.MaxChallenges = int(v)
	}
	if err := params.validate(); err != nil {
		return params, true, err
	}
	return params, true, nil
}

func paramsPath(keysDir string) string {
	return filepath.Join(keysDir, ParamsFileName)
}

func writeKeyParams(keysDir string, params ProverParams) error {
	b, _ := json.MarshalIndent(params, "", "  ")
	return os.WriteFile(paramsPath(keysDir), b, 0600)
}

func readKeyParams(keysDir string) (ProverParams, bool, error) {
	params := defaultParams()
	b, err := os.ReadFile(paramsPath(keysDir))
	if os.IsNotExist(err) {
		return params, false, nil
	}
	if err != nil {
		return params, false, err
	}
	if err := json.Unmarshal(b, &params); err != nil {
		return params, true, err
	}
	if err := params.validate(); err != nil {
		return params, true, err
	}
	return params, true, nil
}

func resolveParams(keysDir, configPath string, setup bool) (ProverParams, error) {
	cfgParams, cfgFound, cfgErr := loadConfigParams(configPath)
	if cfgErr != nil {
		return ProverParams{}, fmt.Errorf("could not load VK config %s: %w", configPath, cfgErr)
	}
	keyParams, keyFound, keyErr := readKeyParams(keysDir)
	if keyErr != nil {
		return ProverParams{}, fmt.Errorf("could not read %s: %w", paramsPath(keysDir), keyErr)
	}

	if setup {
		if cfgFound {
			return cfgParams, nil
		}
		return defaultParams(), nil
	}

	if keyFound {
		if cfgFound && !keyParams.equal(cfgParams) {
			return ProverParams{}, fmt.Errorf(
				"VK config does not match proving keys params. keys=%+v config=%+v. Rerun setup and redeploy/update verifier adapter.",
				keyParams,
				cfgParams,
			)
		}
		return keyParams, nil
	}
	if cfgFound {
		return cfgParams, nil
	}
	return defaultParams(), nil
}

func cmdProve(keysDir string, params ProverParams) error {
	var req ProverRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}
	assignment, inputs, err := buildAssignment(req, params)
	if err != nil {
		return err
	}

	cs := groth16.NewCS(ecc.BN254)
	fcs, err := os.Open(filepath.Join(keysDir, "storageproof.r1cs"))
	if err != nil {
		return err
	}
	if _, err := cs.ReadFrom(fcs); err != nil {
		fcs.Close()
		return err
	}
	fcs.Close()

	pk := groth16.NewProvingKey(ecc.BN254)
	fpk, err := os.Open(filepath.Join(keysDir, "storageproof.pk"))
	if err != nil {
		return err
	}
	if _, err := pk.ReadFrom(fpk); err != nil {
		fpk.Close()
		return err
	}
	fpk.Close()

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return err
	}
	var proofBytes bytes.Buffer
	if _, err := proof.WriteRawTo(&proofBytes); err != nil {
		return err
	}

	resp := ProverResponse{OK: true, SectorRoot: req.Sector.SectorRoot, Round: req.Challenge.Round, Proof: "0x" + hex.EncodeToString(proofBytes.Bytes()), PublicInputs: inputs}
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
	return nil
}

func cmdVerify(keysDir string, params ProverParams) error {
	var req struct {
		Proof        string   `json:"proof"`
		PublicInputs []string `json:"publicInputs"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}
	if req.Proof == "" {
		return errors.New("missing proof")
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	fvk, err := os.Open(filepath.Join(keysDir, "storageproof.vk"))
	if err != nil {
		return err
	}
	if _, err := vk.ReadFrom(fvk); err != nil {
		fvk.Close()
		return err
	}
	fvk.Close()

	proof := groth16.NewProof(ecc.BN254)
	pb, err := hex.DecodeString(cleanHex(req.Proof))
	if err != nil {
		return err
	}
	if _, err := proof.ReadFrom(bytes.NewReader(pb)); err != nil {
		return err
	}

	if len(req.PublicInputs) != 7+params.MaxChallenges {
		return fmt.Errorf("bad public input count: got %d expected %d", len(req.PublicInputs), 7+params.MaxChallenges)
	}
	vals := make([]*big.Int, 0, len(req.PublicInputs))
	for _, s := range req.PublicInputs {
		x, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("bad public input: %s", s)
		}
		vals = append(vals, x)
	}
	assignment := newCircuit(params)
	assignment.RootHi = vals[0]
	assignment.RootLo = vals[1]
	assignment.SeedHi = vals[2]
	assignment.SeedLo = vals[3]
	assignment.Round = vals[4]
	assignment.SectorBlockCount = vals[5]
	assignment.ChallengeCount = vals[6]
	for i := 0; i < params.MaxChallenges; i++ {
		assignment.Indexes[i] = vals[7+i]
	}
	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return err
	}
	fmt.Println(`{"ok":true}`)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// compute-roots: derive sector roots from piece files without needing ZK keys.
// ─────────────────────────────────────────────────────────────────────────────

type computeRootsSectorRequest struct {
	StorageDir  string   `json:"storageDir"`
	PieceRoots  []string `json:"pieceRoots"`
	ZKBlockSize int64    `json:"zkBlockSize"`
	ZKTreeDepth int      `json:"zkTreeDepth"`
}

type computeRootsRequest struct {
	Sectors []computeRootsSectorRequest `json:"sectors"`
}

type computeRootsResponse struct {
	OK                 bool     `json:"ok"`
	Err                string   `json:"err,omitempty"`
	SectorRoots        []string `json:"sectorRoots"`
	ZKPieceCommitments []string `json:"zkPieceCommitments"` // W3 fix: one per sector
}

func cmdComputeRoots(configPath string) error {
	cfgParams, _, _ := loadConfigParams(configPath)

	var req computeRootsRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}

	roots := make([]string, len(req.Sectors))
	zkPCs := make([]string, len(req.Sectors))
	for i, sec := range req.Sectors {
		p := cfgParams
		if sec.ZKBlockSize > 0 {
			p.ZKBlockSize = sec.ZKBlockSize
		}
		if sec.ZKTreeDepth > 0 {
			p.ZKTreeDepth = sec.ZKTreeDepth
		}
		if err := p.validate(); err != nil {
			return fmt.Errorf("sector %d params: %w", i, err)
		}
		sec.ZKBlockSize = p.ZKBlockSize
		sec.ZKTreeDepth = p.ZKTreeDepth
		// Compute zkPieceCommitment for the sector.
		zkPC, err := computeZKPieceCommitmentNative(sec.PieceRoots)
		if err != nil {
			return fmt.Errorf("sector %d commitment: %w", i, err)
		}
		// Build commitment block and append to data leaves.
		dataLeaves, err := sectorLeavesFromStorage(sec.StorageDir, sec.PieceRoots, p.ZKBlockSize)
		if err != nil {
			return fmt.Errorf("sector %d: %w", i, err)
		}
		commitBlock, err := buildCommitmentBlock(zkPC, int64(p.ZKBlockSize))
		if err != nil {
			return fmt.Errorf("sector %d commit block: %w", i, err)
		}
		commitLeaf, commitWords := leafForBlock(commitBlock, blockWordCountForSize(p.ZKBlockSize))
		allLeaves := append(append([]leafInfo{}, dataLeaves...), leafInfo{block: commitBlock, leaf: commitLeaf, words: commitWords})
		st, err := newSparseTree(allLeaves, p.ZKTreeDepth)
		if err != nil {
			return fmt.Errorf("sector %d tree: %w", i, err)
		}
		roots[i] = fieldHex(st.root())
		zkPCs[i] = zkPC
		if err := writeZKSectorCacheFromLeaves(sec.StorageDir, sec, roots[i], zkPC, allLeaves); err != nil {
			return fmt.Errorf("sector %d cache write: %w", i, err)
		}
	}

	b, _ := json.Marshal(computeRootsResponse{OK: true, SectorRoots: roots, ZKPieceCommitments: zkPCs})
	fmt.Println(string(b))
	return nil
}

// cmdPartitionVerify reads a proof+publicInputs JSON from stdin and verifies it
// natively using the stored verifying key. Used for off-chain proof validation.
func cmdPartitionVerify(keysDir string) error {
	var req struct {
		Proof        string   `json:"proof"`
		PublicInputs []string `json:"publicInputs"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		return err
	}
	if req.Proof == "" {
		return errors.New("missing proof")
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	fvk, err := os.Open(filepath.Join(keysDir, "storageproof_partition.vk"))
	if err != nil {
		return fmt.Errorf("open partition vk: %w", err)
	}
	if _, err := vk.ReadFrom(fvk); err != nil {
		fvk.Close()
		return err
	}
	fvk.Close()

	proof := groth16.NewProof(ecc.BN254)
	pb, err := hex.DecodeString(cleanHex(req.Proof))
	if err != nil {
		return err
	}
	if _, err := proof.ReadFrom(bytes.NewReader(pb)); err != nil {
		return err
	}

	// Read params to know N and M.
	params, _, err := readPartitionKeyParams(keysDir)
	if err != nil {
		return fmt.Errorf("read partition key params: %w", err)
	}
	N := params.PartitionSectors
	M := params.MaxChallenges
	expected := 4 + 4*N + N*M
	if len(req.PublicInputs) != expected {
		return fmt.Errorf("bad public input count: got %d expected %d (N=%d M=%d)", len(req.PublicInputs), expected, N, M)
	}

	vals := make([]*big.Int, 0, len(req.PublicInputs))
	for _, s := range req.PublicInputs {
		x, ok := new(big.Int).SetString(s, 10)
		if !ok {
			return fmt.Errorf("bad public input: %s", s)
		}
		vals = append(vals, x)
	}

	// Build a public-only witness to verify against.
	assignment := newPartitionCircuit(params)
	assignment.SeedHi = vals[0]
	assignment.SeedLo = vals[1]
	assignment.Round = vals[2]
	for i := 0; i < N; i++ {
		assignment.RootHi[i] = vals[3+i]
		assignment.RootLo[i] = vals[3+N+i]
		assignment.BlockCounts[i] = vals[3+2*N+i]
	}
	assignment.ChallengeCount = vals[3+3*N]
	for i := 0; i < N; i++ {
		for j := 0; j < M; j++ {
			assignment.Indexes[i][j] = vals[4+3*N+i*M+j]
		}
	}
	// PieceCommitment inputs (W3 fix) at the end
	for i := 0; i < N; i++ {
		assignment.PieceCommitment[i] = vals[4+3*N+N*M+i]
	}

	publicWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return fmt.Errorf("proof invalid: %w", err)
	}
	fmt.Println(`{"ok":true,"message":"partition proof verified (N=` + strconv.Itoa(N) + `, M=` + strconv.Itoa(M) + `, inputs=` + strconv.Itoa(expected) + `)"}`)
	return nil
}

func main() {
	mode := flag.String("mode", "prove", "setup | prove | verify | partition-setup | partition-prove | partition-serve | partition-verify | compute-roots")
	keys := flag.String("keys", "./keys", "directory for r1cs/pk/vk/verifier")
	partitionKeys := flag.String("partition-keys", "", "exact partition keys directory; defaults to <keys>/partition")
	configPathArg := flag.String("config", "", "VK config.json path; default auto-discovers ../../config.json")
	serviceSocket := flag.String("socket", "", "Unix socket path for partition-serve mode")
	flag.Parse()

	configPath := discoverConfigPath(*configPathArg)
	partitionKeysDir := *partitionKeys
	if partitionKeysDir == "" {
		partitionKeysDir = filepath.Join(*keys, "partition")
	}

	var err error
	switch *mode {
	case "setup":
		err = runSetupMode(false, *keys, partitionKeysDir, configPath)

	case "prove":
		params, perr := resolveParams(*keys, configPath, false)
		if perr != nil {
			failJSON(perr)
		}
		err = cmdProve(*keys, params)

	case "verify":
		params, perr := resolveParams(*keys, configPath, false)
		if perr != nil {
			failJSON(perr)
		}
		err = cmdVerify(*keys, params)

	case "partition-setup":
		err = runSetupMode(true, *keys, partitionKeysDir, configPath)

	case "partition-prove":
		pParams, perr := resolvePartitionParams(*keys, partitionKeysDir, configPath, false)
		if perr != nil {
			failJSON(perr)
		}
		err = cmdPartitionProve(partitionKeysDir, pParams)

	case "partition-serve":
		pParams, perr := resolvePartitionParams(*keys, partitionKeysDir, configPath, false)
		if perr != nil {
			failJSON(perr)
		}
		err = cmdPartitionServe(*serviceSocket, partitionKeysDir, pParams)

	case "partition-verify":
		err = cmdPartitionVerify(partitionKeysDir)

	case "compute-roots":
		err = cmdComputeRoots(configPath)

	default:
		err = fmt.Errorf("unknown mode %s", *mode)
	}
	if err != nil {
		failJSON(err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Partition proof circuit and commands
// ─────────────────────────────────────────────────────────────────────────────

const (
	PartitionParamsFileName = "storageproof_partition.params.json"
	PartitionCircuitVersion = "partition-w3-commitment-v1"
)

// PartitionProverParams extends ProverParams with the circuit-level sector count.
type PartitionProverParams struct {
	ProverParams
	PartitionSectors int    `json:"partition_sectors"`
	CircuitVersion   string `json:"partition_circuit_version"`
}

func defaultPartitionParams() PartitionProverParams {
	return PartitionProverParams{
		ProverParams:     defaultParams(),
		PartitionSectors: 16,
		CircuitVersion:   PartitionCircuitVersion,
	}
}

func (p PartitionProverParams) validatePartition() error {
	if err := p.ProverParams.validate(); err != nil {
		return err
	}
	if p.PartitionSectors <= 0 || p.PartitionSectors > 64 {
		return fmt.Errorf("partition_sectors must be in range 1..64")
	}
	if p.CircuitVersion != PartitionCircuitVersion {
		return fmt.Errorf("partition circuit version mismatch: keys=%q current=%q. Rerun partition-setup.", p.CircuitVersion, PartitionCircuitVersion)
	}
	return nil
}

func (p PartitionProverParams) equalPartition(q PartitionProverParams) bool {
	return p.ProverParams.equal(q.ProverParams) &&
		p.PartitionSectors == q.PartitionSectors &&
		p.CircuitVersion == q.CircuitVersion
}

func partitionParamsPath(keysDir string) string {
	return filepath.Join(keysDir, PartitionParamsFileName)
}

func writePartitionKeyParams(keysDir string, params PartitionProverParams) error {
	b, _ := json.MarshalIndent(params, "", "  ")
	return os.WriteFile(partitionParamsPath(keysDir), b, 0600)
}

func readPartitionKeyParams(keysDir string) (PartitionProverParams, bool, error) {
	params := defaultPartitionParams()
	b, err := os.ReadFile(partitionParamsPath(keysDir))
	if os.IsNotExist(err) {
		return params, false, nil
	}
	if err != nil {
		return params, false, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return params, true, err
	}
	if _, ok := raw["partition_circuit_version"]; !ok {
		return params, true, fmt.Errorf("partition key params missing partition_circuit_version. Rerun partition-setup.")
	}
	if err := json.Unmarshal(b, &params); err != nil {
		return params, true, err
	}
	if err := params.validatePartition(); err != nil {
		return params, true, err
	}
	return params, true, nil
}

func resolvePartitionParams(keysDir, partitionKeysDir, configPath string, setup bool) (PartitionProverParams, error) {
	baseParams, _, baseErr := loadConfigParams(configPath)
	if baseErr != nil {
		return PartitionProverParams{}, baseErr
	}
	p := PartitionProverParams{
		ProverParams:     baseParams,
		PartitionSectors: 16,
		CircuitVersion:   PartitionCircuitVersion,
	}

	// Read partition_sectors from config.
	if configPath != "" {
		b, err := os.ReadFile(configPath)
		if err == nil {
			var cfg map[string]interface{}
			if json.Unmarshal(b, &cfg) == nil {
				if v, ok := getInt(cfg, "storageproof_partition_max_sectors", "partition_sectors"); ok {
					p.PartitionSectors = int(v)
				}
			}
		}
	}

	if setup {
		return p, p.validatePartition()
	}

	saved, found, err := readPartitionKeyParams(partitionKeysDir)
	if err != nil {
		return PartitionProverParams{}, fmt.Errorf("could not read %s: %w", partitionParamsPath(partitionKeysDir), err)
	}
	if found {
		if !saved.equalPartition(p) {
			return PartitionProverParams{}, fmt.Errorf(
				"partition key params mismatch: keys=%+v config=%+v. Rerun partition-setup.",
				saved, p)
		}
		return saved, nil
	}
	return PartitionProverParams{}, fmt.Errorf("missing partition parameters; restore the matching published proof bundle")
}

// ─── Partition circuit ────────────────────────────────────────────────────────

// PartitionSectorProofCircuit proves knowledge of challenged blocks in N sectors
// simultaneously. The circuit capacity (N sectors, M challenges, D depth) is fixed
// at compile time. Partitions with fewer than N sectors pad by repeating the last
// real sector's data; the verifier accepts zero-root slots as valid by padding roots.
//
// Public input layout (N = PartitionSectors, M = MaxChallenges):
//
//	[0]              challengeSeedHi
//	[1]              challengeSeedLo
//	[2]              round
//	[3..3+N-1]       sectorRootHi[0..N-1]
//	[3+N..3+2N-1]    sectorRootLo[0..N-1]
//	[3+2N..3+3N-1]   sectorBlockCount[0..N-1]
//	[3+3N]           challengeCount (= M, enforced by circuit)
//	[4+3N..4+3N+NM-1] challengeIndex[i][j]  i=0..N-1, j=0..M-1
//	[4+3N+NM..4+4N+NM-1] pieceCommitment[i]   i=0..N-1  ← W3 fix
//
// Total: 4 + 4N + N*M  (= 132 for N=16, M=4)
type PartitionSectorProofCircuit struct {
	SeedHi          frontend.Variable     `gnark:",public"`
	SeedLo          frontend.Variable     `gnark:",public"`
	Round           frontend.Variable     `gnark:",public"`
	RootHi          []frontend.Variable   `gnark:",public"`
	RootLo          []frontend.Variable   `gnark:",public"`
	BlockCounts     []frontend.Variable   `gnark:",public"`
	ChallengeCount  frontend.Variable     `gnark:",public"`
	Indexes         [][]frontend.Variable `gnark:",public"`
	PieceCommitment []frontend.Variable   `gnark:",public"` // [N] W3 fix

	// Private witness: flattened as [N*M] challenge slots.
	BlockWords [][]frontend.Variable // [N*M][BlockWords]
	Path       [][]frontend.Variable // [N*M][depth]
	PathBits   [][]frontend.Variable // [N*M][depth]

	// Private witness for commitment leaf (W3 fix): one slot per sector.
	CommitWords    [][]frontend.Variable // [N][BlockWords]
	CommitPath     [][]frontend.Variable // [N][depth]
	CommitPathBits [][]frontend.Variable // [N][depth]
}

func newPartitionCircuit(params PartitionProverParams) *PartitionSectorProofCircuit {
	N := params.PartitionSectors
	M := params.MaxChallenges
	D := params.ZKTreeDepth
	wordCount := params.blockWordCount()
	total := N * M

	c := &PartitionSectorProofCircuit{
		RootHi:          make([]frontend.Variable, N),
		RootLo:          make([]frontend.Variable, N),
		BlockCounts:     make([]frontend.Variable, N),
		Indexes:         make([][]frontend.Variable, N),
		PieceCommitment: make([]frontend.Variable, N),
		BlockWords:      make([][]frontend.Variable, total),
		Path:            make([][]frontend.Variable, total),
		PathBits:        make([][]frontend.Variable, total),
		CommitWords:     make([][]frontend.Variable, N),
		CommitPath:      make([][]frontend.Variable, N),
		CommitPathBits:  make([][]frontend.Variable, N),
	}
	for i := 0; i < N; i++ {
		c.Indexes[i] = make([]frontend.Variable, M)
		c.CommitWords[i] = make([]frontend.Variable, wordCount)
		c.CommitPath[i] = make([]frontend.Variable, D)
		c.CommitPathBits[i] = make([]frontend.Variable, D)
	}
	for k := 0; k < total; k++ {
		c.BlockWords[k] = make([]frontend.Variable, wordCount)
		c.Path[k] = make([]frontend.Variable, D)
		c.PathBits[k] = make([]frontend.Variable, D)
	}
	return c
}

func (c *PartitionSectorProofCircuit) Define(api frontend.API) error {
	N := len(c.RootHi)
	M := len(c.Indexes[0])

	api.AssertIsEqual(c.ChallengeCount, M)

	for i := 0; i < N; i++ {
		root := api.Add(api.Mul(c.RootHi[i], two128), c.RootLo[i])

		// ── Challenge block proofs (unchanged) ───────────────────────────────
		for j := 0; j < M; j++ {
			k := i*M + j

			leafInputs := []frontend.Variable{leafTag}
			for w := 0; w < len(c.BlockWords[k]); w++ {
				leafInputs = append(leafInputs, c.BlockWords[k][w])
			}
			cur := mimcHash(api, leafInputs...)

			reconstructedIndex := frontend.Variable(0)
			pow := frontend.Variable(1)
			for level := 0; level < len(c.Path[k]); level++ {
				bit := c.PathBits[k][level]
				api.AssertIsBoolean(bit)
				reconstructedIndex = api.Add(reconstructedIndex, api.Mul(bit, pow))
				pow = api.Mul(pow, 2)

				left := api.Select(bit, c.Path[k][level], cur)
				right := api.Select(bit, cur, c.Path[k][level])
				cur = mimcHash(api, nodeTag, left, right)
			}
			api.AssertIsEqual(reconstructedIndex, c.Indexes[i][j])
			api.AssertIsEqual(cur, root)
		}

		// ── W3 fix: commitment leaf proof ─────────────────────────────────────
		// The commitment block is at leaf position sectorBlockCount (after data
		// blocks). PieceCommitment is a BN254 field element that can exceed 248
		// bits, so it is split into hi/lo across word0/word1 — matching how
		// sectorRoot is encoded (RootHi/RootLo):
		//   word0 = zkPieceCommitment >> 128   (hi)
		//   word1 = zkPieceCommitment & mask128 (lo)
		//   word2..end = 0
		// The full field element is reconstructed as word0*2^128 + word1.
		commitLeafInputs := []frontend.Variable{leafTag}
		for w := 0; w < len(c.CommitWords[i]); w++ {
			commitLeafInputs = append(commitLeafInputs, c.CommitWords[i][w])
		}
		commitCur := mimcHash(api, commitLeafInputs...)
		for level := 0; level < len(c.CommitPath[i]); level++ {
			bit := c.CommitPathBits[i][level]
			api.AssertIsBoolean(bit)
			left := api.Select(bit, c.CommitPath[i][level], commitCur)
			right := api.Select(bit, commitCur, c.CommitPath[i][level])
			commitCur = mimcHash(api, nodeTag, left, right)
		}
		api.AssertIsEqual(commitCur, root)
		// Reconstruct full field element from hi/lo, assert equals public input.
		commitFull := api.Add(api.Mul(c.CommitWords[i][0], two128), c.CommitWords[i][1])
		api.AssertIsEqual(commitFull, c.PieceCommitment[i])
		// words[2..] must be zero (reserved)
		for w := 2; w < len(c.CommitWords[i]); w++ {
			api.AssertIsEqual(c.CommitWords[i][w], 0)
		}
	}
	return nil
}

// ─── Partition setup ──────────────────────────────────────────────────────────

// ─── Partition proof request/response types ───────────────────────────────────

type PartitionSectorMetaForProver struct {
	SectorID         string   `json:"sectorId"`
	SectorRoot       string   `json:"sectorRoot"`
	PieceRoots       []string `json:"pieceRoots"`
	SectorBlockCount int      `json:"sectorBlockCount"`
	ZKBlockSize      int64    `json:"zkBlockSize"`
	ZKTreeDepth      int      `json:"zkTreeDepth"`
	// ZKPieceCommitment is the MiMC commitment to the piece(s) in this sector.
	// It must equal the value registered on-chain and the commitment block leaf.
	ZKPieceCommitment string `json:"zkPieceCommitment,omitempty"`
}

type PartitionProverRequest struct {
	Partition struct {
		Sectors []PartitionSectorMetaForProver `json:"sectors"`
	} `json:"partition"`
	Challenge struct {
		Round         uint64 `json:"round"`
		ChallengeSeed string `json:"challengeSeed"`
	} `json:"challenge"`
	StorageDir   string   `json:"storageDir"`
	CircuitN     int      `json:"circuitN,omitempty"`
	CircuitM     int      `json:"circuitM,omitempty"`
	PublicInputs []string `json:"publicInputs,omitempty"`
}

func canonicalSectorPieceCommitment(sec PartitionSectorMetaForProver) (string, error) {
	zkPC, err := computeZKPieceCommitmentNative(sec.PieceRoots)
	if err != nil {
		return "", err
	}
	if sec.ZKPieceCommitment != "" && !strings.EqualFold(sec.ZKPieceCommitment, zkPC) {
		return "", fmt.Errorf("zkPieceCommitment mismatch: meta=%s computed=%s", sec.ZKPieceCommitment, zkPC)
	}
	return zkPC, nil
}

// ─── Partition prove ──────────────────────────────────────────────────────────

func cmdPartitionProve(keysDir string, params PartitionProverParams) error {
	return cmdPartitionProveWithIO(keysDir, params, os.Stdin, os.Stdout, nil)
}

func cmdPartitionProveWithIO(keysDir string, params PartitionProverParams, input io.Reader, output io.Writer, artifacts *partitionProvingArtifacts) error {
	var req PartitionProverRequest
	if err := json.NewDecoder(input).Decode(&req); err != nil {
		return fmt.Errorf("decode partition prove request: %w", err)
	}
	stage := newPartitionStageLogger()
	stage.Log(
		"request decoded sectors=%d publicInputs=%d storageDir=%s",
		len(req.Partition.Sectors),
		len(req.PublicInputs),
		req.StorageDir,
	)

	// Allow per-request circuit size override (e.g. smaller N for testing).
	if req.CircuitN > 0 {
		params.PartitionSectors = req.CircuitN
	}
	if req.CircuitM > 0 {
		params.MaxChallenges = req.CircuitM
	}
	if err := params.validatePartition(); err != nil {
		return err
	}
	if artifacts != nil && !artifacts.params.equalPartition(params) {
		return fmt.Errorf("request circuit parameters do not match loaded proving artifacts: request=%+v loaded=%+v", params, artifacts.params)
	}

	sectors := req.Partition.Sectors
	K := len(sectors)
	if K == 0 {
		return fmt.Errorf("partition has no sectors")
	}
	N := params.PartitionSectors
	M := params.MaxChallenges
	if K > N {
		return fmt.Errorf("partition has %d sectors, circuit capacity is %d", K, N)
	}
	stage.Log(
		"params ready realSectors=%d circuitSectors=%d challenges=%d depth=%d zkBlockSize=%d blockWords=%d",
		K,
		N,
		M,
		params.ZKTreeDepth,
		params.ZKBlockSize,
		params.blockWordCount(),
	)

	// Pad sector list to N by repeating the last real sector.
	paddedSectors := make([]PartitionSectorMetaForProver, N)
	copy(paddedSectors, sectors)
	for i := K; i < N; i++ {
		paddedSectors[i] = sectors[K-1]
	}
	stage.Log("sector padding done paddedSlots=%d repeatedSlots=%d", N, N-K)

	// Parse seed hi/lo and challenge indexes before loading sector data. With
	// a valid cache we only need the challenged leaves and their Merkle paths.
	seedHi, seedLo, err := splitHiLoFromRoot(req.Challenge.ChallengeSeed)
	if err != nil {
		return fmt.Errorf("bad challenge seed: %w", err)
	}
	stage.Log("challenge seed parsed round=%d", req.Challenge.Round)

	// Extract per-sector challenge indexes from provided public inputs OR derive locally.
	// Public inputs layout (new): [seedHi, seedLo, round, rootHi×N, rootLo×N, bc×N, M, idx×NM, pc×N]
	// Challenge indexes are at positions [4+3N .. 4+3N+NM-1] in both old (116) and new (132) layouts.
	perSectorIndexes := make([][]uint64, N)
	for i := 0; i < N; i++ {
		perSectorIndexes[i] = make([]uint64, M)
	}
	oldLen := 4 + 3*N + N*M
	newLen := 4 + 4*N + N*M
	indexSource := "derived-local"
	if len(req.PublicInputs) == oldLen || len(req.PublicInputs) == newLen {
		indexSource = "provided-public-inputs"
		stage.Log("challenge indexes parse start source=%s publicInputs=%d", indexSource, len(req.PublicInputs))
		base := 4 + 3*N
		for i := 0; i < N; i++ {
			for j := 0; j < M; j++ {
				v, ok := new(big.Int).SetString(req.PublicInputs[base+i*M+j], 10)
				if !ok {
					return fmt.Errorf("bad public input[%d]: %s", base+i*M+j, req.PublicInputs[base+i*M+j])
				}
				perSectorIndexes[i][j] = v.Uint64()
			}
		}
	} else {
		stage.Log("challenge indexes derive start source=%s slots=%d", indexSource, N*M)
		seedBytes, serr := bytes32FromHex(req.Challenge.ChallengeSeed)
		if serr != nil {
			return fmt.Errorf("bad challenge seed hex: %w", serr)
		}
		for i := 0; i < N; i++ {
			bc := uint64(paddedSectors[i].SectorBlockCount)
			idxs, deriveErr := deriveKeccakChallengeIndexes(seedBytes, bc, uint64(M))
			if deriveErr != nil {
				return deriveErr
			}
			perSectorIndexes[i] = idxs
			stage.Log("challenge indexes derived sectorSlot=%d blockCount=%d indexes=%v", i, bc, idxs)
		}
	}
	stage.Log("challenge indexes ready source=%s slots=%d", indexSource, N*M)

	// Build per-sector leaves and ZK trees (including commitment block).
	type challengeWitness struct {
		leaf     leafInfo
		siblings []*big.Int
		bits     []int
	}
	type sectorData struct {
		root              string
		zkPieceCommitment string
		commitBlockLeaf   leafInfo // the commitment block leaf
		commitBlockIdx    int      // index of commitment block in the tree
		challenges        []challengeWitness
		commitSiblings    []*big.Int
		commitBits        []int
	}
	realSectorData := make([]sectorData, K)
	for i, sec := range sectors {
		sectorStart := time.Now()
		zkBlockSize := sec.ZKBlockSize
		if zkBlockSize <= 0 {
			zkBlockSize = int64(params.ZKBlockSize)
		}
		if zkBlockSize != params.ZKBlockSize {
			return fmt.Errorf("sector %d zkBlockSize=%d but partition keys/config use zk_block_size=%d", i, zkBlockSize, params.ZKBlockSize)
		}
		if sec.ZKTreeDepth > 0 && sec.ZKTreeDepth != params.ZKTreeDepth {
			return fmt.Errorf("sector %d zkTreeDepth=%d but partition keys/config use zk_tree_depth=%d", i, sec.ZKTreeDepth, params.ZKTreeDepth)
		}
		stage.Log(
			"sector %d start id=%s pieces=%d expectedBlocks=%d zkBlockSize=%d root=%s",
			i,
			sec.SectorID,
			len(sec.PieceRoots),
			sec.SectorBlockCount,
			zkBlockSize,
			sec.SectorRoot,
		)

		zkPC, cerr := canonicalSectorPieceCommitment(sec)
		if cerr != nil {
			return fmt.Errorf("sector %d commitment: %w", i, cerr)
		}
		stage.Log("sector %d piece commitment ready canonical=true", i)

		commitBlock, err := buildCommitmentBlock(zkPC, zkBlockSize)
		if err != nil {
			return fmt.Errorf("sector %d commit block: %w", i, err)
		}
		commitLeaf, commitWords := leafForBlock(commitBlock, params.blockWordCount())
		commitLI := leafInfo{block: commitBlock, leaf: commitLeaf, words: commitWords}
		commitIdx := sec.SectorBlockCount

		if cache, cacheErr := loadZKSectorCache(req.StorageDir, sec, params); cacheErr == nil {
			challenges := make([]challengeWitness, M)
			for j := 0; j < M; j++ {
				idx := perSectorIndexes[i][j]
				block, berr := readSectorBlockByIndex(req.StorageDir, cache.meta, idx)
				if berr != nil {
					return fmt.Errorf("sector %d cache read block %d: %w", i, idx, berr)
				}
				leaf, words := leafForBlock(block, params.blockWordCount())
				siblings, bits, perr := cache.siblingPath(int(idx))
				if perr != nil {
					return fmt.Errorf("sector %d cache path block %d: %w", i, idx, perr)
				}
				challenges[j] = challengeWitness{
					leaf:     leafInfo{block: block, leaf: leaf, words: words},
					siblings: siblings,
					bits:     bits,
				}
			}
			commitSiblings, commitBits, perr := cache.siblingPath(commitIdx)
			if perr != nil {
				return fmt.Errorf("sector %d cache commitment path: %w", i, perr)
			}
			stage.Log("sector %d cache ready challenges=%d commitIdx=%d took=%.3fs", i, M, commitIdx, time.Since(sectorStart).Seconds())
			realSectorData[i] = sectorData{
				root:              sec.SectorRoot,
				zkPieceCommitment: zkPC,
				commitBlockLeaf:   commitLI,
				commitBlockIdx:    commitIdx,
				challenges:        challenges,
				commitSiblings:    commitSiblings,
				commitBits:        commitBits,
			}
			continue
		} else {
			stage.Log("sector %d cache unavailable, falling back to full tree rebuild: %v", i, cacheErr)
		}

		dataLeaves, err := sectorLeavesFromStorage(req.StorageDir, sec.PieceRoots, zkBlockSize, func(pieceIndex int, pieceRoot string, event string, blocks int, bytesRead int64) {
			if bytesRead > 0 {
				stage.Log(
					"sector %d piece %d %s blocks=%d bytes=%d pieceRoot=%s",
					i,
					pieceIndex,
					event,
					blocks,
					bytesRead,
					pieceRoot,
				)
				return
			}
			stage.Log(
				"sector %d piece %d %s blocks=%d pieceRoot=%s",
				i,
				pieceIndex,
				event,
				blocks,
				pieceRoot,
			)
		})
		if err != nil {
			return fmt.Errorf("sector %d (%s) leaves: %w", i, sec.SectorID, err)
		}
		if len(dataLeaves) != sec.SectorBlockCount {
			return fmt.Errorf("sector %d blockCount mismatch: meta=%d local=%d", i, sec.SectorBlockCount, len(dataLeaves))
		}
		stage.Log("sector %d leaves ready count=%d took=%.3fs", i, len(dataLeaves), time.Since(sectorStart).Seconds())

		// Build full leaf list: data leaves + commitment block at position blockCount.
		allLeaves := append(append([]leafInfo{}, dataLeaves...), commitLI)

		treeStart := time.Now()
		st, err := newSparseTree(allLeaves, params.ZKTreeDepth)
		if err != nil {
			return fmt.Errorf("sector %d tree: %w", i, err)
		}
		gotRoot := fieldHex(st.root())
		if !strings.EqualFold(gotRoot, sec.SectorRoot) {
			return fmt.Errorf("sector %d root mismatch: local=%s meta=%s", i, gotRoot, sec.SectorRoot)
		}
		stage.Log(
			"sector %d sparse tree ready leavesWithCommit=%d depth=%d took=%.3fs root_ok=true",
			i,
			len(allLeaves),
			params.ZKTreeDepth,
			time.Since(treeStart).Seconds(),
		)
		challenges := make([]challengeWitness, M)
		for j := 0; j < M; j++ {
			idx := perSectorIndexes[i][j]
			if idx >= uint64(len(dataLeaves)) {
				return fmt.Errorf("sector %d challenge index %d out of range (%d leaves)", i, idx, len(dataLeaves))
			}
			siblings, bits := st.siblingPath(int(idx))
			challenges[j] = challengeWitness{
				leaf:     dataLeaves[idx],
				siblings: siblings,
				bits:     bits,
			}
		}
		commitSiblings, commitBits := st.siblingPath(commitIdx)
		realSectorData[i] = sectorData{
			root:              sec.SectorRoot,
			zkPieceCommitment: zkPC,
			commitBlockLeaf:   commitLI,
			commitBlockIdx:    commitIdx,
			challenges:        challenges,
			commitSiblings:    commitSiblings,
			commitBits:        commitBits,
		}
	}
	sdata := make([]sectorData, N)
	copy(sdata, realSectorData)
	for i := K; i < N; i++ {
		sdata[i] = realSectorData[K-1]
	}
	stage.Log("sector preparation done real=%d padded=%d", K, N)

	// Build assignment.
	assignmentStart := time.Now()
	assignment := newPartitionCircuit(params)
	assignment.SeedHi = seedHi
	assignment.SeedLo = seedLo
	assignment.Round = req.Challenge.Round
	assignment.ChallengeCount = M

	for i := 0; i < N; i++ {
		rootHi, rootLo, _ := splitHiLoFromRoot(paddedSectors[i].SectorRoot)
		assignment.RootHi[i] = rootHi
		assignment.RootLo[i] = rootLo
		assignment.BlockCounts[i] = paddedSectors[i].SectorBlockCount

		// Set piece commitment public input.
		zkPC, err := bytes32FromHex(sdata[i].zkPieceCommitment)
		if err != nil {
			return fmt.Errorf("sector %d bad zkPieceCommitment: %w", i, err)
		}
		assignment.PieceCommitment[i] = new(big.Int).SetBytes(zkPC)

		// Challenge block witnesses.
		for j := 0; j < M; j++ {
			idx := perSectorIndexes[i][j]
			k := i*M + j
			assignment.Indexes[i][j] = idx

			if j >= len(sdata[i].challenges) {
				return fmt.Errorf("sector %d missing challenge witness %d", i, j)
			}
			cw := sdata[i].challenges[j]
			lf := cw.leaf
			for w := 0; w < len(assignment.BlockWords[k]); w++ {
				assignment.BlockWords[k][w] = lf.words[w]
			}
			for level := 0; level < params.ZKTreeDepth; level++ {
				assignment.Path[k][level] = cw.siblings[level]
				assignment.PathBits[k][level] = cw.bits[level]
			}
		}

		// Commitment block witnesses (W3 fix).
		commitLF := sdata[i].commitBlockLeaf
		for w := 0; w < len(assignment.CommitWords[i]); w++ {
			assignment.CommitWords[i][w] = commitLF.words[w]
		}
		for level := 0; level < params.ZKTreeDepth; level++ {
			assignment.CommitPath[i][level] = sdata[i].commitSiblings[level]
			assignment.CommitPathBits[i][level] = sdata[i].commitBits[level]
		}
	}
	stage.Log("assignment ready took=%.3fs challengeSlots=%d commitSlots=%d", time.Since(assignmentStart).Seconds(), N*M, N)

	// Build public inputs string slice for the response.
	publicInputStart := time.Now()
	pubInputs, piErr := buildPartitionPublicInputs(req, params, perSectorIndexes, seedHi, seedLo)
	if piErr != nil {
		return piErr
	}
	stage.Log("public inputs ready count=%d took=%.3fs", len(pubInputs), time.Since(publicInputStart).Seconds())

	// The persistent service supplies immutable artifacts loaded once. One-shot
	// mode uses the same loader here and therefore follows the identical path.
	if artifacts == nil {
		var loadErr error
		artifacts, loadErr = loadPartitionProvingArtifacts(keysDir, params, stage)
		if loadErr != nil {
			return loadErr
		}
	} else {
		stage.Log("proving artifacts ready source=persistent-service")
	}

	witnessStart := time.Now()
	stage.Log("witness build start")
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return fmt.Errorf("build public witness for local verification: %w", err)
	}
	if err := validatePartitionPublicWitness(publicWitness, pubInputs); err != nil {
		return err
	}
	stage.Log("witness build done took=%.3fs", time.Since(witnessStart).Seconds())

	proveStart := time.Now()
	stage.Log("groth16 prove start")
	proof, err := groth16.Prove(artifacts.cs, artifacts.pk, witness)
	if err != nil {
		return err
	}
	stage.Log("groth16 prove done took=%.3fs", time.Since(proveStart).Seconds())

	verifyStart := time.Now()
	if err := groth16.Verify(proof, artifacts.vk, publicWitness); err != nil {
		return fmt.Errorf("locally verify generated partition proof: %w", err)
	}
	stage.Log("local proof verification done took=%.3fs", time.Since(verifyStart).Seconds())

	serializeStart := time.Now()
	var proofBytes bytes.Buffer
	if _, err := proof.WriteRawTo(&proofBytes); err != nil {
		return err
	}
	stage.Log("proof serialization done bytes=%d took=%.3fs", proofBytes.Len(), time.Since(serializeStart).Seconds())

	resp := ProverResponse{
		OK:           true,
		SectorRoot:   req.Challenge.ChallengeSeed, // use seed as stable identifier
		Round:        req.Challenge.Round,
		Proof:        "0x" + hex.EncodeToString(proofBytes.Bytes()),
		PublicInputs: pubInputs,
	}
	b, _ := json.Marshal(resp)
	stage.Log("response ready publicInputs=%d totalElapsed=%.3fs", len(pubInputs), time.Since(stage.start).Seconds())
	fmt.Fprintln(output, string(b))
	return nil
}

type sectorLeafProgressFunc func(pieceIndex int, pieceRoot string, event string, blocks int, bytesRead int64)

// sectorLeavesFromStorage reads piece files for a sector from the storage directory.
func sectorLeavesFromStorage(storageDir string, pieceRoots []string, zkBlockSize int64, progress ...sectorLeafProgressFunc) ([]leafInfo, error) {
	var cb sectorLeafProgressFunc
	if len(progress) > 0 {
		cb = progress[0]
	}
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	wordCount := blockWordCountForSize(zkBlockSize)
	var out []leafInfo
	for pieceIndex, root := range pieceRoots {
		path := piecePath(storageDir, root)
		if cb != nil {
			cb(pieceIndex, root, "read_start", 0, 0)
		}
		blocks, err := readBlocksWithProgress(path, zkBlockSize, func(blocks int, bytesRead int64) {
			if cb != nil {
				cb(pieceIndex, root, "read_progress", blocks, bytesRead)
			}
		})
		if err != nil {
			return nil, fmt.Errorf("read blocks for %s: %w", root, err)
		}
		if cb != nil {
			cb(pieceIndex, root, "read_done", len(blocks), 0)
		}
		lastHashProgress := time.Now()
		for blockIndex, b := range blocks {
			leaf, words := leafForBlock(b, wordCount)
			out = append(out, leafInfo{block: b, leaf: leaf, words: words})
			done := blockIndex + 1
			if cb != nil && (done%100000 == 0 || time.Since(lastHashProgress) >= 10*time.Second) {
				cb(pieceIndex, root, "hash_progress", done, 0)
				lastHashProgress = time.Now()
			}
		}
		if cb != nil {
			cb(pieceIndex, root, "hash_done", len(blocks), 0)
		}
	}
	return out, nil
}

func splitPieceRootForCommitment(root string) ([]byte, []byte, error) {
	b, err := bytes32FromHex(root)
	if err != nil {
		return nil, nil, err
	}
	x := new(big.Int).SetBytes(b)
	hi := new(big.Int).Rsh(new(big.Int).Set(x), 128)
	lo := new(big.Int).And(x, new(big.Int).Sub(two128, big.NewInt(1)))
	return bigTo32(hi), bigTo32(lo), nil
}

// computeZKPieceCommitmentNative computes MiMC("FT-COMMIT-V2", pieceRoot_1_hi,
// pieceRoot_1_lo, ...). SHA256 roots are split into two 128-bit field elements
// so arbitrary bytes32 roots bind losslessly inside BN254 MiMC.
func computeZKPieceCommitmentNative(pieceRoots []string) (string, error) {
	if len(pieceRoots) == 0 {
		return "", fmt.Errorf("empty pieceRoots")
	}
	parts := [][]byte{[]byte("FT-COMMIT-V2")}
	for _, root := range pieceRoots {
		hi, lo, err := splitPieceRootForCommitment(root)
		if err != nil {
			return "", fmt.Errorf("bad pieceRoot %s: %w", root, err)
		}
		parts = append(parts, hi, lo)
	}
	h, err := mimcHashNativeChecked(parts...)
	if err != nil {
		return "", fmt.Errorf("hash piece commitment: %w", err)
	}
	return fieldHex(h), nil
}

// buildCommitmentBlock builds the zkBlockSize-byte commitment block for a sector.
// The BN254 field element zkPieceCommitment is split hi/lo to fit in 31-byte words:
//
//	word0 (bytes 0..30)  = zkPieceCommitment >> 128  (hi, <= 126 bits)
//	word1 (bytes 31..61) = zkPieceCommitment & mask128 (lo, 128 bits)
//	word2..end = zero
//
// The circuit reconstructs: commitFull = word0 * 2^128 + word1 == PieceCommitment.
func buildCommitmentBlock(zkPieceCommitment string, zkBlockSize int64) ([]byte, error) {
	if zkBlockSize <= 0 {
		zkBlockSize = DefaultZKBlockSize
	}
	if zkBlockSize < MinZKBlockSize {
		return nil, fmt.Errorf("buildCommitmentBlock: zkBlockSize=%d is too small", zkBlockSize)
	}
	fieldBytes, err := bytes32FromHex(zkPieceCommitment)
	if err != nil {
		return nil, fmt.Errorf("buildCommitmentBlock: %w", err)
	}
	val := new(big.Int).SetBytes(fieldBytes)
	mask128 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	hi := new(big.Int).Rsh(val, 128)
	lo := new(big.Int).And(val, mask128)

	block := make([]byte, int(zkBlockSize))
	// word0 at bytes [0..30]: hi right-aligned in 31 bytes
	hiBytes := hi.Bytes()
	if len(hiBytes) > 0 {
		n := len(hiBytes)
		if n > FieldWordBytes {
			n = FieldWordBytes
		}
		copy(block[FieldWordBytes-n:FieldWordBytes], hiBytes[len(hiBytes)-n:])
	}
	// word1 at bytes [31..61]: lo right-aligned in 31 bytes
	loBytes := lo.Bytes()
	if len(loBytes) > 0 {
		n := len(loBytes)
		if n > FieldWordBytes {
			n = FieldWordBytes
		}
		word1End := 2 * FieldWordBytes
		copy(block[word1End-n:word1End], loBytes[len(loBytes)-n:])
	}
	// word2..end remain zero
	return block, nil
}

type zkSectorCacheMeta struct {
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
}

type zkSectorCache struct {
	dir   string
	meta  zkSectorCacheMeta
	empty [][]byte
}

func zkSectorCacheDir(storageDir, sectorRoot string) string {
	return filepath.Join(storageDir, ZKSectorCacheName, cleanHex(sectorRoot))
}

func sameHexList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

func loadZKSectorCache(storageDir string, sec PartitionSectorMetaForProver, params PartitionProverParams) (*zkSectorCache, error) {
	dir := zkSectorCacheDir(storageDir, sec.SectorRoot)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var meta zkSectorCacheMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, err
	}
	if meta.Version != ZKSectorCacheV1 {
		return nil, fmt.Errorf("cache version=%q expected=%q", meta.Version, ZKSectorCacheV1)
	}
	if meta.RootAlg != "" && meta.RootAlg != RootAlgZKMiMCBN254 {
		return nil, fmt.Errorf("cache rootAlg=%q expected=%q", meta.RootAlg, RootAlgZKMiMCBN254)
	}
	if !strings.EqualFold(meta.SectorRoot, sec.SectorRoot) {
		return nil, fmt.Errorf("cache root mismatch")
	}
	if meta.ZKBlockSize != params.ZKBlockSize || meta.ZKTreeDepth != params.ZKTreeDepth {
		return nil, fmt.Errorf("cache params mismatch block=%d/%d depth=%d/%d", meta.ZKBlockSize, params.ZKBlockSize, meta.ZKTreeDepth, params.ZKTreeDepth)
	}
	if meta.SectorBlockCount != sec.SectorBlockCount {
		return nil, fmt.Errorf("cache block count=%d sector=%d", meta.SectorBlockCount, sec.SectorBlockCount)
	}
	if !sameHexList(meta.PieceRoots, sec.PieceRoots) {
		return nil, fmt.Errorf("cache piece roots mismatch")
	}
	zkPC, err := canonicalSectorPieceCommitment(sec)
	if err != nil {
		return nil, fmt.Errorf("sector commitment: %w", err)
	}
	if !strings.EqualFold(meta.ZKPieceCommitment, zkPC) {
		return nil, fmt.Errorf("cache piece commitment mismatch")
	}
	if len(meta.LevelFiles) < params.ZKTreeDepth+1 || len(meta.LevelNodeCounts) < params.ZKTreeDepth+1 || len(meta.EmptyHashes) < params.ZKTreeDepth+1 {
		return nil, fmt.Errorf("cache has incomplete levels")
	}
	if len(meta.PieceBlockCounts) != len(meta.PieceRoots) {
		return nil, fmt.Errorf("cache piece block counts mismatch")
	}
	empty := make([][]byte, params.ZKTreeDepth+1)
	for i := range empty {
		empty[i], err = bytes32FromHex(meta.EmptyHashes[i])
		if err != nil {
			return nil, fmt.Errorf("cache empty hash %d: %w", i, err)
		}
	}
	rootNode, err := readZKCacheNode(dir, meta, params.ZKTreeDepth, 0)
	if err != nil {
		return nil, fmt.Errorf("cache root read: %w", err)
	}
	if !strings.EqualFold(fieldHex(rootNode), sec.SectorRoot) {
		return nil, fmt.Errorf("cache root node mismatch")
	}
	return &zkSectorCache{dir: dir, meta: meta, empty: empty}, nil
}

func readZKCacheNode(dir string, meta zkSectorCacheMeta, level int, pos int) ([]byte, error) {
	if level < 0 || level >= len(meta.LevelFiles) || level >= len(meta.LevelNodeCounts) {
		return nil, fmt.Errorf("level %d out of range", level)
	}
	if pos < 0 || pos >= meta.LevelNodeCounts[level] {
		return nil, fmt.Errorf("node level=%d pos=%d out of range count=%d", level, pos, meta.LevelNodeCounts[level])
	}
	f, err := os.Open(filepath.Join(dir, meta.LevelFiles[level]))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(int64(pos*32), io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, 32)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *zkSectorCache) siblingPath(leafIdx int) ([]*big.Int, []int, error) {
	D := c.meta.ZKTreeDepth
	siblings := make([]*big.Int, D)
	bits := make([]int, D)
	pos := leafIdx
	for level := 0; level < D; level++ {
		sibPos := pos ^ 1
		var sib []byte
		if sibPos < c.meta.LevelNodeCounts[level] {
			var err error
			sib, err = readZKCacheNode(c.dir, c.meta, level, sibPos)
			if err != nil {
				return nil, nil, err
			}
		} else {
			sib = c.empty[level]
		}
		siblings[level] = new(big.Int).SetBytes(sib)
		bits[level] = pos & 1
		pos >>= 1
	}
	return siblings, bits, nil
}

func readSectorBlockByIndex(storageDir string, meta zkSectorCacheMeta, blockIndex uint64) ([]byte, error) {
	if blockIndex >= uint64(meta.SectorBlockCount) {
		return nil, fmt.Errorf("block index %d out of range %d", blockIndex, meta.SectorBlockCount)
	}
	remaining := int(blockIndex)
	for i, count := range meta.PieceBlockCounts {
		if remaining >= count {
			remaining -= count
			continue
		}
		path := piecePath(storageDir, meta.PieceRoots[i])
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		buf := make([]byte, int(meta.ZKBlockSize))
		n, err := f.ReadAt(buf, int64(remaining)*meta.ZKBlockSize)
		if err != nil && !(err == io.EOF && n > 0) {
			if err == io.EOF && n == 0 {
				return nil, nil
			}
			return nil, err
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("block index %d not found in piece map", blockIndex)
}

func countPieceBlocks(path string, zkBlockSize int64) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if info.Size() == 0 {
		return 1, nil
	}
	return int((info.Size() + zkBlockSize - 1) / zkBlockSize), nil
}

func writeCacheLevel(path string, nodes [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, node := range nodes {
		if _, err := f.Write(hashBytes32(node)); err != nil {
			return err
		}
	}
	return nil
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

func writeZKSectorCacheFromLeaves(storageDir string, sec computeRootsSectorRequest, root string, zkPC string, allLeaves []leafInfo) error {
	if storageDir == "" || root == "" || len(allLeaves) == 0 {
		return nil
	}
	base := filepath.Join(storageDir, ZKSectorCacheName)
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	tmpDir := filepath.Join(base, fmt.Sprintf(".tmp-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	empty := make([][]byte, sec.ZKTreeDepth+1)
	empty[0] = emptyLeaf()
	for d := 1; d <= sec.ZKTreeDepth; d++ {
		empty[d] = hashNode(empty[d-1], empty[d-1])
	}

	levelFiles := make([]string, 0, sec.ZKTreeDepth+1)
	levelCounts := make([]int, 0, sec.ZKTreeDepth+1)
	current := make([][]byte, len(allLeaves))
	for i := range allLeaves {
		current[i] = allLeaves[i].leaf
	}
	for level := 0; level <= sec.ZKTreeDepth; level++ {
		name := fmt.Sprintf("level_%02d.bin", level)
		if err := writeCacheLevel(filepath.Join(tmpDir, name), current); err != nil {
			return err
		}
		levelFiles = append(levelFiles, name)
		levelCounts = append(levelCounts, len(current))
		if level == sec.ZKTreeDepth {
			break
		}
		next := make([][]byte, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := empty[level]
			if i+1 < len(current) {
				right = current[i+1]
			}
			next[i/2] = hashNode(left, right)
		}
		current = next
	}

	if len(current) == 0 || !strings.EqualFold(fieldHex(current[0]), root) {
		return fmt.Errorf("cache root mismatch while writing cache")
	}
	pieceCounts := make([]int, 0, len(sec.PieceRoots))
	for _, pieceRoot := range sec.PieceRoots {
		count, err := countPieceBlocks(piecePath(sec.StorageDir, pieceRoot), sec.ZKBlockSize)
		if err != nil {
			return err
		}
		pieceCounts = append(pieceCounts, count)
	}
	emptyHex := make([]string, len(empty))
	for i := range empty {
		emptyHex[i] = fieldHex(empty[i])
	}
	meta := zkSectorCacheMeta{
		Version:           ZKSectorCacheV1,
		RootAlg:           RootAlgZKMiMCBN254,
		SectorRoot:        root,
		ZKBlockSize:       sec.ZKBlockSize,
		ZKTreeDepth:       sec.ZKTreeDepth,
		SectorBlockCount:  len(allLeaves) - 1,
		LeafCount:         len(allLeaves),
		PieceRoots:        append([]string(nil), sec.PieceRoots...),
		PieceBlockCounts:  pieceCounts,
		ZKPieceCommitment: zkPC,
		LevelFiles:        levelFiles,
		LevelNodeCounts:   levelCounts,
		EmptyHashes:       emptyHex,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "meta.json"), b, 0600); err != nil {
		return err
	}
	finalDir := zkSectorCacheDir(storageDir, root)
	if err := os.RemoveAll(finalDir); err != nil {
		return err
	}
	return os.Rename(tmpDir, finalDir)
}

// deriveKeccakChallengeIndexes replicates the on-chain _challengeIndexes algorithm:
//
//	candidate = keccak256(seed ++ counter) % blockCount  (no duplicates)
func deriveKeccakChallengeIndexes(seed []byte, blockCount, challengeCount uint64) ([]uint64, error) {
	if blockCount == 0 {
		return nil, fmt.Errorf("blockCount is zero")
	}
	if challengeCount > blockCount {
		challengeCount = blockCount
	}
	idxs := make([]uint64, 0, challengeCount)
	seen := make(map[uint64]bool)
	counter := uint64(0)
	for uint64(len(idxs)) < challengeCount && counter < (1<<32) {
		// keccak256(seed ++ uint256(counter))
		var counterBytes [32]byte
		binary.BigEndian.PutUint64(counterBytes[24:], counter)
		h := challengeHash32(append(seed, counterBytes[:]...))
		candidate := new(big.Int).SetBytes(h)
		candidate.Mod(candidate, new(big.Int).SetUint64(blockCount))
		idx := candidate.Uint64()
		if !seen[idx] {
			seen[idx] = true
			idxs = append(idxs, idx)
		}
		counter++
	}
	if uint64(len(idxs)) != challengeCount {
		return nil, fmt.Errorf("could not derive %d unique challenge indexes after %d attempts", challengeCount, counter)
	}
	return idxs, nil
}

// buildPartitionPublicInputs constructs the public inputs string slice for the
// partition proof response, matching the on-chain layout (4+4N+NM for W3 fix).
func buildPartitionPublicInputs(req PartitionProverRequest, params PartitionProverParams,
	perSectorIndexes [][]uint64, seedHi, seedLo *big.Int) ([]string, error) {

	N := params.PartitionSectors
	M := params.MaxChallenges
	sectors := req.Partition.Sectors
	K := len(sectors)
	if K == 0 {
		return nil, fmt.Errorf("partition has no sectors")
	}
	if K > N {
		return nil, fmt.Errorf("partition has %d sectors, circuit capacity is %d", K, N)
	}

	// Pad sectors.
	padded := make([]PartitionSectorMetaForProver, N)
	copy(padded, sectors)
	for i := K; i < N; i++ {
		padded[i] = sectors[K-1]
	}

	out := make([]string, 0, 4+4*N+N*M)
	out = append(out, seedHi.String(), seedLo.String())
	out = append(out, strconv.FormatUint(req.Challenge.Round, 10))

	for i := 0; i < N; i++ {
		rhi, _, err := splitHiLoFromRoot(padded[i].SectorRoot)
		if err != nil {
			return nil, err
		}
		out = append(out, rhi.String())
	}
	for i := 0; i < N; i++ {
		_, rlo, _ := splitHiLoFromRoot(padded[i].SectorRoot)
		out = append(out, rlo.String())
	}
	for i := 0; i < N; i++ {
		out = append(out, strconv.Itoa(padded[i].SectorBlockCount))
	}
	out = append(out, strconv.Itoa(M))
	for i := 0; i < N; i++ {
		for j := 0; j < M; j++ {
			out = append(out, strconv.FormatUint(perSectorIndexes[i][j], 10))
		}
	}
	// W3 fix: append pieceCommitment[i] for i=0..N-1
	for i := 0; i < N; i++ {
		pc, err := canonicalSectorPieceCommitment(padded[i])
		if err != nil {
			return nil, fmt.Errorf("sector %d pieceCommitment: %w", i, err)
		}
		pcBytes, err := bytes32FromHex(pc)
		if err != nil {
			return nil, fmt.Errorf("sector %d bad zkPieceCommitment hex: %w", i, err)
		}
		out = append(out, new(big.Int).SetBytes(pcBytes).String())
	}
	return out, nil
}

// challengeHash32 hashes seed||counter for offline challenge index derivation.
// Production partition proofs receive indexes from StorageProofSC via publicInputs.
// This fallback mirrors Solidity keccak256(abi.encodePacked(seed, counter)).
func challengeHash32(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(data)
	return h.Sum(nil)
}
