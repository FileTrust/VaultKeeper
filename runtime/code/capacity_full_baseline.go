package main

// G.3D — durable provenance for the last valid full-capacity baseline.
//
// Live registered/proved/certified byte counters are deliberately absent from the rebuild
// predicate. They can diverge during ordinary incremental operation. A full rebuild is selected
// only when the chain declaration or the durable physical-layout generation differs from the
// provenance committed after the last successfully completed full sweep.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	fullCapacityBaselineVersion = 1
	capacityLayoutStateVersion  = 1
	capacityLayoutScheme        = "fixed-capacity-slots-v1"
)

type FullCapacityBaseline struct {
	Version                   int    `json:"version"`
	ChainID                   string `json:"chainId"`
	CapacityProofContract     string `json:"capacityProofContract"`
	VKAddress                 string `json:"vkAddress"`
	DeclaredCapacityBytes     uint64 `json:"declaredCapacityBytes"`
	CapacityLayoutFingerprint string `json:"capacityLayoutFingerprint"`
	CompletedFullEpochID      uint64 `json:"completedFullEpochId"`
	CapacityProofSequence     uint64 `json:"capacityProofSequence"`
	CompletedAtUnix           uint64 `json:"completedAtUnix"`
}

type fullCapacityBaselineCandidate struct {
	ChainID                   string `json:"chainId"`
	CapacityProofContract     string `json:"capacityProofContract"`
	VKAddress                 string `json:"vkAddress"`
	DeclaredCapacityBytes     uint64 `json:"declaredCapacityBytes"`
	CapacityLayoutFingerprint string `json:"capacityLayoutFingerprint"`
	CompletedFullEpochID      uint64 `json:"completedFullEpochId"`
	ProofSequenceBefore       uint64 `json:"proofSequenceBefore"`
}

type capacityLayoutState struct {
	Version             int    `json:"version"`
	GeometryFingerprint string `json:"geometryFingerprint"`
	LayoutRevision      uint64 `json:"layoutRevision"`
}

type fullBaselineEvaluation struct {
	Initial bool
	Rebuild bool
	Detail  string
}

func fullCapacityBaselinePath(storage string) string {
	return filepath.Join(storage, "capacity-full-baseline.json")
}

func capacityLayoutStatePath(storage string) string {
	return filepath.Join(storage, "capacity-layout-provenance.json")
}

func withDurableCapacityRecordLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
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

func decodeStrictJSONFile(path string, value any) (bool, error) {
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return true, fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return true, fmt.Errorf("decode %s: trailing JSON value", filepath.Base(path))
		}
		return true, fmt.Errorf("decode %s trailing data: %w", filepath.Base(path), err)
	}
	return true, nil
}

func hashCanonicalJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "0x" + hex.EncodeToString(digest[:]), nil
}

func normalizedBaselineAddress(value, label string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 42 || !strings.HasPrefix(value, "0x") {
		return "", fmt.Errorf("%s is not a 20-byte hex address", label)
	}
	if _, err := hex.DecodeString(value[2:]); err != nil {
		return "", fmt.Errorf("%s is not hex: %w", label, err)
	}
	return value, nil
}

func capacityBaselineBinding(cfg ServerConfig) (chainID, contract, vk string, err error) {
	if cfg.ChainID <= 0 {
		return "", "", "", fmt.Errorf("capacity baseline chain id is unavailable")
	}
	contract, err = normalizedBaselineAddress(cfg.CapacityProofContract, "capacity proof contract")
	if err != nil {
		return "", "", "", err
	}
	vk, err = normalizedBaselineAddress(cfg.VKAddress, "VK address")
	if err != nil {
		return "", "", "", err
	}
	return strconv.FormatInt(cfg.ChainID, 10), contract, vk, nil
}

func capacityGeometryFingerprint(cfg ServerConfig) (string, error) {
	slotSize, err := resolvedCapacitySlotSize(cfg)
	if err != nil {
		return "", err
	}
	blockSize := cfg.ZKBlockSize
	if blockSize <= 0 {
		blockSize = DefaultZKBlockSize
	}
	depth := cfg.ZKTreeDepth
	if depth <= 0 {
		depth = DefaultZKTreeDepth
	}
	return hashCanonicalJSON(struct {
		Scheme              string `json:"scheme"`
		SlotSizeBytes       int64  `json:"slotSizeBytes"`
		ZKBlockSize         int64  `json:"zkBlockSize"`
		ZKTreeDepth         int    `json:"zkTreeDepth"`
		DeadlineCount       int    `json:"deadlineCount"`
		PartitionMaxSectors int    `json:"partitionMaxSectors"`
	}{capacityLayoutScheme, slotSize, blockSize, depth, cfg.DeadlineCount, cfg.PartitionMaxSectors})
}

func readCapacityLayoutState(storage string) (state capacityLayoutState, found bool, err error) {
	err = withDurableCapacityRecordLock(capacityLayoutStatePath(storage), func() error {
		var readErr error
		found, readErr = decodeStrictJSONFile(capacityLayoutStatePath(storage), &state)
		return readErr
	})
	if err != nil || !found {
		return state, found, err
	}
	if state.Version != capacityLayoutStateVersion || state.LayoutRevision == 0 ||
		strings.TrimSpace(state.GeometryFingerprint) == "" {
		return state, true, fmt.Errorf("capacity layout provenance is invalid")
	}
	return state, true, nil
}

// recordCapacityLayoutAfterRebalance advances the durable layout revision only after a
// successful physical build. Routine free/data movement with unchanged geometry preserves it.
func recordCapacityLayoutAfterRebalance(storage string, cfg ServerConfig, physicalReplacement bool) error {
	geometry, err := capacityGeometryFingerprint(cfg)
	if err != nil {
		return err
	}
	path := capacityLayoutStatePath(storage)
	return withDurableCapacityRecordLock(path, func() error {
		var state capacityLayoutState
		found, err := decodeStrictJSONFile(path, &state)
		if err != nil {
			return err
		}
		if found && (state.Version != capacityLayoutStateVersion || state.LayoutRevision == 0 ||
			strings.TrimSpace(state.GeometryFingerprint) == "") {
			return fmt.Errorf("capacity layout provenance is invalid")
		}
		changed := !found
		if !found {
			state = capacityLayoutState{Version: capacityLayoutStateVersion, LayoutRevision: 1}
		} else if state.GeometryFingerprint != geometry || physicalReplacement {
			if state.LayoutRevision == math.MaxUint64 {
				return fmt.Errorf("capacity layout revision overflow")
			}
			state.LayoutRevision++
			changed = true
		}
		state.GeometryFingerprint = geometry
		if !changed {
			return nil
		}
		payload, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return err
		}
		return durableAtomicWriteFile(path, append(payload, '\n'), 0600)
	})
}

func currentCapacityLayoutFingerprint(storage string, cfg ServerConfig) (string, error) {
	state, found, err := readCapacityLayoutState(storage)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("capacity layout provenance is missing")
	}
	geometry, err := capacityGeometryFingerprint(cfg)
	if err != nil {
		return "", err
	}
	if state.GeometryFingerprint != geometry {
		return hashCanonicalJSON(struct {
			Geometry string `json:"geometry"`
			Revision uint64 `json:"revision"`
		}{geometry, state.LayoutRevision})
	}
	return hashCanonicalJSON(struct {
		Geometry string `json:"geometry"`
		Revision uint64 `json:"revision"`
	}{state.GeometryFingerprint, state.LayoutRevision})
}

func readFullCapacityBaseline(storage string) (baseline FullCapacityBaseline, found bool, err error) {
	err = withDurableCapacityRecordLock(fullCapacityBaselinePath(storage), func() error {
		var readErr error
		found, readErr = decodeStrictJSONFile(fullCapacityBaselinePath(storage), &baseline)
		return readErr
	})
	if err != nil || !found {
		return baseline, found, err
	}
	if baseline.Version != fullCapacityBaselineVersion || baseline.DeclaredCapacityBytes == 0 ||
		baseline.CompletedFullEpochID == 0 || baseline.CapacityProofSequence == 0 ||
		baseline.CompletedAtUnix == 0 || strings.TrimSpace(baseline.CapacityLayoutFingerprint) == "" {
		return baseline, true, fmt.Errorf("full capacity baseline is invalid")
	}
	return baseline, true, nil
}

func writeFullCapacityBaseline(storage string, baseline FullCapacityBaseline) error {
	baseline.Version = fullCapacityBaselineVersion
	payload, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	path := fullCapacityBaselinePath(storage)
	return withDurableCapacityRecordLock(path, func() error {
		return durableAtomicWriteFile(path, append(payload, '\n'), 0600)
	})
}

func chainHasNoFullCapacityBaseline(status CapacityProofEpochStatus) (bool, error) {
	values := []uint64{status.LastCapacityProofAt, status.CapacityProofSequence,
		status.ProvedBackingBytes, status.CheckpointProofAt}
	zero := 0
	for _, value := range values {
		if value == 0 {
			zero++
		}
	}
	if zero == len(values) && status.CheckpointFreeBytes == 0 && status.CheckpointDataBytes == 0 {
		return true, nil
	}
	if zero != 0 {
		return false, fmt.Errorf("chain full-baseline checkpoint is internally inconsistent")
	}
	return false, nil
}

func evaluateFullCapacityBaseline(
	storage string, status CapacityProofEpochStatus, cfg ServerConfig,
) (fullBaselineEvaluation, error) {
	if cfg.CapacityBytes <= 0 || uint64(cfg.CapacityBytes) != status.DeclaredCapacityBytes {
		return fullBaselineEvaluation{}, fmt.Errorf(
			"configured and chain-declared capacity disagree")
	}
	baseline, found, err := readFullCapacityBaseline(storage)
	if err != nil {
		return fullBaselineEvaluation{}, err
	}
	chainEmpty, err := chainHasNoFullCapacityBaseline(status)
	if err != nil {
		return fullBaselineEvaluation{}, err
	}
	if !found {
		if chainEmpty {
			return fullBaselineEvaluation{Initial: true, Detail: "chain has no completed full baseline"}, nil
		}
		return fullBaselineEvaluation{}, fmt.Errorf(
			"local full capacity baseline is missing while chain has a completed baseline")
	}
	if chainEmpty {
		return fullBaselineEvaluation{}, fmt.Errorf(
			"local full capacity baseline exists while chain has no completed baseline")
	}
	chainID, contract, vk, err := capacityBaselineBinding(cfg)
	if err != nil {
		return fullBaselineEvaluation{}, err
	}
	if baseline.ChainID != chainID || baseline.CapacityProofContract != contract ||
		baseline.VKAddress != vk {
		return fullBaselineEvaluation{}, fmt.Errorf("full capacity baseline binding mismatch")
	}
	if baseline.CapacityProofSequence != status.CapacityProofSequence ||
		baseline.CompletedFullEpochID > status.ProofEpochID ||
		baseline.DeclaredCapacityBytes != status.ProvedBackingBytes {
		return fullBaselineEvaluation{}, fmt.Errorf("local and chain full-baseline provenance disagree")
	}
	if status.CheckpointFreeBytes > math.MaxUint64-status.CheckpointDataBytes {
		return fullBaselineEvaluation{}, fmt.Errorf("chain checkpoint byte total overflows")
	}
	checkpointBytes := status.CheckpointFreeBytes + status.CheckpointDataBytes
	if checkpointBytes < status.ProvedBackingBytes || status.CheckpointProofAt != status.LastCapacityProofAt {
		return fullBaselineEvaluation{}, fmt.Errorf("chain full-baseline checkpoint is ambiguous")
	}
	maxCheckpointBytes := uint64(math.MaxUint64)
	if status.MaxManifestOverheadBytes <= math.MaxUint64-status.ProvedBackingBytes {
		maxCheckpointBytes = status.ProvedBackingBytes + status.MaxManifestOverheadBytes
	}
	if checkpointBytes > maxCheckpointBytes {
		return fullBaselineEvaluation{}, fmt.Errorf("chain full-baseline checkpoint exceeds proof bounds")
	}
	layout, err := currentCapacityLayoutFingerprint(storage, cfg)
	if err != nil {
		return fullBaselineEvaluation{}, err
	}
	rebuild := baseline.DeclaredCapacityBytes != status.DeclaredCapacityBytes ||
		baseline.CapacityLayoutFingerprint != layout
	detail := "declared capacity and physical layout match the last completed full baseline"
	if rebuild {
		detail = "declared capacity or physical layout differs from the last completed full baseline"
	}
	return fullBaselineEvaluation{Rebuild: rebuild, Detail: detail}, nil
}

func newFullCapacityBaselineCandidate(
	storage string, cfg ServerConfig, status CapacityProofEpochStatus, epochID uint64,
) (*fullCapacityBaselineCandidate, error) {
	if cfg.CapacityBytes <= 0 || uint64(cfg.CapacityBytes) != status.DeclaredCapacityBytes {
		return nil, fmt.Errorf("configured and chain-declared capacity disagree")
	}
	chainID, contract, vk, err := capacityBaselineBinding(cfg)
	if err != nil {
		return nil, err
	}
	layout, err := currentCapacityLayoutFingerprint(storage, cfg)
	if err != nil {
		return nil, err
	}
	return &fullCapacityBaselineCandidate{
		ChainID: chainID, CapacityProofContract: contract, VKAddress: vk,
		DeclaredCapacityBytes:     status.DeclaredCapacityBytes,
		CapacityLayoutFingerprint: layout, CompletedFullEpochID: epochID,
		ProofSequenceBefore: status.CapacityProofSequence,
	}, nil
}

func commitCompletedFullCapacityBaseline(
	storage string, journal capacityEpochJournal, status CapacityProofEpochStatus,
) error {
	candidate := journal.FullBaselineCandidate
	if candidate == nil || journal.State != capacityEpochStateCompleted {
		return nil
	}
	if status.Active || status.Invalidated || status.ProofEpochID != candidate.CompletedFullEpochID ||
		status.CapacityProofSequence <= candidate.ProofSequenceBefore ||
		status.ProvedBackingBytes != candidate.DeclaredCapacityBytes ||
		status.CheckpointProofAt == 0 || status.CheckpointProofAt != status.LastCapacityProofAt {
		return fmt.Errorf("completed full epoch lacks an exact authoritative chain checkpoint")
	}
	if status.CheckpointFreeBytes > math.MaxUint64-status.CheckpointDataBytes ||
		status.CheckpointFreeBytes+status.CheckpointDataBytes < candidate.DeclaredCapacityBytes {
		return fmt.Errorf("completed full epoch checkpoint bytes are invalid")
	}
	return writeFullCapacityBaseline(storage, FullCapacityBaseline{
		ChainID: candidate.ChainID, CapacityProofContract: candidate.CapacityProofContract,
		VKAddress: candidate.VKAddress, DeclaredCapacityBytes: candidate.DeclaredCapacityBytes,
		CapacityLayoutFingerprint: candidate.CapacityLayoutFingerprint,
		CompletedFullEpochID:      candidate.CompletedFullEpochID,
		CapacityProofSequence:     status.CapacityProofSequence,
		CompletedAtUnix:           status.CheckpointProofAt,
	})
}
