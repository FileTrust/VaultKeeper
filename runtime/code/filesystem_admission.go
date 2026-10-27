package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const hostFilesystemReservationVersion = 1
const guardedUploadChunkBytes int64 = 8 * 1024 * 1024

// filesystemAdmissionCapacity is physical, host-wide capacity. Logical VK
// capacity is accounted separately by CapacityProofSC and the local lifecycle
// journals.
type filesystemAdmissionCapacity struct {
	AvailableBytes              int64
	WorkspaceReserve            int64
	OutstandingReservationBytes int64
	AllocatableBytes            int64
}

// A host reservation contains only a random protocol commitment and resource
// bounds. It never stores a DO, requester, file ID, piece root, or peer mapping.
type hostFilesystemReservation struct {
	Version                int    `json:"version"`
	Key                    string `json:"key"`
	Device                 uint64 `json:"device"`
	ChainID                int64  `json:"chainId"`
	CapacityProofContract  string `json:"capacityProofContract"`
	RegistrationCommitment string `json:"registrationCommitment"`
	ReservedBytes          int64  `json:"reservedBytes"`
	MaterializedBytes      int64  `json:"materializedBytes"`
	ExpiresAt              int64  `json:"expiresAt"`
	UpdatedAt              string `json:"updatedAt"`
}

type hostFilesystemProfile struct {
	Version          int    `json:"version"`
	Key              string `json:"key"`
	Device           uint64 `json:"device"`
	WorkspaceReserve int64  `json:"workspaceReserve"`
}

func filesystemStats(path string) (available int64, device uint64, err error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return 0, 0, err
	}
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(path, &statfs); err != nil {
		return 0, 0, err
	}
	bytes := new(big.Int).Mul(
		new(big.Int).SetUint64(statfs.Bavail),
		new(big.Int).SetUint64(uint64(statfs.Bsize)),
	)
	if bytes.IsInt64() {
		available = bytes.Int64()
	} else {
		available = math.MaxInt64
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	raw, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("filesystem device identity is unavailable")
	}
	return available, uint64(raw.Dev), nil
}

func filesystemAvailableBytes(path string) (int64, error) {
	available, _, err := filesystemStats(path)
	return available, err
}

func hostFilesystemAdmissionLockPath(storage string) string {
	if proofLock := strings.TrimSpace(os.Getenv(proofHostLockPathEnv)); proofLock != "" {
		return proofLock + ".filesystem-admission"
	}
	absStorage, err := filepath.Abs(storage)
	if err != nil {
		absStorage = storage
	}
	return filepath.Join(filepath.Dir(absStorage), ".filetrust-filesystem-admission.lock")
}

func hostFilesystemReservationDir(storage string) string {
	return hostFilesystemAdmissionLockPath(storage) + ".reservations"
}

func hostFilesystemProfileDir(storage string) string {
	return hostFilesystemAdmissionLockPath(storage) + ".profiles"
}

func hostFilesystemKey(storage, transferID string) string {
	absStorage, err := filepath.Abs(storage)
	if err != nil {
		absStorage = storage
	}
	sum := sha256.Sum256([]byte(filepath.Clean(absStorage) + "\x00" + transferID))
	return hex.EncodeToString(sum[:])
}

func hostFilesystemReservationPath(storage, transferID string) string {
	return filepath.Join(
		hostFilesystemReservationDir(storage),
		hostFilesystemKey(storage, transferID)+".json",
	)
}

func normalizedNonzeroAddress(value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if !common.IsHexAddress(value) {
		return "", fmt.Errorf("%s is not a valid address", label)
	}
	address := common.HexToAddress(value)
	if address == (common.Address{}) {
		return "", fmt.Errorf("%s is the zero address", label)
	}
	return strings.ToLower(address.Hex()), nil
}

func normalizedNonzeroBytes32(value, label string) (string, error) {
	decoded, err := strictPartitionBytes32(value, label)
	if err != nil {
		return "", err
	}
	if decoded == ([32]byte{}) {
		return "", fmt.Errorf("%s is zero", label)
	}
	return "0x" + hex.EncodeToString(decoded[:]), nil
}

func validHostFilesystemReservationKey(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// validateHostFilesystemReservationRecord is the single trust boundary for
// the host-wide ledger. Every reader uses it so a corrupt, renamed, or
// cross-chain record closes admission instead of being ignored or counted
// under a different identity.
func validateHostFilesystemReservationRecord(
	record hostFilesystemReservation, expectedKey, fileName string,
) error {
	if record.Version != hostFilesystemReservationVersion {
		return fmt.Errorf("unsupported version %d", record.Version)
	}
	if !validHostFilesystemReservationKey(record.Key) {
		return fmt.Errorf("invalid reservation key")
	}
	if expectedKey != "" && record.Key != expectedKey {
		return fmt.Errorf("reservation key does not match transfer")
	}
	if fileName != "" && fileName != record.Key+".json" {
		return fmt.Errorf("reservation key does not match filename")
	}
	if record.Device == 0 || record.ChainID <= 0 {
		return fmt.Errorf("invalid filesystem device or chain ID")
	}
	if _, err := normalizedNonzeroAddress(record.CapacityProofContract, "capacity proof contract"); err != nil {
		return err
	}
	if _, err := normalizedNonzeroBytes32(record.RegistrationCommitment, "registration commitment"); err != nil {
		return err
	}
	if record.ReservedBytes <= 0 || record.MaterializedBytes < 0 ||
		record.MaterializedBytes > record.ReservedBytes || record.ExpiresAt <= 0 {
		return fmt.Errorf("invalid reservation byte or expiry bounds")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.UpdatedAt); err != nil {
		return fmt.Errorf("invalid update timestamp: %w", err)
	}
	return nil
}

func normalizedHostFilesystemBinding(
	cfg ServerConfig, record quoteReservationRecord,
) (capacityContract, registrationCommitment string, err error) {
	if cfg.ChainID <= 0 {
		return "", "", fmt.Errorf("host filesystem reservation chain ID is not configured")
	}
	if !validTransferID(record.TransferID) {
		return "", "", fmt.Errorf("host filesystem reservation transfer ID is invalid")
	}
	if record.ReservedCapacityBytes <= 0 || record.TransferDeadline <= 0 {
		return "", "", fmt.Errorf("host filesystem reservation bounds are invalid")
	}
	capacityContract, err = normalizedNonzeroAddress(cfg.CapacityProofContract, "configured capacity proof contract")
	if err != nil {
		return "", "", err
	}
	recordContract, err := normalizedNonzeroAddress(record.CapacityProofContract, "quote capacity proof contract")
	if err != nil {
		return "", "", err
	}
	if recordContract != capacityContract {
		return "", "", fmt.Errorf("quote is bound to a different capacity proof contract")
	}
	registrationCommitment, err = normalizedNonzeroBytes32(
		record.RegistrationCommitment, "registration commitment",
	)
	if err != nil {
		return "", "", err
	}
	return capacityContract, registrationCommitment, nil
}

func hostFilesystemProfilePath(storage string) string {
	return filepath.Join(
		hostFilesystemProfileDir(storage),
		hostFilesystemKey(storage, "profile")+".json",
	)
}

func withHostFilesystemAdmissionLock(storage string, fn func() error) error {
	lockPath := hostFilesystemAdmissionLockPath(storage)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return fmt.Errorf("create host filesystem admission directory: %w", err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open host filesystem admission lock: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire host filesystem admission lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) // best effort on return
	return fn()
}

// derivedFilesystemWorkspaceReserve is unsellable operational headroom. Heavy
// proof builds are serialized host-wide, so one largest known slot is enough;
// exact future upload growth is accounted by the durable reservation ledger.
func derivedFilesystemWorkspaceReserve(cfg ServerConfig) (int64, error) {
	if cfg.FilesystemReserveBytes > 0 {
		return cfg.FilesystemReserveBytes, nil
	}
	slotBytes, err := resolvedCapacitySlotSize(cfg)
	if err != nil {
		return 0, fmt.Errorf("derive proof workspace: %w", err)
	}
	if cfg.CapacityBytes > 0 && slotBytes > cfg.CapacityBytes {
		slotBytes = cfg.CapacityBytes
	}
	return slotBytes, nil
}

func ensureHostFilesystemProfileLocked(cfg ServerConfig, device uint64) error {
	reserve, err := derivedFilesystemWorkspaceReserve(cfg)
	if err != nil {
		return err
	}
	profile := hostFilesystemProfile{
		Version: hostFilesystemReservationVersion,
		Key:     hostFilesystemKey(cfg.Storage, "profile"), Device: device,
		WorkspaceReserve: reserve,
	}
	path := hostFilesystemProfilePath(cfg.Storage)
	if raw, readErr := os.ReadFile(path); readErr == nil {
		var existing hostFilesystemProfile
		if json.Unmarshal(raw, &existing) == nil && existing == profile {
			return nil
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	raw, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(path, raw, 0600)
}

func hostWorkspaceReserveLocked(storage string, device uint64) (int64, error) {
	entries, err := os.ReadDir(hostFilesystemProfileDir(storage))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var reserve int64
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(hostFilesystemProfileDir(storage), entry.Name()))
		if readErr != nil {
			return 0, readErr
		}
		var profile hostFilesystemProfile
		if json.Unmarshal(raw, &profile) != nil ||
			profile.Version != hostFilesystemReservationVersion ||
			profile.Key == "" || profile.Device == 0 || profile.WorkspaceReserve < 0 {
			return 0, fmt.Errorf("invalid host filesystem profile %s", entry.Name())
		}
		if profile.Device == device && profile.WorkspaceReserve > reserve {
			reserve = profile.WorkspaceReserve
		}
	}
	return reserve, nil
}

func loadHostFilesystemReservationLocked(storage, transferID string) (hostFilesystemReservation, bool, error) {
	var record hostFilesystemReservation
	key := hostFilesystemKey(storage, transferID)
	path := hostFilesystemReservationPath(storage, transferID)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, false, err
	}
	if err := validateHostFilesystemReservationRecord(record, key, filepath.Base(path)); err != nil {
		return record, false, fmt.Errorf("invalid durable host filesystem reservation: %w", err)
	}
	return record, true, nil
}

func persistHostFilesystemReservationLocked(storage string, record hostFilesystemReservation) error {
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(hostFilesystemReservationDir(storage), record.Key+".json")
	return durableAtomicWriteFile(path, raw, 0600)
}

func hostOutstandingReservationBytesLocked(storage string, device uint64, excludeKey string) (int64, error) {
	entries, err := os.ReadDir(hostFilesystemReservationDir(storage))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(hostFilesystemReservationDir(storage), entry.Name()))
		if readErr != nil {
			return 0, readErr
		}
		var record hostFilesystemReservation
		if err := json.Unmarshal(raw, &record); err != nil {
			return 0, fmt.Errorf("decode host filesystem reservation %s: %w", entry.Name(), err)
		}
		if err := validateHostFilesystemReservationRecord(record, "", entry.Name()); err != nil {
			return 0, fmt.Errorf("invalid host filesystem reservation %s: %w", entry.Name(), err)
		}
		if record.Device != device || record.Key == excludeKey {
			continue
		}
		remaining := record.ReservedBytes - record.MaterializedBytes
		if total > math.MaxInt64-remaining {
			return 0, fmt.Errorf("host filesystem reservation total overflow")
		}
		total += remaining
	}
	return total, nil
}

func filesystemAdmissionState(cfg ServerConfig) (state filesystemAdmissionCapacity, err error) {
	err = withHostFilesystemAdmissionLock(cfg.Storage, func() error {
		available, device, statErr := filesystemStats(cfg.Storage)
		if statErr != nil {
			return statErr
		}
		if err := ensureHostFilesystemProfileLocked(cfg, device); err != nil {
			return err
		}
		workspace, err := hostWorkspaceReserveLocked(cfg.Storage, device)
		if err != nil {
			return err
		}
		outstanding, err := hostOutstandingReservationBytesLocked(cfg.Storage, device, "")
		if err != nil {
			return err
		}
		allocatable := available - workspace - outstanding
		if allocatable < 0 {
			allocatable = 0
		}
		state = filesystemAdmissionCapacity{
			AvailableBytes: available, WorkspaceReserve: workspace,
			OutstandingReservationBytes: outstanding, AllocatableBytes: allocatable,
		}
		return nil
	})
	return state, err
}

func reserveHostFilesystemCapacity(cfg ServerConfig, record quoteReservationRecord) error {
	if cfg.CapacityBytes <= 0 {
		return nil
	}
	capacityContract, registrationCommitment, err := normalizedHostFilesystemBinding(cfg, record)
	if err != nil {
		return err
	}
	return withHostFilesystemAdmissionLock(cfg.Storage, func() error {
		available, device, err := filesystemStats(cfg.Storage)
		if err != nil {
			return err
		}
		if err := ensureHostFilesystemProfileLocked(cfg, device); err != nil {
			return err
		}
		if existing, found, loadErr := loadHostFilesystemReservationLocked(cfg.Storage, record.TransferID); loadErr != nil {
			return loadErr
		} else if found {
			if existing.Device != device || existing.ReservedBytes != record.ReservedCapacityBytes ||
				existing.ChainID != cfg.ChainID ||
				!strings.EqualFold(existing.CapacityProofContract, cfg.CapacityProofContract) ||
				!strings.EqualFold(existing.RegistrationCommitment, record.RegistrationCommitment) {
				return fmt.Errorf("transferId is already bound to a different host filesystem reservation")
			}
			return nil
		}
		workspace, err := hostWorkspaceReserveLocked(cfg.Storage, device)
		if err != nil {
			return err
		}
		key := hostFilesystemKey(cfg.Storage, record.TransferID)
		outstanding, err := hostOutstandingReservationBytesLocked(cfg.Storage, device, key)
		if err != nil {
			return err
		}
		allocatable := available - workspace - outstanding
		if record.ReservedCapacityBytes > allocatable {
			return fmt.Errorf(
				"insufficient physical capacity: available=%d workspaceReserve=%d hostReserved=%d allocatable=%d required=%d",
				available, workspace, outstanding, max64(0, allocatable), record.ReservedCapacityBytes,
			)
		}
		hostRecord := hostFilesystemReservation{
			Version: hostFilesystemReservationVersion, Key: key, Device: device,
			ChainID: cfg.ChainID, CapacityProofContract: capacityContract,
			RegistrationCommitment: registrationCommitment,
			ReservedBytes:          record.ReservedCapacityBytes, ExpiresAt: record.TransferDeadline,
			UpdatedAt: nowRFC3339(),
		}
		return persistHostFilesystemReservationLocked(cfg.Storage, hostRecord)
	})
}

// preserveHostFilesystemCapacity recreates a missing ledger entry only after
// CapacityProofSC has already confirmed the obligation. It may make host
// allocatable capacity zero, which is the required fail-closed result; it never
// rejects or silently forgets an obligation that already exists on-chain.
func preserveHostFilesystemCapacity(cfg ServerConfig, record quoteReservationRecord) error {
	if cfg.CapacityBytes <= 0 {
		return nil
	}
	capacityContract, registrationCommitment, err := normalizedHostFilesystemBinding(cfg, record)
	if err != nil {
		return err
	}
	return withHostFilesystemAdmissionLock(cfg.Storage, func() error {
		_, device, err := filesystemStats(cfg.Storage)
		if err != nil {
			return err
		}
		if err := ensureHostFilesystemProfileLocked(cfg, device); err != nil {
			return err
		}
		if existing, found, loadErr := loadHostFilesystemReservationLocked(cfg.Storage, record.TransferID); loadErr != nil {
			return loadErr
		} else if found {
			if existing.Device != device || existing.ReservedBytes != record.ReservedCapacityBytes ||
				existing.ChainID != cfg.ChainID ||
				!strings.EqualFold(existing.CapacityProofContract, cfg.CapacityProofContract) ||
				!strings.EqualFold(existing.RegistrationCommitment, record.RegistrationCommitment) {
				return fmt.Errorf("conflicting authoritative host filesystem reservation")
			}
			return nil
		}
		materialized := fileSizeIfExists(transferPartialPath(cfg.Storage, record.TransferID))
		if materialized > record.ReservedCapacityBytes {
			materialized = record.ReservedCapacityBytes
		}
		hostRecord := hostFilesystemReservation{
			Version: hostFilesystemReservationVersion,
			Key:     hostFilesystemKey(cfg.Storage, record.TransferID), Device: device,
			ChainID: cfg.ChainID, CapacityProofContract: capacityContract,
			RegistrationCommitment: registrationCommitment,
			ReservedBytes:          record.ReservedCapacityBytes, MaterializedBytes: materialized,
			ExpiresAt: record.TransferDeadline, UpdatedAt: nowRFC3339(),
		}
		return persistHostFilesystemReservationLocked(cfg.Storage, hostRecord)
	})
}

// syncHostFilesystemReservationMaterialized converts future reserved growth
// into bytes already present on disk. Statfs falls as the file grows while this
// amount rises, keeping host-wide allocatable capacity accurate.
func syncHostFilesystemReservationMaterialized(cfg ServerConfig, transferID string, materialized int64) error {
	if cfg.CapacityBytes <= 0 {
		return nil
	}
	return withHostFilesystemAdmissionLock(cfg.Storage, func() error {
		record, found, err := loadHostFilesystemReservationLocked(cfg.Storage, transferID)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("durable host filesystem reservation is missing")
		}
		if materialized < 0 || materialized > record.ReservedBytes {
			return fmt.Errorf("invalid materialized upload size %d", materialized)
		}
		available, device, err := filesystemStats(cfg.Storage)
		if err != nil {
			return err
		}
		if record.Device != device {
			return fmt.Errorf("host filesystem reservation moved to a different device")
		}
		if err := ensureHostFilesystemProfileLocked(cfg, device); err != nil {
			return err
		}
		workspace, err := hostWorkspaceReserveLocked(cfg.Storage, device)
		if err != nil {
			return err
		}
		others, err := hostOutstandingReservationBytesLocked(cfg.Storage, device, record.Key)
		if err != nil {
			return err
		}
		future := record.ReservedBytes - materialized
		if available < workspace || future > available-workspace-others {
			return fmt.Errorf(
				"physical filesystem safety reserve exhausted: available=%d workspaceReserve=%d hostReserved=%d futureTransferBytes=%d",
				available, workspace, others, future,
			)
		}
		if record.MaterializedBytes == materialized {
			// The authoritative Statfs + ledger invariant was still checked above;
			// avoid an unnecessary durable rewrite for a probe at the same offset.
			return nil
		}
		record.MaterializedBytes = materialized
		record.UpdatedAt = nowRFC3339()
		return persistHostFilesystemReservationLocked(cfg.Storage, record)
	})
}

// copyNWithHostFilesystemReservation grows a partial upload in bounded quanta.
// Before every quantum, all local VK processes agree on the same host ledger;
// after it, the newly materialized bytes are checkpointed durably. A storage
// registration is never attempted if this guard fails.
func copyNWithHostFilesystemReservation(
	cfg ServerConfig, transferID string, dst io.Writer, src io.Reader, offset, remaining int64,
) (int64, error) {
	if cfg.CapacityBytes <= 0 {
		return io.CopyN(dst, src, remaining)
	}
	if err := syncHostFilesystemReservationMaterialized(cfg, transferID, offset); err != nil {
		return 0, err
	}
	var copied int64
	for copied < remaining {
		if err := syncHostFilesystemReservationMaterialized(cfg, transferID, offset+copied); err != nil {
			return copied, err
		}
		chunk := remaining - copied
		if chunk > guardedUploadChunkBytes {
			chunk = guardedUploadChunkBytes
		}
		n, copyErr := io.CopyN(dst, src, chunk)
		copied += n
		if syncErr := syncHostFilesystemReservationMaterialized(cfg, transferID, offset+copied); syncErr != nil {
			return copied, syncErr
		}
		if copyErr != nil {
			return copied, copyErr
		}
	}
	return copied, nil
}

func releaseHostFilesystemCapacity(storage, transferID string) error {
	return withHostFilesystemAdmissionLock(storage, func() error {
		path := hostFilesystemReservationPath(storage, transferID)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		dir, err := os.Open(filepath.Dir(path))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
}

func snapshotHostFilesystemReservations(storage string) (records []hostFilesystemReservation, err error) {
	err = withHostFilesystemAdmissionLock(storage, func() error {
		entries, readErr := os.ReadDir(hostFilesystemReservationDir(storage))
		if os.IsNotExist(readErr) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			raw, readErr := os.ReadFile(filepath.Join(hostFilesystemReservationDir(storage), entry.Name()))
			if readErr != nil {
				return readErr
			}
			var record hostFilesystemReservation
			if err := json.Unmarshal(raw, &record); err != nil {
				return fmt.Errorf("decode host filesystem reservation %s: %w", entry.Name(), err)
			}
			if err := validateHostFilesystemReservationRecord(record, "", entry.Name()); err != nil {
				return fmt.Errorf("invalid host filesystem reservation %s: %w", entry.Name(), err)
			}
			records = append(records, record)
		}
		return nil
	})
	return records, err
}

func releaseHostFilesystemReservationRecord(storage string, expected hostFilesystemReservation) error {
	return withHostFilesystemAdmissionLock(storage, func() error {
		path := filepath.Join(hostFilesystemReservationDir(storage), expected.Key+".json")
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var current hostFilesystemReservation
		if err := json.Unmarshal(raw, &current); err != nil {
			return err
		}
		// Never remove a reservation that changed while its chain state was read.
		if current.Key != expected.Key || current.RegistrationCommitment != expected.RegistrationCommitment ||
			current.ExpiresAt != expected.ExpiresAt || current.UpdatedAt != expected.UpdatedAt {
			return nil
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		dir, err := os.Open(filepath.Dir(path))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	})
}

// reconcileHostFilesystemReservations is the crash/disappeared-VK safety net.
// It never trusts host time and never releases on RPC uncertainty. A record is
// considered only after authoritative chain time passed its complete signed
// transfer window, then only a terminal/absent CapacityProof state can remove it.
func reconcileHostFilesystemReservations(cfg ServerConfig, chainNow int64) {
	records, err := snapshotHostFilesystemReservations(cfg.Storage)
	if err != nil {
		log.Printf("[filesystem-admission] shared reservation ledger unreadable; preserving all entries: %v", err)
		return
	}
	for _, record := range records {
		if record.ChainID != cfg.ChainID ||
			!strings.EqualFold(record.CapacityProofContract, cfg.CapacityProofContract) ||
			chainNow <= record.ExpiresAt {
			continue
		}
		chain, readErr := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
		if readErr != nil {
			log.Printf("[filesystem-admission] RPC uncertain; preserving host reservation key=%s: %v", truncate(record.Key, 16), readErr)
			continue
		}
		releasable := false
		switch chain.State {
		case capacityQuoteNone, capacityQuoteStored, capacityQuoteDeletionPending,
			capacityQuoteReleased, capacityQuoteExpired:
			releasable = true
		case capacityQuoteQuoted, capacityQuoteActiveTransfer:
			if chainNow <= int64(chain.ExpiresAt) {
				continue
			}
			if err := expireCapacityQuoteOnChain(cfg, record.RegistrationCommitment); err != nil {
				log.Printf("[filesystem-admission] authoritative expiry failed; preserving key=%s: %v", truncate(record.Key, 16), err)
				continue
			}
			releasable = true
		}
		if releasable {
			if err := releaseHostFilesystemReservationRecord(cfg.Storage, record); err != nil {
				log.Printf("[filesystem-admission] terminal reservation release failed key=%s: %v", truncate(record.Key, 16), err)
			}
		}
	}
}

func ensureFilesystemCapacityForNewObligation(cfg ServerConfig, requiredBytes int64) error {
	if cfg.CapacityBytes <= 0 {
		return nil
	}
	state, err := filesystemAdmissionState(cfg)
	if err != nil {
		return fmt.Errorf("filesystem capacity safety unavailable: %w", err)
	}
	if requiredBytes > state.AllocatableBytes {
		return fmt.Errorf(
			"insufficient physical capacity: available=%d workspaceReserve=%d hostReserved=%d allocatable=%d required=%d",
			state.AvailableBytes, state.WorkspaceReserve, state.OutstandingReservationBytes,
			state.AllocatableBytes, requiredBytes,
		)
	}
	return nil
}
