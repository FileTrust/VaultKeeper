package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const transferRecordVersion = 1

var transferStateMu sync.Mutex

type storeTransferRecord struct {
	Version                int        `json:"version"`
	TransferID             string     `json:"transferId"`
	BindingHash            string     `json:"bindingHash"`
	Status                 string     `json:"status"`
	ReservedCapacityBytes  int64      `json:"reservedCapacityBytes,omitempty"`
	PaymentCommitment      string     `json:"paymentCommitment,omitempty"`
	RegistrationCommitment string     `json:"registrationCommitment,omitempty"`
	RegistrationDeadline   int64      `json:"registrationDeadline,omitempty"`
	CreatedAt              string     `json:"createdAt"`
	UpdatedAt              string     `json:"updatedAt"`
	CompletedStore         *StoreResp `json:"completedStore,omitempty"`
}

func persistStoreTransferRegistration(storage string, req StoreReq, creds PaymentCredentials) error {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	record, exists, err := loadStoreTransferRecord(storage, req.TransferID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("resumable transfer state is missing")
	}
	binding, err := storeTransferBindingHash(req)
	if err != nil {
		return err
	}
	if record.Version != transferRecordVersion || record.BindingHash != binding {
		return fmt.Errorf("transferId is already bound to different immutable transfer metadata")
	}
	record.PaymentCommitment = strings.ToLower(creds.PaymentCommitment)
	record.RegistrationCommitment = strings.ToLower(creds.RegistrationCommitment)
	record.RegistrationDeadline = creds.RegistrationDeadline
	record.UpdatedAt = nowRFC3339()
	return persistStoreTransferRecord(storage, record)
}

func removeExpiredStoreTransferReservations(storage string, creds PaymentCredentials) int {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	entries, err := os.ReadDir(transferStateDir(storage))
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(transferStateDir(storage), entry.Name())
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		var record storeTransferRecord
		if json.Unmarshal(raw, &record) != nil || record.Status != "partial" {
			continue
		}
		paymentMatch := creds.PaymentCommitment != "" && strings.EqualFold(
			record.PaymentCommitment, creds.PaymentCommitment,
		)
		registrationMatch := creds.RegistrationCommitment != "" && strings.EqualFold(
			record.RegistrationCommitment, creds.RegistrationCommitment,
		)
		if !paymentMatch && !registrationMatch {
			continue
		}
		_ = os.Remove(transferPartialPath(storage, record.TransferID))
		if os.Remove(path) == nil {
			removed++
		}
	}
	return removed
}

type transferMetrics struct {
	ActiveUploads          int    `json:"activeUploads"`
	ActiveDownloads        int    `json:"activeDownloads"`
	ActiveDeletes          int    `json:"activeDeletes"`
	QueuedTransfers        int    `json:"queuedTransfers"`
	BusyResponses          uint64 `json:"busyResponses"`
	AcceptedTransfers      uint64 `json:"acceptedTransfers"`
	MaxUploads             int    `json:"maxUploads"`
	MaxDownloads           int    `json:"maxDownloads"`
	MaxQueued              int    `json:"maxQueued"`
	MaxPerPeer             int    `json:"maxPerPeer"`
	MaxTemporaryBytes      int64  `json:"maxTemporaryUploadBytes"`
	PartialUploadBytes     int64  `json:"partialUploadBytes"`
	TemporaryBytesReserved int64  `json:"temporaryUploadBytesReserved"`
	ProofWorkActive        bool   `json:"proofWorkActive"`
}

type transferAdmissionController struct {
	mu                sync.Mutex
	storage           string
	maxUploads        int
	maxDeletes        int
	maxDownloads      int
	maxQueued         int
	maxPerPeer        int
	maxTemporaryBytes int64
	queueWait         time.Duration
	retryAfterSeconds int64
	activeUploads     int
	activeDownloads   int
	activeDeletes     int
	queued            int
	peerActive        map[string]int
	activeUploadPaths map[string]int64
	busyResponses     uint64
	acceptedTransfers uint64
	proofStateChecked time.Time
	proofStateActive  bool
}

type transferLease struct {
	controller *transferAdmissionController
	kind       string
	identity   string
	uploadPath string
	activity   *foregroundActivityLease
	once       sync.Once
}

func resolvedMaxTemporaryUploadBytes(cfg ServerConfig) int64 {
	if cfg.MaxTemporaryUploadBytes > 0 {
		return cfg.MaxTemporaryUploadBytes
	}
	perUploadLimit := cfg.MaxPieceSizeBytes
	if perUploadLimit <= 0 && cfg.ZKBlockSize > 0 && cfg.ZKTreeDepth >= 0 && cfg.ZKTreeDepth < 63 {
		if cfg.ZKBlockSize <= int64(^uint64(0)>>1)>>cfg.ZKTreeDepth {
			perUploadLimit = cfg.ZKBlockSize << cfg.ZKTreeDepth
		}
	}
	derivedLimit := int64(0)
	if perUploadLimit > 0 {
		uploads := int64(max(1, cfg.MaxConcurrentUploads))
		if perUploadLimit <= int64(^uint64(0)>>1)/uploads {
			derivedLimit = perUploadLimit * uploads
		}
	}
	if cfg.CapacityBytes > 0 && (derivedLimit <= 0 || cfg.CapacityBytes < derivedLimit) {
		return cfg.CapacityBytes
	}
	if derivedLimit > 0 {
		return derivedLimit
	}
	return 4 * 1024 * 1024 * 1024
}

func newTransferAdmissionController(storage string, cfg ServerConfig) *transferAdmissionController {
	return &transferAdmissionController{
		storage:           storage,
		maxUploads:        max(1, cfg.MaxConcurrentUploads),
		maxDownloads:      max(1, cfg.MaxConcurrentDownloads),
		maxQueued:         max(0, cfg.MaxQueuedTransfers),
		maxPerPeer:        max(1, cfg.MaxTransfersPerPeer),
		maxTemporaryBytes: resolvedMaxTemporaryUploadBytes(cfg),
		queueWait:         time.Duration(max64(0, cfg.TransferQueueWaitSeconds)) * time.Second,
		retryAfterSeconds: max64(1, cfg.TransferRetryAfterSeconds),
		peerActive:        make(map[string]int),
		activeUploadPaths: make(map[string]int64),
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func transferIdentity(wallet, peerID string) string {
	if strings.TrimSpace(wallet) != "" {
		return "wallet:" + strings.ToLower(strings.TrimSpace(wallet))
	}
	return "peer:" + strings.TrimSpace(peerID)
}

func (c *transferAdmissionController) effectiveLimit(kind string) int {
	switch kind {
	case "upload":
		return c.maxUploads
	case "delete":
		// E.2: background deletion processing has its own RESERVED budget. It is not shared
		// with uploads, so upload saturation can never consume the delete-processing floor.
		return c.deleteProcessingLimit()
	}
	return c.maxDownloads
}

// deleteProcessingLimit is the guaranteed delete-processing floor, independent of uploads.
func (c *transferAdmissionController) deleteProcessingLimit() int {
	if c.maxDeletes > 0 {
		return c.maxDeletes
	}
	limit := c.maxUploads / 2
	if limit < 1 {
		limit = 1
	}
	return limit
}

func (c *transferAdmissionController) proofActiveLocked() bool {
	if time.Since(c.proofStateChecked) >= 250*time.Millisecond {
		c.proofStateActive = proofWorkActive()
		c.proofStateChecked = time.Now()
	}
	return c.proofStateActive
}

func (c *transferAdmissionController) activeForKind(kind string) int {
	// E.2: upload and delete processing are accounted SEPARATELY. Sharing one counter let a
	// saturated upload workload consume the whole write-side budget and starve deletion
	// processing, which must retain a guaranteed floor of its own.
	switch kind {
	case "upload":
		return c.activeUploads
	case "delete":
		return c.activeDeletes
	}
	return c.activeDownloads
}

func (c *transferAdmissionController) inactivePartialBytesLocked() int64 {
	tmp := tmpDir(c.storage)
	var total int64
	_ = filepath.WalkDir(tmp, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".part") {
			return nil
		}
		if _, active := c.activeUploadPaths[path]; active {
			return nil
		}
		if info, statErr := entry.Info(); statErr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func (c *transferAdmissionController) canAdmitLocked(kind, identity, uploadPath string, uploadSize int64) bool {
	if c.activeForKind(kind) >= c.effectiveLimit(kind) || c.peerActive[identity] >= c.maxPerPeer {
		return false
	}
	if kind == "upload" && c.maxTemporaryBytes > 0 {
		reserved := int64(0)
		for _, size := range c.activeUploadPaths {
			reserved += size
		}
		if uploadPath != "" {
			if _, exists := c.activeUploadPaths[uploadPath]; exists {
				return false
			}
		}
		// inactivePartialBytesLocked includes this transfer's existing partial
		// file. Reserve only the bytes needed to grow it to the declared size.
		remaining := uploadSize - fileSizeIfExists(uploadPath)
		if remaining < 0 {
			return false
		}
		if c.inactivePartialBytesLocked()+reserved+remaining > c.maxTemporaryBytes {
			return false
		}
	}
	return true
}

func (c *transferAdmissionController) acquire(kind, identity, uploadPath string, uploadSize int64) (*transferLease, int64, error) {
	deadline := time.Now().Add(c.queueWait)
	queued := false
	for {
		c.mu.Lock()
		if c.canAdmitLocked(kind, identity, uploadPath, uploadSize) {
			if queued {
				c.queued--
			}
			if kind == "upload" {
				c.activeUploads++
				if uploadPath != "" {
					c.activeUploadPaths[uploadPath] = uploadSize
				}
			} else if kind == "delete" {
				c.activeDeletes++
			} else {
				c.activeDownloads++
			}
			c.peerActive[identity]++
			c.acceptedTransfers++
			c.mu.Unlock()
			return &transferLease{
				controller: c, kind: kind, identity: identity, uploadPath: uploadPath,
				activity: beginForegroundActivity(kind),
			}, 0, nil
		}
		if !queued {
			// E.2: a deletion is durably accepted and queued BEFORE this point, so a full
			// delete-processing budget may only DELAY background work — never turn it away.
			if c.queued >= c.maxQueued && kind != "delete" {
				c.busyResponses++
				retry := c.retryAfterSeconds
				c.mu.Unlock()
				return nil, retry, fmt.Errorf("transfer admission queue is full")
			}
			c.queued++
			queued = true
		}
		// E.2: an accepted deletion waits for its reserved permit instead of being turned away.
		// Its journal entry is already durable, so returning Busy here would abandon queued
		// deletion work that must still be processed.
		if kind != "delete" && (c.queueWait == 0 || !time.Now().Before(deadline)) {
			c.queued--
			c.busyResponses++
			retry := c.retryAfterSeconds
			c.mu.Unlock()
			return nil, retry, fmt.Errorf("transfer resources are busy")
		}
		c.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
}

func (l *transferLease) Release() {
	if l == nil || l.controller == nil {
		return
	}
	l.once.Do(func() {
		c := l.controller
		c.mu.Lock()
		if l.kind == "upload" {
			if c.activeUploads > 0 {
				c.activeUploads--
			}
			delete(c.activeUploadPaths, l.uploadPath)
		} else if l.kind == "delete" {
			if c.activeDeletes > 0 {
				c.activeDeletes--
			}
		} else if c.activeDownloads > 0 {
			c.activeDownloads--
		}
		if c.peerActive[l.identity] <= 1 {
			delete(c.peerActive, l.identity)
		} else {
			c.peerActive[l.identity]--
		}
		c.mu.Unlock()
		l.activity.Release()
	})
}

func (c *transferAdmissionController) snapshot() transferMetrics {
	c.mu.Lock()
	defer c.mu.Unlock()
	partialBytes := c.inactivePartialBytesLocked()
	reservedBytes := partialBytes
	for path, size := range c.activeUploadPaths {
		partialBytes += fileSizeIfExists(path)
		reservedBytes += size
	}
	return transferMetrics{
		ActiveUploads: c.activeUploads, ActiveDownloads: c.activeDownloads,
		ActiveDeletes:   c.activeDeletes,
		QueuedTransfers: c.queued, BusyResponses: c.busyResponses,
		AcceptedTransfers: c.acceptedTransfers, MaxUploads: c.maxUploads,
		MaxDownloads: c.maxDownloads, MaxQueued: c.maxQueued, MaxPerPeer: c.maxPerPeer,
		MaxTemporaryBytes: c.maxTemporaryBytes, PartialUploadBytes: partialBytes,
		TemporaryBytesReserved: reservedBytes,
		ProofWorkActive:        c.proofActiveLocked(),
	}
}

func validTransferID(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func transferStateDir(storage string) string {
	return filepath.Join(storage, "transfer-state")
}

func transferStatePath(storage, transferID string) string {
	return filepath.Join(transferStateDir(storage), safeID(transferID)+".json")
}

func transferPartialPath(storage, transferID string) string {
	return filepath.Join(tmpDir(storage), "transfer-"+safeID(transferID)+".part")
}

func storeTransferBindingHash(req StoreReq) (string, error) {
	binding := struct {
		TransferID             string `json:"transferId"`
		FileID                 string `json:"fileId"`
		Name                   string `json:"name"`
		PieceIndex             int    `json:"pieceIndex"`
		Size                   int64  `json:"size"`
		ServiceEnd             int64  `json:"serviceEnd"`
		CommitmentNonce        string `json:"commitmentNonce"`
		PaymentCommitment      string `json:"paymentCommitment"`
		DeletionAuthHash       string `json:"deletionAuthHash"`
		FileFormat             string `json:"fileFormat"`
		Uploader               string `json:"uploader"`
		ExpectedPieceRoot      string `json:"expectedPieceRoot"`
		ExpectedPieceBlockSize int64  `json:"expectedPieceBlockSize"`
	}{
		TransferID: req.TransferID, FileID: normalizeFileID(req.FileID),
		Name: filepath.Base(req.Name), PieceIndex: req.PieceIndex, Size: req.Size,
		ServiceEnd: req.ServiceEnd, CommitmentNonce: strings.ToLower(req.CommitmentNonce),
		PaymentCommitment: strings.ToLower(req.PaymentCommitment),
		DeletionAuthHash:  strings.ToLower(req.DeletionAuthHash), FileFormat: req.FileFormat,
		Uploader:               strings.ToLower(req.Uploader),
		ExpectedPieceRoot:      strings.ToLower(req.ExpectedPieceRoot),
		ExpectedPieceBlockSize: req.ExpectedPieceBlockSize,
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func loadStoreTransferRecord(storage, transferID string) (storeTransferRecord, bool, error) {
	var record storeTransferRecord
	raw, err := os.ReadFile(transferStatePath(storage, transferID))
	if os.IsNotExist(err) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, false, err
	}
	return record, true, nil
}

func persistStoreTransferRecord(storage string, record storeTransferRecord) error {
	if err := os.MkdirAll(transferStateDir(storage), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(transferStatePath(storage, record.TransferID), raw, 0600)
}

func reservedStoreTransferCapacityBytesLocked(storage, excludeTransferID string) int64 {
	entries, err := os.ReadDir(transferStateDir(storage))
	if err != nil {
		return 0
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(transferStateDir(storage), entry.Name()))
		if readErr != nil {
			continue
		}
		var record storeTransferRecord
		if json.Unmarshal(raw, &record) != nil || record.Status != "partial" ||
			record.TransferID == excludeTransferID || record.ReservedCapacityBytes <= 0 {
			continue
		}
		if record.ReservedCapacityBytes > int64(^uint64(0)>>1)-total {
			return int64(^uint64(0) >> 1)
		}
		total += record.ReservedCapacityBytes
	}
	return total
}

func ensureCapacityAvailableForUnreservedPiece(storage string, totalCapacityBytes, pieceSize, zkBlockSize int64) error {
	if totalCapacityBytes <= 0 {
		return nil
	}
	accounting, err := computeCapacityAccounting(storage, totalCapacityBytes)
	if err != nil {
		return err
	}
	transferStateMu.Lock()
	reserved, reservationErr := reservedAdmissionCapacityBytesLocked(storage, "", "", "")
	transferStateMu.Unlock()
	if reservationErr != nil {
		return fmt.Errorf("read durable capacity reservations: %w", reservationErr)
	}
	required := capacityBytesRequiredForPiece(pieceSize, zkBlockSize)
	if accounting.UsedBytes+reserved+required > totalCapacityBytes {
		return fmt.Errorf(
			"insufficient unreserved capacity: used=%d reserved=%d required=%d declared=%d",
			accounting.UsedBytes, reserved, required, totalCapacityBytes,
		)
	}
	return nil
}

// ensureAdmissionCapacityAvailableForUnreservedPiece treats the configured
// margin as an admission close threshold. If current unreserved free capacity
// is above the threshold, one piece that physically fits may cross it. The
// resulting durable reservation closes admission to every later new store.
// Resumes use the separate hard-cap check against their existing reservation.
func ensureAdmissionCapacityAvailableForUnreservedPiece(
	storage string, totalCapacityBytes, pieceSize, zkBlockSize, marginBytes int64,
) error {
	if totalCapacityBytes <= 0 {
		return nil
	}
	accounting, err := computeCapacityAccounting(storage, totalCapacityBytes)
	if err != nil {
		return err
	}
	transferStateMu.Lock()
	reserved, reservationErr := reservedAdmissionCapacityBytesLocked(storage, "", "", "")
	transferStateMu.Unlock()
	if reservationErr != nil {
		return fmt.Errorf("read durable capacity reservations: %w", reservationErr)
	}
	required := capacityBytesRequiredForPiece(pieceSize, zkBlockSize)
	if marginBytes < 0 {
		marginBytes = 0
	}
	free := totalCapacityBytes - accounting.UsedBytes - reserved
	if free <= marginBytes {
		return fmt.Errorf(
			"admission closed: used=%d reserved=%d required=%d margin=%d declared=%d",
			accounting.UsedBytes, reserved, required, marginBytes, totalCapacityBytes,
		)
	}
	if required > free {
		return fmt.Errorf(
			"insufficient unreserved capacity: used=%d reserved=%d required=%d declared=%d",
			accounting.UsedBytes, reserved, required, totalCapacityBytes,
		)
	}
	return nil
}

// reserveStoreTransferCapacity persists admission for a resumable upload. The
// caller holds storeCapacityMu, making sector accounting and all reservations a
// single admission decision. Existing reservations are idempotent on resume.
func reserveStoreTransferCapacity(storage string, req StoreReq, totalCapacityBytes, zkBlockSize, marginBytes int64) error {
	if totalCapacityBytes <= 0 {
		return nil
	}
	accounting, err := computeCapacityAccounting(storage, totalCapacityBytes)
	if err != nil {
		return err
	}
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	record, exists, err := loadStoreTransferRecord(storage, req.TransferID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("resumable transfer state is missing")
	}
	binding, err := storeTransferBindingHash(req)
	if err != nil {
		return err
	}
	if record.Version != transferRecordVersion || record.BindingHash != binding {
		return fmt.Errorf("transferId is already bound to different immutable transfer metadata")
	}
	if record.Status == "completed" {
		return nil
	}
	if record.ReservedCapacityBytes > 0 {
		return associateQuoteReservationWithTransferLocked(storage, req)
	}
	reserved, err := reservedAdmissionCapacityBytesLocked(
		storage, record.TransferID, req.TransferID, req.PaymentCommitment,
	)
	if err != nil {
		return fmt.Errorf("read durable capacity reservations: %w", err)
	}
	required := capacityBytesRequiredForPiece(req.Size, zkBlockSize)
	// Keep the quote's privacy-padded allocation through the conversion. The
	// transfer and quote records are de-duplicated by payment commitment.
	if quote, found, quoteErr := findQuoteReservationLocked(storage, req.TransferID, req.PaymentCommitment); quoteErr != nil {
		return quoteErr
	} else if found && quote.ReservedCapacityBytes > required {
		required = quote.ReservedCapacityBytes
	}
	if marginBytes < 0 {
		marginBytes = 0
	}
	free := totalCapacityBytes - accounting.UsedBytes - reserved
	if free <= marginBytes {
		return fmt.Errorf(
			"admission closed: used=%d reserved=%d required=%d margin=%d declared=%d",
			accounting.UsedBytes, reserved, required, marginBytes, totalCapacityBytes,
		)
	}
	if required > free {
		return fmt.Errorf(
			"insufficient unreserved capacity: used=%d reserved=%d required=%d declared=%d",
			accounting.UsedBytes, reserved, required, totalCapacityBytes,
		)
	}
	record.ReservedCapacityBytes = required
	record.UpdatedAt = nowRFC3339()
	if err := persistStoreTransferRecord(storage, record); err != nil {
		return err
	}
	return associateQuoteReservationWithTransferLocked(storage, req)
}

func durableAtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".transfer-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func loadOrCreateStoreTransfer(storage string, req StoreReq) (storeTransferRecord, error) {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	return loadOrCreateStoreTransferLocked(storage, req)
}

func existingStoreTransferMatches(storage string, req StoreReq) (bool, error) {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	if !validTransferID(req.TransferID) {
		return false, nil
	}
	binding, err := storeTransferBindingHash(req)
	if err != nil {
		return false, err
	}
	record, exists, err := loadStoreTransferRecord(storage, req.TransferID)
	if err != nil || !exists {
		return false, err
	}
	if record.Version != transferRecordVersion || record.BindingHash != binding {
		return false, fmt.Errorf("transferId is already bound to different immutable transfer metadata")
	}
	return true, nil
}

func loadOrCreateStoreTransferLocked(storage string, req StoreReq) (storeTransferRecord, error) {
	if !validTransferID(req.TransferID) {
		return storeTransferRecord{}, fmt.Errorf("invalid transferId")
	}
	binding, err := storeTransferBindingHash(req)
	if err != nil {
		return storeTransferRecord{}, err
	}
	record, exists, err := loadStoreTransferRecord(storage, req.TransferID)
	if err != nil {
		return record, err
	}
	if exists {
		if record.Version != transferRecordVersion || record.BindingHash != binding {
			return record, fmt.Errorf("transferId is already bound to different immutable transfer metadata")
		}
		record.UpdatedAt = nowRFC3339()
		if err := persistStoreTransferRecord(storage, record); err != nil {
			return record, err
		}
		return record, nil
	}
	now := nowRFC3339()
	record = storeTransferRecord{
		Version: transferRecordVersion, TransferID: req.TransferID,
		BindingHash: binding, Status: "partial", CreatedAt: now, UpdatedAt: now,
	}
	return record, persistStoreTransferRecord(storage, record)
}

func completeStoreTransfer(storage string, req StoreReq, response StoreResp) error {
	if req.TransferID == "" {
		return nil
	}
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	record, err := loadOrCreateStoreTransferLocked(storage, req)
	if err != nil {
		return err
	}
	response.TransferID = req.TransferID
	response.Complete = true
	record.Status = "completed"
	record.UpdatedAt = nowRFC3339()
	record.CompletedStore = &response
	return persistStoreTransferRecord(storage, record)
}

func cleanupTransferState(storage string, cfg ServerConfig) {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	now := time.Now()
	partialTTL := time.Duration(max64(1, cfg.PartialUploadTTLSeconds)) * time.Second
	completedTTL := time.Duration(max64(1, cfg.CompletedTransferTTLSeconds)) * time.Second
	entries, err := os.ReadDir(transferStateDir(storage))
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(transferStateDir(storage), entry.Name())
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				continue
			}
			var record storeTransferRecord
			if json.Unmarshal(raw, &record) != nil || !validTransferID(record.TransferID) {
				continue
			}
			updated, parseErr := time.Parse(time.RFC3339Nano, record.UpdatedAt)
			if parseErr != nil {
				continue
			}
			ttl := partialTTL
			if record.Status == "completed" {
				ttl = completedTTL
			}
			partialPath := transferPartialPath(storage, record.TransferID)
			if info, statErr := os.Stat(partialPath); statErr == nil && info.ModTime().After(updated) {
				updated = info.ModTime()
			}
			if now.Sub(updated) >= ttl {
				_ = os.Remove(partialPath)
				_ = os.Remove(path)
			}
		}
	}
	legacyEntries, _ := os.ReadDir(tmpDir(storage))
	for _, entry := range legacyEntries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "resume-") || !strings.HasSuffix(entry.Name(), ".part") {
			continue
		}
		path := filepath.Join(tmpDir(storage), entry.Name())
		if info, statErr := entry.Info(); statErr == nil && now.Sub(info.ModTime()) >= partialTTL {
			_ = os.Remove(path)
		}
	}
}

func runTransferStateGC(stop <-chan struct{}, storage string, cfg ServerConfig) {
	cleanupTransferState(storage, cfg)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			cleanupTransferState(storage, cfg)
		}
	}
}
