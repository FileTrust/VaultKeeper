package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const (
	quoteReservationRecordVersion  = 1
	quoteReservationPendingChain   = "pending_chain"
	quoteReservationQuoted         = "quoted"
	quoteReservationEscrowSeen     = "escrow_seen"
	quoteReservationActiveTransfer = "active_transfer"
	quoteReservationStored         = "stored"
	quoteReservationDeletion       = "deletion_pending"
	quoteReservationReleased       = "released"
	quoteReservationExpired        = "expired"

	capacityQuoteNone            uint8 = 0
	capacityQuoteQuoted          uint8 = 1
	capacityQuoteStored          uint8 = 2
	capacityQuoteDeletionPending uint8 = 3
	capacityQuoteReleased        uint8 = 4
	capacityQuoteExpired         uint8 = 5
	capacityQuoteActiveTransfer  uint8 = 6
)

var (
	reserveCapacityQuoteSelector = ethcrypto.Keccak256(
		[]byte("reserveQuote(bytes32,uint64,uint64)"),
	)[:4]
	expireCapacityQuoteSelector = ethcrypto.Keccak256(
		[]byte("expireQuote(bytes32)"),
	)[:4]
	escrowDeletionTxCostSelector = ethcrypto.Keccak256(
		[]byte("deletionTxCostEstimate()"),
	)[:4]
	activateCapacityQuoteSelector = ethcrypto.Keccak256(
		[]byte("activateQuote(bytes32,uint64)"),
	)[:4]
	getCapacityQuoteSelector = ethcrypto.Keccak256(
		[]byte("getQuoteReservation(bytes32)"),
	)[:4]
	escrowRegistrationTimeoutSelector = ethcrypto.Keccak256(
		[]byte("finalizeRegistrationTimeoutSeconds()"),
	)[:4]
	escrowMaxRegistrationTimeoutSelector = ethcrypto.Keccak256(
		[]byte("maxRegistrationTimeoutSeconds()"),
	)[:4]
	capacityMaxActiveTransferSelector = ethcrypto.Keccak256(
		[]byte("maxActiveTransferSeconds()"),
	)[:4]
)

// quoteReservationRecord contains only random protocol commitments, capacity
// bounds, and timing. It intentionally never contains the DO address, file ID,
// piece root, requester address, or any routing relationship. The one exception
// is FileHash, a hash of the file id that the per-file limits need; a keeper
// already keeps the file id itself for every piece it stores.
type quoteReservationRecord struct {
	Version           int    `json:"version"`
	TransferID        string `json:"transferId"`
	IdentityHash      string `json:"identityHash"`
	Status            string `json:"status"`
	PaymentCommitment string `json:"paymentCommitment"`
	SizeCommitment    string `json:"sizeCommitment"`
	LinkCommitment    string `json:"linkCommitment"`
	// LinkNonce opens LinkCommitment. The quote gives it to the data owner, who
	// needs it to settle or refund the escrow on chain; a retried quote gives the
	// same one.
	LinkNonce              string `json:"linkNonce,omitempty"`
	RegistrationCommitment string `json:"registrationCommitment"`
	PieceSize              int64  `json:"pieceSize"`
	ReservedCapacityBytes  int64  `json:"reservedCapacityBytes"`
	ServiceEnd             int64  `json:"serviceEnd"`
	QuoteValidUntil        int64  `json:"quoteValidUntil"`
	ReservationExpiresAt   int64  `json:"reservationExpiresAt"`
	TransferDeadline       int64  `json:"transferDeadline"`
	AgreedPriceWei         string `json:"agreedPriceWei"`
	VKSignature            string `json:"vkSignature"`
	CapacityProofContract  string `json:"capacityProofContract"`
	ReservationTxHash      string `json:"reservationTxHash,omitempty"`
	CreatedAt              string `json:"createdAt"`
	UpdatedAt              string `json:"updatedAt"`
	// FileHash is a hash of the file id, never the id itself; it is what lets the
	// per-file limits count quotes for one file.
	FileHash string `json:"fileHash,omitempty"`
	// UnusedExpiredAt is the chain time at which a quote the data owner never
	// came back for (never paid and sent) expired. Zero for every other outcome,
	// including a reservation that failed on the keeper's own side.
	UnusedExpiredAt int64 `json:"unusedExpiredAt,omitempty"`
	// RetryDemandID is request-local only. It suppresses creation of a second demand when an
	// authenticated retry still cannot fit; it is never persisted in quote state.
	RetryDemandID string `json:"-"`
}

type blockedAdmissionRefusal struct {
	cause      error
	demand     BlockedAdmissionDemand
	capability string
}

func (e *blockedAdmissionRefusal) Error() string { return e.cause.Error() }
func (e *blockedAdmissionRefusal) Unwrap() error { return e.cause }

type capacityQuoteReservation struct {
	VKAddress             string
	ReservedCapacityBytes uint64
	ExpiresAt             uint64
	State                 uint8
}

func quoteReservationDir(storage string) string {
	return filepath.Join(storage, "quote-reservations")
}

func quoteReservationPath(storage, transferID string) string {
	return filepath.Join(quoteReservationDir(storage), safeID(transferID)+".json")
}

func quoteReservationIdentityHash(identity string) string {
	sum := sha256.Sum256([]byte("FileTrustQuoteIdentityV1\x00" + identity))
	return hex.EncodeToString(sum[:])
}

func resolvedQuoteReservationQuantum(cfg ServerConfig) int64 {
	quantum := cfg.QuoteReservationQuantumBytes
	if quantum <= 0 {
		quantum = DefaultQuoteReservationQuantumBytes
	}
	blockSize := cfg.ZKBlockSize
	if blockSize <= 0 {
		blockSize = DefaultZKBlockSize
	}
	if quantum < blockSize {
		quantum = blockSize
	}
	// The allocation unit must itself be representable by the proof blocks.
	if rem := quantum % blockSize; rem != 0 {
		quantum += blockSize - rem
	}
	return quantum
}

func quoteReservedCapacityBytes(pieceSize int64, cfg ServerConfig) (int64, error) {
	if pieceSize <= 0 {
		return 0, fmt.Errorf("invalid quote piece size")
	}
	quantum := resolvedQuoteReservationQuantum(cfg)
	if pieceSize > math.MaxInt64-(quantum-1) {
		return 0, fmt.Errorf("quote capacity reservation overflows int64")
	}
	return ((pieceSize + quantum - 1) / quantum) * quantum, nil
}

func resolvedMaxOutstandingQuotes(cfg ServerConfig) int {
	if cfg.MaxOutstandingQuoteReservations > 0 {
		return cfg.MaxOutstandingQuoteReservations
	}
	return DefaultMaxOutstandingQuoteReservations
}

func resolvedMaxOutstandingQuotesPerIdentity(cfg ServerConfig) int {
	if cfg.MaxOutstandingQuotesPerIdentity > 0 {
		return cfg.MaxOutstandingQuotesPerIdentity
	}
	return DefaultMaxOutstandingQuotesPerIdentity
}

func resolvedMaxOpenQuotesPerFile(cfg ServerConfig) int {
	if cfg.MaxOpenQuotesPerFile > 0 {
		return cfg.MaxOpenQuotesPerFile
	}
	return DefaultMaxOpenQuotesPerFile
}

func resolvedMaxUnusedQuotesPerFile(cfg ServerConfig) int {
	if cfg.MaxUnusedQuotesPerFile > 0 {
		return cfg.MaxUnusedQuotesPerFile
	}
	return DefaultMaxUnusedQuotesPerFile
}

func resolvedUnusedQuoteWindowSeconds(cfg ServerConfig) int64 {
	if cfg.UnusedQuoteWindowSeconds > 0 {
		return cfg.UnusedQuoteWindowSeconds
	}
	return DefaultUnusedQuoteWindowSeconds
}

// quoteFileLimitRefusal applies the two per-file limits to the records already
// on disk, or returns "" when the file may be quoted.
//
// Proving a real file costs the requester money once, but without these limits
// one such file could hold capacity on a keeper forever: ask, let the quote
// lapse, ask again. A real upload places one piece of a file on each keeper and
// pays for it within seconds, so it never comes near either limit.
func quoteFileLimitRefusal(cfg ServerConfig, quotes []quoteReservationRecord, fileHash string, chainNow int64) string {
	if fileHash == "" {
		return ""
	}
	open, unused := 0, 0
	windowStart := chainNow - resolvedUnusedQuoteWindowSeconds(cfg)
	for _, candidate := range quotes {
		if candidate.FileHash != fileHash {
			continue
		}
		if quoteReservationConsumesLocalCapacity(candidate.Status) {
			open++
		}
		if candidate.UnusedExpiredAt > 0 && candidate.UnusedExpiredAt > windowStart {
			unused++
		}
	}
	if open >= resolvedMaxOpenQuotesPerFile(cfg) {
		return "quote reservation per-file limit reached; retry after an existing quote for this file settles"
	}
	if unused >= resolvedMaxUnusedQuotesPerFile(cfg) {
		return "too many unused quotes for this file on this vault keeper; refused until the unused-quote window passes"
	}
	return ""
}

func loadQuoteReservation(storage, transferID string) (quoteReservationRecord, bool, error) {
	var record quoteReservationRecord
	raw, err := os.ReadFile(quoteReservationPath(storage, transferID))
	if os.IsNotExist(err) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, false, err
	}
	if record.Version != quoteReservationRecordVersion || !validTransferID(record.TransferID) ||
		record.RegistrationCommitment == "" || record.PaymentCommitment == "" ||
		record.ReservedCapacityBytes <= 0 {
		return record, false, fmt.Errorf("invalid durable quote reservation %s", filepath.Base(quoteReservationPath(storage, transferID)))
	}
	return record, true, nil
}

func persistQuoteReservation(storage string, record quoteReservationRecord) error {
	if record.Version != quoteReservationRecordVersion || !validTransferID(record.TransferID) {
		return fmt.Errorf("invalid quote reservation record")
	}
	if err := os.MkdirAll(quoteReservationDir(storage), 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(quoteReservationPath(storage, record.TransferID), raw, 0600)
}

func quoteReservationConsumesLocalCapacity(status string) bool {
	switch status {
	case quoteReservationPendingChain, quoteReservationQuoted, quoteReservationEscrowSeen, quoteReservationActiveTransfer:
		return true
	default:
		return false
	}
}

// quoteReservationSettled reports that this transferId's reservation has reached
// an outcome, so it can never take a new escrow deposit again.
func quoteReservationSettled(status string) bool {
	switch status {
	case quoteReservationExpired, quoteReservationReleased,
		quoteReservationStored, quoteReservationDeletion:
		return true
	default:
		return false
	}
}

// quoteReuseVerdict answers one question about an existing reservation a caller is
// trying to reuse: is this over, is it merely waiting, or is it still live?
type quoteReuseVerdict struct {
	// Settled: the outcome is already decided. The caller must be told so, and
	// told which outcome, because the two ends need opposite handling -- a stored
	// piece is already delivered, while an expired or released one discharged its
	// obligation without delivering anything.
	Settled bool
	// Busy: still live but past its quote validity, so the reservation reconciler
	// has to settle it on chain before anyone can say what it became. Retrying is
	// the right advice here, because the answer really is about to change.
	Busy   bool
	Status string
}

// classifyQuoteReservationReuse decides what an existing reservation means for a
// caller reusing its transferId.
//
// ORDER MATTERS, and it used to be wrong. The handler asked "is the quote still
// in date?" before "has this reservation already finished?", so every settled
// reservation -- which by definition has an expiry in the past -- answered "busy,
// awaiting authoritative capacity reconciliation, retry in 5s". Nothing was going
// to change, because the reconciler had already done its work; the status WAS the
// answer, and the branch that reported it was unreachable.
//
// Live on 2026-09-30: three data owners each had one piece whose earlier quote had
// lapsed and been expired by the reconciler. Every retry was told "busy", so each
// upload waited for a keeper that had nothing left to say. On the keeper box, 340
// reservations were stored and 30 expired, and not one was live -- every single one
// of them would have answered "busy, retry" for as long as anyone asked.
//
// The data owner already knows how to recover from a truthful answer: a peer job
// with no escrow, no bytes and no response is cancellable pre-obligation, after
// which the next attempt carries a fresh transferId. All that was missing was
// being told.
func classifyQuoteReservationReuse(
	record quoteReservationRecord, chainNow int64,
) quoteReuseVerdict {
	if quoteReservationSettled(record.Status) {
		return quoteReuseVerdict{Settled: true, Status: record.Status}
	}
	if chainNow > record.QuoteValidUntil {
		return quoteReuseVerdict{Busy: true, Status: record.Status}
	}
	return quoteReuseVerdict{Status: record.Status}
}

func loadAllQuoteReservationsLocked(storage string) ([]quoteReservationRecord, error) {
	entries, err := os.ReadDir(quoteReservationDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]quoteReservationRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(quoteReservationDir(storage), entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		var record quoteReservationRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode quote reservation %s: %w", entry.Name(), err)
		}
		if record.Version != quoteReservationRecordVersion || !validTransferID(record.TransferID) ||
			record.ReservedCapacityBytes <= 0 {
			return nil, fmt.Errorf("invalid quote reservation %s", entry.Name())
		}
		records = append(records, record)
	}
	return records, nil
}

// reservedAdmissionCapacityBytesLocked combines resumable-transfer and quote
// reservations without double-counting a quote that has already converted to
// a durable transfer. transferStateMu must be held by the caller.
func reservedAdmissionCapacityBytesLocked(
	storage, excludeTransferID, excludeQuoteTransferID, excludePaymentCommitment string,
) (int64, error) {
	return reservedAdmissionCapacityBytesAtLocked(
		storage, excludeTransferID, excludeQuoteTransferID, excludePaymentCommitment, time.Now().Unix(),
	)
}

// reservedAdmissionCapacityBytesAtLocked reconstructs the exact live durable
// reservation set at the chain timestamp used by the certification read. A
// converted transfer and its quote count once; expired, released, cancelled,
// stored, and deletion-pending records count zero.
func reservedAdmissionCapacityBytesAtLocked(
	storage, excludeTransferID, excludeQuoteTransferID, excludePaymentCommitment string,
	observationUnix int64,
) (int64, error) {
	if observationUnix <= 0 {
		return 0, fmt.Errorf("reservation observation time is unavailable")
	}
	quotes, err := loadAllQuoteReservationsLocked(storage)
	if err != nil {
		return 0, err
	}
	quotesByPayment := make(map[string]quoteReservationRecord, len(quotes))
	for _, quote := range quotes {
		if quote.PaymentCommitment != "" {
			quotesByPayment[strings.ToLower(quote.PaymentCommitment)] = quote
		}
	}
	entries, err := os.ReadDir(transferStateDir(storage))
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	var total int64
	reservedPayments := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(transferStateDir(storage), entry.Name()))
		if readErr != nil {
			return 0, readErr
		}
		var record storeTransferRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return 0, fmt.Errorf("decode transfer reservation %s: %w", entry.Name(), err)
		}
		if record.Status != "partial" || record.TransferID == excludeTransferID ||
			record.ReservedCapacityBytes <= 0 {
			continue
		}
		if quote, found := quotesByPayment[strings.ToLower(record.PaymentCommitment)]; found {
			if !quoteReservationConsumesLocalCapacity(quote.Status) || quote.ReservationExpiresAt <= observationUnix {
				continue
			}
		} else if record.RegistrationDeadline > 0 && record.RegistrationDeadline <= observationUnix {
			continue
		}
		if total > math.MaxInt64-record.ReservedCapacityBytes {
			return 0, fmt.Errorf("capacity reservation total overflow")
		}
		total += record.ReservedCapacityBytes
		if record.PaymentCommitment != "" {
			reservedPayments[strings.ToLower(record.PaymentCommitment)] = struct{}{}
		}
	}

	for _, record := range quotes {
		if !quoteReservationConsumesLocalCapacity(record.Status) ||
			record.ReservationExpiresAt <= observationUnix ||
			record.TransferID == excludeQuoteTransferID ||
			(excludePaymentCommitment != "" && strings.EqualFold(record.PaymentCommitment, excludePaymentCommitment)) {
			continue
		}
		if _, converted := reservedPayments[strings.ToLower(record.PaymentCommitment)]; converted {
			continue
		}
		if total > math.MaxInt64-record.ReservedCapacityBytes {
			return 0, fmt.Errorf("capacity reservation total overflow")
		}
		total += record.ReservedCapacityBytes
	}
	return total, nil
}

// reserveLocalQuoteCapacity is called while storeCapacityMu is held. The
// durable local write happens before any quote can be returned and immediately
// participates in every admission decision.
func reserveLocalQuoteCapacity(cfg ServerConfig, record quoteReservationRecord) error {
	certified, err := readCertifiedCapacityForAdmission(cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", AdmissionClosureChainUnavailable, err)
	}
	if certified.FreshCertifiedFreeCapacity > cfg.CapacityBytes {
		return fmt.Errorf("%s: certified free exceeds declared capacity", AdmissionClosureRecoveryDisagreement)
	}
	if safety := readG5AdmissionSafety(
		cfg.Storage, cfg, time.Unix(certified.ChainTimestamp, 0),
	); safety.ClosureReason != "" {
		return fmt.Errorf("%s: %s", safety.ClosureReason, safety.Detail)
	}
	physical, err := filesystemAdmissionState(cfg)
	if err != nil || record.ReservedCapacityBytes > physical.AllocatableBytes {
		return fmt.Errorf("%s: physical capacity cannot satisfy reservation: %v",
			AdmissionClosureRecoveryDisagreement, err)
	}
	transferStateMu.Lock()
	if existing, found, loadErr := loadQuoteReservation(cfg.Storage, record.TransferID); loadErr != nil {
		transferStateMu.Unlock()
		return loadErr
	} else if found {
		if existing.IdentityHash == record.IdentityHash && existing.PieceSize == record.PieceSize &&
			existing.ServiceEnd == record.ServiceEnd {
			transferStateMu.Unlock()
			return reserveHostFilesystemCapacity(cfg, existing)
		}
		transferStateMu.Unlock()
		return fmt.Errorf("transferId is already bound to different quote metadata")
	}
	quotes, err := loadAllQuoteReservationsLocked(cfg.Storage)
	if err != nil {
		transferStateMu.Unlock()
		return err
	}
	active, perIdentity := 0, 0
	for _, candidate := range quotes {
		if !quoteReservationConsumesLocalCapacity(candidate.Status) {
			continue
		}
		active++
		if candidate.IdentityHash == record.IdentityHash {
			perIdentity++
		}
	}
	if active >= resolvedMaxOutstandingQuotes(cfg) {
		transferStateMu.Unlock()
		return fmt.Errorf("quote reservation limit reached; retry after existing quotes settle")
	}
	if perIdentity >= resolvedMaxOutstandingQuotesPerIdentity(cfg) {
		transferStateMu.Unlock()
		return fmt.Errorf("quote reservation per-identity limit reached; retry after an existing quote settles")
	}
	if refusal := quoteFileLimitRefusal(cfg, quotes, record.FileHash, certified.ChainTimestamp); refusal != "" {
		transferStateMu.Unlock()
		return errors.New(refusal)
	}
	reserved, err := reservedAdmissionCapacityBytesAtLocked(
		cfg.Storage, "", "", "", certified.ChainTimestamp,
	)
	if err != nil {
		transferStateMu.Unlock()
		return err
	}
	margin := admissionMarginBytes(cfg)
	unreserved, safe := subtractAdmissionCapacity(certified.FreshCertifiedFreeCapacity, reserved, margin)
	// MARGIN = LAST ACCEPTANCE, NOT A FLOOR.
	//
	// The margin exists so a keeper can always honour one final request and then stop
	// cleanly, instead of refusing while it still visibly holds free bytes. Admission
	// stays open while unreserved capacity is still above the margin (safe > 0); while
	// open, a request may consume the margin itself. The store that does so drives
	// unreserved below the margin, and every later call sees safe <= 0 and is closed.
	//
	// Comparing the request against `safe` instead made the keeper refuse a 6 MB piece
	// while holding 102 MB free against a 100 MB margin — and 102 MB free is exactly
	// what the requester's own capacity probe then reported as "space still available".
	// The keeper said full, the probe said not full, the drain vote reset, and the test
	// could never terminate. Bounded overshoot is the point of the margin; a keeper that
	// can never spend it just refuses early and never closes.
	//
	// Concurrency is already handled: `reserved` counts active quote reservations and the
	// whole decision runs under transferStateMu, so a second request sees the first one's
	// bytes and is refused rather than dipping into the margin again.
	if safe <= 0 || record.ReservedCapacityBytes > unreserved {
		transferStateMu.Unlock()
		// G.4B: this is the ONE closure a deletion release can fix, and no reservation was
		// created. Record a private blocked demand so the scheduler can decide whether an exact
		// unresolved release obligation would make this request admissible before its lifecycle
		// deadline. Creation is best-effort: a failure here must never change the refusal.
		cause := fmt.Errorf(
			"%s: freshCertified=%d reserved=%d margin=%d required=%d safeAllocatable=%d",
			AdmissionClosureCertifiedInsufficient, certified.FreshCertifiedFreeCapacity,
			reserved, margin, record.ReservedCapacityBytes, safe,
		)
		if record.RetryDemandID == "" {
			if demand, capability, created := recordBlockedAdmissionDemandForQuote(
				cfg, record, uint64(max64(safe, 0)), certified); created {
				return &blockedAdmissionRefusal{
					cause: cause, demand: demand, capability: capability,
				}
			}
		}
		return cause
	}
	if err := persistQuoteReservation(cfg.Storage, record); err != nil {
		transferStateMu.Unlock()
		return err
	}
	transferStateMu.Unlock()
	if err := reserveHostFilesystemCapacity(cfg, record); err != nil {
		// No chain transaction is attempted until both durable layers exist, so
		// this local record can be released definitively on physical rejection.
		transferStateMu.Lock()
		if current, found, loadErr := loadQuoteReservation(cfg.Storage, record.TransferID); loadErr == nil && found &&
			current.Status == quoteReservationPendingChain {
			current.Status = quoteReservationExpired
			current.UpdatedAt = nowRFC3339()
			_ = persistQuoteReservation(cfg.Storage, current)
		}
		transferStateMu.Unlock()
		return err
	}
	return nil
}

func findQuoteReservationLocked(storage, transferID, paymentCommitment string) (quoteReservationRecord, bool, error) {
	if validTransferID(transferID) {
		if record, found, err := loadQuoteReservation(storage, transferID); err != nil || found {
			return record, found, err
		}
	}
	records, err := loadAllQuoteReservationsLocked(storage)
	if err != nil {
		return quoteReservationRecord{}, false, err
	}
	for _, record := range records {
		if paymentCommitment != "" && strings.EqualFold(record.PaymentCommitment, paymentCommitment) {
			return record, true, nil
		}
	}
	return quoteReservationRecord{}, false, nil
}

// associateQuoteReservationWithTransferLocked performs the conversion in the
// safe order: the transfer reservation is persisted first, then the quote is
// marked escrow-seen. A crash between the writes is conservatively de-duplicated
// by paymentCommitment during restart accounting.
func associateQuoteReservationWithTransferLocked(storage string, req StoreReq) error {
	if req.PaymentCommitment == "" {
		return nil
	}
	quote, found, err := findQuoteReservationLocked(storage, req.TransferID, req.PaymentCommitment)
	if err != nil {
		return err
	}
	if !found {
		// Legacy/non-capacity deployments can carry payment commitments without
		// CapacityProofSC. Capacity-backed stores are separately required to pass
		// validateQuoteReservationForStore before this conversion.
		return nil
	}
	if quote.PieceSize != req.Size || !strings.EqualFold(quote.PaymentCommitment, req.PaymentCommitment) {
		return fmt.Errorf("durable quote reservation does not match transfer")
	}
	if quote.Status == quoteReservationExpired || quote.Status == quoteReservationReleased {
		return fmt.Errorf("durable quote capacity reservation is no longer active")
	}

	// Persist the common blinded commitments in the transfer record before
	// changing quote state. Restart accounting can then identify both records as
	// one obligation even if the process stops between these two durable writes.
	transfer, exists, err := loadStoreTransferRecord(storage, req.TransferID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("resumable transfer state is missing during quote conversion")
	}
	binding, err := storeTransferBindingHash(req)
	if err != nil {
		return err
	}
	if transfer.Version != transferRecordVersion || transfer.BindingHash != binding {
		return fmt.Errorf("transferId is already bound to different immutable transfer metadata")
	}
	if transfer.PaymentCommitment != "" && !strings.EqualFold(transfer.PaymentCommitment, quote.PaymentCommitment) {
		return fmt.Errorf("transfer is bound to a different payment commitment")
	}
	if transfer.RegistrationCommitment != "" &&
		!strings.EqualFold(transfer.RegistrationCommitment, quote.RegistrationCommitment) {
		return fmt.Errorf("transfer is bound to a different registration commitment")
	}
	transfer.PaymentCommitment = strings.ToLower(quote.PaymentCommitment)
	transfer.RegistrationCommitment = strings.ToLower(quote.RegistrationCommitment)
	transfer.UpdatedAt = nowRFC3339()
	if err := persistStoreTransferRecord(storage, transfer); err != nil {
		return err
	}

	if quote.Status != quoteReservationStored && quote.Status != quoteReservationDeletion {
		quote.Status = quoteReservationEscrowSeen
	}
	quote.UpdatedAt = nowRFC3339()
	return persistQuoteReservation(storage, quote)
}

func markQuoteReservationStored(storage, transferID, paymentCommitment string) error {
	if paymentCommitment == "" {
		return nil
	}
	transferStateMu.Lock()
	record, found, err := findQuoteReservationLocked(storage, transferID, paymentCommitment)
	if err != nil {
		transferStateMu.Unlock()
		return err
	}
	if !found {
		transferStateMu.Unlock()
		return fmt.Errorf("durable quote capacity reservation is missing after registration")
	}
	record.Status = quoteReservationStored
	record.UpdatedAt = nowRFC3339()
	if err := persistQuoteReservation(storage, record); err != nil {
		transferStateMu.Unlock()
		return err
	}
	transferStateMu.Unlock()
	return releaseHostFilesystemCapacity(storage, record.TransferID)
}

func quoteResponseFromReservation(record quoteReservationRecord, escrowContract string) QuoteResp {
	return QuoteResp{
		OK: true, PaymentCommitment: record.PaymentCommitment,
		SizeCommitment: record.SizeCommitment, LinkCommitment: record.LinkCommitment,
		LinkNonce:              record.LinkNonce,
		RegistrationCommitment: record.RegistrationCommitment,
		AgreedPriceWei:         record.AgreedPriceWei, ServiceEnd: record.ServiceEnd,
		VKEscrowContract: escrowContract, QuoteValidUntil: record.QuoteValidUntil,
		VKSignature: record.VKSignature, TransferID: record.TransferID,
		CapacityProofContract: record.CapacityProofContract,
		ReservedCapacityBytes: record.ReservedCapacityBytes,
		ReservationExpiresAt:  record.ReservationExpiresAt,
		ReservationTxHash:     record.ReservationTxHash,
		TransferDeadline:      record.TransferDeadline,
		QuoteVersion:          2,
	}
}

func uint64ABIWord(value uint64) []byte {
	word := make([]byte, 32)
	new(big.Int).SetUint64(value).FillBytes(word)
	return word
}

func decodeUint64ABIWord(word []byte, label string) (uint64, error) {
	if len(word) != 32 {
		return 0, fmt.Errorf("%s is not one ABI word", label)
	}
	n := new(big.Int).SetBytes(word)
	if n.BitLen() > 64 {
		return 0, fmt.Errorf("%s exceeds uint64", label)
	}
	return n.Uint64(), nil
}

func getCapacityQuoteReservation(cfg ServerConfig, registrationCommitment string) (capacityQuoteReservation, error) {
	var out capacityQuoteReservation
	if !common.IsHexAddress(cfg.CapacityProofContract) {
		return out, fmt.Errorf("capacity proof contract is not configured")
	}
	calldata := append(append([]byte{}, getCapacityQuoteSelector...), hexToBytes32(registrationCommitment)...)
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{"to": common.HexToAddress(cfg.CapacityProofContract).Hex(), "data": "0x" + hex.EncodeToString(calldata)},
		"latest",
	})
	if err != nil {
		return out, err
	}
	rawHex := strings.TrimPrefix(result, "0x")
	if len(rawHex) < 4*64 {
		return out, fmt.Errorf("%w: CapacityProofSC.getQuoteReservation returned %d hex chars", ErrRPCUnavailable, len(rawHex))
	}
	raw, err := hex.DecodeString(rawHex[:4*64])
	if err != nil {
		return out, fmt.Errorf("%w: decode CapacityProofSC quote reservation: %v", ErrRPCUnavailable, err)
	}
	out.VKAddress = common.BytesToAddress(raw[12:32]).Hex()
	if out.ReservedCapacityBytes, err = decodeUint64ABIWord(raw[32:64], "reservedBytes"); err != nil {
		return capacityQuoteReservation{}, err
	}
	if out.ExpiresAt, err = decodeUint64ABIWord(raw[64:96], "expiresAt"); err != nil {
		return capacityQuoteReservation{}, err
	}
	state, err := decodeUint64ABIWord(raw[96:128], "state")
	if err != nil || state > math.MaxUint8 {
		return capacityQuoteReservation{}, fmt.Errorf("invalid quote reservation state")
	}
	out.State = uint8(state)
	return out, nil
}

func capacityQuoteMatches(record quoteReservationRecord, chain capacityQuoteReservation, expectedVK string) bool {
	return chain.State == capacityQuoteQuoted && strings.EqualFold(chain.VKAddress, expectedVK) &&
		chain.ReservedCapacityBytes == uint64(record.ReservedCapacityBytes) &&
		chain.ExpiresAt == uint64(record.ReservationExpiresAt)
}

// quoteHoldFeeWei is what the keeper spends on chain to hold and later release
// one quote's capacity. The quote is signed before either transaction is sent,
// so the fee is the configured gas at the same fixed gas price the keeper sends
// both with. A data owner who stores pays it inside the quoted price; one who
// leaves before paying costs the keeper it, which the per-file limits bound.
func quoteHoldFeeWei(cfg ServerConfig) *big.Int {
	if cfg.QuoteHoldGas <= 0 {
		return big.NewInt(0)
	}
	gasPrice := cfg.FixedGasPriceWei
	if gasPrice <= 0 {
		gasPrice = 1_000_000 // the same fallback sendCapacityQuoteTransaction uses
	}
	return new(big.Int).Mul(big.NewInt(cfg.QuoteHoldGas), big.NewInt(gasPrice))
}

// escrowPieceTxCostWei reads VKEscrow.deletionTxCostEstimate: what the escrow
// pays a keeper in full, on top of its time share, when the data owner deletes
// early -- the keeper's own store and delete transactions for one piece. The
// escrow can never pay out more than was deposited, so it is also the lowest
// storage price a quote may carry. Read from the chain rather than configured,
// so a keeper and a data owner can never disagree about it.
func escrowPieceTxCostWei(cfg ServerConfig) (*big.Int, error) {
	if !common.IsHexAddress(cfg.VKEscrowContract) {
		return nil, fmt.Errorf("VK escrow contract is not configured")
	}
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.VKEscrowContract).Hex(),
			"data": "0x" + hex.EncodeToString(escrowDeletionTxCostSelector),
		},
		"latest",
	})
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil || len(raw) < 32 {
		return nil, fmt.Errorf("%w: invalid VKEscrow.deletionTxCostEstimate response", ErrRPCUnavailable)
	}
	return new(big.Int).SetBytes(raw[len(raw)-32:]), nil
}

// quotedPriceWei is the price a keeper signs: the storage price, raised to the
// escrow's per-piece cost when it is lower, plus the hold fee. The minimum is
// what lets the escrow pay a keeper's own transactions back in full when a
// small or short piece is deleted early.
func quotedPriceWei(storagePriceWei string, minimumWei *big.Int, cfg ServerConfig) string {
	price, ok := new(big.Int).SetString(storagePriceWei, 10)
	if !ok {
		return storagePriceWei
	}
	if minimumWei != nil && price.Cmp(minimumWei) < 0 {
		price.Set(minimumWei)
	}
	return price.Add(price, quoteHoldFeeWei(cfg)).String()
}

func sendCapacityQuoteTransaction(cfg ServerConfig, calldata []byte, functionName string) (string, error) {
	if cfg.RPCURL == "" || !common.IsHexAddress(cfg.CapacityProofContract) ||
		cfg.VKPrivKeyHex == "" || !common.IsHexAddress(cfg.VKAddress) || cfg.ChainID <= 0 {
		return "", fmt.Errorf("capacity quote transaction is not fully configured")
	}
	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return "", fmt.Errorf("capacity quote private key: %w", err)
	}
	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.CapacityProofContract)
	accountLock, err := acquireAccountTxLock(fromAddr.Hex())
	if err != nil {
		return "", err
	}
	defer accountLock.Release()
	nonce, err := rpcGetTransactionCount(cfg.RPCURL, fromAddr.Hex())
	if err != nil {
		return "", fmt.Errorf("capacity quote nonce: %w", err)
	}
	gasLimit, err := rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, nil)
	if err != nil {
		return "", fmt.Errorf("capacity quote estimateGas: %w", err)
	}
	gasLimit = gasLimit * 12 / 10
	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signed, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(cfg.ChainID)), privKey)
	if err != nil {
		return "", fmt.Errorf("capacity quote sign: %w", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("capacity quote marshal: %w", err)
	}
	txHash, err := rpcSendRawTransaction(cfg.RPCURL, raw)
	if err != nil {
		return "", fmt.Errorf("capacity quote send: %w", err)
	}
	receipt, err := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second)
	if err != nil {
		return txHash, fmt.Errorf("capacity quote receipt: %w", err)
	}
	status, ok := new(big.Int).SetString(strings.TrimPrefix(receipt.Status, "0x"), 16)
	if !ok || status.Sign() != 1 {
		return txHash, fmt.Errorf("CapacityProofSC.%s transaction reverted", functionName)
	}
	logMinedTx("vk:CapacityProofSC."+functionName, cfg.RPCURL, cfg.ChainID,
		fromAddr.Hex(), "CapacityProofSC", functionName, toAddr.Hex(), signed, receipt, nil)
	return txHash, nil
}

// reserveCapacityQuoteOnChain is idempotent and reconciles an ambiguous send or
// receipt timeout by reading the authoritative reservation before returning an
// error. A quote response is never emitted until this succeeds.
func reserveCapacityQuoteOnChain(cfg ServerConfig, record quoteReservationRecord) (string, error) {
	chain, err := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
	if err != nil {
		return "", err
	}
	if capacityQuoteMatches(record, chain, cfg.VKAddress) {
		return record.ReservationTxHash, nil
	}
	if chain.State != capacityQuoteNone {
		return "", fmt.Errorf("conflicting on-chain quote reservation state=%d", chain.State)
	}
	calldata := make([]byte, 0, 4+3*32)
	calldata = append(calldata, reserveCapacityQuoteSelector...)
	calldata = append(calldata, hexToBytes32(record.RegistrationCommitment)...)
	calldata = append(calldata, uint64ABIWord(uint64(record.ReservedCapacityBytes))...)
	calldata = append(calldata, uint64ABIWord(uint64(record.ReservationExpiresAt))...)
	txHash, sendErr := sendCapacityQuoteTransaction(cfg, calldata, "reserveQuote")
	if sendErr != nil {
		reconciled, readErr := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
		if readErr == nil && capacityQuoteMatches(record, reconciled, cfg.VKAddress) {
			return txHash, nil
		}
		if readErr != nil {
			return txHash, fmt.Errorf("%w; authoritative reconciliation failed: %v", sendErr, readErr)
		}
		return txHash, sendErr
	}
	confirmed, err := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
	if err != nil {
		return txHash, fmt.Errorf("reservation mined but confirmation read failed: %w", err)
	}
	if !capacityQuoteMatches(record, confirmed, cfg.VKAddress) {
		return txHash, fmt.Errorf("mined capacity quote reservation does not match durable terms")
	}
	return txHash, nil
}

func expireCapacityQuoteOnChain(cfg ServerConfig, registrationCommitment string) error {
	calldata := append(append([]byte{}, expireCapacityQuoteSelector...), hexToBytes32(registrationCommitment)...)
	_, sendErr := sendCapacityQuoteTransaction(cfg, calldata, "expireQuote")
	if sendErr != nil {
		chain, readErr := getCapacityQuoteReservation(cfg, registrationCommitment)
		if readErr == nil && (chain.State == capacityQuoteExpired || chain.State == capacityQuoteReleased) {
			return nil
		}
		return sendErr
	}
	chain, err := getCapacityQuoteReservation(cfg, registrationCommitment)
	if err != nil {
		return err
	}
	if chain.State != capacityQuoteExpired && chain.State != capacityQuoteReleased {
		return fmt.Errorf("quote reservation remains active after expiry transaction")
	}
	return nil
}

func activateCapacityQuoteOnChain(cfg ServerConfig, record quoteReservationRecord, activeUntil int64) error {
	if activeUntil <= 0 || activeUntil > record.TransferDeadline {
		return fmt.Errorf("invalid active transfer deadline")
	}
	chain, err := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
	if err != nil {
		return err
	}
	if !strings.EqualFold(chain.VKAddress, cfg.VKAddress) ||
		chain.ReservedCapacityBytes != uint64(record.ReservedCapacityBytes) {
		return fmt.Errorf("authoritative quote reservation does not match active transfer")
	}
	if chain.State == capacityQuoteStored {
		return nil
	}
	if chain.State == capacityQuoteActiveTransfer && chain.ExpiresAt >= uint64(activeUntil) {
		return nil
	}
	if chain.State != capacityQuoteQuoted && chain.State != capacityQuoteActiveTransfer {
		return fmt.Errorf("quote reservation cannot activate from state=%d", chain.State)
	}
	calldata := make([]byte, 0, 4+2*32)
	calldata = append(calldata, activateCapacityQuoteSelector...)
	calldata = append(calldata, hexToBytes32(record.RegistrationCommitment)...)
	calldata = append(calldata, uint64ABIWord(uint64(activeUntil))...)
	_, sendErr := sendCapacityQuoteTransaction(cfg, calldata, "activateQuote")
	if sendErr != nil {
		reconciled, readErr := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
		if readErr == nil && reconciled.State == capacityQuoteActiveTransfer &&
			strings.EqualFold(reconciled.VKAddress, cfg.VKAddress) && reconciled.ExpiresAt >= uint64(activeUntil) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("%w; activation reconciliation failed: %v", sendErr, readErr)
		}
		return sendErr
	}
	confirmed, err := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
	if err != nil {
		return err
	}
	if confirmed.State != capacityQuoteActiveTransfer || confirmed.ExpiresAt < uint64(activeUntil) {
		return fmt.Errorf("active transfer reservation was not confirmed")
	}
	return nil
}

func markQuoteReservationActive(storage, transferID, paymentCommitment string, activeUntil int64) error {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	record, found, err := findQuoteReservationLocked(storage, transferID, paymentCommitment)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("durable quote reservation is missing during activation")
	}
	if activeUntil > record.ReservationExpiresAt {
		record.ReservationExpiresAt = activeUntil
	}
	record.Status = quoteReservationActiveTransfer
	record.UpdatedAt = nowRFC3339()
	return persistQuoteReservation(storage, record)
}

type quoteActivationLease struct {
	stop chan struct{}
	done chan struct{}
}

func (lease *quoteActivationLease) Stop() {
	if lease == nil {
		return
	}
	select {
	case <-lease.stop:
	default:
		close(lease.stop)
	}
	<-lease.done
}

func startQuoteActivationLease(cfg ServerConfig, req StoreReq, creds PaymentCredentials) (*quoteActivationLease, error) {
	if cfg.CapacityBytes <= 0 || req.PaymentCommitment == "" {
		return nil, nil
	}
	transferStateMu.Lock()
	record, found, err := findQuoteReservationLocked(cfg.Storage, req.TransferID, req.PaymentCommitment)
	transferStateMu.Unlock()
	if err != nil {
		return nil, err
	}
	if !found || record.TransferDeadline <= 0 || creds.RegistrationDeadline != record.TransferDeadline {
		return nil, fmt.Errorf("escrow deadline does not match signed durable transfer deadline")
	}
	chainState, err := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
	if err != nil {
		return nil, err
	}
	if chainState.State == capacityQuoteStored {
		return nil, nil
	}
	maxActive, err := maximumActiveTransferSeconds(cfg)
	if err != nil {
		return nil, err
	}
	activate := func() (int64, error) {
		chainNow, clockErr := rpcLatestBlockTimestamp(cfg.RPCURL)
		if clockErr != nil {
			return 0, clockErr
		}
		if chainNow >= record.TransferDeadline {
			return 0, fmt.Errorf("signed transfer registration deadline has elapsed")
		}
		activeUntil := record.TransferDeadline
		if maxActive <= math.MaxInt64 && activeUntil > chainNow+int64(maxActive) {
			activeUntil = chainNow + int64(maxActive)
		}
		if err := activateCapacityQuoteOnChain(cfg, record, activeUntil); err != nil {
			return 0, err
		}
		if err := markQuoteReservationActive(cfg.Storage, req.TransferID, req.PaymentCommitment, activeUntil); err != nil {
			return 0, err
		}
		return activeUntil, nil
	}
	activeUntil, err := activate()
	if err != nil {
		return nil, err
	}
	lease := &quoteActivationLease{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(lease.done)
		for activeUntil < record.TransferDeadline {
			// activeUntil is Solidity block time, not host time. Derive the
			// renewal interval from the latest block so NTP/validator skew cannot
			// cause either a transaction storm or a missed capacity lease.
			chainNow, clockErr := rpcLatestBlockTimestamp(cfg.RPCURL)
			wait := 5 * time.Second
			if clockErr == nil {
				remainingSeconds := activeUntil - chainNow
				if remainingSeconds <= 2 {
					wait = 0
				} else {
					wait = time.Duration(max64(1, remainingSeconds/2)) * time.Second
				}
			}
			timer := time.NewTimer(wait)
			select {
			case <-lease.stop:
				timer.Stop()
				return
			case <-timer.C:
			}
			next, renewErr := activate()
			if renewErr != nil {
				log.Printf("[quote-reservation] active transfer renewal failed transfer=%s: %v", req.TransferID, renewErr)
				// Retry promptly; the contract remains conservative if activation
				// ultimately expires and FileRegistration will refuse consumption.
				retry := time.NewTimer(5 * time.Second)
				select {
				case <-lease.stop:
					retry.Stop()
					return
				case <-retry.C:
				}
				continue
			}
			activeUntil = next
		}
	}()
	return lease, nil
}

func escrowRegistrationTimeoutSeconds(cfg ServerConfig) (uint64, error) {
	if !common.IsHexAddress(cfg.VKEscrowContract) {
		return 0, fmt.Errorf("VK escrow contract is not configured")
	}
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{"to": common.HexToAddress(cfg.VKEscrowContract).Hex(), "data": "0x" + hex.EncodeToString(escrowRegistrationTimeoutSelector)},
		"latest",
	})
	if err != nil {
		return 0, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil || len(raw) < 32 {
		return 0, fmt.Errorf("%w: invalid VKEscrow registration timeout", ErrRPCUnavailable)
	}
	timeout, err := decodeUint64ABIWord(raw[len(raw)-32:], "finalizeRegistrationTimeoutSeconds")
	if err != nil || timeout == 0 {
		return 0, fmt.Errorf("invalid VKEscrow registration timeout")
	}
	return timeout, nil
}

func uint64ContractView(rpcURL, contract string, selector []byte, label string) (uint64, error) {
	if !common.IsHexAddress(contract) {
		return 0, fmt.Errorf("%s contract is not configured", label)
	}
	result, err := rpcCall(rpcURL, "eth_call", []any{
		map[string]string{"to": common.HexToAddress(contract).Hex(), "data": "0x" + hex.EncodeToString(selector)},
		"latest",
	})
	if err != nil {
		return 0, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil || len(raw) < 32 {
		return 0, fmt.Errorf("%w: invalid %s response", ErrRPCUnavailable, label)
	}
	return decodeUint64ABIWord(raw[len(raw)-32:], label)
}

func maximumRegistrationTimeoutSeconds(cfg ServerConfig) (uint64, error) {
	value, err := uint64ContractView(
		cfg.RPCURL, cfg.VKEscrowContract, escrowMaxRegistrationTimeoutSelector,
		"VKEscrow.maxRegistrationTimeoutSeconds",
	)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, fmt.Errorf("VKEscrow maximum registration timeout is zero")
	}
	return value, nil
}

func maximumActiveTransferSeconds(cfg ServerConfig) (uint64, error) {
	value, err := uint64ContractView(
		cfg.RPCURL, cfg.CapacityProofContract, capacityMaxActiveTransferSelector,
		"CapacityProofSC.maxActiveTransferSeconds",
	)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, fmt.Errorf("CapacityProofSC maximum active transfer time is zero")
	}
	return value, nil
}

func quoteTransferDeadline(
	chainNow, quoteValidUntil, reservedBytes int64, cfg ServerConfig, maxRegistrationSeconds uint64,
) (int64, error) {
	rate := cfg.QuoteTransferMinBytesPerSecond
	if rate <= 0 {
		rate = DefaultQuoteTransferMinBytesPerSecond
	}
	grace := cfg.QuoteTransferRecoveryGraceSeconds
	if grace <= 0 {
		grace = DefaultQuoteTransferRecoveryGraceSeconds
	}
	transferSeconds := reservedBytes / rate
	if reservedBytes%rate != 0 {
		transferSeconds++
	}
	if transferSeconds > math.MaxInt64-grace {
		return 0, fmt.Errorf("derived transfer deadline overflows")
	}
	transferSeconds += grace
	if quoteValidUntil > math.MaxInt64-transferSeconds {
		return 0, fmt.Errorf("derived transfer deadline overflows")
	}
	deadline := quoteValidUntil + transferSeconds
	if maxRegistrationSeconds > math.MaxInt64 || deadline-chainNow > int64(maxRegistrationSeconds) {
		return 0, fmt.Errorf(
			"piece cannot meet configured registration safety window: required=%ds maximum=%ds",
			deadline-chainNow, maxRegistrationSeconds,
		)
	}
	return deadline, nil
}

func confirmLocalQuoteReservation(storage, transferID, txHash string) error {
	transferStateMu.Lock()
	defer transferStateMu.Unlock()
	record, found, err := loadQuoteReservation(storage, transferID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("durable quote reservation disappeared")
	}
	record.Status = quoteReservationQuoted
	if txHash != "" {
		record.ReservationTxHash = txHash
	}
	record.UpdatedAt = nowRFC3339()
	return persistQuoteReservation(storage, record)
}

func releaseFailedLocalQuoteReservation(storage, transferID string) error {
	transferStateMu.Lock()
	record, found, err := loadQuoteReservation(storage, transferID)
	if err != nil || !found {
		transferStateMu.Unlock()
		return err
	}
	// Only a definitely absent on-chain reservation may use this path.
	record.Status = quoteReservationExpired
	record.UpdatedAt = nowRFC3339()
	if err := persistQuoteReservation(storage, record); err != nil {
		transferStateMu.Unlock()
		return err
	}
	transferStateMu.Unlock()
	return releaseHostFilesystemCapacity(storage, transferID)
}

func reconcileQuoteReservationsOnce(cfg ServerConfig) {
	if cfg.CapacityBytes <= 0 || !common.IsHexAddress(cfg.CapacityProofContract) {
		return
	}
	chainNow, err := rpcLatestBlockTimestamp(cfg.RPCURL)
	if err != nil {
		log.Printf("[quote-reservation] chain time unavailable; preserving every reservation: %v", err)
		return
	}
	reconcileHostFilesystemReservations(cfg, chainNow)
	transferStateMu.Lock()
	records, err := loadAllQuoteReservationsLocked(cfg.Storage)
	transferStateMu.Unlock()
	if err != nil {
		log.Printf("[quote-reservation] local state unreadable; admission remains fail-closed: %v", err)
		return
	}
	for _, record := range records {
		if !quoteReservationConsumesLocalCapacity(record.Status) {
			if err := releaseHostFilesystemCapacity(cfg.Storage, record.TransferID); err != nil {
				log.Printf("[quote-reservation] terminal host reservation release failed transfer=%s: %v", record.TransferID, err)
			}
			continue
		}
		chain, readErr := getCapacityQuoteReservation(cfg, record.RegistrationCommitment)
		if readErr != nil {
			log.Printf("[quote-reservation] RPC uncertain; preserving transfer=%s: %v", record.TransferID, readErr)
			continue
		}
		if chain.State == capacityQuoteQuoted || chain.State == capacityQuoteActiveTransfer {
			if hostErr := reserveHostFilesystemCapacity(cfg, record); hostErr != nil {
				if preserveErr := preserveHostFilesystemCapacity(cfg, record); preserveErr != nil {
					log.Printf("[quote-reservation] authoritative host reservation unavailable transfer=%s: reserve=%v preserve=%v", record.TransferID, hostErr, preserveErr)
				} else {
					log.Printf("[quote-reservation] restored fail-closed host reservation transfer=%s after: %v", record.TransferID, hostErr)
				}
			}
		}
		newStatus := ""
		switch chain.State {
		case capacityQuoteStored:
			newStatus = quoteReservationStored
		case capacityQuoteDeletionPending:
			newStatus = quoteReservationDeletion
		case capacityQuoteReleased:
			newStatus = quoteReservationReleased
		case capacityQuoteExpired:
			newStatus = quoteReservationExpired
		case capacityQuoteQuoted:
			if chainNow <= record.ReservationExpiresAt {
				continue
			}
			if err := expireCapacityQuoteOnChain(cfg, record.RegistrationCommitment); err != nil {
				log.Printf("[quote-reservation] expiry not confirmed; preserving transfer=%s: %v", record.TransferID, err)
				continue
			}
			newStatus = quoteReservationExpired
		case capacityQuoteActiveTransfer:
			if chainNow >= 0 && uint64(chainNow) <= chain.ExpiresAt {
				continue
			}
			if err := expireCapacityQuoteOnChain(cfg, record.RegistrationCommitment); err != nil {
				log.Printf("[quote-reservation] active transfer expiry not confirmed; preserving transfer=%s: %v", record.TransferID, err)
				continue
			}
			newStatus = quoteReservationExpired
		case capacityQuoteNone:
			// A response is returned only after state=Quoted is confirmed. None can
			// therefore be released only after the complete registration window.
			if chainNow <= record.ReservationExpiresAt {
				continue
			}
			newStatus = quoteReservationExpired
		default:
			continue
		}
		transferStateMu.Lock()
		current, found, loadErr := loadQuoteReservation(cfg.Storage, record.TransferID)
		if loadErr == nil && found && quoteReservationConsumesLocalCapacity(current.Status) {
			applyReconciledQuoteStatus(&current, newStatus, chainNow)
			loadErr = persistQuoteReservation(cfg.Storage, current)
		}
		transferStateMu.Unlock()
		if loadErr != nil {
			log.Printf("[quote-reservation] persist reconciliation failed transfer=%s: %v", record.TransferID, loadErr)
			continue
		}
		if !quoteReservationConsumesLocalCapacity(newStatus) {
			if releaseErr := releaseHostFilesystemCapacity(cfg.Storage, record.TransferID); releaseErr != nil {
				log.Printf("[quote-reservation] host reservation release failed transfer=%s: %v", record.TransferID, releaseErr)
				continue
			}
		}
		log.Printf("[quote-reservation] reconciled transfer=%s state=%s", record.TransferID, newStatus)
		forceAdmissionRegistrySync(cfg)
	}
}

// applyReconciledQuoteStatus moves a live reservation to its reconciled
// outcome. Only a delivered quote that was never paid and sent counts against
// its file: one still pending on chain failed on the keeper's own side, and one
// with escrow seen or a transfer under way was paid for.
func applyReconciledQuoteStatus(record *quoteReservationRecord, newStatus string, chainNow int64) {
	if newStatus == quoteReservationExpired && record.Status == quoteReservationQuoted {
		record.UnusedExpiredAt = chainNow
	}
	record.Status = newStatus
	record.UpdatedAt = nowRFC3339()
}

func runQuoteReservationReconciler(stop <-chan struct{}, cfg ServerConfig) {
	reconcileQuoteReservationsOnce(cfg)
	interval := cfg.QuoteReservationReconcileSeconds
	if interval <= 0 {
		interval = DefaultQuoteReservationReconcileSeconds
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			reconcileQuoteReservationsOnce(cfg)
		}
	}
}

func validateQuoteReservationForStore(cfg ServerConfig, req StoreReq, creds PaymentCredentials) error {
	if req.PaymentCommitment == "" || cfg.CapacityBytes <= 0 {
		return nil
	}
	transferStateMu.Lock()
	record, found, err := findQuoteReservationLocked(cfg.Storage, req.TransferID, req.PaymentCommitment)
	transferStateMu.Unlock()
	if err != nil {
		return err
	}
	if !found || record.PieceSize != req.Size ||
		!strings.EqualFold(record.RegistrationCommitment, creds.RegistrationCommitment) {
		return fmt.Errorf("matching durable quote capacity reservation is missing")
	}
	chain, err := getCapacityQuoteReservation(cfg, creds.RegistrationCommitment)
	if err != nil {
		return fmt.Errorf("%w: verify CapacityProofSC quote reservation: %v", ErrRPCUnavailable, err)
	}
	if !strings.EqualFold(chain.VKAddress, cfg.VKAddress) ||
		chain.ReservedCapacityBytes != uint64(record.ReservedCapacityBytes) ||
		(chain.State != capacityQuoteQuoted && chain.State != capacityQuoteActiveTransfer && chain.State != capacityQuoteStored) {
		return fmt.Errorf("authoritative quote capacity reservation does not match transfer")
	}
	return nil
}

func removeUnpublishedQuoteCredentials(storage string, paymentCommitment string) {
	if paymentCommitment == "" {
		return
	}
	if err := os.Remove(paymentCredPath(storage, paymentCommitment)); err != nil && !os.IsNotExist(err) {
		log.Printf("[quote-reservation] cleanup unused credentials failed: %v", err)
	}
}

func isDefiniteNoCapacityReservation(err error) bool {
	return err == nil || !errors.Is(err, ErrRPCUnavailable)
}
