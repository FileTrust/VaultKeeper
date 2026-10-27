package main

// G.4B — durable blocked-admission demand.
//
// A blocked demand records that ONE authenticated, otherwise-valid upload request was refused
// solely because certified capacity was insufficient. It exists so the scheduler can answer a
// single question: would completing one exact unresolved G.4 deletion-release obligation make a
// real pending request admissible before that obligation's lifecycle deadline?
//
// Privacy is a hard requirement, not a nicety. Before deletion begins, the DO–VK relationship
// must not be publicly observable, so the record deliberately contains NO requester identity, no
// file identity, no commitment hash and no VK address. The DemandID is a fresh 32-byte random
// value, and the requester holds an opaque capability token whose SHA-256 is the only thing
// stored. Nothing here is ever written on chain.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const blockedAdmissionDemandVersion = 1

// BlockedDemandState is the demand lifecycle.
type BlockedDemandState string

const (
	BlockedDemandPending       BlockedDemandState = "pending"
	BlockedDemandReadyForRetry BlockedDemandState = "ready_for_retry"
	BlockedDemandConsumed      BlockedDemandState = "consumed"
	BlockedDemandCancelled     BlockedDemandState = "cancelled"
	BlockedDemandExpired       BlockedDemandState = "expired"
)

// BlockedAdmissionDemand is the VK-local durable record.
//
// Deliberately absent: DO address, requester public key, file identifier, commitment hash,
// owner identity, VK address, peer ID. `SessionScope` is a salted, VK-local, non-portable
// bucket used ONLY for per-requester rate limiting; it cannot be correlated to an identity by
// anyone without this VK's local salt, and it never leaves the host.
type BlockedAdmissionDemand struct {
	Version  int    `json:"version"`
	DemandID string `json:"demandId"` // 32 random bytes, hex

	RequestedBytes uint64 `json:"requestedBytes"`

	ObservationBlock   uint64 `json:"observationBlock"`
	SafeAllocatable    uint64 `json:"safeAllocatable"`
	CertifiedShortfall uint64 `json:"certifiedShortfall"`

	CreatedAtUnix              int64 `json:"createdAtUnix"`
	ExpiresAtUnix              int64 `json:"expiresAtUnix"`
	LastConfirmedPendingAtUnix int64 `json:"lastConfirmedPendingAtUnix"`

	State BlockedDemandState `json:"state"`

	// CapabilityHash is SHA-256 of the opaque capability token handed to the requester. The
	// token itself is never persisted, so a stolen durable record cannot be used to poll,
	// cancel or retry the demand.
	CapabilityHash string `json:"capabilityHash"`
	// SessionScope is a local salted bucket for rate limiting only.
	SessionScope string `json:"sessionScope,omitempty"`
}

// blockedDemandLimits bounds the abuse surface.
type blockedDemandLimits struct {
	MaxPerScope int
	MaxTotal    int
	MaxLifetime time.Duration
}

func resolvedBlockedDemandLimits(cfg ServerConfig) blockedDemandLimits {
	// The request's own PendingUntil is applied separately in createBlockedAdmissionDemand.
	// QuoteTransferRecoveryGraceSeconds is only ONE term in that deadline; treating the grace
	// term itself as the whole request lifetime can expire a demand before one conservative
	// proof finishes. Keep the independent abuse cap at thirty minutes and then take
	// min(PendingUntil, cap) below.
	_ = cfg
	return blockedDemandLimits{MaxPerScope: 4, MaxTotal: 64, MaxLifetime: 30 * time.Minute}
}

func blockedDemandDir(storage string) string {
	return filepath.Join(storage, "blocked-admission-demands")
}

func blockedDemandPath(storage, demandID string) string {
	return filepath.Join(blockedDemandDir(storage), demandID+".json")
}

func blockedDemandLockPath(storage string) string {
	return filepath.Join(storage, "blocked-admission-demands.lock")
}

func withBlockedDemandLock(storage string, fn func() error) error {
	if err := os.MkdirAll(blockedDemandDir(storage), 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(blockedDemandLockPath(storage), os.O_CREATE|os.O_RDWR, 0o600)
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

// ─── identity and capability ───────────────────────────────────────────────────────────

// newDemandID returns 32 cryptographically random bytes. It is derived from nothing.
func newDemandID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("blocked demand id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// newCapabilityToken returns the opaque token given to the requester and the hash stored.
func newCapabilityToken() (token, hash string, err error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", fmt.Errorf("blocked demand capability: %w", err)
	}
	token = hex.EncodeToString(raw[:])
	sum := sha256.Sum256(raw[:])
	return token, hex.EncodeToString(sum[:]), nil
}

func capabilityMatches(token, storedHash string) bool {
	raw, err := hex.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 32 {
		return false
	}
	sum := sha256.Sum256(raw)
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(storedHash)) == 1
}

// blockedDemandSessionScope derives the rate-limit bucket. The requester reference is salted
// with a VK-local secret and truncated, so it is a local counting bucket and not a stable
// requester-to-VK identifier that anyone else could reproduce or correlate.
func blockedDemandSessionScope(storage, requesterReference string) string {
	reference := strings.TrimSpace(requesterReference)
	if reference == "" {
		return ""
	}
	salt := blockedDemandLocalSalt(storage)
	sum := sha256.Sum256(append(append([]byte{}, salt...), []byte(reference)...))
	return hex.EncodeToString(sum[:8])
}

// blockedDemandLocalSalt lazily creates a host-local salt. It never leaves the VK.
func blockedDemandLocalSalt(storage string) []byte {
	path := filepath.Join(storage, "blocked-admission-demands.salt")
	if existing, err := os.ReadFile(path); err == nil && len(existing) >= 32 {
		return existing[:32]
	}
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return []byte("filetrust-blocked-demand-fallback-salt")
	}
	_ = os.MkdirAll(storage, 0o700)
	_ = atomicWriteFile(path, salt[:], 0o600)
	return salt[:]
}

// ─── persistence ───────────────────────────────────────────────────────────────────────

func validBlockedDemand(demand BlockedAdmissionDemand) bool {
	if demand.Version != blockedAdmissionDemandVersion {
		return false
	}
	if len(demand.DemandID) != 64 {
		return false
	}
	if _, err := hex.DecodeString(demand.DemandID); err != nil {
		return false
	}
	if demand.RequestedBytes == 0 || demand.CapabilityHash == "" {
		return false
	}
	// A demand with no finite expiry can never qualify; refuse to store one.
	if demand.CreatedAtUnix <= 0 || demand.ExpiresAtUnix <= demand.CreatedAtUnix {
		return false
	}
	switch demand.State {
	case BlockedDemandPending, BlockedDemandReadyForRetry, BlockedDemandConsumed,
		BlockedDemandCancelled, BlockedDemandExpired:
	default:
		return false
	}
	return true
}

func writeBlockedDemand(storage string, demand BlockedAdmissionDemand) error {
	if !validBlockedDemand(demand) {
		return fmt.Errorf("refusing to write an invalid blocked admission demand")
	}
	raw, err := json.MarshalIndent(demand, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(blockedDemandDir(storage), 0o700); err != nil {
		return err
	}
	return atomicWriteFile(blockedDemandPath(storage, demand.DemandID), append(raw, '\n'), 0o600)
}

func readBlockedDemand(storage, demandID string) (BlockedAdmissionDemand, bool, error) {
	raw, err := os.ReadFile(blockedDemandPath(storage, demandID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BlockedAdmissionDemand{}, false, nil
		}
		return BlockedAdmissionDemand{}, false, err
	}
	var demand BlockedAdmissionDemand
	if err := json.Unmarshal(raw, &demand); err != nil {
		return BlockedAdmissionDemand{}, false, fmt.Errorf(
			"blocked admission demand %s is unreadable: %w", demandID, err)
	}
	if !validBlockedDemand(demand) {
		return BlockedAdmissionDemand{}, false, fmt.Errorf(
			"blocked admission demand %s failed validation", demandID)
	}
	return demand, true, nil
}

// listBlockedDemands returns every readable demand. A corrupt file is skipped rather than
// failing the whole sweep: it cannot create urgency, which is the conservative direction.
func listBlockedDemands(storage string) ([]BlockedAdmissionDemand, error) {
	entries, err := os.ReadDir(blockedDemandDir(storage))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	demands := make([]BlockedAdmissionDemand, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		demand, ok, err := readBlockedDemand(storage, id)
		if err != nil || !ok {
			continue
		}
		demands = append(demands, demand)
	}
	sort.Slice(demands, func(i, j int) bool {
		if demands[i].CreatedAtUnix != demands[j].CreatedAtUnix {
			return demands[i].CreatedAtUnix < demands[j].CreatedAtUnix
		}
		return demands[i].DemandID < demands[j].DemandID
	})
	return demands, nil
}

// ─── creation ──────────────────────────────────────────────────────────────────────────

// BlockedDemandRequest is what the quote gate offers when it refuses a request.
type BlockedDemandRequest struct {
	RequestedBytes uint64
	// RequesterReference is used ONLY to derive the local rate-limit bucket and is never
	// persisted in the clear.
	RequesterReference string
	// Authenticated must be true. An unauthenticated request can never create urgency.
	Authenticated bool
	// PendingUntil is the request's own finite expiry. G.4B never invents one.
	PendingUntil time.Time

	ObservationBlock uint64
	SafeAllocatable  uint64
	// ClosureReason must be exactly certified_capacity_insufficient.
	ClosureReason string
	// ReservationCreated must be false — a request that reserved capacity is not blocked.
	ReservationCreated bool
}

var (
	errDemandNotCapacityClosure = errors.New("blocked demand requires the certified-capacity closure reason")
	errDemandNoFiniteExpiry     = errors.New("blocked demand requires a real finite request expiry")
	errDemandUnauthenticated    = errors.New("blocked demand requires an authenticated request")
	errDemandLimitReached       = errors.New("blocked demand limit reached")
)

// createBlockedAdmissionDemand records ONE blocked demand and returns the opaque capability
// token. Every precondition is mandatory.
func createBlockedAdmissionDemand(
	storage string, cfg ServerConfig, request BlockedDemandRequest, now time.Time,
) (BlockedAdmissionDemand, string, error) {
	if !request.Authenticated {
		return BlockedAdmissionDemand{}, "", errDemandUnauthenticated
	}
	if request.ClosureReason != AdmissionClosureCertifiedInsufficient {
		// Every other closure — proof unavailable, storage overload, recovery disagreement,
		// chain or reservation state unreadable, unsafe backlog, authorization or policy
		// rejection — describes a fault or a refusal that a deletion cannot fix.
		return BlockedAdmissionDemand{}, "", errDemandNotCapacityClosure
	}
	if request.ReservationCreated {
		return BlockedAdmissionDemand{}, "", fmt.Errorf(
			"blocked demand requires that no reservation was created")
	}
	if request.RequestedBytes == 0 {
		return BlockedAdmissionDemand{}, "", fmt.Errorf("blocked demand requires a positive size")
	}
	if request.PendingUntil.IsZero() || !request.PendingUntil.After(now) {
		return BlockedAdmissionDemand{}, "", errDemandNoFiniteExpiry
	}

	limits := resolvedBlockedDemandLimits(cfg)
	expires := request.PendingUntil
	if maximum := now.Add(limits.MaxLifetime); expires.After(maximum) {
		expires = maximum
	}
	scope := blockedDemandSessionScope(storage, request.RequesterReference)

	var created BlockedAdmissionDemand
	var token string
	err := withBlockedDemandLock(storage, func() error {
		existing, err := listBlockedDemands(storage)
		if err != nil {
			return err
		}
		totalOutstanding, scopeOutstanding := 0, 0
		for _, demand := range existing {
			if !demandCountsAsOutstanding(demand, now) {
				continue
			}
			totalOutstanding++
			if scope != "" && demand.SessionScope == scope {
				scopeOutstanding++
			}
		}
		if totalOutstanding >= limits.MaxTotal {
			return fmt.Errorf("%w: %d outstanding for this VK", errDemandLimitReached, totalOutstanding)
		}
		if scope != "" && scopeOutstanding >= limits.MaxPerScope {
			return fmt.Errorf("%w: %d outstanding for this requester", errDemandLimitReached, scopeOutstanding)
		}

		id, err := newDemandID()
		if err != nil {
			return err
		}
		issued, hash, err := newCapabilityToken()
		if err != nil {
			return err
		}
		token = issued
		shortfall := uint64(0)
		if request.RequestedBytes > request.SafeAllocatable {
			shortfall = request.RequestedBytes - request.SafeAllocatable
		}
		created = BlockedAdmissionDemand{
			Version:                    blockedAdmissionDemandVersion,
			DemandID:                   id,
			RequestedBytes:             request.RequestedBytes,
			ObservationBlock:           request.ObservationBlock,
			SafeAllocatable:            request.SafeAllocatable,
			CertifiedShortfall:         shortfall,
			CreatedAtUnix:              now.Unix(),
			ExpiresAtUnix:              expires.Unix(),
			LastConfirmedPendingAtUnix: now.Unix(),
			State:                      BlockedDemandPending,
			CapabilityHash:             hash,
			SessionScope:               scope,
		}
		return writeBlockedDemand(storage, created)
	})
	if err != nil {
		return BlockedAdmissionDemand{}, "", err
	}
	return created, token, nil
}

// demandCountsAsOutstanding reports whether a demand still occupies a limit slot.
func demandCountsAsOutstanding(demand BlockedAdmissionDemand, now time.Time) bool {
	switch demand.State {
	case BlockedDemandPending, BlockedDemandReadyForRetry:
		return now.Unix() < demand.ExpiresAtUnix
	default:
		return false
	}
}

// DemandStillPending is the frozen liveness predicate. Only a demand satisfying it may
// contribute to urgency.
func DemandStillPending(demand BlockedAdmissionDemand, now time.Time) bool {
	if demand.State != BlockedDemandPending {
		return false
	}
	if now.Unix() >= demand.ExpiresAtUnix {
		return false
	}
	return true
}

// ─── capability-gated transitions ──────────────────────────────────────────────────────

// confirmBlockedDemandPending refreshes liveness on an authenticated poll. The requester
// proves possession of the capability token; no identity is stored or compared.
func confirmBlockedDemandPending(
	storage, demandID, capabilityToken string, now time.Time,
) (BlockedAdmissionDemand, error) {
	var updated BlockedAdmissionDemand
	err := withBlockedDemandLock(storage, func() error {
		demand, ok, err := readBlockedDemand(storage, demandID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("blocked demand not found")
		}
		if !capabilityMatches(capabilityToken, demand.CapabilityHash) {
			return fmt.Errorf("blocked demand capability mismatch")
		}
		// Ready-for-retry is not a licence to START a new retry after expiry. The quote path
		// calls this before creating any reservation, so this check prevents an expired demand
		// from consuming capacity.
		if now.Unix() >= demand.ExpiresAtUnix {
			return fmt.Errorf("blocked demand has expired")
		}
		if !DemandStillPending(demand, now) && demand.State != BlockedDemandReadyForRetry {
			return fmt.Errorf("blocked demand is no longer pending")
		}
		demand.LastConfirmedPendingAtUnix = now.Unix()
		updated = demand
		return writeBlockedDemand(storage, demand)
	})
	return updated, err
}

// cancelBlockedDemand removes a demand from urgency at the requester's instruction.
func cancelBlockedDemand(storage, demandID, capabilityToken string, now time.Time) error {
	return withBlockedDemandLock(storage, func() error {
		demand, ok, err := readBlockedDemand(storage, demandID)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if !capabilityMatches(capabilityToken, demand.CapabilityHash) {
			return fmt.Errorf("blocked demand capability mismatch")
		}
		demand.State = BlockedDemandCancelled
		demand.LastConfirmedPendingAtUnix = now.Unix()
		return writeBlockedDemand(storage, demand)
	})
}

// markBlockedDemandReadyForRetry is set only after a re-read of block-pinned G.5 state shows the
// request now fits. It reserves nothing.
func markBlockedDemandReadyForRetry(storage, demandID string, now time.Time) error {
	return withBlockedDemandLock(storage, func() error {
		demand, ok, err := readBlockedDemand(storage, demandID)
		if err != nil || !ok {
			return err
		}
		if demand.State != BlockedDemandPending {
			return nil
		}
		demand.State = BlockedDemandReadyForRetry
		demand.LastConfirmedPendingAtUnix = now.Unix()
		return writeBlockedDemand(storage, demand)
	})
}

// consumeBlockedDemand marks a demand consumed. The caller must already have created the normal
// G.5 reservation: capacity is never pre-reserved on a projection.
func consumeBlockedDemand(storage, demandID, capabilityToken string, now time.Time) error {
	return withBlockedDemandLock(storage, func() error {
		demand, ok, err := readBlockedDemand(storage, demandID)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("blocked demand not found")
		}
		if !capabilityMatches(capabilityToken, demand.CapabilityHash) {
			return fmt.Errorf("blocked demand capability mismatch")
		}
		if demand.State != BlockedDemandReadyForRetry {
			return fmt.Errorf("blocked demand is not ready for retry")
		}
		// The quote path already capability-checks expiry before it starts the retry, then calls
		// this only AFTER the normal on-chain reservation is confirmed. Do not strand that real
		// reservation if expiry is crossed between those two operations: consumption is the
		// truthful terminal bookkeeping transition, not permission to create capacity.
		demand.State = BlockedDemandConsumed
		demand.LastConfirmedPendingAtUnix = now.Unix()
		return writeBlockedDemand(storage, demand)
	})
}

// expireBlockedDemands sweeps demands past their expiry. A requester that simply disappears
// releases no capacity, because none was ever reserved for it.
func expireBlockedDemands(storage string, now time.Time) (int, error) {
	expired := 0
	err := withBlockedDemandLock(storage, func() error {
		demands, err := listBlockedDemands(storage)
		if err != nil {
			return err
		}
		for _, demand := range demands {
			if demand.State != BlockedDemandPending && demand.State != BlockedDemandReadyForRetry {
				continue
			}
			if now.Unix() < demand.ExpiresAtUnix {
				continue
			}
			demand.State = BlockedDemandExpired
			if writeErr := writeBlockedDemand(storage, demand); writeErr != nil {
				return writeErr
			}
			expired++
		}
		return nil
	})
	return expired, err
}

// ─── aggregate observability ───────────────────────────────────────────────────────────

// BlockedDemandMetrics are the ONLY blocked-demand values that may be published. They carry no
// identifier, no token and no requester reference.
type BlockedDemandMetrics struct {
	BlockedDemandCount     int           `json:"blockedDemandCount"`
	BlockedDemandBytes     uint64        `json:"blockedDemandBytes"`
	OldestBlockedDemandAge time.Duration `json:"oldestBlockedDemandAge"`
	QualifiedUrgencyCount  int           `json:"qualifiedUrgencyCount"`
}

func collectBlockedDemandMetrics(storage string, now time.Time) (BlockedDemandMetrics, error) {
	demands, err := listBlockedDemands(storage)
	if err != nil {
		return BlockedDemandMetrics{}, err
	}
	metrics := BlockedDemandMetrics{}
	for _, demand := range demands {
		if !DemandStillPending(demand, now) {
			continue
		}
		metrics.BlockedDemandCount++
		metrics.BlockedDemandBytes += demand.RequestedBytes
		if age := now.Sub(time.Unix(demand.CreatedAtUnix, 0)); age > metrics.OldestBlockedDemandAge {
			metrics.OldestBlockedDemandAge = age
		}
	}
	return metrics, nil
}

// ─── quote-gate bridge ─────────────────────────────────────────────────────────────────

// blockedDemandIssuedTokens holds capability tokens for demands created during this process.
// recordBlockedAdmissionDemandForQuote is the production bridge from the G.5 quote gate.
//
// It is best-effort by design: a blocked demand is an optimisation input to the scheduler, and
// failing to record one must never alter the refusal the requester receives.
func recordBlockedAdmissionDemandForQuote(
	cfg ServerConfig, record quoteReservationRecord, safeAllocatable uint64,
	certified CertifiedCapacityAdmissionStatus,
) (BlockedAdmissionDemand, string, bool) {
	if record.ReservedCapacityBytes <= 0 {
		return BlockedAdmissionDemand{}, "", false
	}
	// The request must carry its OWN finite expiry. TransferDeadline is the complete signed
	// request window (quote validity + size-aware transfer + recovery), while QuoteValidUntil
	// covers only the initial escrow action. The thirty-minute demand cap remains independent.
	expiry := record.TransferDeadline
	if expiry <= 0 {
		expiry = record.ReservationExpiresAt
	}
	if expiry <= 0 {
		expiry = record.QuoteValidUntil
	}
	if expiry <= 0 {
		return BlockedAdmissionDemand{}, "", false
	}
	now := time.Now()
	demand, token, err := createBlockedAdmissionDemand(cfg.Storage, cfg, BlockedDemandRequest{
		RequestedBytes: uint64(record.ReservedCapacityBytes),
		// The identity hash is a request-scoped value used only to derive the local salted
		// rate-limit bucket; it is hashed with a host-local secret and never persisted raw.
		RequesterReference: record.IdentityHash,
		Authenticated:      true, // reached only after full quote authentication and validation
		PendingUntil:       time.Unix(expiry, 0),
		ObservationBlock:   certified.ObservationBlock,
		SafeAllocatable:    safeAllocatable,
		ClosureReason:      AdmissionClosureCertifiedInsufficient,
		ReservationCreated: false,
	}, now)
	if err != nil {
		// Limits reached, no finite expiry, or a durable write problem. All are non-fatal.
		return BlockedAdmissionDemand{}, "", false
	}
	// The plaintext capability exists only in this return value and the private QuoteProtocol
	// response. Only its hash is durable.
	return demand, token, true
}
