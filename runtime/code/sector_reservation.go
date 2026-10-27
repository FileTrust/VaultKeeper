package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// B.1 sector-cap reservation under a short allocator lock.
//
// Partition selection used to read committed sectors, pick a slot, and only take the partition
// lifecycle lock afterwards. Two uploads could therefore observe the same final free slot and
// both place a sector into it. B.1 introduces a dedicated allocator lock whose ONLY job is the
// short "select a target + record the reservation" transition, and makes every sector-cap count
// include outstanding reservations as well as committed sectors.
//
// Invariants:
//   - the allocator lock is cross-process (flock) and is held for a bounded, tiny window;
//   - no chain RPC, network transfer, artifact construction, proving, or long-running disk work
//     may happen while it is held (enforced by instrumentation, see noteAllocatorForbiddenWork);
//   - a reservation is bound to a stable upload-operation identity AND its physical target
//     (sector ID + partition coordinates), so retrying one operation reuses/reconciles its
//     reservation instead of consuming a second slot;
//   - reservations of different operations are independent: each commits or releases on its own,
//     and neither can be committed or released by another operation.
//
// Durable ownership fields (owner process/host/instance, creation and heartbeat times) are
// written for B.4; the startup sweep and full abandoned-reservation recovery are deferred to B.4.

const sectorSlotReservationVersion = 1

const (
	sectorSlotReservationActive    = "active"
	sectorSlotReservationCommitted = "committed"
)

// allocatorLockHoldBudget bounds how long the allocator lock may be held. Exceeding it does not
// fail the operation but is logged and recorded: it means long work leaked into the section.
var allocatorLockHoldBudget = 250 * time.Millisecond

var (
	// ErrNoFreeSectorSlot means every partition slot is occupied by a committed sector or an
	// outstanding reservation. Callers surface this as a capacity rejection.
	ErrNoFreeSectorSlot = errors.New("no free sector-cap slot")
	// ErrSectorSlotReservationNotOwned protects one operation's reservation from being
	// committed or released by another operation.
	ErrSectorSlotReservationNotOwned = errors.New("sector slot reservation belongs to another upload operation")
)

// sectorSlotReservation records one operation's claim on exactly one sector-cap slot.
type sectorSlotReservation struct {
	Version int `json:"version"`
	// OperationID is the stable upload-operation identity (survives retries and restarts).
	OperationID string `json:"operationId"`
	// Physical target: the selected sector and its partition coordinates.
	SectorID         string `json:"sectorId"`
	PartitionKind    string `json:"partitionKind"`
	DeadlineIndex    int    `json:"deadlineIndex"`
	PartitionIndex   int    `json:"partitionIndex"`
	ExpirationBucket int    `json:"expirationBucket"`

	State       string `json:"state"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	Reconciles  int    `json:"reconciles,omitempty"`
	CommittedAt string `json:"committedAt,omitempty"`

	// Durable ownership for B.4 abandoned-reservation recovery (not swept in B.1).
	OwnerPID        int    `json:"ownerPid,omitempty"`
	OwnerHost       string `json:"ownerHost,omitempty"`
	OwnerInstanceID string `json:"ownerInstanceId,omitempty"`
	LastHeartbeatAt string `json:"lastHeartbeatAt,omitempty"`
}

func (r sectorSlotReservation) bucketKey() partitionBucketKey {
	kind := r.PartitionKind
	if strings.TrimSpace(kind) == "" {
		kind = PartitionKindData
	}
	return partitionBucketKey{
		deadlineIndex: r.DeadlineIndex, partitionIndex: r.PartitionIndex, kind: kind,
	}
}

func (r sectorSlotReservation) active() bool {
	return r.State == sectorSlotReservationActive
}

// vkProcessInstanceID distinguishes this process's reservations from those of a previous run
// with a recycled PID. Generated once per process.
var vkProcessInstanceID = func() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("pid-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}()

func sectorAllocatorDir(storage string) string {
	return filepath.Join(storage, "allocator")
}

func sectorAllocatorLockPath(storage string) string {
	return filepath.Join(sectorAllocatorDir(storage), "allocator.lock")
}

func sectorSlotReservationDir(storage string) string {
	return filepath.Join(sectorAllocatorDir(storage), "reservations")
}

func sectorSlotReservationPath(storage, operationID string) string {
	return filepath.Join(sectorSlotReservationDir(storage), lifecycleOperationID(operationID)+".json")
}

// ── Allocator-lock instrumentation ────────────────────────────────────────────────────────────
//
// The allocator lock must never wrap long-running work. These counters make that provable:
// every instrumented long operation (chain RPC, network transfer, artifact/root construction,
// proving) calls noteAllocatorForbiddenWork, which records a violation if the allocator lock is
// held anywhere in this process at that moment.

var (
	allocatorLockHeldCount    atomic.Int64
	allocatorLockAcquisitions atomic.Int64
	allocatorLockMaxHoldNanos atomic.Int64
	allocatorForbiddenWork    atomic.Int64
	allocatorLastForbidden    atomic.Value // string
	// B.2: taking the allocator lock while a partition lifecycle lock is held would invert the
	// single permitted lock order `allocator (brief) → partition`.
	allocatorLockOrderViolations atomic.Int64
)

func allocatorLockHeldNow() bool { return allocatorLockHeldCount.Load() > 0 }

// noteAllocatorForbiddenWork is called at the entry of every long-running operation that must
// never run under the allocator lock. It is observational: it records and logs a violation
// rather than failing, so instrumentation can never break a live upload.
func noteAllocatorForbiddenWork(kind string) {
	if !allocatorLockHeldByCurrent() {
		return
	}
	allocatorForbiddenWork.Add(1)
	allocatorLastForbidden.Store(kind)
	log.Printf("[allocator ✗] long-running work %q began while the allocator lock was held", kind)
}

type allocatorLockStats struct {
	Acquisitions        int64
	MaxHoldNanos        int64
	ForbiddenWork       int64
	LastForbidden       string
	CurrentlyHeld       bool
	HoldBudgetNano      int64
	LockOrderViolations int64
}

func readAllocatorLockStats() allocatorLockStats {
	last, _ := allocatorLastForbidden.Load().(string)
	return allocatorLockStats{
		Acquisitions:        allocatorLockAcquisitions.Load(),
		MaxHoldNanos:        allocatorLockMaxHoldNanos.Load(),
		ForbiddenWork:       allocatorForbiddenWork.Load(),
		LastForbidden:       last,
		CurrentlyHeld:       allocatorLockHeldNow(),
		HoldBudgetNano:      allocatorLockHoldBudget.Nanoseconds(),
		LockOrderViolations: allocatorLockOrderViolations.Load(),
	}
}

// withSectorAllocatorLock runs fn under the dedicated cross-process allocator lock. fn must do
// only the short selection/reservation transition — never RPC, transfer, proving, or bulk I/O.
func withSectorAllocatorLock(storage string, fn func() error) error {
	if err := os.MkdirAll(sectorSlotReservationDir(storage), 0700); err != nil {
		return fmt.Errorf("create allocator directory: %w", err)
	}
	lock, err := os.OpenFile(sectorAllocatorLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open allocator lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire allocator lock: %w", err)
	}
	// B.2/B.3 lock-order guard: the allocator lock is the OUTERMOST of the three upload-path
	// locks, so it is only ever taken with neither a partition nor the coordination lock held.
	partitionHeld := partitionLockHeldByCurrent()
	coordinationHeld := coordinationLockHeldByCurrent()
	if partitionHeld || coordinationHeld {
		allocatorLockOrderViolations.Add(1)
		log.Printf("[allocator ✗] lock-order inversion: allocator lock taken while an inner lock is held "+
			"(partition=%t coordination=%t)", partitionHeld, coordinationHeld)
	}
	held := time.Now()
	allocatorLockHeldCount.Add(1)
	ownerID := allocatorLockOwners.acquired()
	allocatorLockAcquisitions.Add(1)
	defer func() {
		elapsed := time.Since(held).Nanoseconds()
		for {
			prev := allocatorLockMaxHoldNanos.Load()
			if elapsed <= prev || allocatorLockMaxHoldNanos.CompareAndSwap(prev, elapsed) {
				break
			}
		}
		allocatorLockOwners.released(ownerID)
		allocatorLockHeldCount.Add(-1)
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		if elapsed > allocatorLockHoldBudget.Nanoseconds() {
			log.Printf("[allocator] hold %s exceeded budget %s — long work may have leaked into the allocator section",
				time.Duration(elapsed).Round(time.Millisecond), allocatorLockHoldBudget)
		}
	}()
	return fn()
}

// ── Durable reservation records ───────────────────────────────────────────────────────────────

func readSectorSlotReservationUnlocked(storage, operationID string) (sectorSlotReservation, bool, error) {
	payload, err := os.ReadFile(sectorSlotReservationPath(storage, operationID))
	if os.IsNotExist(err) {
		return sectorSlotReservation{}, false, nil
	}
	if err != nil {
		return sectorSlotReservation{}, false, err
	}
	var record sectorSlotReservation
	if json.Unmarshal(payload, &record) != nil || record.Version != sectorSlotReservationVersion ||
		strings.TrimSpace(record.OperationID) == "" {
		// Unreadable reservation metadata must never silently free a slot that may be in use.
		// Preserve it for B.4 and report it.
		return sectorSlotReservation{}, false, fmt.Errorf("unreadable sector slot reservation for operation %s", operationID)
	}
	return record, true, nil
}

func writeSectorSlotReservationUnlocked(storage string, record sectorSlotReservation) error {
	record.Version = sectorSlotReservationVersion
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sectorSlotReservationDir(storage), 0700); err != nil {
		return err
	}
	return durableAtomicWriteFile(sectorSlotReservationPath(storage, record.OperationID), payload, 0600)
}

func removeSectorSlotReservationUnlocked(storage, operationID string) error {
	err := os.Remove(sectorSlotReservationPath(storage, operationID))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if dir, dirErr := os.Open(sectorSlotReservationDir(storage)); dirErr == nil {
		defer dir.Close()
		_ = dir.Sync()
	}
	return nil
}

// listSectorSlotReservationsUnlocked returns every durable reservation record. A record that
// cannot be decoded is reported rather than ignored: silently skipping it would under-count the
// sector cap and could over-admit.
func listSectorSlotReservationsUnlocked(storage string) ([]sectorSlotReservation, error) {
	entries, err := os.ReadDir(sectorSlotReservationDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []sectorSlotReservation
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(sectorSlotReservationDir(storage), entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		var record sectorSlotReservation
		if json.Unmarshal(payload, &record) != nil || record.Version != sectorSlotReservationVersion ||
			strings.TrimSpace(record.OperationID) == "" {
			return nil, fmt.Errorf("unreadable sector slot reservation %s", entry.Name())
		}
		out = append(out, record)
	}
	return out, nil
}

// activeSectorSlotReservationCount reports how many slots are currently reserved (observability
// and admission reporting).
func activeSectorSlotReservationCount(storage string) (int, error) {
	records, err := listSectorSlotReservationsUnlocked(storage)
	if err != nil {
		return 0, err
	}
	active := 0
	for _, record := range records {
		if record.active() {
			active++
		}
	}
	return active, nil
}

// ── Sanctioned combined-occupancy read protocol ───────────────────────────────────────────────
//
// Reservation records and committed sectors are two separate data sources. Reading them in the
// wrong order can produce a TORN view that omits BOTH states of a slot in transition, because a
// commit makes the sector durable and only THEN unlinks the reservation (the unlink is lock-free
// so it can land between an allocator's two reads):
//
//	unsafe:  read committed (sector not durable yet) → [commit: write sector, unlink] →
//	         read reservations (reservation already gone)  ⇒ slot counted ZERO — over-admission
//
// The only sanctioned order is therefore RESERVATIONS FIRST, COMMITTED SECOND:
//
//	safe:    read reservations → [commit lands anywhere] → read committed
//	         · commit before the reservation read  ⇒ the committed read sees the sector;
//	         · commit after the reservation read   ⇒ the saved reservation still counts;
//	         · a concurrent release can only over-count temporarily, never under-count.
//
// Every site that combines the two views MUST go through loadSectorSlotOccupancySnapshot.
type sectorSlotOccupancySnapshot struct {
	// reservations is the active-reservation snapshot, taken FIRST.
	reservations []sectorSlotReservation
	// state is the committed-sector view, taken SECOND.
	state packedDataPartitionState
}

// sectorSlotSnapshotBarrierForTest, when non-nil, runs between the two reads. Tests use it to
// force the exact interleaving the read protocol defends against. Always nil in production.
var sectorSlotSnapshotBarrierForTest func()

// sectorSlotSnapshotCommittedFirstForTest deliberately restores the UNSAFE order so a test can
// demonstrate that it over-admits and that the safe order does not. Always false in production.
var sectorSlotSnapshotCommittedFirstForTest bool

// loadSectorSlotOccupancySnapshot reads both occupancy sources in the sanctioned order.
// ignoreSectorID excludes one sector from the committed view (an operation's own sector, which a
// crashed earlier attempt may already have written, must not be counted alongside its own
// reservation).
func loadSectorSlotOccupancySnapshot(
	storage string, cfg ServerConfig, ignoreSectorID string,
) (sectorSlotOccupancySnapshot, error) {
	var snapshot sectorSlotOccupancySnapshot
	if sectorSlotSnapshotCommittedFirstForTest {
		state, err := loadPackedDataPartitionState(storage, cfg, ignoreSectorID)
		if err != nil {
			return snapshot, err
		}
		if barrier := sectorSlotSnapshotBarrierForTest; barrier != nil {
			barrier()
		}
		records, err := listSectorSlotReservationsUnlocked(storage)
		if err != nil {
			return snapshot, err
		}
		return sectorSlotOccupancySnapshot{reservations: records, state: state}, nil
	}
	records, err := listSectorSlotReservationsUnlocked(storage)
	if err != nil {
		return snapshot, err
	}
	if barrier := sectorSlotSnapshotBarrierForTest; barrier != nil {
		barrier()
	}
	state, err := loadPackedDataPartitionState(storage, cfg, ignoreSectorID)
	if err != nil {
		return snapshot, err
	}
	return sectorSlotOccupancySnapshot{reservations: records, state: state}, nil
}

// occupied reports committed sectors plus active reservations on a slot, counting a reservation
// whose sector has already become committed exactly once. excludeOperationID omits one
// operation's own reservation (so it never counts itself out of its own slot).
func (s sectorSlotOccupancySnapshot) occupied(key partitionBucketKey, excludeOperationID string) int {
	occupied := s.state.counts[key]
	for _, record := range s.reservations {
		if !record.active() || record.bucketKey() != key {
			continue
		}
		if excludeOperationID != "" && record.OperationID == excludeOperationID {
			continue
		}
		// Deduplicate: this reservation's sector is already counted as committed.
		if s.state.sectorIDs[key][strings.ToLower(record.SectorID)] {
			continue
		}
		occupied++
	}
	return occupied
}

// reservationsOnSlot counts this operation's own active reservations on a slot.
func (s sectorSlotOccupancySnapshot) reservationsOnSlot(key partitionBucketKey, operationID string) int {
	count := 0
	for _, record := range s.reservations {
		if record.active() && record.bucketKey() == key && record.OperationID == operationID {
			count++
		}
	}
	return count
}

// bucketConflict reports whether the slot already holds a sector or another operation's
// reservation of a different expiration bucket.
func (s sectorSlotOccupancySnapshot) bucketConflict(key partitionBucketKey, bucket int, excludeOperationID string) bool {
	if !s.state.sameBucketOnly(key, bucket) {
		return true
	}
	for _, record := range s.reservations {
		if !record.active() || record.bucketKey() != key {
			continue
		}
		if excludeOperationID != "" && record.OperationID == excludeOperationID {
			continue
		}
		if record.ExpirationBucket != bucket {
			return true
		}
	}
	return false
}

func (s sectorSlotOccupancySnapshot) sealed(key partitionBucketKey) bool {
	return s.state.sealed[key]
}

// ── Reserve / commit / release ────────────────────────────────────────────────────────────────

// reserveSectorSlotForUpload atomically (across processes) selects a data-partition target for a
// NEW sector and records the reservation, counting committed sectors AND outstanding
// reservations against the sector cap. Retrying the same upload operation reuses its existing
// reservation — or reconciles it onto a still-valid target — instead of consuming a second slot.
//
// Only the short selection + reservation transition happens under the allocator lock.
func reserveSectorSlotForUpload(
	storage string, cfg ServerConfig, operationID, proposedSectorID string, expirationBucket int,
) (sectorSlotReservation, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return sectorSlotReservation{}, fmt.Errorf("sector slot reservation requires a stable upload-operation identity")
	}
	if strings.TrimSpace(proposedSectorID) == "" {
		return sectorSlotReservation{}, fmt.Errorf("sector slot reservation requires a sector target")
	}
	// B.4: NEW allocation stays closed until startup reservation recovery completes. Retrying an
	// operation that already holds a reservation is still allowed below, so recovery never
	// strands an in-flight upload.
	gateErr := ensureSectorAllocationOpen()
	var reservation sectorSlotReservation
	err := withSectorAllocatorLock(storage, func() error {
		now := nowRFC3339()
		existing, found, readErr := readSectorSlotReservationUnlocked(storage, operationID)
		if readErr != nil {
			return readErr
		}
		if found && existing.State == sectorSlotReservationCommitted {
			// Already converted to committed occupancy; the sector itself now holds the slot.
			reservation = existing
			return nil
		}

		// Sanctioned combined read: reservations first, committed sectors second. This
		// operation's own sector is excluded from the committed view so its own reservation is
		// counted exactly once.
		ownSectorID := proposedSectorID
		if found {
			ownSectorID = existing.SectorID
		}
		if gateErr != nil && !(found && existing.active()) {
			// No existing reservation for this operation: this would be a NEW allocation.
			return gateErr
		}
		snapshot, occErr := loadSectorSlotOccupancySnapshot(storage, cfg, ownSectorID)
		if occErr != nil {
			return occErr
		}

		if found && existing.active() {
			// Retry of the same operation: reuse its slot when the recorded target is still a
			// valid placement, otherwise reconcile the SAME reservation onto a new target.
			stillValid := packedDataPartitionTargetUsable(
				cfg, existing.DeadlineIndex, existing.PartitionIndex, existing.ExpirationBucket,
				snapshot, operationID,
			)
			if stillValid && existing.ExpirationBucket == expirationBucket {
				existing.UpdatedAt = now
				existing.LastHeartbeatAt = now
				existing.OwnerPID, existing.OwnerHost, existing.OwnerInstanceID = ownerIdentity()
				if err := writeSectorSlotReservationUnlocked(storage, existing); err != nil {
					return err
				}
				reservation = existing
				return nil
			}
			dl, pt, selectErr := selectPackedDataPartitionSlot(
				cfg, expirationBucket, existing.SectorID, snapshot, operationID,
			)
			if selectErr != nil {
				return selectErr
			}
			existing.DeadlineIndex, existing.PartitionIndex = dl, pt
			existing.ExpirationBucket = expirationBucket
			existing.PartitionKind = PartitionKindData
			existing.State = sectorSlotReservationActive
			existing.Reconciles++
			existing.UpdatedAt = now
			existing.LastHeartbeatAt = now
			existing.OwnerPID, existing.OwnerHost, existing.OwnerInstanceID = ownerIdentity()
			if err := writeSectorSlotReservationUnlocked(storage, existing); err != nil {
				return err
			}
			reservation = existing
			return nil
		}

		dl, pt, selectErr := selectPackedDataPartitionSlot(
			cfg, expirationBucket, proposedSectorID, snapshot, operationID,
		)
		if selectErr != nil {
			return selectErr
		}
		pid, host, instance := ownerIdentity()
		record := sectorSlotReservation{
			OperationID: operationID, SectorID: proposedSectorID,
			PartitionKind: PartitionKindData, DeadlineIndex: dl, PartitionIndex: pt,
			ExpirationBucket: expirationBucket, State: sectorSlotReservationActive,
			CreatedAt: now, UpdatedAt: now, LastHeartbeatAt: now,
			OwnerPID: pid, OwnerHost: host, OwnerInstanceID: instance,
		}
		if err := writeSectorSlotReservationUnlocked(storage, record); err != nil {
			return err
		}
		reservation = record
		return nil
	})
	if err != nil {
		return sectorSlotReservation{}, err
	}
	return reservation, nil
}

func ownerIdentity() (int, string, string) {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return os.Getpid(), host, vkProcessInstanceID
}

// commitSectorSlotReservation converts one operation's reservation into committed occupancy
// exactly once: the durable sector now holds the slot, so the reservation record is retired.
// It reports true only for the call that performed the conversion. Another operation can never
// commit this reservation — the record is addressed by operation identity and its sector target
// is verified before retirement.
//
// It deliberately does NOT take the allocator lock. Commit is the only reservation transition
// that happens while the caller still holds the target's partition lifecycle lock, and the single
// permitted lock order is `allocator (brief) → partition`; taking the allocator lock here would
// invert it. No lock is needed for correctness:
//
//   - the record is owned exclusively by one upload operation (whose attempts are serialised by
//     the store lifecycle lock), so there is no competing writer;
//   - retirement is a single atomic unlink, so any concurrent reader sees a whole record set;
//   - the sector is made durable BEFORE this call, so the slot can never be observed as
//     "neither committed nor reserved" — a selector that misses the reservation necessarily
//     sees the sector that replaced it.
func commitSectorSlotReservation(storage, operationID, sectorID string) (bool, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return false, fmt.Errorf("commit sector slot reservation requires an upload-operation identity")
	}
	record, found, err := readSectorSlotReservationUnlocked(storage, operationID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil // already converted (or never reserved): not this call's conversion
	}
	if record.OperationID != operationID {
		return false, ErrSectorSlotReservationNotOwned
	}
	if strings.TrimSpace(sectorID) != "" && !strings.EqualFold(record.SectorID, sectorID) {
		return false, fmt.Errorf("%w: reservation targets sector %s, not %s",
			ErrSectorSlotReservationNotOwned, record.SectorID, sectorID)
	}
	if !record.active() {
		return false, nil
	}
	if err := removeSectorSlotReservationUnlocked(storage, operationID); err != nil {
		return false, err
	}
	return true, nil
}

// releaseSectorSlotReservation drops one operation's reservation, making the slot selectable
// again. Another operation can never release this reservation.
func releaseSectorSlotReservation(storage, operationID string) (bool, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return false, fmt.Errorf("release sector slot reservation requires an upload-operation identity")
	}
	released := false
	err := withSectorAllocatorLock(storage, func() error {
		record, found, readErr := readSectorSlotReservationUnlocked(storage, operationID)
		if readErr != nil {
			return readErr
		}
		if !found {
			return nil
		}
		if record.OperationID != operationID {
			return ErrSectorSlotReservationNotOwned
		}
		if err := removeSectorSlotReservationUnlocked(storage, operationID); err != nil {
			return err
		}
		released = true
		return nil
	})
	return released, err
}

// uploadOperationIdentity derives the stable upload-operation identity used to bind a
// reservation. It reuses the store flow's durable capacity-mutation operation ID when present
// (store:<commitmentHash>), and otherwise derives a stable ID from the piece root, so a retry of
// the same upload always resolves to the same reservation.
func uploadOperationIdentity(mutation *capacityMutationLease, meta PieceMeta) string {
	if mutation != nil {
		if id := strings.TrimSpace(mutation.OperationID()); id != "" {
			return id
		}
	}
	return storeCapacityMutationOperationID("", meta.PieceRoot)
}
