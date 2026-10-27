package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// B.4 reservation recovery — operation-driven reconciliation plus a startup orphan sweep.
//
// A B.1 sector-cap reservation is durable, so a crash can leave one behind. Recovering it wrongly
// is dangerous in one direction only: releasing a slot whose sector actually exists would let the
// cap be exceeded and could relocate a durable sector's slot. B.4 therefore never releases on
// evidence of *liveness* — PID, host, process instance, heartbeat age and expiry are diagnostic
// only. Release requires positive proof from the owning operation journal AND authoritative local
// sector state.
//
// Order: the operation-driven path runs FIRST whenever the owning upload operation still exists;
// the sweep handles only what is left unresolved after that.

const sectorSlotRecoveryMetricsVersion = 1

// Reservation recovery classifications.
const (
	reservationClassLiveOperation   = "live_operation"
	reservationClassCommittedSector = "committed_sector"
	reservationClassSafeToRelease   = "safe_to_release"
	reservationClassAmbiguous       = "ambiguous"
	reservationClassCorrupt         = "corrupt"
)

// reservationRecoveryFacts is everything the classifier is allowed to consider. Owner liveness is
// deliberately absent: it can never justify releasing a slot.
type reservationRecoveryFacts struct {
	RecordReadable bool
	// Owning upload-operation journal.
	OperationReadable bool
	OperationFound    bool
	OperationTerminal bool
	// Authoritative local sector state for the EXACT reserved target.
	SectorDurableAtReservedTarget bool
	SectorProvablyAbsent          bool
}

// classifyReservationRecovery is pure. Precedence is safety-ordered:
//
//	corrupt           — nothing may be concluded; fail closed
//	committed_sector  — the exact reserved sector is durable; the slot is occupied, not free
//	live_operation    — the owning operation still exists and is not terminal; leave it alone
//	safe_to_release   — operation absent or terminal AND the sector is provably not durable
//	ambiguous         — anything else; preserve and degrade health
func classifyReservationRecovery(facts reservationRecoveryFacts) string {
	if !facts.RecordReadable {
		return reservationClassCorrupt
	}
	if facts.SectorDurableAtReservedTarget {
		return reservationClassCommittedSector
	}
	if !facts.OperationReadable {
		return reservationClassAmbiguous
	}
	if facts.OperationFound && !facts.OperationTerminal {
		return reservationClassLiveOperation
	}
	if (!facts.OperationFound || facts.OperationTerminal) && facts.SectorProvablyAbsent {
		return reservationClassSafeToRelease
	}
	return reservationClassAmbiguous
}

// ── Fact gathering ────────────────────────────────────────────────────────────────────────────

// reservationOwningOperation finds the upload-operation journal that owns a reservation, matching
// on the STABLE upload-operation identity rather than on any path or timestamp.
func reservationOwningOperation(storage, operationID string) (StoreLifecycleOperation, bool, bool, error) {
	operations, err := listStoreLifecycleOperations(storage)
	if err != nil {
		// The journal is unreadable: nothing may be concluded about ownership.
		return StoreLifecycleOperation{}, false, false, err
	}
	for _, operation := range operations {
		if storeCapacityMutationOperationID(operation.CommitmentHash, operation.PieceRoot) == operationID {
			return operation, true, true, nil
		}
		// Legacy identity derived from the piece root alone.
		if storeCapacityMutationOperationID("", operation.PieceRoot) == operationID {
			return operation, true, true, nil
		}
	}
	return StoreLifecycleOperation{}, false, true, nil
}

// gatherReservationRecoveryFacts reads the reservation, its owning operation, and authoritative
// local sector state.
func gatherReservationRecoveryFacts(
	storage string, record sectorSlotReservation, recordReadable bool,
) reservationRecoveryFacts {
	facts := reservationRecoveryFacts{RecordReadable: recordReadable}
	if !recordReadable {
		return facts
	}
	operation, found, readable, err := reservationOwningOperation(storage, record.OperationID)
	facts.OperationReadable = readable && err == nil
	facts.OperationFound = found
	facts.OperationTerminal = found && operation.Terminal

	sector, err := readSector(storage, record.SectorID)
	switch {
	case err == nil:
		// The EXACT reserved target: same sector, still assigned to the reserved coordinates.
		if strings.EqualFold(sector.SectorID, record.SectorID) && sector.Status != "deleted" &&
			sector.PartitionAssigned &&
			sector.DeadlineIndex == record.DeadlineIndex && sector.PartitionIndex == record.PartitionIndex {
			facts.SectorDurableAtReservedTarget = true
		}
		// A sector that exists but does not match the reserved target proves nothing either way.
	case os.IsNotExist(err):
		facts.SectorProvablyAbsent = true
	default:
		// Unreadable sector state: neither durable nor provably absent → ambiguous.
	}
	return facts
}

// ── Terminal action, revalidated under the allocator lock ─────────────────────────────────────

// finalizeReservationRecovery performs the single terminal action for one reservation. It takes
// the allocator lock (never a partition lock, so no inversion is possible), REVALIDATES that the
// reservation record is byte-for-byte the one that was classified, and only then acts. Two
// processes racing therefore produce exactly one terminal action: the loser sees a changed or
// absent record and does nothing.
func finalizeReservationRecovery(storage string, expected sectorSlotReservation, class string) (bool, error) {
	if class != reservationClassCommittedSector && class != reservationClassSafeToRelease {
		return false, nil // preserve-only classes never modify anything
	}
	acted := false
	err := withSectorAllocatorLock(storage, func() error {
		current, found, readErr := readSectorSlotReservationUnlocked(storage, expected.OperationID)
		if readErr != nil {
			return readErr
		}
		if !found || current != expected {
			// Superseded by the owning operation or another recovery pass: not our action.
			return nil
		}
		if err := removeSectorSlotReservationUnlocked(storage, expected.OperationID); err != nil {
			return err
		}
		acted = true
		return nil
	})
	return acted, err
}

// ── Metrics ───────────────────────────────────────────────────────────────────────────────────

type sectorSlotRecoveryMetrics struct {
	Version                    int    `json:"version"`
	LastSweepAt                string `json:"lastSweepAt"`
	Active                     int    `json:"activeReservations"`
	RecoveredCommitted         int    `json:"recoveredAsCommitted"`
	ReleasedAbandoned          int    `json:"releasedAbandoned"`
	RetainedAmbiguous          int    `json:"retainedAmbiguous"`
	RetainedLive               int    `json:"retainedLiveOperation"`
	Corrupt                    int    `json:"corruptUnreadable"`
	OldestUnresolvedAgeSeconds int64  `json:"oldestUnresolvedAgeSeconds"`
	LastError                  string `json:"lastError,omitempty"`
	RecoveryComplete           bool   `json:"startupRecoveryComplete"`
}

func sectorSlotRecoveryMetricsPath(storage string) string {
	return filepath.Join(sectorAllocatorDir(storage), "reservation-recovery.json")
}

func readSectorSlotRecoveryMetrics(storage string) (sectorSlotRecoveryMetrics, bool, error) {
	payload, err := os.ReadFile(sectorSlotRecoveryMetricsPath(storage))
	if os.IsNotExist(err) {
		return sectorSlotRecoveryMetrics{}, false, nil
	}
	if err != nil {
		return sectorSlotRecoveryMetrics{}, false, err
	}
	var metrics sectorSlotRecoveryMetrics
	if json.Unmarshal(payload, &metrics) != nil || metrics.Version != sectorSlotRecoveryMetricsVersion {
		return sectorSlotRecoveryMetrics{}, false, nil
	}
	return metrics, true, nil
}

func writeSectorSlotRecoveryMetrics(storage string, metrics sectorSlotRecoveryMetrics) error {
	metrics.Version = sectorSlotRecoveryMetricsVersion
	payload, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sectorAllocatorDir(storage), 0700); err != nil {
		return err
	}
	return durableAtomicWriteFile(sectorSlotRecoveryMetricsPath(storage), payload, 0600)
}

// ── Operation-driven reconciliation, then the sweep ───────────────────────────────────────────

// reconcileSectorSlotReservationForOperation is the operation-driven path. It classifies one
// operation's reservation and takes at most one terminal action. A live operation's reservation
// is preserved so the same operation can reuse or reconcile it.
func reconcileSectorSlotReservationForOperation(storage, operationID string) (string, bool, error) {
	record, found, err := readSectorSlotReservationUnlocked(storage, operationID)
	if err != nil {
		return reservationClassCorrupt, false, err
	}
	if !found {
		return "", false, nil
	}
	facts := gatherReservationRecoveryFacts(storage, record, true)
	class := classifyReservationRecovery(facts)
	acted, actErr := finalizeReservationRecovery(storage, record, class)
	return class, acted, actErr
}

// sweepSectorSlotReservations runs operation-driven reconciliation for every durable reservation
// first, then classifies whatever remains. It is idempotent: repeated runs converge and never
// double-commit, double-release, or relocate a slot.
func sweepSectorSlotReservations(storage string, now time.Time) (sectorSlotRecoveryMetrics, error) {
	metrics := sectorSlotRecoveryMetrics{LastSweepAt: now.UTC().Format(time.RFC3339Nano)}

	entries, err := os.ReadDir(sectorSlotReservationDir(storage))
	if os.IsNotExist(err) {
		metrics.RecoveryComplete = true
		return metrics, writeSectorSlotRecoveryMetrics(storage, metrics)
	}
	if err != nil {
		metrics.LastError = err.Error()
		_ = writeSectorSlotRecoveryMetrics(storage, metrics)
		return metrics, err
	}

	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(sectorSlotReservationDir(storage), entry.Name())
		payload, readErr := os.ReadFile(path)
		var record sectorSlotReservation
		readable := readErr == nil &&
			json.Unmarshal(payload, &record) == nil &&
			record.Version == sectorSlotReservationVersion &&
			strings.TrimSpace(record.OperationID) != ""
		if !readable {
			// Corrupt metadata fails CLOSED: the capacity it may represent stays consumed and
			// the condition is exposed, never silently treated as a free slot.
			metrics.Corrupt++
			metrics.Active++
			if firstErr == nil {
				firstErr = fmt.Errorf("unreadable sector slot reservation %s", entry.Name())
			}
			log.Printf("[reservation-recovery ✗] unreadable reservation %s: capacity preserved, operator action required", entry.Name())
			continue
		}
		if !record.active() {
			continue
		}

		facts := gatherReservationRecoveryFacts(storage, record, true)
		class := classifyReservationRecovery(facts)
		acted, actErr := finalizeReservationRecovery(storage, record, class)
		if actErr != nil {
			if firstErr == nil {
				firstErr = actErr
			}
			metrics.RetainedAmbiguous++
			metrics.Active++
			continue
		}
		switch class {
		case reservationClassCommittedSector:
			if acted {
				metrics.RecoveredCommitted++
			}
			// The durable sector now holds the slot; it is NOT free.
		case reservationClassSafeToRelease:
			if acted {
				metrics.ReleasedAbandoned++
			}
		case reservationClassLiveOperation:
			metrics.RetainedLive++
			metrics.Active++
		default:
			metrics.RetainedAmbiguous++
			metrics.Active++
			log.Printf("[reservation-recovery] ambiguous reservation op=%s dl%d-pt%d preserved",
				record.OperationID, record.DeadlineIndex, record.PartitionIndex)
		}
		if class != reservationClassCommittedSector && class != reservationClassSafeToRelease {
			if age := unresolvedReservationAgeSeconds(record, now); age > metrics.OldestUnresolvedAgeSeconds {
				metrics.OldestUnresolvedAgeSeconds = age
			}
		}
	}

	if firstErr != nil {
		metrics.LastError = firstErr.Error()
	}
	metrics.RecoveryComplete = firstErr == nil
	writeErr := writeSectorSlotRecoveryMetrics(storage, metrics)
	if firstErr != nil {
		return metrics, firstErr
	}
	return metrics, writeErr
}

func unresolvedReservationAgeSeconds(record sectorSlotReservation, now time.Time) int64 {
	created, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.CreatedAt))
	if err != nil {
		return 0
	}
	if age := int64(now.Sub(created).Seconds()); age > 0 {
		return age
	}
	return 0
}

// ── Startup barrier: allocation stays closed until recovery completes ─────────────────────────

const (
	sectorAllocationPending = "pending"
	sectorAllocationReady   = "ready"
	sectorAllocationFailed  = "failed"
)

var (
	sectorAllocationMu    sync.Mutex
	sectorAllocationPhase = sectorAllocationPending
	sectorAllocationErr   error
)

// ensureSectorAllocationOpen gates NEW upload allocation. Downloads and durable deletion
// acceptance are unaffected — only slot allocation is closed.
func ensureSectorAllocationOpen() error {
	sectorAllocationMu.Lock()
	defer sectorAllocationMu.Unlock()
	switch sectorAllocationPhase {
	case sectorAllocationReady:
		return nil
	case sectorAllocationFailed:
		return fmt.Errorf("sector slot allocation is closed: reservation recovery failed: %w", sectorAllocationErr)
	default:
		return fmt.Errorf("sector slot allocation is closed until startup reservation recovery completes")
	}
}

func setSectorAllocationPhase(phase string, err error) {
	sectorAllocationMu.Lock()
	defer sectorAllocationMu.Unlock()
	sectorAllocationPhase = phase
	sectorAllocationErr = err
}

func sectorAllocationOpen() bool {
	sectorAllocationMu.Lock()
	defer sectorAllocationMu.Unlock()
	return sectorAllocationPhase == sectorAllocationReady
}

// runSectorSlotRecoveryBarrier is the startup ordering required before new upload allocation
// opens:
//
//	load durable upload-operation journals
//	→ run operation-driven reservation reconciliation
//	→ sweep the remaining reservations
//	→ verify reservation metadata is readable
//	→ open the allocator/admission gate
//
// A failed or incomplete sweep leaves allocation CLOSED.
func runSectorSlotRecoveryBarrier(storage string) error {
	setSectorAllocationPhase(sectorAllocationPending, nil)

	// 1. Durable upload-operation journals must be readable before anything is concluded.
	if _, err := listStoreLifecycleOperations(storage); err != nil {
		setSectorAllocationPhase(sectorAllocationFailed, err)
		return fmt.Errorf("reservation recovery: read upload operation journals: %w", err)
	}

	// 2/3. Operation-driven reconciliation runs first, inside the sweep, for every reservation
	// whose owning operation still exists; the sweep then resolves the remainder.
	metrics, err := sweepSectorSlotReservations(storage, time.Now())
	if err != nil {
		setSectorAllocationPhase(sectorAllocationFailed, err)
		return fmt.Errorf("reservation recovery sweep: %w", err)
	}

	// 4. Reservation metadata must be readable end to end.
	if _, err := listSectorSlotReservationsUnlocked(storage); err != nil {
		setSectorAllocationPhase(sectorAllocationFailed, err)
		return fmt.Errorf("reservation recovery: reservation metadata unreadable: %w", err)
	}
	if metrics.Corrupt > 0 {
		err := fmt.Errorf("%d unreadable sector slot reservation(s) require operator action", metrics.Corrupt)
		setSectorAllocationPhase(sectorAllocationFailed, err)
		return err
	}

	// 5. Only now does allocation open.
	setSectorAllocationPhase(sectorAllocationReady, nil)
	log.Printf("[reservation-recovery] complete: committed=%d released=%d ambiguous=%d live=%d active=%d",
		metrics.RecoveredCommitted, metrics.ReleasedAbandoned, metrics.RetainedAmbiguous,
		metrics.RetainedLive, metrics.Active)
	return nil
}
