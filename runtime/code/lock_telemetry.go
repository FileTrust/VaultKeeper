package main

import (
	"bytes"
	"log"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
)

// B.3 lock discipline.
//
// The upload path may hold exactly three locks, in exactly one order, each for a bounded local
// transition:
//
//	allocator (brief: select/reconcile + durably reserve)   — B.1
//	  → partition lifecycle (authoritative recheck + partition-local write) — B.2
//	      → capacity coordination (innermost, where required)
//
// Nothing unbounded — chain RPC, peer/network transfer, ZK-root construction, prover execution —
// may run while ANY of them is held; that work belongs outside all three.
//
// These counters make both rules observable rather than merely documented. They are
// process-wide and observational: a violation is recorded and logged, never fatal, so
// instrumentation can never break a live upload.

var (
	// Lock-class occupancy. partitionLifecycleLocksHeld lives with the partition lock itself;
	// allocatorLockHeldCount lives with the allocator lock.
	coordinationLocksHeld atomic.Int64

	// Long external work observed under each lock class.
	forbiddenWorkUnderAllocator    atomic.Int64
	forbiddenWorkUnderPartition    atomic.Int64
	forbiddenWorkUnderCoordination atomic.Int64
	lastForbiddenWorkKind          atomic.Value // string

	// Ordering violations. Allocator-under-partition/coordination is counted by
	// allocatorLockOrderViolations (declared with the allocator lock).
	coordinationBeforePartitionViolations atomic.Int64

	allocatorLockOwners    lockOwnerTracker
	partitionLockOwners    lockOwnerTracker
	coordinationLockOwners lockOwnerTracker
)

func coordinationLockHeldNow() bool { return coordinationLocksHeld.Load() > 0 }

// The occupancy counters above answer whether a lock is held anywhere in this process.  That is
// useful operational telemetry, but it cannot establish confinement: concurrent proof and
// mutation goroutines legitimately overlap.  Ownership tracking answers the narrower question
// the discipline requires — whether the goroutine starting long work itself owns the lock.
// Go has no public goroutine-local storage API, so this diagnostic-only tracker reads the stable
// numeric prefix emitted by runtime.Stack.  If that format is ever unavailable, it falls back to
// conservative process-wide detection rather than hiding a possible violation.
type lockOwnerTracker struct {
	mu   sync.Mutex
	held map[uint64]int
}

func currentLockOwnerID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	fields := bytes.Fields(buf[:n])
	if len(fields) < 2 || string(fields[0]) != "goroutine" {
		return 0
	}
	id, _ := strconv.ParseUint(string(fields[1]), 10, 64)
	return id
}

func (tracker *lockOwnerTracker) acquired() uint64 {
	id := currentLockOwnerID()
	if id == 0 {
		return 0
	}
	tracker.mu.Lock()
	if tracker.held == nil {
		tracker.held = make(map[uint64]int)
	}
	tracker.held[id]++
	tracker.mu.Unlock()
	return id
}

func (tracker *lockOwnerTracker) released(id uint64) {
	if id == 0 {
		return
	}
	tracker.mu.Lock()
	if tracker.held[id] <= 1 {
		delete(tracker.held, id)
	} else {
		tracker.held[id]--
	}
	tracker.mu.Unlock()
}

func (tracker *lockOwnerTracker) heldByCurrent(processHeld bool) bool {
	id := currentLockOwnerID()
	if id == 0 {
		return processHeld
	}
	tracker.mu.Lock()
	held := tracker.held[id] > 0
	tracker.mu.Unlock()
	return held
}

func allocatorLockHeldByCurrent() bool {
	return allocatorLockOwners.heldByCurrent(allocatorLockHeldNow())
}

func partitionLockHeldByCurrent() bool {
	return partitionLockOwners.heldByCurrent(partitionLifecycleLockHeldNow())
}

func coordinationLockHeldByCurrent() bool {
	return coordinationLockOwners.heldByCurrent(coordinationLockHeldNow())
}

// noteLockConfinedWork is called at the entry of every operation that must never run while an
// upload-path lock is held. It attributes the violation to each lock class that was held.
func noteLockConfinedWork(kind string) {
	violated := false
	allocatorHeld := allocatorLockHeldByCurrent()
	partitionHeld := partitionLockHeldByCurrent()
	coordinationHeld := coordinationLockHeldByCurrent()
	if allocatorHeld {
		forbiddenWorkUnderAllocator.Add(1)
		// Retained for B.1/B.2 compatibility: allocatorLockStats.ForbiddenWork.
		allocatorForbiddenWork.Add(1)
		allocatorLastForbidden.Store(kind)
		violated = true
	}
	if partitionHeld {
		forbiddenWorkUnderPartition.Add(1)
		violated = true
	}
	if coordinationHeld {
		forbiddenWorkUnderCoordination.Add(1)
		violated = true
	}
	if violated {
		lastForbiddenWorkKind.Store(kind)
		log.Printf("[lock ✗] long-running work %q began while an upload-path lock was held "+
			"(allocator=%t partition=%t coordination=%t)",
			kind, allocatorHeld, partitionHeld, coordinationHeld)
	}
}

// noteCoordinationLockAcquired/Released bracket the innermost lock so ordering can be checked.
func noteCoordinationLockAcquired() {
	coordinationLocksHeld.Add(1)
	coordinationLockOwners.acquired()
}
func noteCoordinationLockReleased() {
	coordinationLockOwners.released(currentLockOwnerID())
	coordinationLocksHeld.Add(-1)
}

// notePartitionLockAcquiring is called immediately before a partition lifecycle lock is taken.
// Holding the innermost coordination lock at that moment inverts the permitted order.
func notePartitionLockAcquiring() {
	if coordinationLockHeldByCurrent() {
		coordinationBeforePartitionViolations.Add(1)
		log.Printf("[lock ✗] order inversion: partition lifecycle lock taken while the coordination lock is held")
	}
}

type lockDisciplineStats struct {
	ForbiddenUnderAllocator    int64
	ForbiddenUnderPartition    int64
	ForbiddenUnderCoordination int64
	LastForbiddenKind          string

	AllocatorUnderOuterLock     int64 // allocator taken while partition/coordination held
	CoordinationBeforePartition int64 // partition taken while coordination held
	AllocatorLockAcquisitions   int64
	AllocatorMaxHoldNanos       int64
	PartitionLocksHeldNow       int64
	CoordinationLocksHeldNow    int64
	AllocatorLockCurrentlyHeld  bool
}

func readLockDisciplineStats() lockDisciplineStats {
	last, _ := lastForbiddenWorkKind.Load().(string)
	return lockDisciplineStats{
		ForbiddenUnderAllocator:     forbiddenWorkUnderAllocator.Load(),
		ForbiddenUnderPartition:     forbiddenWorkUnderPartition.Load(),
		ForbiddenUnderCoordination:  forbiddenWorkUnderCoordination.Load(),
		LastForbiddenKind:           last,
		AllocatorUnderOuterLock:     allocatorLockOrderViolations.Load(),
		CoordinationBeforePartition: coordinationBeforePartitionViolations.Load(),
		AllocatorLockAcquisitions:   allocatorLockAcquisitions.Load(),
		AllocatorMaxHoldNanos:       allocatorLockMaxHoldNanos.Load(),
		PartitionLocksHeldNow:       partitionLifecycleLocksHeld.Load(),
		CoordinationLocksHeldNow:    coordinationLocksHeld.Load(),
		AllocatorLockCurrentlyHeld:  allocatorLockHeldNow(),
	}
}

// totalViolations is the single number a "clean run" assertion checks.
func (s lockDisciplineStats) totalViolations() int64 {
	return s.ForbiddenUnderAllocator + s.ForbiddenUnderPartition + s.ForbiddenUnderCoordination +
		s.AllocatorUnderOuterLock + s.CoordinationBeforePartition
}

// partitionWriteBarrierForTest, when non-nil, runs at the partition-local write transition —
// inside the partition lifecycle lock for new sectors. Tests use it to prove that uploads on
// different partitions overlap there. Always nil in production.
var partitionWriteBarrierForTest func(deadlineIndex, partitionIndex int)
