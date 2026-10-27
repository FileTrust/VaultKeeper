package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Capacity partitions are built by the proof-daemon process while data-sector
// mutations happen in the VK server process. These errors are retryable: they
// mean that publishing the local capacity snapshot would not currently be an
// exact, stable representation of the VK's storage.
var ErrCapacityPublicationDeferred = errors.New("capacity snapshot publication deferred")

const capacityMutationRecordVersion = 1

type capacityMutationRecord struct {
	Version      int    `json:"version"`
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	PID          int    `json:"pid"`
	ProcessStart string `json:"processStart,omitempty"`
	StartedAt    string `json:"startedAt"`
}

type capacityMutationLease struct {
	storage         string
	path            string
	operationID     string
	journalSequence uint64
	once            sync.Once
}

var capacityMutationSequence atomic.Uint64

func capacityCoordinationDir(storage string) string {
	return filepath.Join(storage, "capacity-coordination")
}

func capacityCoordinationLockPath(storage string) string {
	return filepath.Join(capacityCoordinationDir(storage), "publication.lock")
}

func capacityBuildLockPath(storage string) string {
	return filepath.Join(capacityCoordinationDir(storage), "build.lock")
}

func capacityChainPublicationLockPath(storage string) string {
	return filepath.Join(capacityCoordinationDir(storage), "chain-publication.lock")
}

func capacityMutationDir(storage string) string {
	return filepath.Join(capacityCoordinationDir(storage), "mutations")
}

func withCapacityCoordinationLock(storage string, fn func() error) error {
	if strings.TrimSpace(storage) == "" {
		return fmt.Errorf("capacity coordination requires a storage directory")
	}
	if err := os.MkdirAll(capacityCoordinationDir(storage), 0700); err != nil {
		return fmt.Errorf("create capacity coordination directory: %w", err)
	}
	file, err := os.OpenFile(capacityCoordinationLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open capacity publication lock: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire capacity publication lock: %w", err)
	}
	// B.3: the coordination lock is the innermost of the three upload-path locks.
	noteCoordinationLockAcquired()
	defer noteCoordinationLockReleased()
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

// withCapacityChainPublicationLock is the cross-process transaction barrier for publishing an
// exact capacity snapshot.  It is deliberately distinct from the short upload-path coordination
// lock: chain RPC may run while this barrier is held, but never while the coordination lock is
// held.  Mutation waiters cross the same barrier after publishing their durable intent.
func withCapacityChainPublicationLock(storage string, fn func() error) error {
	if strings.TrimSpace(storage) == "" {
		return fmt.Errorf("capacity chain publication requires a storage directory")
	}
	if err := os.MkdirAll(capacityCoordinationDir(storage), 0700); err != nil {
		return fmt.Errorf("create capacity coordination directory: %w", err)
	}
	file, err := os.OpenFile(capacityChainPublicationLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open capacity chain publication lock: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire capacity chain publication lock: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return fn()
}

// acquireCapacityBuildLock serializes rebuilds for one VK across the server,
// proof daemon, and maintenance commands. It does not block transfers: the
// long-lived build lock is distinct from the short publication lock.
func acquireCapacityBuildLock(storage string) (*os.File, error) {
	if strings.TrimSpace(storage) == "" {
		return nil, fmt.Errorf("capacity build coordination requires a storage directory")
	}
	if err := os.MkdirAll(capacityCoordinationDir(storage), 0700); err != nil {
		return nil, fmt.Errorf("create capacity coordination directory: %w", err)
	}
	file, err := os.OpenFile(capacityBuildLockPath(storage), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open capacity build lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire capacity build lock: %w", err)
	}
	return file, nil
}

func releaseCapacityBuildLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

// linuxProcessStartToken is stable for the lifetime of a process and prevents
// a stale lease from becoming live again if its PID is later reused.
func linuxProcessStartToken(pid int) string {
	payload, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	// The command name (field 2) is parenthesized and may contain spaces. The
	// remaining fields begin at field 3; process start time is field 22.
	end := strings.LastIndexByte(string(payload), ')')
	if end < 0 || end+1 >= len(payload) {
		return ""
	}
	fields := strings.Fields(string(payload[end+1:]))
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}

func capacityMutationRecordLive(record capacityMutationRecord) bool {
	if record.Version != capacityMutationRecordVersion || record.PID <= 0 || record.ID == "" {
		return false
	}
	if err := syscall.Kill(record.PID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	if record.ProcessStart != "" {
		current := linuxProcessStartToken(record.PID)
		if current == "" || current != record.ProcessStart {
			return false
		}
	}
	return true
}

func durableRemoveCapacityMutationRecord(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// liveCapacityMutationsLocked returns all live mutation leases and removes
// malformed/crash-stale records. The caller must hold the publication lock.
func liveCapacityMutationsLocked(storage string) ([]capacityMutationRecord, error) {
	dir := capacityMutationDir(storage)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]capacityMutationRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		payload, readErr := os.ReadFile(path)
		var record capacityMutationRecord
		if readErr != nil || json.Unmarshal(payload, &record) != nil || !capacityMutationRecordLive(record) {
			if removeErr := durableRemoveCapacityMutationRecord(path); removeErr != nil {
				return nil, fmt.Errorf("remove stale capacity mutation lease %s: %w", entry.Name(), removeErr)
			}
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

// beginCapacityMutation publishes intent before a process changes sector state.
// The durable waiter record is installed before waiting for the publication
// lock. This gives foreground work priority between partition transactions: a
// publisher finishing one transaction sees the waiter and cannot immediately
// begin another. The lock acquisition is still required as a barrier, so the
// caller cannot mutate local state while an already-started chain transaction
// is in flight.
func beginCapacityMutation(storage, kind string) (*capacityMutationLease, error) {
	if strings.TrimSpace(storage) == "" {
		return nil, fmt.Errorf("capacity mutation requires a storage directory")
	}
	if err := os.MkdirAll(capacityMutationDir(storage), 0700); err != nil {
		return nil, fmt.Errorf("create capacity mutation directory: %w", err)
	}
	sequence := capacityMutationSequence.Add(1)
	id := fmt.Sprintf("%d-%d-%d", os.Getpid(), time.Now().UnixNano(), sequence)
	record := capacityMutationRecord{
		Version:      capacityMutationRecordVersion,
		ID:           id,
		Kind:         strings.TrimSpace(kind),
		PID:          os.Getpid(),
		ProcessStart: linuxProcessStartToken(os.Getpid()),
		StartedAt:    nowRFC3339(),
	}
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(capacityMutationDir(storage), id+".json")
	if err := durableAtomicWriteFile(path, payload, 0600); err != nil {
		return nil, fmt.Errorf("persist capacity mutation lease: %w", err)
	}
	lease := &capacityMutationLease{storage: storage, path: path}

	// Crossing the lock is a publication barrier. The record already prevents
	// new publication attempts, while an attempt that passed its pre-check before
	// this record was installed must finish before this function returns.
	err = withCapacityChainPublicationLock(storage, func() error {
		return withCapacityCoordinationLock(storage, func() error {
			if _, err := liveCapacityMutationsLocked(storage); err != nil {
				return err
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("capacity mutation lease disappeared before barrier: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		if removeErr := durableRemoveCapacityMutationRecord(path); removeErr != nil {
			log.Printf("[capacity] failed to remove rejected mutation lease %s: %v", path, removeErr)
		}
		return nil, err
	}
	return lease, nil
}

func (lease *capacityMutationLease) Release() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		if err := withCapacityCoordinationLock(lease.storage, func() error {
			return durableRemoveCapacityMutationRecord(lease.path)
		}); err != nil {
			// Leaving a live lease is safe (publication remains deferred), and the
			// next coordination pass will remove it after this process exits.
			log.Printf("[capacity] mutation lease release warning: %v", err)
		}
	})
}

func capacityPublicationGuardLocked(storage string) error {
	records, err := liveCapacityMutationsLocked(storage)
	if err != nil {
		return err
	}
	planned, err := plannedCapacityMutationRecordsUnlocked(storage)
	if err != nil {
		return err
	}
	if len(records) == 0 && len(planned) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(records)+len(planned))
	for _, record := range records {
		kind := record.Kind
		if kind == "" {
			kind = "unknown"
		}
		kinds = append(kinds, kind)
	}
	for _, record := range planned {
		kind := record.MutationType
		if kind == "" {
			kind = "unknown-planned"
		}
		kinds = append(kinds, kind)
	}
	return fmt.Errorf("%w: %d live and %d crash-recoverable mutation(s) active (%s)",
		ErrCapacityPublicationDeferred, len(records), len(planned), strings.Join(kinds, ", "))
}
