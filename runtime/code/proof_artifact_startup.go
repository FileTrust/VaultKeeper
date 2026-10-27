package main

import (
	"errors"
	"fmt"
	"sync"
)

// A.2 startup barrier.
//
// The pre-A.2 artifact migration and the owner-safe orphan sweep MUST complete successfully
// before any scheduler, reconciler, recovery worker, or external prover consumes an
// artifact. This barrier is that gate: `runArtifactStartupBarrier` runs migration then sweep
// synchronously and, only on success, opens the gate; `ensureArtifactStartupComplete` is
// checked immediately before every artifact-consuming dispatch and FAILS CLOSED until the
// barrier has opened. If migration/validation fails, the gate stays closed — proving stays
// disabled rather than the error being logged while workers keep running.

type artifactStartupState int

const (
	artifactStartupPending artifactStartupState = iota
	artifactStartupReady
	artifactStartupFailed
)

var (
	artifactStartupMu    sync.Mutex
	artifactStartupPhase = artifactStartupPending
	artifactStartupErr   error
)

// ErrArtifactStartupIncomplete gates artifact consumption before the barrier has opened.
var ErrArtifactStartupIncomplete = errors.New("partition proof artifact startup migration not complete; proving disabled")

// runArtifactStartupBarrier runs the pre-A.2 migration then the owner-safe orphan sweep. On
// success it opens the proving gate; on failure the gate stays closed (proving disabled) and
// the error is returned so the caller can fail closed. It is idempotent once ready.
func runArtifactStartupBarrier(storage string) error {
	artifactStartupMu.Lock()
	defer artifactStartupMu.Unlock()
	if artifactStartupPhase == artifactStartupReady {
		return nil
	}
	if _, err := migratePartitionProofArtifactDirs(storage); err != nil {
		artifactStartupPhase = artifactStartupFailed
		artifactStartupErr = fmt.Errorf("legacy artifact migration failed (proving disabled): %w", err)
		return artifactStartupErr
	}
	if _, err := sweepOrphanPartitionArtifactDirs(storage); err != nil {
		artifactStartupPhase = artifactStartupFailed
		artifactStartupErr = fmt.Errorf("orphan artifact sweep failed (proving disabled): %w", err)
		return artifactStartupErr
	}
	artifactStartupPhase = artifactStartupReady
	artifactStartupErr = nil
	return nil
}

// ensureArtifactStartupComplete fails closed unless the startup barrier has opened. It is the
// authoritative gate checked before any artifact-consuming action, so no worker can invoke
// the external prover on an artifact before migration + sweep have completed successfully.
func ensureArtifactStartupComplete() error {
	artifactStartupMu.Lock()
	defer artifactStartupMu.Unlock()
	switch artifactStartupPhase {
	case artifactStartupReady:
		return nil
	case artifactStartupFailed:
		if artifactStartupErr != nil {
			return artifactStartupErr
		}
		return ErrArtifactStartupIncomplete
	default:
		return ErrArtifactStartupIncomplete
	}
}

// ensureProofArtifactWritesEnabled gates EVERY proof-affecting write transition — freeze,
// re-pin, artifact creation, submit, abandon, reanchor, capacity-epoch open, deletion
// mutation/declaration, and cleanup — behind the same barrier. On barrier failure it fails
// closed so the VK cannot create new proof obligations (uploads) or advance any part of the
// proof-artifact state machine while the existing artifact state is unmigrated or malformed.
func ensureProofArtifactWritesEnabled() error {
	return ensureArtifactStartupComplete()
}

// artifactStartupProofReady reports whether the proving gate is open, for health/readiness.
func artifactStartupProofReady() (bool, string) {
	if err := ensureArtifactStartupComplete(); err != nil {
		return false, err.Error()
	}
	return true, ""
}
