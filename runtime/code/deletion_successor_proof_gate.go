package main

// G.4B — the ONE narrow exception to "a pending deletion blocks proving".
//
// THE CONTRADICTION THIS RESOLVES (reproduced live 2026-08-12)
//
// Qualified lifecycle urgency selects exactly the successor identity of an unresolved deletion and
// opens a one-member incremental campaign for it. The capacity proof scheduler then proves with
// `allowPendingDeletion=false`, so `partitionHasPendingDeletion` returned true and the prover
// failed with "partition deletion in progress" on every scan. The campaign sat at `progress=0/1`
// forever, the freeze was never broadcast, and the chain kept reporting `snapshotExists=false`.
//
// The two rules contradicted each other, and G.4's own journal says which one is right:
//
//	SealedContentVersion / SealedContentHash record the immutable post-delete
//	successor that must be proved before confirm.
//	                                   -- DeletionLifecycleOperation, lifecycle_reconcile.go:95-97
//
// So proving the exact declared successor is REQUIRED by G.4, not a weakening of it. Everything
// else on a partition with a pending deletion stays blocked exactly as before.
//
// THE RULE
//
//	exactly one unresolved deletion operation for this partition   (0 or >1 -> fail closed)
//	operation not terminal (satisfied/confirmed) and not quarantined
//	the post-delete successor is durably registered (SuccessorRegisteredAtUnix > 0)
//	the content being proved IS the chain's current ACTIVE revision for this coordinate
//	if the successor was already sealed, it matches that seal exactly (half-seal -> fail closed)
//	the deleted piece is ABSENT from the content being proved
//	the proof is carried by a capacity incremental campaign, not the standalone deletion slot
//	-> ALLOW
//
// The chain-content check plus the deleted-piece-absent check together prove the content is the
// POST-delete revision: if the chain still held the pre-delete revision, content equal to it would
// still carry the deleted piece, and content without the piece would not equal it.
//
//	source/old revision · unrelated partition · wrong successor revision · wrong obligation ·
//	successor not current · deleted piece still present · terminal/quarantined obligation ·
//	standalone proof · any ambiguity
//	-> BLOCK
//
// Read-only: it reads the durable deletion journal and the live partition. It never mutates
// deletion state, never edits a journal, and never bypasses a freeze claim or authority rule.

import (
	"fmt"
	"strings"
)

// deletionSuccessorTerminalPhases are phases where no successor proof is owed any more. Proving
// under a pending deletion is only ever justified while the obligation is still unresolved.
func deletionSuccessorPhaseIsTerminal(phase string) bool {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "satisfied", "confirmed", "released", "completed", "abandoned", "quarantined":
		return true
	}
	return false
}

// exactDeletionSuccessorProofPermitted reports whether `live` is the exact declared successor of a
// single unresolved deletion obligation, and may therefore be proved despite the pending deletion.
//
// The bool is the decision; the string explains an ALLOW for the log. Any error, ambiguity or
// mismatch yields false.
func exactDeletionSuccessorProofPermitted(
	storage, chainCmd string, live PartitionMeta, proofEpochID uint64,
) (bool, string, error) {
	// The standalone deletion slot has its own non-preemptible path and its own rules; this
	// exception exists for the capacity incremental campaign that qualified urgency opens.
	if proofEpochID&standaloneDeletionProofFlag != 0 {
		return false, "", nil
	}
	if live.PartitionKind != PartitionKindData {
		return false, "", nil
	}

	operations, err := listDeletionLifecycleOperations(storage)
	if err != nil {
		return false, "", fmt.Errorf("read deletion lifecycle operations: %w", err)
	}

	// Exactly one unresolved obligation may claim this physical partition. Zero means the pending
	// marker did not come from a declared successor; more than one is ambiguous lineage.
	var matched []DeletionLifecycleOperation
	for _, operation := range operations {
		if operation.DeadlineIndex != live.DeadlineIndex ||
			operation.PartitionIndex != live.PartitionIndex {
			continue
		}
		if deletionSuccessorPhaseIsTerminal(operation.Phase) {
			continue
		}
		matched = append(matched, operation)
	}
	if len(matched) != 1 {
		return false, "", nil
	}
	operation := matched[0]

	// The post-delete successor must be durably registered on chain before anything may be proved
	// under a pending deletion. This anchor is written when the successor is registered
	// (lifecycle_reconcile.go, before any proof-ownership decision), so it is never circular.
	if operation.SuccessorRegisteredAtUnix <= 0 {
		return false, "", nil
	}

	// The content about to be proved must BE the chain's current active revision.
	//
	// ORDERING NOTE (live 2026-08-12): this check must NOT be predicated on
	// `SealedContentHash`/`SealedContentVersion`. Those fields are written at
	// lifecycle_reconcile.go:1533-1534, which is reached only AFTER
	// `directDeletionProofOwnershipDeferred` declines to defer. Once qualified urgency owns the
	// successor that branch defers unconditionally, so the sealed fields are never written, and
	// requiring them here deadlocked the exact path this exception exists to unblock: the campaign
	// waited for a seal that only a post-freeze step could write. Chain state is the authority, and
	// `sealDeletionSuccessorSnapshot` asserts this very same predicate before sealing.
	//
	// DOMAIN NOTE: the comparison stays entirely in the CHAIN (Keccak/ABI) domain.
	// `live.ContentHash` is the PRIVATE local scheduling hash (SHA-256) and must never be compared
	// against a chain hash — doing so produced a false "hash divergence" diagnosis earlier.
	if chainCmd == "" {
		return false, "", nil
	}
	versionStatus, versionErr := partitionVersionStatusOnChain(chainCmd, live)
	if versionErr != nil {
		return false, "", fmt.Errorf("read partition version status: %w", versionErr)
	}
	if !versionStatus.Active {
		// The successor must be the ACTIVE/current registered identity.
		return false, "", nil
	}
	if !partitionMatchesChainContent(versionStatus, live) {
		// The local content is not the exact revision the chain currently holds.
		return false, "", nil
	}

	// If the successor identity has already been sealed, it is immutable: the content being proved
	// must match it exactly. A half-written seal is ambiguous and fails closed.
	sealedHash := strings.TrimSpace(operation.SealedContentHash)
	if sealedHash != "" || operation.SealedContentVersion != 0 {
		if sealedHash == "" || operation.SealedContentVersion == 0 {
			return false, "", nil
		}
		if versionStatus.ContentVersion != operation.SealedContentVersion {
			return false, "", nil
		}
		if !sameRoot(versionStatus.ContentHash, sealedHash) {
			return false, "", nil
		}
	}

	// The deleted piece must be gone from the content being proved. If it is still present this is
	// the pre-delete state, which is exactly what the original gate exists to refuse.
	deletedPiece := strings.TrimSpace(operation.PieceRoot)
	if deletedPiece == "" {
		return false, "", nil
	}
	for _, sector := range live.Sectors {
		for _, pieceRoot := range sector.PieceRoots {
			if sameRoot(pieceRoot, deletedPiece) {
				return false, "", nil
			}
		}
		if strings.TrimSpace(operation.SectorID) != "" &&
			strings.EqualFold(strings.TrimSpace(sector.SectorID), strings.TrimSpace(operation.SectorID)) {
			// The sector the deleted piece lived in must itself have been rewritten or removed;
			// an unchanged sector id carrying the old bytes is not the successor.
			if sameRoot(sector.SectorRoot, operation.PieceRoot) {
				return false, "", nil
			}
		}
	}

	return true, fmt.Sprintf(
		"operation=%s successorVersion=%d successorHash=%s sealed=%t deletedPieceAbsent=true",
		shortDeletionOperationID(operation.CommitmentHash),
		versionStatus.ContentVersion, shortDeletionOperationID(versionStatus.ContentHash),
		sealedHash != "",
	), nil
}

// shortDeletionOperationID trims a hex identifier for logging. It never emits requester, file or
// capability identity — only the operation/content identifiers already present in proof logs.
func shortDeletionOperationID(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 18 {
		return trimmed
	}
	return trimmed[:18]
}
