package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A.2.5 cross-process atomic freeze claiming (review round: point 1).
//
// A pure decision followed later by the on-chain freeze is a TOCTOU race: two processes can
// both observe "slot free", both be granted, and both broadcast — the contract lets one win
// and the loser thrashes on retry. This closes that window with a durable, GENERATION-BOUND
// authority claim established ATOMICALLY under the per-partition cross-process flock:
//
//   acquire per-partition flock
//     → gather chain-reconciled inputs → arbitrate
//     → refuse if the OTHER authority holds an unexpired claim
//     → else (if this authority is granted) persist a fresh claim with a bumped sequence
//   release flock
//   ... a process MUST revalidate its exact claim (authority + sequence, unexpired)
//       immediately before broadcasting the freeze; a superseded/expired claim defers.
//
// Same-authority double-run is handled by the sequence: the later acquire bumps the seq, so
// the earlier holder fails revalidation and defers — exactly one broadcasts. A crashed
// claimant's claim expires after freezeClaimTTL, so the slot is never deadlocked.

const partitionFreezeClaimVersion = 1

var freezeClaimTTL = 15 * time.Minute

// freeze broadcast-attempt states (A.2.5 ambiguous-broadcast closure).
const (
	freezeAttemptNone             = ""
	freezeAttemptBroadcastPending = "broadcast_pending"
	freezeAttemptConfirmed        = "confirmed"
	freezeAttemptFailed           = "failed"
)

type partitionFreezeClaim struct {
	Version        int    `json:"version"`
	PartitionKind  string `json:"partitionKind"`
	DeadlineIndex  int    `json:"deadlineIndex"`
	PartitionIndex int    `json:"partitionIndex"`
	Authority      string `json:"authority"` // "capacity" | "deletion"
	ClaimSeq       uint64 `json:"claimSeq"`
	ClaimedAtUnix  int64  `json:"claimedAtUnix"`
	ExpiresAtUnix  int64  `json:"expiresAtUnix"`

	// ConsecutiveDeletionGrants counts how many times in a row this partition's single slot
	// has gone to a deletion without capacity getting a turn. Carried forward across claims
	// and cleared the moment capacity is granted, so it measures starvation and nothing else.
	//
	// It lives in the claim record because that record is the one durable per-partition fact
	// already written under the per-partition flock on every grant; a separate file would
	// need its own locking to stay consistent with the grant it describes.
	ConsecutiveDeletionGrants int `json:"consecutiveDeletionGrants,omitempty"`

	// Broadcast attempt lineage. Once a freeze transaction may be in flight, AttemptState is
	// broadcast_pending and the claim is NEVER expired by TTL — only chain reconciliation
	// (sender-nonce consumption + on-chain slot) can retire or supersede it. The recorded
	// fields are all non-secret and enough to reconcile the attempt after a crash / lost RPC.
	AttemptState string `json:"attemptState,omitempty"`
	// Expected full A.0 on-chain slot identity of the in-flight freeze — the slot must match ALL
	// FOUR fields (proofEpochId + contentVersion + contentHash + frozenSnapshotNonce) to count as
	// this attempt winning. A slot matching only the first three but carrying another nonce is a
	// DIFFERENT freeze/reanchor and must not confirm this lineage.
	AttemptProofEpochID   uint64 `json:"attemptProofEpochId,omitempty"`
	AttemptContentVersion uint64 `json:"attemptContentVersion,omitempty"`
	AttemptContentHash    string `json:"attemptContentHash,omitempty"`
	AttemptSnapshotNonce  uint64 `json:"attemptSnapshotNonce,omitempty"`
	AttemptGeneration     uint64 `json:"attemptGeneration,omitempty"`
	// Immutable call binding — a same-nonce replacement may change ONLY fee fields, never the
	// target contract or freeze arguments.
	AttemptChainID      int64  `json:"attemptChainId,omitempty"`
	AttemptSender       string `json:"attemptSender,omitempty"`
	AttemptContract     string `json:"attemptContract,omitempty"`
	AttemptCalldataHash string `json:"attemptCalldataHash,omitempty"`
	AttemptSenderNonce  uint64 `json:"attemptSenderNonce,omitempty"`
	AttemptTxHash       string `json:"attemptTxHash,omitempty"`
	AttemptUpdatedAt    string `json:"attemptUpdatedAt,omitempty"`
}

// canonicalFreezeCallHash binds the immutable freeze call: chain, contract, physical partition,
// and the full A.0 target identity (proofEpochId + contentVersion + contentHash +
// frozenSnapshotNonce). Any change to the target contract or freeze arguments changes this hash;
// fee fields are not part of it.
func canonicalFreezeCallHash(chainID int64, contract string, partition PartitionMeta, id freezeExpectedIdentity) string {
	h := sha256.New()
	_, _ = h.Write([]byte("filetrust-freeze-call-v1\x00"))
	_, _ = h.Write([]byte(fmt.Sprintf("%d\x00", chainID)))
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(contract)) + "\x00"))
	_, _ = h.Write([]byte(partition.PartitionKind))
	_, _ = h.Write([]byte(fmt.Sprintf("\x00%d\x00%d\x00", partition.DeadlineIndex, partition.PartitionIndex)))
	_, _ = h.Write([]byte(fmt.Sprintf("%d\x00%d\x00", id.ProofEpochID, id.ContentVersion)))
	_, _ = h.Write([]byte(strings.ToLower(strings.TrimSpace(id.ContentHash)) + "\x00"))
	_, _ = h.Write([]byte(fmt.Sprintf("%d", id.SnapshotNonce)))
	return hex.EncodeToString(h.Sum(nil))
}

// freezeAttemptOutcome is the reconciliation of an in-flight broadcast attempt.
type freezeAttemptOutcome int

const (
	freezeAttemptDefer            freezeAttemptOutcome = iota // this authority must not broadcast
	freezeAttemptResumeFailed                                 // proven failed/replaced → retire, arbitrate
	freezeAttemptConfirmedWon                                 // slot matches exact identity → attempt won
	freezeAttemptRetrySameLineage                             // slot free, same authority may retry lineage
)

// reconcileFreezeBroadcast resolves a broadcast_pending attempt from CHAIN FACTS ONLY (never
// the claim TTL), matching the slot's FULL A.0 identity against the attempt's EXPECTED identity:
//
//  1. slot occupied by the exact expected identity           → attempt confirmed (won).
//  2. sender nonce consumed AND slot does not match          → conclusively failed/reverted/replaced
//     → retire and resume arbitration.
//  3. nonce unconsumed AND slot free                         → potentially live: other authority
//     defers; same authority may retry the
//     same nonce lineage.
//  4. nonce unconsumed AND slot occupied by a DIFFERENT id   → still potentially live: DO NOT retire
//     and DO NOT grant EITHER authority a new
//     unrelated broadcast (a temporary other
//     holder is not conclusive).
func reconcileFreezeBroadcast(att partitionFreezeClaim, me freezeHolder, slot freezeSlotIdentity, nonceConsumed bool) freezeAttemptOutcome {
	slotMatches := slot.Exists &&
		slot.ProofEpochID == att.AttemptProofEpochID &&
		slot.ContentVersion == att.AttemptContentVersion &&
		sameRoot(slot.ContentHash, att.AttemptContentHash) &&
		slot.SnapshotNonce == att.AttemptSnapshotNonce
	if slotMatches {
		return freezeAttemptConfirmedWon // case 1: exact 4-field A.0 identity
	}
	if nonceConsumed {
		return freezeAttemptResumeFailed // case 2
	}
	if slot.Exists {
		return freezeAttemptDefer // case 4: different holder, nonce live → neither gets a new freeze
	}
	// case 3: slot free, nonce unconsumed.
	if freezeAuthorityString(me) == att.Authority {
		return freezeAttemptRetrySameLineage
	}
	return freezeAttemptDefer
}

// existingAuthorityOrNone names the previous claim holder for the grant log, or "none" when
// this is the first claim on the partition. Logging only.
func existingAuthorityOrNone(existing partitionFreezeClaim, found bool) string {
	if !found {
		return "none"
	}
	if authority := strings.TrimSpace(existing.Authority); authority != "" {
		return authority
	}
	return "none"
}

func freezeAuthorityString(me freezeHolder) string {
	switch me {
	case freezeHolderCapacity:
		return "capacity"
	case freezeHolderDeletion:
		return "deletion"
	default:
		return "none"
	}
}

func partitionFreezeClaimDir(storage string) string {
	return filepath.Join(partitionProofSnapshotRoot(storage), "freeze-claims")
}

func partitionFreezeClaimPath(storage, kind string, dl, pt int) string {
	return filepath.Join(partitionFreezeClaimDir(storage), partitionProofSnapshotQueueName(kind, dl, pt)+".claim")
}

// readFreezeClaimUnlocked reads the durable claim (caller holds the partition flock).
func readFreezeClaimUnlocked(storage, kind string, dl, pt int) (partitionFreezeClaim, bool, error) {
	payload, err := os.ReadFile(partitionFreezeClaimPath(storage, kind, dl, pt))
	if os.IsNotExist(err) {
		return partitionFreezeClaim{}, false, nil
	}
	if err != nil {
		return partitionFreezeClaim{}, false, err
	}
	var claim partitionFreezeClaim
	if err := json.Unmarshal(payload, &claim); err != nil {
		return partitionFreezeClaim{}, false, fmt.Errorf("decode freeze claim: %w", err)
	}
	if claim.PartitionKind != kind || claim.DeadlineIndex != dl || claim.PartitionIndex != pt {
		return partitionFreezeClaim{}, false, fmt.Errorf("freeze claim identity mismatch")
	}
	return claim, true, nil
}

func writeFreezeClaimUnlocked(storage string, claim partitionFreezeClaim) error {
	claim.Version = partitionFreezeClaimVersion
	payload, err := json.MarshalIndent(claim, "", "  ")
	if err != nil {
		return err
	}
	return durableAtomicWriteFile(partitionFreezeClaimPath(storage, claim.PartitionKind, claim.DeadlineIndex, claim.PartitionIndex), payload, 0600)
}

// acquirePartitionFreezeClaim runs the complete gather → arbitrate → claim transition under
// the per-partition cross-process flock. It returns whether this authority may proceed, the
// generation-bound claim sequence to revalidate against, and the arbiter decision/reason.
func acquirePartitionFreezeClaim(storage string, oracle freezeChainOracle, partition PartitionMeta, me freezeHolder, now time.Time) (granted bool, seq uint64, decision freezeDecision, reason string, err error) {
	kind, dl, pt := partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex
	lockErr := withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
		in, gErr := gatherPartitionFreezeInputs(storage, oracle, partition, now)
		if gErr != nil {
			return gErr
		}
		decision, reason = arbitratePartitionFreeze(in, now)
		myProceed := freezeAuthorityMayProceed(decision, in.Holder, me)

		existing, found, rErr := readFreezeClaimUnlocked(storage, kind, dl, pt)
		if rErr != nil {
			return rErr
		}
		// A broadcast_pending attempt whose freeze transaction may still be live is resolved by
		// CHAIN FACTS (the slot's FULL A.0 identity + sender-nonce consumption), never by the
		// claim TTL. A merely-occupied slot with a DIFFERENT identity is NOT conclusive.
		if found && existing.AttemptState == freezeAttemptBroadcastPending {
			slot, sErr := oracle.FrozenSlot(partition)
			if sErr != nil {
				return sErr
			}
			confirmedNonce, nErr := oracle.ConfirmedSenderNonce()
			if nErr != nil {
				return nErr
			}
			nonceConsumed := confirmedNonce > existing.AttemptSenderNonce
			switch reconcileFreezeBroadcast(existing, me, slot, nonceConsumed) {
			case freezeAttemptDefer:
				// Either the other authority (case 3) or ANY authority while a different holder
				// occupies with the nonce still live (case 4): no new unrelated freeze broadcast.
				granted = false
				reason = fmt.Sprintf("in-flight %s freeze may still be live (nonce %d unconsumed); deferring", existing.Authority, existing.AttemptSenderNonce)
				return nil
			case freezeAttemptRetrySameLineage:
				// Slot free, same authority: resume its own claim/lineage (same nonce), no new tx family.
				granted, seq = true, existing.ClaimSeq
				reason = "same-authority retry on the existing broadcast nonce lineage"
				return nil
			case freezeAttemptConfirmedWon:
				// Slot matches the exact expected A.0 identity: the attempt won. Retire the lineage
				// and continue — normal arbitration sees the on-chain holder (this authority).
				existing.AttemptState = freezeAttemptConfirmed
				if wErr := writeFreezeClaimUnlocked(storage, existing); wErr != nil {
					return wErr
				}
			case freezeAttemptResumeFailed:
				// Nonce consumed but slot does not match: conclusively failed/reverted/replaced.
				// Retire and continue to normal arbitration on a fresh sequence.
			}
		}
		// capacity-must-abandon is not a freeze grant: capacity must run its abandon (handled by
		// the caller), never take a fresh claim, and deletion must wait for the slot to free.
		if decision == freezeDecisionCapacityMustAbandon {
			granted = false
			return nil
		}
		// A pre-broadcast reservation TTL applies ONLY when there is no live broadcast attempt.
		// A pre-broadcast claim protects a real gather->broadcast window, not an authority that
		// has already completed its durable work. Live G.7 found a standalone deletion proof
		// completing with a plain (never-broadcast) deletion claim still inside its TTL; the
		// successor capacity campaign then waited up to 15 minutes despite both chain and the
		// lifecycle journal saying deletion no longer wanted the slot. Preserve ambiguous
		// broadcast_pending claims above, but let a terminal owner be superseded immediately.
		ownerStillWants := (existing.Authority == "deletion" && in.DeletionWantsSlot) ||
			(existing.Authority == "capacity" && in.CapacityWantsSlot)
		activeOther := found && existing.AttemptState != freezeAttemptBroadcastPending &&
			existing.Authority != freezeAuthorityString(me) && ownerStillWants &&
			now.Unix() < existing.ExpiresAtUnix
		if activeOther {
			granted = false
			reason = fmt.Sprintf("%s holds an unexpired freeze claim", existing.Authority)
			return nil
		}
		if !myProceed {
			granted = false
			return nil
		}
		nextSeq := uint64(1)
		if found {
			nextSeq = existing.ClaimSeq + 1
		}
		// Starvation bookkeeping for capacityIsOwedATurn. A deletion grant adds one; a
		// capacity grant clears the debt. Written under the same per-partition flock and in
		// the same record as the grant itself, so the count can never disagree with what
		// actually happened.
		grants := 0
		if found {
			grants = existing.ConsecutiveDeletionGrants
		}
		switch me {
		case freezeHolderDeletion:
			grants++
		case freezeHolderCapacity:
			grants = 0
		}
		claim := partitionFreezeClaim{
			PartitionKind: kind, DeadlineIndex: dl, PartitionIndex: pt,
			Authority: freezeAuthorityString(me), ClaimSeq: nextSeq,
			ClaimedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(freezeClaimTTL).Unix(),
			ConsecutiveDeletionGrants: grants,
		}
		if wErr := writeFreezeClaimUnlocked(storage, claim); wErr != nil {
			return wErr
		}
		// One line per grant, so slot contention on a partition is measurable instead of
		// guessed at. heldSeconds is how long the PREVIOUS holder kept the slot, which is the
		// real cost of one cycle; queue is how many unresolved deletions are waiting on it.
		//
		// This is the evidence needed to decide whether several deletions sharing one
		// successor proof is worth a DeletionReleaseSC change (the chain allows only one
		// unresolved deletion per partition today). A shallow queue means it is not.
		heldSeconds := int64(-1)
		if found && existing.ClaimedAtUnix > 0 {
			heldSeconds = now.Unix() - existing.ClaimedAtUnix
		}
		log.Printf("[freeze-slot] granted %s kind=%s dl=%d pt=%d seq=%d queue=%d "+
			"deletionGrantsInARow=%d previousHolder=%s heldSeconds=%d",
			freezeAuthorityString(me), kind, dl, pt, nextSeq, in.DeletionQueueDepth,
			grants, existingAuthorityOrNone(existing, found), heldSeconds)
		granted, seq = true, nextSeq
		return nil
	})
	if lockErr != nil {
		return false, 0, freezeDecisionNone, "", lockErr
	}
	return granted, seq, decision, reason, nil
}

// markFreezeBroadcastPending durably transitions the held claim to broadcast_pending BEFORE
// the freeze transaction is sent, recording the sender nonce (fetched now) so the attempt can
// be reconciled after a crash / lost RPC. From this point the claim is never TTL-expired.
// freezeExpectedIdentity is the full A.0 on-chain slot identity a freeze attempt targets,
// including the expected next frozenSnapshotNonce.
type freezeExpectedIdentity struct {
	ProofEpochID   uint64
	ContentVersion uint64
	ContentHash    string
	SnapshotNonce  uint64
	Generation     uint64
}

// markFreezeBroadcastPending durably records the broadcast attempt with the EXACTLY reserved
// Ethereum sender nonce (allocated by the caller while holding the sender-wide account
// transaction lock) — not a re-read confirmed count — so the journal describes the real freeze
// transaction. It is called BEFORE the freeze is broadcast.
func markFreezeBroadcastPending(storage string, partition PartitionMeta, me freezeHolder, seq uint64, id freezeExpectedIdentity, senderNonce uint64, now time.Time) error {
	chainID := activeFreezeChainConfig.ChainID
	sender := activeFreezeChainConfig.VKAddress
	contract := activeFreezeChainConfig.StorageProofContract
	calldataHash := canonicalFreezeCallHash(chainID, contract, partition, id)
	kind, dl, pt := partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex
	return withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
		claim, found, rErr := readFreezeClaimUnlocked(storage, kind, dl, pt)
		if rErr != nil {
			return rErr
		}
		if !found || claim.Authority != freezeAuthorityString(me) || claim.ClaimSeq != seq {
			return fmt.Errorf("freeze claim not held by %s at seq %d; refusing to record broadcast attempt", freezeAuthorityString(me), seq)
		}
		if claim.AttemptState == freezeAttemptBroadcastPending {
			// A same-nonce replacement may change ONLY fee fields — never the target contract or
			// freeze arguments. Reject a retry whose immutable call identity differs.
			if claim.AttemptCalldataHash != calldataHash ||
				!sameRoot(claim.AttemptContract, contract) || claim.AttemptChainID != chainID {
				return fmt.Errorf("refusing same-nonce freeze replacement with a changed immutable call identity (contract/calldata)")
			}
			// Keep the ORIGINAL sender nonce lineage (fee-bump only).
		} else {
			claim.AttemptSenderNonce = senderNonce
		}
		claim.AttemptState = freezeAttemptBroadcastPending
		claim.AttemptProofEpochID = id.ProofEpochID
		claim.AttemptContentVersion = id.ContentVersion
		claim.AttemptContentHash = id.ContentHash
		claim.AttemptSnapshotNonce = id.SnapshotNonce
		claim.AttemptGeneration = id.Generation
		claim.AttemptChainID = chainID
		claim.AttemptSender = sender
		claim.AttemptContract = contract
		claim.AttemptCalldataHash = calldataHash
		claim.AttemptUpdatedAt = nowRFC3339()
		return writeFreezeClaimUnlocked(storage, claim)
	})
}

// resolveFreezeBroadcastAttempt marks the attempt confirmed or failed once the on-chain
// outcome is known, retiring the broadcast_pending state so normal arbitration can resume.
func resolveFreezeBroadcastAttempt(storage string, partition PartitionMeta, me freezeHolder, seq uint64, state, txHash string) error {
	kind, dl, pt := partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex
	return withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
		claim, found, rErr := readFreezeClaimUnlocked(storage, kind, dl, pt)
		if rErr != nil {
			return rErr
		}
		if !found || claim.Authority != freezeAuthorityString(me) || claim.ClaimSeq != seq ||
			claim.AttemptState != freezeAttemptBroadcastPending {
			return nil // superseded/already resolved — nothing to do
		}
		claim.AttemptState = state
		if txHash != "" {
			claim.AttemptTxHash = txHash
		}
		claim.AttemptUpdatedAt = nowRFC3339()
		return writeFreezeClaimUnlocked(storage, claim)
	})
}

// freezeBroadcastCoord carries the A.2.5 freeze-claim context into the freeze broadcast so
// the reserved sender nonce can be journalled against the exact claim before broadcasting.
type freezeBroadcastCoord struct {
	storage string
	me      freezeHolder
	seq     uint64
}

// coordinatedFreezeBroadcast performs the freeze as the sender-wide coordinated operation the
// A.2.5 lineage requires, REUSING the existing account transaction coordinator
// (acquireAccountTxLock / vks.py account_transaction_lock, the shared flock at
// filetrust-chain-tx-locks/<sender>.lock):
//
//	acquire the sender account flock
//	  → reserve the exact next sender nonce (pending count, under the flock)
//	  → durably journal broadcast_pending with THAT nonce + immutable call identity
//	  → broadcast the freeze forcing that exact nonce (subprocess skips its own flock,
//	    uses the explicit nonce, and echoes it back)
//	  → verify the subprocess used exactly the reserved nonce
//	release the flock
//
// The reserved nonce is thus provably the actual broadcast nonce, and no other sender
// transaction (freeze/submit/abandon/reanchor/capacity/deletion — all of which take the same
// flock) can consume it in between.
func coordinatedFreezeBroadcast(coord freezeBroadcastCoord, chainCmd string, partition PartitionMeta, proofEpochID, round uint64) (FrozenPartitionSnapshotStatus, string, error) {
	cfg := activeFreezeChainConfig
	// Without a configured sender/RPC (unit/dev), fall back to the plain freeze, which still
	// serialises via the subprocess's own account_transaction_lock.
	if cfg.VKAddress == "" || cfg.RPCURL == "" {
		return freezePartitionSnapshotOnChain(chainCmd, partition, proofEpochID, round)
	}
	lock, err := acquireAccountTxLock(cfg.VKAddress)
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", err
	}
	defer lock.Release()

	reservedNonce, err := rpcAccountTransactionCount(cfg, cfg.VKAddress) // "pending", under the flock
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", fmt.Errorf("reserve sender nonce: %w", err)
	}
	// Expected full A.0 identity: the freeze increments the per-partition frozenSnapshotNonce
	// counter, so it will carry (current counter) + 1.
	preSlot, err := frozenPartitionSnapshotStatusOnChain(chainCmd, partition)
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", err
	}
	version, err := partitionVersionStatusOnChain(chainCmd, partition)
	if err != nil {
		return FrozenPartitionSnapshotStatus{}, "", err
	}
	expectedID := freezeExpectedIdentity{
		ProofEpochID: proofEpochID, ContentVersion: version.ContentVersion,
		ContentHash: version.ContentHash, SnapshotNonce: preSlot.SnapshotNonce + 1,
	}
	if err := markFreezeBroadcastPending(coord.storage, partition, coord.me, coord.seq, expectedID, reservedNonce, time.Now()); err != nil {
		return FrozenPartitionSnapshotStatus{}, "", err
	}
	// Broadcast forcing the exact reserved nonce; the subprocess must not re-select or re-lock.
	status, tx, usedNonce, err := freezePartitionSnapshotOnChainWithNonce(chainCmd, partition, proofEpochID, round, reservedNonce, true, true)
	if err != nil {
		return status, tx, err
	}
	if usedNonce != reservedNonce {
		return status, tx, fmt.Errorf("freeze subprocess used sender nonce %d, not the reserved/journalled %d", usedNonce, reservedNonce)
	}
	return status, tx, nil
}

// revalidatePartitionFreezeClaim confirms, under the flock, that this authority still holds
// the EXACT generation-bound claim (same sequence, unexpired) it was granted. It MUST be
// called immediately before broadcasting the freeze so a superseded/expired claim defers.
func revalidatePartitionFreezeClaim(storage string, partition PartitionMeta, me freezeHolder, seq uint64, now time.Time) (bool, error) {
	kind, dl, pt := partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex
	valid := false
	err := withPartitionProofSnapshotLock(storage, kind, dl, pt, func() error {
		claim, found, rErr := readFreezeClaimUnlocked(storage, kind, dl, pt)
		if rErr != nil {
			return rErr
		}
		valid = found && claim.Authority == freezeAuthorityString(me) &&
			claim.ClaimSeq == seq && now.Unix() < claim.ExpiresAtUnix
		return nil
	})
	return valid, err
}
