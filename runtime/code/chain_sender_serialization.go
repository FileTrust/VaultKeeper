package main

// DEFECT H — ONE SERIALIZATION DOMAIN PER ETHEREUM SENDER.
//
// THE INVARIANT
//
//	Every transaction that uses a given Ethereum sender must participate in ONE
//	serialization domain for nonce allocation, broadcast and reconciliation.
//
// HOW IT WAS VIOLATED (proven from smoke8 VK1, 2026-08-16 14:47:37)
//
//	real-on-chain adapter: ambiguous broadcast for freezePartitionSnapshot:
//	  tx=0x22b7e8c1... stateApplied=false: nonce has already been used
//
//	The same sender was guarded by TWO disjoint locks:
//
//	  family A — Go raw-RPC senders (file_registration, quote_reservation,
//	             vk_registry x3, deletion x2, coordinatedFreezeBroadcast)
//	             lock: $FILETRUST_CHAIN_TX_LOCK_DIR/<addr>.lock   (flock, chain_tx_lock.go)
//
//	  family B — the adapter subprocess, all 12 tx-producing methods
//	             lock: $D1_CHAIN_TX_LOCK_DIR/vk-<addr>.lock       (mkdir, adapter)
//
//	Different directory, different filename, different mechanism — so they did not
//	mutually exclude. Confirmed on disk: the run's txlocks/ held exactly the three
//	VK sender addresses while the adapter locked under txlocks/node/, and each VK's
//	D1_VK_ADDRESS is that same sender.
//
//	coordinatedFreezeBroadcast reserves a nonce under the family-A lock and passes
//	callerHoldsAccountLock=true, which makes the adapter SKIP its family-B lock. Any
//	concurrent family-B transaction (submitFrozenPartitionZkProof, sealPartitionSnapshot,
//	registerOrUpdatePartition, ...) then calls getTransactionCount(sender,"pending") and is
//	handed the SAME nonce that family A reserved but has not yet broadcast. Whichever
//	broadcasts second loses with "nonce has already been used".
//
// WHY Go -> adapter IS A SAFE TOTAL ORDER (required before adopting it globally)
//
//	There is no adapter -> Go edge, by construction: the adapter is a separate Node
//	process invoked as a subprocess and it never calls back into Go code, so it can
//	never acquire the Go account lock. Verified additionally that no existing holder of
//	the Go account lock invokes a tx-producing chain command while holding it — the sole
//	exception is coordinatedFreezeBroadcast, which announces itself with
//	CallerHoldsAccountLock and is skipped below. The resulting global order is
//
//	    operation flock -> storeCapacityMu -> partition lifecycle lock
//	    Go account lock -> adapter signer lock
//
//	and the account-lock edge is disjoint from the convergence-lock chain: no function
//	holds a partition lifecycle lock or storeCapacityMu across a chain transaction (that
//	is B.3's rule, enforced by the lock-discipline telemetry), so the union stays acyclic.
//
// WHAT THIS DOES NOT DO
//
//	It does not replace or weaken the adapter's own lock, which stays as an inner guard
//	for any caller that is not Go. It does not change nonce SELECTION, the A.2.5
//	reserve-and-journal protocol, or any contract precondition. It only guarantees that
//	family A and family B can never be inside their nonce windows at the same time.

import "strings"

// chainTxProducingActions is the exact set of adapter actions that BROADCAST a transaction
// for the VK sender. Read-only actions must stay out: serialising them would put every
// status poll behind the sender lock for no benefit.
//
// Kept in sync with the adapter's this.send(...) call sites (d1_chain_onchain_adapter.js):
// declareCapacity, beginProofEpoch, abortProofEpoch, openBatch, abandonIncrementalBatch,
// freezePartitionSnapshot, sealPartitionSnapshot, reanchorFrozenPartitionSnapshot,
// abandonFrozenPartitionSnapshot, submitFrozenPartitionZkProof, registerOrUpdatePartition,
// deactivatePartition, submitPartitionZkProofDeterministic.
var chainTxProducingActions = map[string]bool{
	"register_partition":                   true,
	"deactivate_partition":                 true,
	"declare_capacity":                     true,
	"begin_capacity_proof_epoch":           true,
	"open_capacity_incremental_batch":      true,
	"abandon_incremental_batch":            true,
	"abort_capacity_proof_epoch":           true,
	"freeze_partition_snapshot":            true,
	"seal_partition_snapshot":              true,
	"reanchor_frozen_partition_snapshot":   true,
	"abandon_frozen_partition_snapshot":    true,
	"submit_frozen_partition_zk_proof":     true,
	"submit_partition_proof_deterministic": true,
}

// chainActionBroadcastsTransaction reports whether an adapter action sends a transaction.
// Unknown actions are treated as NON-broadcasting: this serialisation is an optimisation of
// correctness for known senders, and silently locking on every future read action would be a
// worse failure mode than leaving an unknown action unserialised, which is the status quo.
// A new tx-producing action must be added to the map above; the regression test pins the map
// against the adapter's real send() call sites so an omission fails the build's test run.
func chainActionBroadcastsTransaction(action string) bool {
	return chainTxProducingActions[strings.ToLower(strings.TrimSpace(action))]
}

// chainSenderSerializationAddress returns the VK sender whose nonce must be serialised, or ""
// when no sender is configured (unit/dev), in which case the adapter's own lock remains the
// only guard exactly as before.
func chainSenderSerializationAddress() string {
	return strings.TrimSpace(activeFreezeChainConfig.VKAddress)
}

// withChainSenderSerialization runs fn while holding the ONE sender-wide account lock, when
// this call broadcasts a transaction and the caller does not already hold that lock.
//
// It is deliberately a no-op when:
//   - the action does not broadcast (reads must not serialise),
//   - the caller already holds the lock (CallerHoldsAccountLock — coordinatedFreezeBroadcast),
//     because the Go account lock is a plain flock and re-acquiring it in the same process
//     would self-deadlock,
//   - no sender address is configured.
func withChainSenderSerialization(req ChainProofCommandRequest, fn func(bool) (ChainProofCommandResponse, error)) (ChainProofCommandResponse, error) {
	if req.CallerHoldsAccountLock || !chainActionBroadcastsTransaction(req.Action) {
		return fn(req.CallerHoldsAccountLock)
	}
	address := chainSenderSerializationAddress()
	if address == "" {
		return fn(false)
	}
	lock, err := acquireAccountTxLock(address)
	if err != nil {
		return ChainProofCommandResponse{}, err
	}
	defer lock.Release()
	return fn(true)
}
