package main

import "strings"

// ── The empty-transaction mutation class ─────────────────────────────────────────────────────
//
// A chain-mutating action returns a transaction hash on success. But a mutation can legitimately
// return (err == nil, tx == "") when the adapter sends NO transaction because the requested state
// is ALREADY current on chain (a benign no-op — proven in Run 17: a re-register of unchanged
// capacity content returned `registerTx: "", transaction: null, ok: true, active: true`). The
// danger (Run-16 VK4/VK2 wedge) is the opposite reading: if a caller treats err == nil as "done"
// and advances its durable local state, an empty tx that actually meant "the change did NOT reach
// chain" leaves local != chain FOREVER — the partition can never reconcile and the VK wedges.
//
// The two cases are indistinguishable from the return value alone. They are only separable by
// reading CHAIN TRUTH. Every mutation site that would advance durable local state must therefore
// classify an empty tx into exactly one of:
//
//	A. read-back proves the requested state IS already current -> mutationApplied (successful no-op)
//	B. read-back proves the requested state is NOT current      -> mutationNotApplied (hold + retry)
//	C. read-back unavailable / ambiguous                        -> mutationUnverifiable (fail closed)
//
// The invariant: never silently advance durable local state merely because err == nil. A job is
// HELD and retried, never lost, and never marked done on an unverified empty tx.
type mutationOutcome int

const (
	// mutationApplied: the mutation is durably reflected on chain — either a real transaction was
	// returned, or an empty tx was proven (by read-back) to be a no-op because the requested state
	// was already current. The caller MAY advance durable local state.
	mutationApplied mutationOutcome = iota
	// mutationNotApplied: an empty tx and the read-back proves the requested state is NOT current.
	// The change did not reach chain. The caller MUST NOT advance durable state; hold and retry.
	mutationNotApplied
	// mutationUnverifiable: an empty tx and the read-back was unavailable or ambiguous. The outcome
	// is unknown, so the caller MUST fail closed (treat as not applied) and retry — never advance
	// on doubt.
	mutationUnverifiable
)

// classifyMutationTx applies the empty-transaction classification. A non-empty tx is unambiguously
// applied and readBack is never consulted (no extra chain read on the normal path). An empty tx
// delegates to readBack, which must report whether the requested end-state is already current on
// chain (true) or not (false), or return an error when chain truth cannot be established.
func classifyMutationTx(tx string, readBack func() (bool, error)) (mutationOutcome, error) {
	if strings.TrimSpace(tx) != "" {
		return mutationApplied, nil
	}
	current, err := readBack()
	if err != nil {
		return mutationUnverifiable, err
	}
	if current {
		return mutationApplied, nil
	}
	return mutationNotApplied, nil
}

// capacityPartitionRegistrationCurrentOnChain is the read-back for a capacity partition
// registration. It answers: is p's exact content the CURRENT active registered identity on chain?
// It reuses the same chain-content-hash derivation the pinned selection view-builder trusts
// (partitionChainContentHash + sameRoot), so a "current" verdict here is identical to the one that
// lets a partition into a capacity batch — an empty-tx no-op classified A cannot later be rejected
// by the view-builder as a stale identity.
func capacityPartitionRegistrationCurrentOnChain(cfg ServerConfig, p PartitionMeta) (bool, error) {
	onChain, err := listActiveCapacityPartitionsOnChain(cfg.ChainProofCmd)
	if err != nil {
		return false, err // C: chain truth unavailable
	}
	for _, info := range onChain {
		if info.DeadlineIndex != p.DeadlineIndex || info.PartitionIndex != p.PartitionIndex {
			continue
		}
		// Present but not a valid current identity -> the registration is NOT satisfied.
		if !info.Active || info.ContentVersion == 0 {
			return false, nil // B
		}
		challengeCount := info.ChallengeCount
		if challengeCount == 0 {
			challengeCount = uint16(cfg.ChallengeCount)
		}
		want, err := partitionChainContentHash(p, challengeCount)
		if err != nil {
			return false, err // C: cannot derive the comparison hash -> ambiguous, fail closed
		}
		// A if the on-chain content is exactly ours; B if the chain still holds different content.
		return sameRoot(want, info.ContentHash), nil
	}
	// Not registered on chain at all -> NOT current.
	return false, nil // B
}
