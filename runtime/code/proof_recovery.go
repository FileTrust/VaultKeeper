package main

// A.4 recovery / terminal-state classification.
//
// Every post-A.3 proof/deletion failure shape is routed deterministically to exactly one
// action, derived from AUTHORITATIVE CHAIN STATE plus the FULL LOCAL IDENTITY (A.0 tuple +
// A.1 generation) and the durable failure history. The classifier is PURE (no I/O): the
// caller gathers the facts (chain reads + local record) and records/acts on the result.

type proofRecoveryAction string

const (
	recoveryResume         proofRecoveryAction = "resume"          // retryable → bounded backoff
	recoverySupersede      proofRecoveryAction = "supersede"       // stale identity → retire, NO broadcast
	recoveryReconstruct    proofRecoveryAction = "reconstruct"     // rebuild artifact (identity still authoritative)
	recoveryAbandonReplace proofRecoveryAction = "abandon_replace" // abandon exact A.0 id, replace w/ newer generation
	recoveryTerminal       proofRecoveryAction = "terminal"        // permanently failed / operator action required
)

func (a proofRecoveryAction) terminal() bool { return a == recoveryTerminal }

// proofRecoveryFacts is the complete, chain-reconciled input the classifier reasons over.
type proofRecoveryFacts struct {
	// ChainCertain is false when an RPC/decode error occurred while gathering these facts. On
	// uncertainty the classifier performs NO destructive transition.
	ChainCertain bool

	// A.1 generation: the record the worker holds vs the live durable frozen generation.
	LocalGeneration uint64
	LiveGeneration  uint64

	// The full A.0 identity the local record expects.
	LocalProofEpochID   uint64
	LocalContentVersion uint64
	LocalContentHash    string
	LocalSnapshotNonce  uint64

	// The authoritative on-chain frozen-slot identity.
	ChainSlotExists     bool
	ChainProofEpochID   uint64
	ChainContentVersion uint64
	ChainContentHash    string
	ChainSnapshotNonce  uint64

	// Artifact + content authority.
	ArtifactPresent           bool // the pinned artifact directory exists and validates
	ArtifactReconstructable   bool // the source pieces are still available to rebuild it
	ContentStillAuthoritative bool // the local content is still the chain's current/expected content

	// Failure history.
	ConsecutiveFailures int
	MaxFailures         int
}

// chainMatchesLocalA0 reports whether the on-chain frozen slot holds this record's exact A.0
// identity (epoch + contentVersion + contentHash + frozenSnapshotNonce).
func chainMatchesLocalA0(f proofRecoveryFacts) bool {
	return f.ChainProofEpochID == f.LocalProofEpochID &&
		f.ChainContentVersion == f.LocalContentVersion &&
		sameRoot(f.ChainContentHash, f.LocalContentHash) &&
		f.ChainSnapshotNonce == f.LocalSnapshotNonce
}

// classifyProofRecovery deterministically routes a failure. The ordering is significant:
// uncertainty and identity-staleness are decided BEFORE any reconstruct/abandon/terminal
// transition, so a destructive action is never taken on an unreliable read or a superseded
// record.
func classifyProofRecovery(f proofRecoveryFacts) (proofRecoveryAction, string) {
	// (1) Uncertainty first: an unreliable chain read performs no destructive transition.
	if !f.ChainCertain {
		return recoveryResume, "chain query uncertain; retry without any destructive transition"
	}
	// (2) Stale local generation (A.1): a newer frozen generation replaced ours → supersede
	// WITHOUT broadcasting (the newer generation owns the slot).
	if f.LocalGeneration != 0 && f.LiveGeneration != 0 && f.LocalGeneration < f.LiveGeneration {
		return recoverySupersede, "local generation superseded by a newer frozen generation"
	}
	// (3) Stale A.0 identity: the chain slot is held by a DIFFERENT full identity than ours →
	// supersede without broadcasting (our record no longer describes the on-chain freeze).
	if f.ChainSlotExists && !chainMatchesLocalA0(f) {
		return recoverySupersede, "chain frozen slot holds a different snapshot identity; local record superseded"
	}
	// (4) Artifact corruption/absence — reconstruct ONLY when the complete snapshot identity is
	// still authoritative and the source bytes remain; otherwise supersede or terminate.
	if !f.ArtifactPresent {
		switch {
		case f.ContentStillAuthoritative && f.ArtifactReconstructable:
			return recoveryReconstruct, "artifact absent but the complete snapshot identity is authoritative and reconstructable"
		case !f.ContentStillAuthoritative:
			return recoverySupersede, "artifact absent and the content is no longer authoritative"
		default:
			return recoveryTerminal, "artifact absent and unreconstructable; operator action required"
		}
	}
	// (5) Content is no longer authoritative but our old freeze still holds the slot → abandon
	// the EXACT A.0 identity and replace with a strictly newer local generation.
	if !f.ContentStillAuthoritative {
		return recoveryAbandonReplace, "content changed; abandon the exact snapshot identity and replace with a newer generation"
	}
	// (6) Exhausted the retry budget → terminal (stops automatic transactions).
	if f.MaxFailures > 0 && f.ConsecutiveFailures >= f.MaxFailures {
		return recoveryTerminal, "consecutive failures exceeded the retry budget; operator action required"
	}
	// (7) Otherwise a transient error → resume with bounded backoff.
	return recoveryResume, "transient failure; retry with bounded backoff"
}
