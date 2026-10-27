package main

import (
	"context"
	"fmt"
)

// activeFreezeChainConfig carries the RPC / contract fields the freeze oracle needs for the
// on-chain deletion-declaration check. It is set once at daemon/server startup (read-only
// thereafter) so provePartitionSnapshotCandidate can build a real oracle from a chainCmd
// without threading the full ServerConfig through the proof scheduler.
var activeFreezeChainConfig ServerConfig

// chainFreezeOracle answers the arbiter's on-chain questions from live chain truth.
type chainFreezeOracle struct {
	chainCmd string
	cfg      ServerConfig
}

func realFreezeOracle(chainCmd string) freezeChainOracle {
	return chainFreezeOracle{chainCmd: chainCmd, cfg: activeFreezeChainConfig}
}

func (o chainFreezeOracle) FrozenSlot(partition PartitionMeta) (freezeSlotIdentity, error) {
	st, err := frozenPartitionSnapshotStatusOnChain(o.chainCmd, partition)
	if err != nil {
		return freezeSlotIdentity{}, err
	}
	return freezeSlotIdentity{
		Exists: st.Exists, ProofEpochID: st.ProofEpochID,
		ContentVersion: st.ContentVersion, ContentHash: st.ContentHash,
		SnapshotNonce: st.SnapshotNonce,
	}, nil
}

func (o chainFreezeOracle) DeletionDeclared(commitment string) (bool, error) {
	if o.cfg.FileRegistrationContract == "" || o.cfg.RPCURL == "" {
		return false, fmt.Errorf("freeze oracle: on-chain deletion-declaration check requires FileRegistrationContract + RPCURL")
	}
	declared, _, err := deletionStatusOnChain(o.cfg, commitment)
	return declared, err
}

func (o chainFreezeOracle) ChainClock() (int64, int64, error) {
	clk, err := proofClockStatusOnChain(o.chainCmd)
	if err != nil {
		return 0, 0, err
	}
	return clk.ChainTimestamp, clk.ProofPeriodSeconds, nil
}

func (o chainFreezeOracle) ConfirmedSenderNonce() (uint64, error) {
	if o.cfg.RPCURL == "" || o.cfg.VKAddress == "" {
		return 0, fmt.Errorf("freeze oracle: confirmed sender nonce requires RPCURL + VKAddress")
	}
	return rpcGetConfirmedTransactionCountCtx(context.Background(), o.cfg.RPCURL, o.cfg.VKAddress)
}
