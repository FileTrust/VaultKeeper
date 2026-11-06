package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Call under the shared account lock. A heartbeat keeps its original envelope
// until reconciled, including when its broadcast response was lost. A stale
// pending count must not assign that reserved nonce to another operation.
func rpcAccountTransactionCount(cfg ServerConfig, address string) (uint64, error) {
	return rpcAccountTransactionCountCtx(context.Background(), cfg, address)
}

func rpcAccountTransactionCountCtx(ctx context.Context, cfg ServerConfig, address string) (uint64, error) {
	nonce, err := rpcGetTransactionCountCtx(ctx, cfg.RPCURL, address)
	if err != nil {
		return 0, err
	}
	return guardHeartbeatNonce(ctx, cfg, address, nonce)
}

func guardHeartbeatNonce(ctx context.Context, cfg ServerConfig, address string, nonce uint64) (uint64, error) {
	if cfg.Storage == "" {
		return nonce, nil
	}
	data, err := os.ReadFile(filepath.Join(cfg.Storage, "registry-heartbeat.json"))
	if os.IsNotExist(err) {
		return nonce, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: read pending account heartbeat: %v", ErrRPCUnavailable, err)
	}
	var pending pendingHeartbeat
	if err := json.Unmarshal(data, &pending); err != nil {
		return 0, fmt.Errorf("%w: invalid pending account heartbeat", ErrRPCUnavailable)
	}
	if pending.ChainID != cfg.ChainID || !strings.EqualFold(pending.Address, address) ||
		!strings.EqualFold(pending.Target, cfg.VKRegistryContract) || pending.Hash == "" {
		return 0, fmt.Errorf("%w: pending account heartbeat identity/network mismatch", ErrRPCUnavailable)
	}
	if nonce > pending.Nonce {
		return nonce, nil
	}
	confirmed, err := rpcGetConfirmedTransactionCountCtx(ctx, cfg.RPCURL, address)
	if err != nil {
		return 0, err
	}
	if confirmed > pending.Nonce {
		// The envelope's nonce is consumed. Leave its journal for the heartbeat
		// worker to reconcile, and never regress to the stale pending response.
		return confirmed, nil
	}
	return 0, fmt.Errorf("%w: account heartbeat transaction is unresolved; retry after reconciliation", ErrRPCUnavailable)
}
