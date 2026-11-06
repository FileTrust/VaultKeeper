package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

const registryHeartbeatInterval = 30 * time.Minute

// Wallet/chain-specific fixed phases spread load without cumulative jitter.
func nextHeartbeatSlot(now time.Time, chainID int64, address, purpose string, interval time.Duration) time.Time {
	identity := fmt.Sprintf("filetrust:%s:%d:%s", purpose, chainID, strings.ToLower(address))
	digest := sha256.Sum256([]byte(identity))
	seconds := int64(interval / time.Second)
	phase := int64(binary.BigEndian.Uint64(digest[:8]) % uint64(seconds))
	n := now.Unix()
	next := (n/seconds)*seconds + phase
	if next <= n {
		next += seconds
	}
	return time.Unix(next, 0)
}

type pendingHeartbeat struct {
	ChainID int64  `json:"chain_id"`
	Address string `json:"address"`
	Target  string `json:"target"`
	Nonce   uint64 `json:"nonce"`
	Hash    string `json:"hash"`
	Raw     string `json:"raw"`
}

func registryHeartbeatTick(ctx context.Context, cfg ServerConfig) (bool, error) {
	vkRegMu.Lock()
	defer vkRegMu.Unlock()
	lock, err := acquireAccountTxLock(cfg.VKAddress)
	if err != nil {
		return false, err
	}
	defer lock.Release()
	path := filepath.Join(cfg.Storage, "registry-heartbeat.json")
	var pending pendingHeartbeat
	raw, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(raw, &pending); err != nil {
			return false, err
		}
		if pending.ChainID != cfg.ChainID || !strings.EqualFold(pending.Address, cfg.VKAddress) || !strings.EqualFold(pending.Target, cfg.VKRegistryContract) {
			return false, fmt.Errorf("saved heartbeat identity/network mismatch")
		}
		receipt, e := rpcGetTransactionReceiptCtx(ctx, cfg.RPCURL, pending.Hash)
		if e != nil {
			return false, e
		}
		if receipt != nil {
			if err = os.Remove(path); err != nil {
				return false, err
			}
			if decimalFromHex(receipt.Status) != "1" {
				return false, fmt.Errorf("heartbeat reverted")
			}
			log.Printf("[heartbeat] confirmed tx=%s", pending.Hash)
			return true, nil
		}
		confirmed, e := rpcGetConfirmedTransactionCountCtx(ctx, cfg.RPCURL, cfg.VKAddress)
		if e != nil {
			return false, e
		}
		if confirmed > pending.Nonce {
			if err = os.Remove(path); err != nil {
				return false, err
			}
			return false, fmt.Errorf("heartbeat nonce consumed; retry required")
		}
	} else if !os.IsNotExist(err) {
		return false, err
	} else {
		priv, e := ParseVKPrivKey(cfg.VKPrivKeyHex)
		if e != nil {
			return false, e
		}
		if !strings.EqualFold(ethcrypto.PubkeyToAddress(priv.PublicKey).Hex(), cfg.VKAddress) {
			return false, fmt.Errorf("heartbeat signer mismatch")
		}
		nonce, e := rpcAccountTransactionCountCtx(ctx, cfg, cfg.VKAddress)
		if e != nil {
			return false, e
		}
		confirmed, e := rpcGetConfirmedTransactionCountCtx(ctx, cfg.RPCURL, cfg.VKAddress)
		if e != nil {
			return false, e
		}
		if nonce != confirmed {
			return false, fmt.Errorf("account transaction pending")
		}
		calldata := ethcrypto.Keccak256([]byte("heartbeat()"))[:4]
		gas, e := rpcEstimateGas(cfg.RPCURL, cfg.VKAddress, cfg.VKRegistryContract, calldata, big.NewInt(0))
		if e != nil {
			return false, e
		}
		suggested, e := rpcCallCtx(ctx, cfg.RPCURL, "eth_gasPrice", []any{})
		if e != nil {
			return false, e
		}
		gasPrice, ok := new(big.Int).SetString(strings.TrimPrefix(suggested, "0x"), 16)
		if !ok {
			return false, fmt.Errorf("invalid gas price")
		}
		if gasPrice.Cmp(big.NewInt(cfg.FixedGasPriceWei)) < 0 {
			gasPrice = big.NewInt(cfg.FixedGasPriceWei)
		}
		tx := types.NewTransaction(nonce, common.HexToAddress(cfg.VKRegistryContract), big.NewInt(0), gas*12/10, gasPrice, calldata)
		signed, e := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(cfg.ChainID)), priv)
		if e != nil {
			return false, e
		}
		raw, e = signed.MarshalBinary()
		if e != nil {
			return false, e
		}
		pending = pendingHeartbeat{cfg.ChainID, cfg.VKAddress, cfg.VKRegistryContract, nonce, signed.Hash().Hex(), hex.EncodeToString(raw)}
		encoded, e := json.Marshal(pending)
		if e != nil {
			return false, e
		}
		if e = atomicWriteFile(path, encoded, 0o600); e != nil {
			return false, e
		}
	}
	raw, err = hex.DecodeString(pending.Raw)
	if err != nil {
		return false, err
	}
	// Retry the exact signed bytes/hash. Never allocate a new nonce on timeout.
	_, err = rpcSendRawTransaction(cfg.RPCURL, raw)
	return false, err
}

func runRegistryHeartbeat(ctx context.Context, cfg ServerConfig) {
	if cfg.VKRegistryContract == "" || cfg.VKPrivKeyHex == "" {
		return
	}
	due := nextHeartbeatSlot(time.Now(), cfg.ChainID, cfg.VKAddress, "registry-heartbeat", registryHeartbeatInterval)
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	retryAt := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-timer.C:
			_, pendingErr := os.Stat(filepath.Join(cfg.Storage, "registry-heartbeat.json"))
			if (now.Before(due) && os.IsNotExist(pendingErr)) || now.Before(retryAt) {
				continue
			}
			confirmed, err := registryHeartbeatTick(ctx, cfg)
			if confirmed {
				due = nextHeartbeatSlot(time.Now(), cfg.ChainID, cfg.VKAddress, "registry-heartbeat", registryHeartbeatInterval)
			}
			if err != nil {
				log.Printf("[heartbeat] check/send unavailable; retry in 60s")
			}
			retryAt = time.Now().Add(time.Minute)
		}
	}
}
