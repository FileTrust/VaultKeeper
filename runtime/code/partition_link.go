package main

import (
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

// ─── Partition linking (privacy fix) ──────────────────────────────────────────
//
// FileRegistrationSC.verifyPartitionContainsSector() flips partitionLinked to
// true once the sector is provably inside the partition the record names. The
// contract documents the call as "callable by anyone" and verifies everything
// itself by reading StorageProofSC — the sender supplies no evidence, so who
// sends it cannot change the outcome.
//
// It used to be sent by the DO. That leaked the whole relationship: the sender
// was the DO's wallet and the argument pointed at a record that names the VK,
// so DO↔VK was public from upload time onward — bypassing the commitment
// scheme that is supposed to hide it until service end. The VK sends it now.
//
// The VK also has the incentive to send it: registrationCurrentProofStatus()
// returns current=false while partitionLinked is false, and claimEscrow()
// requires a current proof. An unlinked record is an unpaid record.
//
// Migration safety: when a pending migration exists, this call also sets
// migrationDeclared for the old slot. That remains sound with the VK as sender
// because the contract only reaches that branch after confirming the sector is
// genuinely present at the new coordinates in on-chain partition state.

// verifyPartitionContainsSector(bytes32)
var verifyPartitionContainsSectorSelector = ethcrypto.Keccak256(
	[]byte("verifyPartitionContainsSector(bytes32)"),
)[:4]

// maxPartitionLinksPerSweep bounds the work of one reconciler tick so a large
// backlog cannot turn a single sweep into an unbounded burst of transactions.
const maxPartitionLinksPerSweep = 32

// linkPartitionOnChain sends verifyPartitionContainsSector() for one record.
//
// Returns ("", nil) when there is nothing to do — not configured, record absent,
// owned by another VK, or already linked. Returns ("", err) when the link is not
// possible yet; that is the normal case while the partition is still being
// registered, and the caller is expected to retry on the next sweep.
func linkPartitionOnChain(cfg ServerConfig, commitmentHash string) (txHash string, err error) {
	// Chain work must never run under the short allocator lock.
	noteLockConfinedWork("partition-link-rpc")
	if cfg.FileRegistrationContract == "" {
		return "", nil // registration layer disabled
	}
	if cfg.RPCURL == "" {
		return "", fmt.Errorf("partition_link: RPCURL not configured")
	}
	if cfg.VKPrivKeyHex == "" {
		return "", fmt.Errorf("partition_link: VKPrivKeyHex not configured")
	}
	if strings.TrimSpace(commitmentHash) == "" {
		return "", nil
	}

	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.FileRegistrationContract)

	// ── Pre-check: skip records that are absent, foreign, or already linked ──
	record, checkErr := rpcGetFileStorageRecord(cfg.RPCURL, cfg.FileRegistrationContract, commitmentHash)
	logEthCall("vk:FileRegistrationSC.fileRecords", cfg.RPCURL, cfg.ChainID, "FileRegistrationSC", "fileRecords", cfg.FileRegistrationContract, cfg.VKAddress, statusFromErr(checkErr), map[string]any{
		"commitment_hash":  commitmentHash,
		"exists":           record.Exists,
		"partition_linked": record.PartitionLinked,
		"target_function":  "verifyPartitionContainsSector",
	})
	if checkErr != nil {
		return "", fmt.Errorf("partition_link: pre-check record: %w", checkErr)
	}
	if !record.Exists {
		return "", nil // not registered (yet) — the store lifecycle owns that
	}
	if !strings.EqualFold(record.VKAddress, cfg.VKAddress) {
		return "", nil // another VK's record; never ours to link
	}
	if record.PartitionLinked {
		return "", nil // already linked — idempotent success
	}

	privKey, parseErr := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if parseErr != nil {
		return "", fmt.Errorf("partition_link: parse privkey: %w", parseErr)
	}

	// ── Build calldata: selector (4) + bytes32 commitmentHash (32) ───────────
	calldata := make([]byte, 0, 4+32)
	calldata = append(calldata, verifyPartitionContainsSectorSelector...)
	calldata = append(calldata, hexToBytes32(commitmentHash)...)

	// ── Nonce → sign → send, serialised against the registration sender ──────
	// Both paths spend nonces from the same VK account, so they share the mutex.
	fileRegMu.Lock()
	defer fileRegMu.Unlock()
	accountLock, lockErr := acquireAccountTxLock(fromAddr.Hex())
	if lockErr != nil {
		return "", fmt.Errorf("partition_link: %w", lockErr)
	}
	defer accountLock.Release()

	// estimateGas doubles as the readiness gate. While the sector is not yet in
	// the partition the call reverts, so we learn that here and send nothing.
	gasLimit, gasErr := rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, nil)
	logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(gasErr), map[string]any{
		"gas_estimate":    gasLimit,
		"target_function": "verifyPartitionContainsSector",
	})
	if gasErr != nil {
		return "", fmt.Errorf("partition_link: not linkable yet: %w", gasErr)
	}
	gasLimit = gasLimit * 12 / 10 // +20% buffer

	nonce, nonceErr := rpcAccountTransactionCount(cfg, fromAddr.Hex())
	logEthCall("vk:eth.getTransactionCount", cfg.RPCURL, cfg.ChainID, "eth", "getTransactionCount", "", fromAddr.Hex(), statusFromErr(nonceErr), map[string]any{
		"nonce":           nonce,
		"target_function": "verifyPartitionContainsSector",
	})
	if nonceErr != nil {
		return "", fmt.Errorf("partition_link: get nonce: %w", nonceErr)
	}

	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	logEthCall("vk:eth.gasPrice", cfg.RPCURL, cfg.ChainID, "eth", "gasPrice", "", fromAddr.Hex(), "success", map[string]any{
		"result":          gasPrice.String(),
		"target_function": "verifyPartitionContainsSector",
	})

	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signer := types.NewEIP155Signer(big.NewInt(cfg.ChainID))
	signedTx, signErr := types.SignTx(tx, signer, privKey)
	if signErr != nil {
		return "", fmt.Errorf("partition_link: sign tx: %w", signErr)
	}
	rawBytes, marshalErr := signedTx.MarshalBinary()
	if marshalErr != nil {
		return "", fmt.Errorf("partition_link: marshal tx: %w", marshalErr)
	}

	txHash, err = rpcSendRawTransaction(cfg.RPCURL, rawBytes)
	details := map[string]any{
		"commitment_hash": commitmentHash,
		"sector_root":     record.SectorRoot,
		"deadline_index":  record.DeadlineIndex,
		"partition_index": record.PartitionIndex,
	}
	if err == nil {
		if receipt, receiptErr := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
			logMinedTx("vk:FileRegistrationSC.verifyPartitionContainsSector", cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "FileRegistrationSC", "verifyPartitionContainsSector", toAddr.Hex(), signedTx, receipt, details)
		} else {
			if receiptErr != nil {
				log.Printf("[partition_link] receipt wait failed; logging submitted tx only: %v", receiptErr)
			}
			logSubmittedTx("vk:FileRegistrationSC.verifyPartitionContainsSector", cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "FileRegistrationSC", "verifyPartitionContainsSector", toAddr.Hex(), signedTx, txHash, details)
		}
	}
	if err != nil {
		return "", fmt.Errorf("partition_link: send tx: %w", err)
	}

	log.Printf("[partition_link] linked  commitmentHash=%s  sectorRoot=%s  tx=%s",
		truncate(commitmentHash, 18), truncate(record.SectorRoot, 18), txHash)
	return txHash, nil
}

// listStoredCommitmentHashes returns the commitmentHash of every piece this VK
// has stored, read from the durable payment-credentials directory. Quote-only
// entries are keyed by paymentCommitment and carry no commitmentHash yet; they
// are skipped because nothing is registered for them.
func listStoredCommitmentHashes(storage string) ([]string, error) {
	entries, err := os.ReadDir(paymentDir(storage))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(paymentDir(storage), entry.Name()))
		if readErr != nil {
			continue
		}
		var creds PaymentCredentials
		if json.Unmarshal(payload, &creds) != nil {
			continue
		}
		if strings.TrimSpace(creds.CommitmentHash) == "" {
			continue
		}
		hashes = append(hashes, creds.CommitmentHash)
	}
	return hashes, nil
}

// reconcilePartitionLinks links every stored record that the chain still shows
// as unlinked. A record becomes linkable only once its partition is registered,
// so "not linkable yet" is the ordinary state right after a store and is logged
// at low volume rather than treated as a failure.
func reconcilePartitionLinks(cfg ServerConfig) {
	if cfg.FileRegistrationContract == "" {
		return
	}
	hashes, err := listStoredCommitmentHashes(cfg.Storage)
	if err != nil {
		log.Printf("[partition_link] list stored commitments failed: %v", err)
		return
	}
	attempted := 0
	for _, commitmentHash := range hashes {
		if attempted >= maxPartitionLinksPerSweep {
			log.Printf("[partition_link] sweep cap reached (%d); remaining records retry next tick",
				maxPartitionLinksPerSweep)
			return
		}
		txHash, linkErr := linkPartitionOnChain(cfg, commitmentHash)
		if linkErr != nil {
			attempted++
			log.Printf("[partition_link] pending commitmentHash=%s: %v",
				truncate(commitmentHash, 18), linkErr)
			continue
		}
		if txHash != "" {
			attempted++
		}
	}
}
