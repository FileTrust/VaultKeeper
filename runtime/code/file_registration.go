package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// ErrAlreadyRegistered is returned when the commitmentHash is already registered
// on FileRegistrationSC by this same VK address. The caller should treat this as
// a successful no-op (idempotent retry), not a failure.
var ErrAlreadyRegistered = errors.New("file_reg: commitmentHash already registered by this VK")

// ErrRPCUnavailable identifies transport failures and unusable JSON-RPC
// responses. Callers may safely ask the client to retry these failures; they
// must not classify them as requester misconduct.
var ErrRPCUnavailable = errors.New("rpc unavailable or invalid response")

// fileRegMu serialises the nonce-fetch → sign → send sequence so that concurrent
// store requests on the same VK process do not race on the account nonce.
var fileRegMu sync.Mutex

// ─── Commitment helpers ───────────────────────────────────────────────────────

// computeCommitmentHash returns keccak256(abi.encodePacked(pieceRoot, nonce)).
// Both inputs are 0x-prefixed (or bare) 32-byte hex strings.
// Matches Solidity: keccak256(abi.encodePacked(bytes32(pieceRoot), bytes32(nonce)))
func computeCommitmentHash(pieceRoot, nonce string) (string, error) {
	pr := hexToBytes32(pieceRoot)
	nc := hexToBytes32(nonce)
	combined := append(pr, nc...)
	hash := ethcrypto.Keccak256Hash(combined)
	return "0x" + hex.EncodeToString(hash[:]), nil
}

// computeSectorIdHashHex returns keccak256(sectorId_as_utf8_bytes) as 0x hex.
func computeSectorIdHashHex(sectorID string) string {
	h := ethcrypto.Keccak256Hash([]byte(sectorID))
	return "0x" + hex.EncodeToString(h[:])
}

// computePiecePositionHashHex returns keccak256(uint256(leafIndex) || nonce_bytes32).
// leafIndex is encoded as a 32-byte big-endian unsigned integer.
func computePiecePositionHashHex(leafIndex int, nonce string) string {
	idxBytes := make([]byte, 32)
	big.NewInt(int64(leafIndex)).FillBytes(idxBytes)
	nc := hexToBytes32(nonce)
	combined := append(idxBytes, nc...)
	h := ethcrypto.Keccak256Hash(combined)
	return "0x" + hex.EncodeToString(h[:])
}

// ─── On-chain registration ────────────────────────────────────────────────────

// Function selectors — computed once at init.
var (
	// registerFileStorage(bytes32,bytes32,bytes32,uint8,uint8,uint64,bytes32)
	// 7 params: commitmentHash, sectorRoot, zkPieceCommitment, deadlineIndex,
	//           partitionIndex, serviceEnd, registrationCommitment.
	registerFileStorageSelector = ethcrypto.Keccak256(
		[]byte("registerFileStorage(bytes32,bytes32,bytes32,uint8,uint8,uint64,bytes32)"),
	)[:4]

	// registerFileStorageV2(bytes32,bytes32,bytes32,uint8,uint8,uint64,bytes32,bytes32)
	// Adds deletionAuthHash = keccak256(DO-chosen deletion secret).
	registerFileStorageV2Selector = ethcrypto.Keccak256(
		[]byte("registerFileStorageV2(bytes32,bytes32,bytes32,uint8,uint8,uint64,bytes32,bytes32)"),
	)[:4]

	// recordExists(bytes32) → bool
	recordExistsSelector = ethcrypto.Keccak256([]byte("recordExists(bytes32)"))[:4]

	// fileRecords(bytes32) → FileStorageRecord tuple (public mapping getter)
	// Struct has 8 fields × 32 bytes = 256 bytes → 512 hex chars.
	// vkAddress is at ABI slot index 2 (byte offset 2×32=64, hex chars [128:192]).
	fileRecordsSelector = ethcrypto.Keccak256([]byte("fileRecords(bytes32)"))[:4]
)

// registerFileStorageOnChain sends a registerFileStorage() transaction to
// FileRegistrationSC and returns the transaction hash on success.
//
// Behavior:
//   - Returns ("", nil) when FileRegistrationContract is not configured (skipped).
//   - Returns (txHash, nil) on successful submission.
//   - Returns ("", ErrAlreadyRegistered) when the record already exists on-chain
//     under this same VK address — the caller should treat this as success.
//   - Returns ("", err) on any other error — the caller must fail the store.
//
// Note: we wait only for mempool acceptance, not block confirmation. The txHash
// is included in the receipt so the DO can verify confirmation independently.
func registerFileStorageOnChain(
	cfg ServerConfig,
	commitmentHash string,
	sectorRoot string,
	zkPieceCommitment string,
	deadlineIndex int,
	partitionIndex int,
	serviceEnd int64,
	registrationCommitment string,
	deletionAuthHash string,
) (txHash string, err error) {
	// B.1: chain registration must never run under the short allocator lock.
	noteLockConfinedWork("file-registration-rpc")
	if cfg.FileRegistrationContract == "" {
		return "", nil // not configured; registration layer disabled
	}
	if cfg.RPCURL == "" {
		return "", fmt.Errorf("file_reg: RPCURL not configured")
	}
	if cfg.VKPrivKeyHex == "" {
		return "", fmt.Errorf("file_reg: VKPrivKeyHex not configured")
	}

	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.FileRegistrationContract)

	// ── Pre-check: detect existing registration before spending gas ──────────
	// If the record exists and was registered by this VK, treat as idempotent
	// success (retry after a previous attempt that stored the tx but lost the
	// response). If registered by a different VK, that is an unexpected collision.
	exists, existingVK, existingDeletionAuthHash, checkErr := rpcGetRecordVKAddress(cfg.RPCURL, cfg.FileRegistrationContract, commitmentHash)
	logEthCall("vk:FileRegistrationSC.fileRecords", cfg.RPCURL, cfg.ChainID, "FileRegistrationSC", "fileRecords", cfg.FileRegistrationContract, cfg.VKAddress, statusFromErr(checkErr), map[string]any{
		"commitment_hash": commitmentHash,
		"exists":          exists,
	})
	if checkErr != nil {
		return "", fmt.Errorf("file_reg: pre-check record: %w", checkErr)
	}
	if exists {
		if strings.EqualFold(existingVK, cfg.VKAddress) {
			if deletionAuthHash != "" && !strings.EqualFold(existingDeletionAuthHash, deletionAuthHash) {
				return "", fmt.Errorf(
					"file_reg: existing deletionAuthHash mismatch for commitmentHash %s",
					truncate(commitmentHash, 18),
				)
			}
			log.Printf("[file_reg] commitmentHash already registered by this VK — idempotent ok  hash=%s",
				truncate(commitmentHash, 18))
			return "", ErrAlreadyRegistered
		}
		return "", fmt.Errorf(
			"file_reg: commitmentHash already registered by different VK %s (collision)",
			existingVK,
		)
	}

	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return "", fmt.Errorf("file_reg: parse privkey: %w", err)
	}

	// ── Build ABI-encoded calldata ────────────────────────────────────────────
	// registerFileStorage(...):   7 params.
	// registerFileStorageV2(...): 8 params, adding deletionAuthHash.
	//
	// Common params:
	//   4  bytes  selector
	//   32 bytes  commitmentHash         (bytes32)
	//   32 bytes  sectorRoot             (bytes32)
	//   32 bytes  zkPieceCommitment      (bytes32)
	//   32 bytes  deadlineIndex          (uint8  → left-padded)
	//   32 bytes  partitionIndex         (uint8  → left-padded)
	//   32 bytes  serviceEnd             (uint64 → left-padded)
	//   32 bytes  registrationCommitment (bytes32) — bytes32(0) for legacy stores
	//   32 bytes  deletionAuthHash       (bytes32) — V2 only
	useV2 := deletionAuthHash != ""
	paramCount := 7
	if useV2 {
		paramCount = 8
	}
	calldata := make([]byte, 0, 4+paramCount*32)
	if useV2 {
		calldata = append(calldata, registerFileStorageV2Selector...)
	} else {
		calldata = append(calldata, registerFileStorageSelector...)
	}
	calldata = append(calldata, hexToBytes32(commitmentHash)...)
	calldata = append(calldata, hexToBytes32(sectorRoot)...)
	calldata = append(calldata, hexToBytes32(zkPieceCommitment)...)

	dlPad := make([]byte, 32)
	dlPad[31] = byte(deadlineIndex)
	calldata = append(calldata, dlPad...)

	ptPad := make([]byte, 32)
	ptPad[31] = byte(partitionIndex)
	calldata = append(calldata, ptPad...)

	sePad := make([]byte, 32)
	big.NewInt(serviceEnd).FillBytes(sePad)
	calldata = append(calldata, sePad...)

	// registrationCommitment — pass bytes32(0) when empty (legacy / no escrow flow).
	calldata = append(calldata, hexToBytes32(registrationCommitment)...)
	if useV2 {
		calldata = append(calldata, hexToBytes32(deletionAuthHash)...)
	}

	// ── Nonce → sign → send (serialised to prevent concurrent nonce collisions) ──
	// Multiple pieces may arrive at the same VK concurrently (e.g. when n > number
	// of VKs). Holding the mutex from nonce-fetch through send guarantees each
	// goroutine uses a unique, incrementing nonce.
	fileRegMu.Lock()
	defer fileRegMu.Unlock()
	accountLock, err := acquireAccountTxLock(fromAddr.Hex())
	if err != nil {
		return "", fmt.Errorf("file_reg: %w", err)
	}
	defer accountLock.Release()

	nonce, err := rpcGetTransactionCount(cfg.RPCURL, fromAddr.Hex())
	logEthCall("vk:eth.getTransactionCount", cfg.RPCURL, cfg.ChainID, "eth", "getTransactionCount", "", fromAddr.Hex(), statusFromErr(err), map[string]any{
		"nonce":           nonce,
		"target_function": "registerFileStorage",
	})
	if err != nil {
		return "", fmt.Errorf("file_reg: get nonce: %w", err)
	}
	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	logEthCall("vk:eth.gasPrice", cfg.RPCURL, cfg.ChainID, "eth", "gasPrice", "", fromAddr.Hex(), "success", map[string]any{
		"result":          gasPrice.String(),
		"target_function": "registerFileStorage",
	})
	gasLimit, err := rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, nil)
	logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(err), map[string]any{
		"gas_estimate":    gasLimit,
		"target_function": "registerFileStorage",
	})
	if err != nil {
		// estimateGas failure usually means the tx would revert. Propagate as error
		// so the store fails cleanly rather than sending a doomed tx.
		return "", fmt.Errorf("file_reg: estimateGas: %w", err)
	}
	gasLimit = gasLimit * 12 / 10 // +20% buffer

	chainID := big.NewInt(cfg.ChainID)

	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signer := types.NewEIP155Signer(chainID)
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		return "", fmt.Errorf("file_reg: sign tx: %w", err)
	}
	rawBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("file_reg: marshal tx: %w", err)
	}
	txHash, err = rpcSendRawTransaction(cfg.RPCURL, rawBytes)
	details := map[string]any{
		"commitment_hash": commitmentHash,
		"sector_root":     sectorRoot,
		"deadline_index":  deadlineIndex,
		"partition_index": partitionIndex,
		"deletion_auth":   useV2,
	}
	if err == nil {
		if receipt, receiptErr := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
			logMinedTx("vk:FileRegistrationSC.registerFileStorage", cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "FileRegistrationSC", "registerFileStorage", toAddr.Hex(), signedTx, receipt, details)
		} else {
			if receiptErr != nil {
				log.Printf("[file_reg] receipt wait failed; logging submitted tx only: %v", receiptErr)
			}
			logSubmittedTx("vk:FileRegistrationSC.registerFileStorage", cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "FileRegistrationSC", "registerFileStorage", toAddr.Hex(), signedTx, txHash, details)
		}
	}
	if err != nil {
		return "", fmt.Errorf("file_reg: send tx: %w", err)
	}

	log.Printf("[file_reg] tx submitted  commitmentHash=%s  sectorRoot=%s  tx=%s",
		truncate(commitmentHash, 18), truncate(sectorRoot, 18), txHash)
	return txHash, nil
}

// ─── JSON-RPC helpers ─────────────────────────────────────────────────────────

type rpcReq struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      int    `json:"id"`
}

type rpcResp struct {
	Result string `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type rpcRawResp struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type rpcReceipt struct {
	TransactionHash   string `json:"transactionHash"`
	BlockNumber       string `json:"blockNumber"`
	Status            string `json:"status"`
	GasUsed           string `json:"gasUsed"`
	EffectiveGasPrice string `json:"effectiveGasPrice"`
}

func rpcCall(rpcURL, method string, params []any) (string, error) {
	return rpcCallCtx(context.Background(), rpcURL, method, params)
}

// rpcCallCtx is the context-aware form of rpcCall: the HTTP request aborts promptly when
// ctx is cancelled or its deadline passes, in addition to the per-call 15s HTTP timeout.
func rpcCallCtx(ctx context.Context, rpcURL, method string, params []any) (string, error) {
	raw, err := rpcCallRawCtx(ctx, rpcURL, method, params)
	if err != nil {
		return "", err
	}
	var result string
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("%w: rpc %s expected string result: %v", ErrRPCUnavailable, method, err)
	}
	result = strings.TrimSpace(result)
	if result == "" || strings.EqualFold(result, "0x") {
		return "", fmt.Errorf("%w: rpc %s returned empty result", ErrRPCUnavailable, method)
	}
	return result, nil
}

func rpcCallRaw(rpcURL, method string, params []any) (json.RawMessage, error) {
	return rpcCallRawCtx(context.Background(), rpcURL, method, params)
}

// rpcCallRawCtx honours ctx cancellation: the request is built with the context (so the
// transport aborts on cancel), a fresh attempt is never started after cancellation, and
// retry backoff sleeps are interruptible.
func rpcCallRawCtx(ctx context.Context, rpcURL, method string, params []any) (json.RawMessage, error) {
	body, err := json.Marshal(rpcReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return nil, fmt.Errorf("rpc %s request encode: %w", method, err)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	attempts := 1
	if isRetryableRPCRead(method) {
		attempts = 4
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("%w (cancelled: %v)", lastErr, ctxErr)
			}
			return nil, fmt.Errorf("%w: rpc %s cancelled: %v", ErrRPCUnavailable, method, ctxErr)
		}
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
		if reqErr != nil {
			return nil, fmt.Errorf("rpc %s request build: %w", method, reqErr)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		resp, postErr := client.Do(httpReq)
		if postErr != nil {
			lastErr = fmt.Errorf("%w: rpc %s transport: %v", ErrRPCUnavailable, method, postErr)
		} else {
			var out rpcRawResp
			decodeErr := json.NewDecoder(resp.Body).Decode(&out)
			_ = resp.Body.Close()
			switch {
			case resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices:
				lastErr = fmt.Errorf(
					"%w: rpc %s returned HTTP %s",
					ErrRPCUnavailable, method, resp.Status,
				)
			case decodeErr != nil:
				lastErr = fmt.Errorf("%w: rpc %s decode: %v", ErrRPCUnavailable, method, decodeErr)
			case out.Error != nil && isChainNotYetVisible(out.Error.Message):
				// The chain accepted the data but cannot serve it yet. On a
				// single-process dev chain this never happens; on a Cosmos EVM
				// chain a transaction is committed first and indexed a moment
				// later, so a read issued in between is answered with an error
				// rather than silence. It is a wait, not a failure, and the
				// retry loop below is exactly the right response.
				lastErr = fmt.Errorf("%w: rpc %s not yet available: %s",
					ErrRPCUnavailable, method, out.Error.Message)
			case out.Error != nil:
				// Anything else is a real answer -- a revert, a bad argument, an
				// unsupported method -- and retrying would only hide it.
				return nil, fmt.Errorf("rpc %s error: %s", method, out.Error.Message)
			default:
				result := bytes.TrimSpace(out.Result)
				if len(result) > 0 && !bytes.Equal(result, []byte("null")) {
					return result, nil
				}
				lastErr = fmt.Errorf("%w: rpc %s returned no result", ErrRPCUnavailable, method)
			}
		}
		if attempt+1 < attempts {
			// Interruptible backoff: never sleep past cancellation.
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w (cancelled: %v)", lastErr, ctx.Err())
			case <-time.After(time.Duration(250*(1<<attempt)) * time.Millisecond):
			}
		}
	}
	return nil, lastErr
}

// isChainNotYetVisible reports whether an RPC error means "committed, but not
// readable yet" rather than "wrong".
//
// It must stay narrow. A revert, a bad argument or an unknown method are real
// answers and have to surface on the first attempt; only the not-yet-indexed
// family may be waited out. The phrasing below is what a Cosmos EVM node returns
// while its EVM index catches up with a freshly committed block.
func isChainNotYetVisible(message string) bool {
	lower := strings.ToLower(message)
	if strings.Contains(lower, "reverted") || strings.Contains(lower, "invalid") {
		return false
	}
	return strings.Contains(lower, "tx not found") ||
		strings.Contains(lower, "not found: hash") ||
		strings.Contains(lower, "failed to get receipts from comet block") ||
		strings.Contains(lower, "failed to get rpc block") ||
		strings.Contains(lower, "failed to fetch header by number") ||
		strings.Contains(lower, "is not ready") ||
		strings.Contains(lower, "height is not available") ||
		strings.Contains(lower, "requested block height is bigger")
}

func isRetryableRPCRead(method string) bool {
	return strings.HasPrefix(method, "eth_get") ||
		method == "eth_call" ||
		method == "eth_estimateGas" ||
		method == "eth_blockNumber" ||
		method == "eth_chainId" ||
		method == "eth_gasPrice" ||
		method == "eth_maxPriorityFeePerGas" ||
		method == "eth_feeHistory" ||
		strings.HasPrefix(method, "net_") ||
		strings.HasPrefix(method, "web3_")
}

func rpcLatestBlockTimestamp(rpcURL string) (int64, error) {
	raw, err := rpcCallRaw(rpcURL, "eth_getBlockByNumber", []any{"latest", false})
	if err != nil {
		return 0, err
	}
	var block struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(raw, &block); err != nil {
		return 0, fmt.Errorf("%w: decode latest block: %v", ErrRPCUnavailable, err)
	}
	timestamp, ok := new(big.Int).SetString(strings.TrimPrefix(block.Timestamp, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("%w: invalid latest block timestamp %q", ErrRPCUnavailable, block.Timestamp)
	}
	return timestamp.Int64(), nil
}

func rpcWaitTransactionReceipt(rpcURL, txHash string, timeout time.Duration) (*rpcReceipt, error) {
	return rpcWaitTransactionReceiptCtx(context.Background(), rpcURL, txHash, timeout)
}

func rpcWaitTransactionReceiptCtx(ctx context.Context, rpcURL, txHash string, timeout time.Duration) (*rpcReceipt, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("receipt wait cancelled for %s: %w", txHash, ctxErr)
		}
		receipt, err := rpcGetTransactionReceipt(rpcURL, txHash)
		if err != nil {
			lastErr = err
		} else if receipt != nil {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("receipt wait cancelled for %s: %w", txHash, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("transaction receipt timeout for %s", txHash)
}

func rpcGetTransactionReceipt(rpcURL, txHash string) (*rpcReceipt, error) {
	return rpcGetTransactionReceiptCtx(context.Background(), rpcURL, txHash)
}

// rpcNullableResultCtx performs a single context-aware JSON-RPC call where a null result
// is MEANINGFUL (e.g. eth_getTransactionReceipt / eth_getTransactionByHash for an unknown
// hash) rather than an error: it returns (nil, nil) for null.
func rpcNullableResultCtx(ctx context.Context, rpcURL, method string, params []any) (json.RawMessage, error) {
	body, _ := json.Marshal(rpcReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	client := &http.Client{Timeout: 15 * time.Second}
	httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if reqErr != nil {
		return nil, fmt.Errorf("rpc %s request build: %w", method, reqErr)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("rpc %s: %w", method, err)
	}
	defer resp.Body.Close()
	var out rpcRawResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("rpc %s decode: %w", method, err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc %s error: %s", method, out.Error.Message)
	}
	result := bytes.TrimSpace(out.Result)
	if len(result) == 0 || bytes.Equal(result, []byte("null")) {
		return nil, nil
	}
	return result, nil
}

func rpcGetTransactionReceiptCtx(ctx context.Context, rpcURL, txHash string) (*rpcReceipt, error) {
	result, err := rpcNullableResultCtx(ctx, rpcURL, "eth_getTransactionReceipt", []any{txHash})
	if err != nil || result == nil {
		return nil, err
	}
	var receipt rpcReceipt
	if err := json.Unmarshal(result, &receipt); err != nil {
		return nil, fmt.Errorf("rpc eth_getTransactionReceipt result decode: %w", err)
	}
	return &receipt, nil
}

// rpcTransactionInMempoolCtx reports whether the node currently knows the transaction
// (pending in the mempool or already mined). A null result means the node has never seen
// it or has dropped it.
func rpcTransactionInMempoolCtx(ctx context.Context, rpcURL, txHash string) (bool, error) {
	result, err := rpcNullableResultCtx(ctx, rpcURL, "eth_getTransactionByHash", []any{txHash})
	if err != nil {
		return false, err
	}
	return result != nil, nil
}


type onChainFileStorageRecord struct {
	Exists            bool
	SectorRoot        string
	ZKPieceCommitment string
	VKAddress         string
	DeadlineIndex     int
	PartitionIndex    int
	ServiceEnd        uint64
	PartitionLinked   bool
	DeletionAuthHash  string
}

func decodeFileStorageRecordResult(result string) (onChainFileStorageRecord, error) {
	var record onChainFileStorageRecord
	raw := strings.TrimPrefix(strings.TrimSpace(result), "0x")
	if len(raw) < 320 { // slots 0..4 are required through partitionIndex
		return record, nil
	}
	slot := func(index int) string {
		start := index * 64
		if start+64 > len(raw) {
			return ""
		}
		return raw[start : start+64]
	}
	vkSlot := slot(2)
	if vkSlot == "" || vkSlot == strings.Repeat("0", 64) {
		return record, nil
	}
	parseUint := func(index int) (uint64, error) {
		value := slot(index)
		if value == "" {
			return 0, fmt.Errorf("file record missing ABI slot %d", index)
		}
		n, ok := new(big.Int).SetString(value, 16)
		if !ok || !n.IsUint64() {
			return 0, fmt.Errorf("file record slot %d is not uint64", index)
		}
		return n.Uint64(), nil
	}
	deadline, err := parseUint(3)
	if err != nil {
		return record, err
	}
	partition, err := parseUint(4)
	if err != nil {
		return record, err
	}
	serviceEnd, err := parseUint(5)
	if err != nil && slot(5) != "" {
		return record, err
	}

	record = onChainFileStorageRecord{
		Exists:            true,
		SectorRoot:        "0x" + slot(0),
		ZKPieceCommitment: "0x" + slot(1),
		VKAddress:         common.HexToAddress("0x" + vkSlot[24:]).Hex(),
		DeadlineIndex:     int(deadline),
		PartitionIndex:    int(partition),
		ServiceEnd:        serviceEnd,
		PartitionLinked:   slot(7) != "" && slot(7) != strings.Repeat("0", 64),
	}
	if authSlot := slot(8); authSlot != "" && authSlot != strings.Repeat("0", 64) {
		record.DeletionAuthHash = "0x" + authSlot
	}
	return record, nil
}

func rpcGetFileStorageRecord(rpcURL, contractAddr, commitmentHash string) (onChainFileStorageRecord, error) {
	// calldata: selector (4) + bytes32 commitmentHash (32) = 36 bytes
	calldata := make([]byte, 0, 4+32)
	calldata = append(calldata, fileRecordsSelector...)
	calldata = append(calldata, hexToBytes32(commitmentHash)...)

	result, err := rpcCall(rpcURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(contractAddr).Hex(),
			"data": "0x" + hex.EncodeToString(calldata),
		},
		"latest",
	})
	if err != nil {
		return onChainFileStorageRecord{}, err
	}
	return decodeFileStorageRecordResult(result)
}

// rpcGetRecordVKAddress is the narrow record lookup used by the idempotent
// registration and lifecycle recovery paths.
func rpcGetRecordVKAddress(rpcURL, contractAddr, commitmentHash string) (bool, string, string, error) {
	record, err := rpcGetFileStorageRecord(rpcURL, contractAddr, commitmentHash)
	if err != nil {
		return false, "", "", err
	}
	return record.Exists, record.VKAddress, record.DeletionAuthHash, nil
}

func rpcGetTransactionCount(rpcURL, address string) (uint64, error) {
	return rpcGetTransactionCountCtx(context.Background(), rpcURL, address)
}

// rpcGetConfirmedTransactionCountCtx returns the sender's CONFIRMED ("latest") account
// nonce — unlike the "pending" variant, this is proof of consumption: a stored nonce
// strictly below this value has definitively been used by a mined transaction.
func rpcGetConfirmedTransactionCountCtx(ctx context.Context, rpcURL, address string) (uint64, error) {
	result, err := rpcCallCtx(ctx, rpcURL, "eth_getTransactionCount", []any{address, "latest"})
	if err != nil {
		return 0, err
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(result, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("bad confirmed nonce result: %s", result)
	}
	return n.Uint64(), nil
}

func rpcGetTransactionCountCtx(ctx context.Context, rpcURL, address string) (uint64, error) {
	result, err := rpcCallCtx(ctx, rpcURL, "eth_getTransactionCount", []any{address, "pending"})
	if err != nil {
		return 0, err
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(result, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("bad nonce result: %s", result)
	}
	return n.Uint64(), nil
}

func rpcEstimateGas(rpcURL, from, to string, data []byte, value *big.Int) (uint64, error) {
	return rpcEstimateGasCtx(context.Background(), rpcURL, from, to, data, value)
}

func rpcEstimateGasCtx(ctx context.Context, rpcURL, from, to string, data []byte, value *big.Int) (uint64, error) {
	params := map[string]string{
		"from": from,
		"to":   to,
		"data": "0x" + hex.EncodeToString(data),
	}
	if value != nil && value.Sign() > 0 {
		params["value"] = "0x" + value.Text(16)
	}
	result, err := rpcCallCtx(ctx, rpcURL, "eth_estimateGas", []any{params})
	if err != nil {
		return 0, err
	}
	g, ok := new(big.Int).SetString(strings.TrimPrefix(result, "0x"), 16)
	if !ok {
		return 0, fmt.Errorf("bad estimateGas result: %s", result)
	}
	return g.Uint64(), nil
}

func rpcSendRawTransaction(rpcURL string, rawTx []byte) (string, error) {
	return rpcSendRawTransactionCtx(context.Background(), rpcURL, rawTx)
}

func rpcSendRawTransactionCtx(ctx context.Context, rpcURL string, rawTx []byte) (string, error) {
	return rpcCallCtx(ctx, rpcURL, "eth_sendRawTransaction", []any{"0x" + hex.EncodeToString(rawTx)})
}

// ─── Utility ──────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
