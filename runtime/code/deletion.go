package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Function selectors for deletion-related on-chain calls.
var (
	// registerFileDeletion(bytes32)
	registerFileDeletionSelector = ethcrypto.Keccak256(
		[]byte("registerFileDeletion(bytes32)"),
	)[:4]

	// registerFileDeletionAuthorized(bytes32,bytes32)
	registerFileDeletionAuthorizedSelector = ethcrypto.Keccak256(
		[]byte("registerFileDeletionAuthorized(bytes32,bytes32)"),
	)[:4]

	// confirmFileDeletion(bytes32)
	confirmFileDeletionSelector = ethcrypto.Keccak256(
		[]byte("confirmFileDeletion(bytes32)"),
	)[:4]

	// isDeletionDeclared(bytes32)
	isDeletionDeclaredSelector = ethcrypto.Keccak256(
		[]byte("isDeletionDeclared(bytes32)"),
	)[:4]

	// isDeletionConfirmed(bytes32)
	isDeletionConfirmedSelector = ethcrypto.Keccak256(
		[]byte("isDeletionConfirmed(bytes32)"),
	)[:4]

	// commitmentHashIsActive(bytes32) reports whether a commitment is the CURRENT
	// registration. It is false when the record is absent, when the registration
	// expired, or when its deletion is confirmed — so it must be preferred over
	// isDeletionConfirmed alone, which misses the expired case.
	commitmentHashIsActiveSelector = ethcrypto.Keccak256(
		[]byte("commitmentHashIsActive(bytes32)"),
	)[:4]

	expiredCommitmentHashSelector = ethcrypto.Keccak256(
		[]byte("expiredCommitmentHashes(bytes32)"),
	)[:4]

	expiredRegistrationCommitmentSelector = ethcrypto.Keccak256(
		[]byte("expiredRegistrationCommitments(bytes32)"),
	)[:4]

	// claimEscrowOnDeletion(bytes32,bytes32,bytes32,bytes32,bytes32)
	claimEscrowOnDeletionSelector = ethcrypto.Keccak256(
		[]byte("claimEscrowOnDeletion(bytes32,bytes32,bytes32,bytes32,bytes32)"),
	)[:4]

	escrowStatusSelector = ethcrypto.Keccak256(
		[]byte("escrowStatus(bytes32)"),
	)[:4]
	deletionOperationIDSelector = ethcrypto.Keccak256(
		[]byte("deletionOperationIds(bytes32)"),
	)[:4]
	deletionReleaseOperationSelector = ethcrypto.Keccak256(
		[]byte("getOperation(bytes32)"),
	)[:4]
)

const (
	deletionReleaseAwaitingSuccessorIdentity uint8 = 1
	deletionReleaseAwaitingSuccessorProof    uint8 = 2
	deletionReleaseSatisfied                 uint8 = 3
	deletionReleaseConfirmed                 uint8 = 4
)

type deletionReleaseOperationStatus struct {
	OperationID      string
	Revision         uint64
	Route            uint8
	State            uint8
	RecoveryRequired bool
	RecoveryReason   uint8
}

func deletionReleaseStatusOnChain(
	ctx context.Context, cfg ServerConfig, commitmentHash string,
) (deletionReleaseOperationStatus, error) {
	return deletionReleaseStatusOnChainAtBlock(ctx, cfg, commitmentHash, "latest")
}

// deletionReleaseStatusOnChainAtBlock is the block-pinned variant used when one scheduler
// decision must not combine state from different heads. Other reconciliation callers retain the
// existing latest-state wrapper above.
func deletionReleaseStatusOnChainAtBlock(
	ctx context.Context, cfg ServerConfig, commitmentHash, blockTag string,
) (deletionReleaseOperationStatus, error) {
	var status deletionReleaseOperationStatus
	if strings.TrimSpace(blockTag) == "" {
		return status, fmt.Errorf("deletion release block tag is empty")
	}
	if !common.IsHexAddress(cfg.FileRegistrationContract) ||
		!common.IsHexAddress(cfg.DeletionReleaseContract) {
		return status, fmt.Errorf("deletion release contracts are not configured")
	}
	operationCall := append(append([]byte{}, deletionOperationIDSelector...),
		hexToBytes32(commitmentHash)...)
	operationResult, err := rpcCallCtx(ctx, cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.FileRegistrationContract).Hex(),
			"data": "0x" + hex.EncodeToString(operationCall),
		}, blockTag,
	})
	if err != nil {
		return status, err
	}
	operationHex := strings.TrimPrefix(operationResult, "0x")
	if len(operationHex) < 64 || operationHex[:64] == strings.Repeat("0", 64) {
		return status, fmt.Errorf("deletion release operation is missing")
	}
	status.OperationID = "0x" + operationHex[:64]
	statusCall := append(append([]byte{}, deletionReleaseOperationSelector...),
		hexToBytes32(status.OperationID)...)
	result, err := rpcCallCtx(ctx, cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.DeletionReleaseContract).Hex(),
			"data": "0x" + hex.EncodeToString(statusCall),
		}, blockTag,
	})
	if err != nil {
		return status, err
	}
	rawHex := strings.TrimPrefix(result, "0x")
	if len(rawHex) < 18*64 {
		return status, fmt.Errorf("DeletionReleaseSC.getOperation returned %d hex chars", len(rawHex))
	}
	raw, err := hex.DecodeString(rawHex[:18*64])
	if err != nil {
		return status, fmt.Errorf("decode deletion release operation: %w", err)
	}
	if status.Revision, err = decodeUint64ABIWord(raw[13*32:14*32], "revision"); err != nil {
		return deletionReleaseOperationStatus{}, err
	}
	route, err := decodeUint64ABIWord(raw[14*32:15*32], "route")
	if err != nil || route > 255 {
		return deletionReleaseOperationStatus{}, fmt.Errorf("invalid deletion release route")
	}
	state, err := decodeUint64ABIWord(raw[15*32:16*32], "state")
	if err != nil || state > 255 {
		return deletionReleaseOperationStatus{}, fmt.Errorf("invalid deletion release state")
	}
	reason, err := decodeUint64ABIWord(raw[17*32:18*32], "recoveryReason")
	if err != nil || reason > 255 {
		return deletionReleaseOperationStatus{}, fmt.Errorf("invalid deletion release recovery reason")
	}
	status.Route = uint8(route)
	status.State = uint8(state)
	status.RecoveryRequired = new(big.Int).SetBytes(raw[16*32:17*32]).Sign() != 0
	status.RecoveryReason = uint8(reason)
	return status, nil
}

func deletionStatusOnChain(cfg ServerConfig, commitmentHash string) (declared bool, confirmed bool, err error) {
	return deletionStatusOnChainCtx(context.Background(), cfg, commitmentHash)
}

// deletionStatusOnChainCtx is the context-aware form: both eth_call queries abort promptly
// on ctx cancellation.
func deletionStatusOnChainCtx(ctx context.Context, cfg ServerConfig, commitmentHash string) (declared bool, confirmed bool, err error) {
	if cfg.FileRegistrationContract == "" {
		return false, false, fmt.Errorf("deletion: FileRegistrationContract not configured")
	}
	if cfg.RPCURL == "" {
		return false, false, fmt.Errorf("deletion: RPCURL not configured")
	}
	declared, err = deletionBoolCall(ctx, cfg, isDeletionDeclaredSelector, commitmentHash)
	if err != nil {
		return false, false, err
	}
	confirmed, err = deletionBoolCall(ctx, cfg, isDeletionConfirmedSelector, commitmentHash)
	if err != nil {
		return declared, false, err
	}
	return declared, confirmed, nil
}

// rpcCommitmentHashIsActive reports whether a commitment is still the current
// registration on chain. A false answer means the commitment is historical —
// absent, expired, or deletion-confirmed. An error means the answer is unknown
// and callers must NOT treat it as "not active".
func rpcCommitmentHashIsActive(cfg ServerConfig, commitmentHash string) (bool, error) {
	return deletionBoolCall(
		context.Background(), cfg, commitmentHashIsActiveSelector, commitmentHash,
	)
}

func deletionBoolCall(ctx context.Context, cfg ServerConfig, selector []byte, commitmentHash string) (bool, error) {
	calldata := make([]byte, 0, 36)
	calldata = append(calldata, selector...)
	calldata = append(calldata, hexToBytes32(commitmentHash)...)
	result, err := rpcCallCtx(ctx, cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.FileRegistrationContract).Hex(),
			"data": "0x" + hex.EncodeToString(calldata),
		},
		"latest",
	})
	if err != nil {
		return false, err
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(result, "0x"), 16)
	if !ok {
		return false, fmt.Errorf("bad deletion status result: %s", result)
	}
	return n.Sign() != 0, nil
}

// buildDeletionDeclarationCalldata validates the (optional) authorization secret and
// builds the exact calldata for the declaration transaction. It returns the calldata and
// the target function name. The secret is embedded in calldata only (its unavoidable and
// intended destination: it becomes public on-chain when the transaction lands); it is
// never logged or persisted by any caller.
func buildDeletionDeclarationCalldata(commitmentHash, deletionAuthSecret string) ([]byte, string, error) {
	useAuthorized := strings.TrimSpace(deletionAuthSecret) != ""
	paramCount := 1
	if useAuthorized {
		raw := strings.TrimPrefix(strings.TrimSpace(deletionAuthSecret), "0x")
		if len(raw) != 64 {
			return nil, "", fmt.Errorf("deletion: deletionAuthSecret must be a 0x-prefixed 32-byte hex value")
		}
		if _, decErr := hex.DecodeString(raw); decErr != nil {
			return nil, "", fmt.Errorf("deletion: deletionAuthSecret must be valid hex")
		}
		if raw == strings.Repeat("0", 64) {
			return nil, "", fmt.Errorf("deletion: deletionAuthSecret must not be zero")
		}
		if !strings.HasPrefix(deletionAuthSecret, "0x") {
			deletionAuthSecret = "0x" + raw
		}
		paramCount = 2
	}
	calldata := make([]byte, 0, 4+paramCount*32)
	fn := "registerFileDeletion"
	if useAuthorized {
		calldata = append(calldata, registerFileDeletionAuthorizedSelector...)
		fn = "registerFileDeletionAuthorized"
	} else {
		calldata = append(calldata, registerFileDeletionSelector...)
	}
	calldata = append(calldata, hexToBytes32(commitmentHash)...)
	if useAuthorized {
		calldata = append(calldata, hexToBytes32(deletionAuthSecret)...)
	}
	return calldata, fn, nil
}

func deletionDeclarationConfigCheck(cfg ServerConfig) error {
	if cfg.FileRegistrationContract == "" {
		return fmt.Errorf("deletion: FileRegistrationContract not configured")
	}
	if cfg.RPCURL == "" {
		return fmt.Errorf("deletion: RPCURL not configured")
	}
	if cfg.VKPrivKeyHex == "" {
		return fmt.Errorf("deletion: VKPrivKeyHex not configured")
	}
	return nil
}

func effectiveDeletionGasPriceWei(cfg ServerConfig) int64 {
	if cfg.FixedGasPriceWei > 0 {
		return cfg.FixedGasPriceWei
	}
	return 1_000_000
}

// signDeletionDeclarationTx deterministically builds and signs the declaration
// transaction from explicit nonce/gas parameters. go-ethereum's ECDSA signing is
// RFC6979-style deterministic, so identical inputs (chain id, nonce, gas, calldata, key)
// reproduce the identical raw transaction and hash — the basis for exact same-hash
// rebroadcast without persisting the raw transaction (or the secret it embeds).
func signDeletionDeclarationTx(
	cfg ServerConfig, calldata []byte, nonce, gasLimit uint64, gasPriceWei int64,
) (txHashHex, rawHex string, err error) {
	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return "", "", fmt.Errorf("parse privkey: %w", err)
	}
	toAddr := common.HexToAddress(cfg.FileRegistrationContract)
	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, big.NewInt(gasPriceWei), calldata)
	signer := types.NewEIP155Signer(big.NewInt(cfg.ChainID))
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		return "", "", fmt.Errorf("sign tx: %w", err)
	}
	rawBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return "", "", fmt.Errorf("marshal tx: %w", err)
	}
	return signedTx.Hash().Hex(), hex.EncodeToString(rawBytes), nil
}

// declarationCalldataHash is the immutable calldata identity persisted in the attempt
// journal: a hash only, so the secret embedded in authorized-deletion calldata never
// touches disk while remaining verifiable on reconstruction.
func declarationCalldataHash(calldata []byte) string {
	sum := sha256.Sum256(calldata)
	return hex.EncodeToString(sum[:])
}

// declarationSenderAddress derives the sender from the ACTUAL signing key, so a changed
// key is detected even if cfg.VKAddress was left stale.
func declarationSenderAddress(cfg ServerConfig) (string, error) {
	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return "", fmt.Errorf("parse privkey: %w", err)
	}
	return ethcrypto.PubkeyToAddress(privKey.PublicKey).Hex(), nil
}

// verifyDeletionDeclarationEnvelope checks the persisted immutable envelope identity
// against the current configuration, signing key, and reconstructed calldata. ANY
// mismatch means deterministic reconstruction is unsafe: the caller must STOP (never
// broadcast, never silently replace) — the old transaction may still mine elsewhere.
func verifyDeletionDeclarationEnvelope(
	cfg ServerConfig, attempt deletionDeclarationAttempt, calldata []byte,
) error {
	if attempt.ChainID != cfg.ChainID {
		return fmt.Errorf("declaration envelope chainId drift: stored %d, current %d", attempt.ChainID, cfg.ChainID)
	}
	if !strings.EqualFold(attempt.ContractAddress, common.HexToAddress(cfg.FileRegistrationContract).Hex()) {
		return fmt.Errorf("declaration envelope contract drift: stored %s, current %s",
			attempt.ContractAddress, cfg.FileRegistrationContract)
	}
	if attempt.TxType != 0 {
		return fmt.Errorf("declaration envelope tx type %d unsupported", attempt.TxType)
	}
	if attempt.ValueWei != 0 {
		return fmt.Errorf("declaration envelope value %d must be zero", attempt.ValueWei)
	}
	sender, err := declarationSenderAddress(cfg)
	if err != nil {
		return err
	}
	if !strings.EqualFold(attempt.Sender, sender) {
		return fmt.Errorf("declaration envelope signer drift: stored %s, current key yields %s", attempt.Sender, sender)
	}
	if !strings.EqualFold(attempt.CalldataHash, declarationCalldataHash(calldata)) {
		return fmt.Errorf("declaration envelope calldata hash mismatch (different secret or commitment)")
	}
	return nil
}

// newSignedDeletionDeclaration prepares a NEW declaration attempt: it acquires the
// account transaction locks, fetches the pending nonce, estimates gas, and signs — but
// does NOT broadcast. The caller persists the attempt record first, then broadcasts, then
// calls Release() to free the account locks (held across persist+broadcast so no other
// sender can race this nonce). On error the locks are already released.
func newSignedDeletionDeclaration(
	ctx context.Context, cfg ServerConfig, commitmentHash, deletionAuthSecret string,
) (signedDeclaration, error) {
	var sd signedDeclaration
	if err := deletionDeclarationConfigCheck(cfg); err != nil {
		return sd, err
	}
	calldata, fn, err := buildDeletionDeclarationCalldata(commitmentHash, deletionAuthSecret)
	if err != nil {
		return sd, err
	}
	sender, err := declarationSenderAddress(cfg)
	if err != nil {
		return sd, err
	}
	fromAddr := common.HexToAddress(cfg.VKAddress)

	fileRegMu.Lock()
	accountLock, lockErr := acquireAccountTxLock(fromAddr.Hex())
	if lockErr != nil {
		fileRegMu.Unlock()
		return sd, lockErr
	}
	unlock := func() {
		accountLock.Release()
		fileRegMu.Unlock()
	}

	nonce, err := rpcAccountTransactionCountCtx(ctx, cfg, fromAddr.Hex())
	if err != nil {
		unlock()
		return sd, fmt.Errorf("get nonce: %w", err)
	}
	gasLimit, err := rpcEstimateGasCtx(ctx, cfg.RPCURL, fromAddr.Hex(), common.HexToAddress(cfg.FileRegistrationContract).Hex(), calldata, nil)
	if err != nil {
		unlock()
		return sd, fmt.Errorf("estimateGas: %w", err)
	}
	gasLimit = gasLimit * 12 / 10 // +20% buffer
	gasPriceWei := effectiveDeletionGasPriceWei(cfg)

	txHashHex, rawHex, err := signDeletionDeclarationTx(cfg, calldata, nonce, gasLimit, gasPriceWei)
	if err != nil {
		unlock()
		return sd, err
	}
	log.Printf("[deletion] %s declaration signed  commitmentHash=%s  tx=%s  nonce=%d",
		fn, truncate(commitmentHash, 18), truncate(txHashHex, 18), nonce)
	return signedDeclaration{
		TxHash:          txHashHex,
		Nonce:           nonce,
		GasLimit:        gasLimit,
		GasPriceWei:     gasPriceWei,
		ChainID:         cfg.ChainID,
		Sender:          sender,
		ContractAddress: common.HexToAddress(cfg.FileRegistrationContract).Hex(),
		CalldataHash:    declarationCalldataHash(calldata),
		RawHex:          rawHex,
		Release:         unlock,
	}, nil
}

// rebuildSignedDeletionDeclaration deterministically reconstructs a persisted attempt's
// ACTIVE transaction from its envelope plus the request-re-supplied secret, after full
// envelope verification. matches=false (or err) means the identical transaction could not
// be safely reproduced and NOTHING may be broadcast under the old identity.
func rebuildSignedDeletionDeclaration(
	cfg ServerConfig, commitmentHash, deletionAuthSecret string,
	attempt deletionDeclarationAttempt,
) (rawHex string, matches bool, err error) {
	if err := deletionDeclarationConfigCheck(cfg); err != nil {
		return "", false, err
	}
	calldata, _, err := buildDeletionDeclarationCalldata(commitmentHash, deletionAuthSecret)
	if err != nil {
		return "", false, err
	}
	if err := verifyDeletionDeclarationEnvelope(cfg, attempt, calldata); err != nil {
		return "", false, err
	}
	txHashHex, rawHex, err := signDeletionDeclarationTx(cfg, calldata, attempt.Nonce, attempt.GasLimit, attempt.GasPriceWei)
	if err != nil {
		return "", false, err
	}
	return rawHex, strings.EqualFold(txHashHex, attempt.TxHash), nil
}

// signDeletionDeclarationReplacement builds the SAME-NONCE fee-bump replacement of a
// persisted attempt: identical envelope (chain id, sender, contract, type, value,
// calldata, nonce, gas limit) with only the gas price changed. Because it shares the
// nonce, at most one transaction of the lineage can ever mine.
func signDeletionDeclarationReplacement(
	cfg ServerConfig, commitmentHash, deletionAuthSecret string,
	attempt deletionDeclarationAttempt, newGasPriceWei int64,
) (txHashHex, rawHex string, err error) {
	if err := deletionDeclarationConfigCheck(cfg); err != nil {
		return "", "", err
	}
	if newGasPriceWei <= attempt.GasPriceWei {
		return "", "", fmt.Errorf("replacement gas price %d must exceed current %d", newGasPriceWei, attempt.GasPriceWei)
	}
	calldata, _, err := buildDeletionDeclarationCalldata(commitmentHash, deletionAuthSecret)
	if err != nil {
		return "", "", err
	}
	if err := verifyDeletionDeclarationEnvelope(cfg, attempt, calldata); err != nil {
		return "", "", err
	}
	return signDeletionDeclarationTx(cfg, calldata, attempt.Nonce, attempt.GasLimit, newGasPriceWei)
}

// registerFileDeletionOnChain sends a deletion declaration to FileRegistrationSC.
// When deletionAuthSecret is present, it uses the V2 authorized path.
// LEGACY direct path: production declaration now goes through the durable
// declaration-attempt journal (resolveDeletionDeclarationLocked) so ambiguous broadcast
// outcomes reconcile by exact transaction hash instead of re-declaring blindly.
func registerFileDeletionOnChain(cfg ServerConfig, commitmentHash, deletionAuthSecret string) (string, error) {
	return registerFileDeletionOnChainCtx(context.Background(), cfg, commitmentHash, deletionAuthSecret)
}

// registerFileDeletionOnChainCtx is the context-aware form used under the bounded
// declaration claim: every RPC step aborts promptly on ctx cancellation and no new step
// starts after the deadline.
func registerFileDeletionOnChainCtx(ctx context.Context, cfg ServerConfig, commitmentHash, deletionAuthSecret string) (string, error) {
	if cfg.FileRegistrationContract == "" {
		return "", fmt.Errorf("deletion: FileRegistrationContract not configured")
	}
	if cfg.RPCURL == "" {
		return "", fmt.Errorf("deletion: RPCURL not configured")
	}
	if cfg.VKPrivKeyHex == "" {
		return "", fmt.Errorf("deletion: VKPrivKeyHex not configured")
	}

	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.FileRegistrationContract)

	useAuthorized := strings.TrimSpace(deletionAuthSecret) != ""
	paramCount := 1
	if useAuthorized {
		raw := strings.TrimPrefix(strings.TrimSpace(deletionAuthSecret), "0x")
		if len(raw) != 64 {
			return "", fmt.Errorf("deletion: deletionAuthSecret must be a 0x-prefixed 32-byte hex value")
		}
		if _, decErr := hex.DecodeString(raw); decErr != nil {
			return "", fmt.Errorf("deletion: deletionAuthSecret must be valid hex")
		}
		if raw == strings.Repeat("0", 64) {
			return "", fmt.Errorf("deletion: deletionAuthSecret must not be zero")
		}
		if !strings.HasPrefix(deletionAuthSecret, "0x") {
			deletionAuthSecret = "0x" + raw
		}
		paramCount = 2
	}
	calldata := make([]byte, 0, 4+paramCount*32)
	if useAuthorized {
		calldata = append(calldata, registerFileDeletionAuthorizedSelector...)
	} else {
		calldata = append(calldata, registerFileDeletionSelector...)
	}
	calldata = append(calldata, hexToBytes32(commitmentHash)...)
	if useAuthorized {
		calldata = append(calldata, hexToBytes32(deletionAuthSecret)...)
	}

	fn := "registerFileDeletion"
	if useAuthorized {
		fn = "registerFileDeletionAuthorized"
	}
	txHash, err := sendDeletionTxCtx(ctx, cfg, fromAddr, toAddr, calldata,
		"FileRegistrationSC", fn,
		map[string]any{"commitment_hash": commitmentHash, "authorized": useAuthorized})
	if err != nil {
		return "", fmt.Errorf("deletion: %s: %w", fn, err)
	}
	log.Printf("[deletion] %s mined  commitmentHash=%s  tx=%s",
		fn, truncate(commitmentHash, 18), txHash)
	return txHash, nil
}

// confirmFileDeletionOnChain sends confirmFileDeletion(commitmentHash) to
// FileRegistrationSC and returns the tx hash.
func confirmFileDeletionOnChain(cfg ServerConfig, commitmentHash string) (string, error) {
	if cfg.FileRegistrationContract == "" {
		return "", fmt.Errorf("deletion: FileRegistrationContract not configured")
	}
	if cfg.RPCURL == "" {
		return "", fmt.Errorf("deletion: RPCURL not configured")
	}
	if cfg.VKPrivKeyHex == "" {
		return "", fmt.Errorf("deletion: VKPrivKeyHex not configured")
	}

	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.FileRegistrationContract)

	calldata := make([]byte, 0, 36)
	calldata = append(calldata, confirmFileDeletionSelector...)
	calldata = append(calldata, hexToBytes32(commitmentHash)...)

	txHash, err := sendDeletionTx(cfg, fromAddr, toAddr, calldata,
		"FileRegistrationSC", "confirmFileDeletion",
		map[string]any{"commitment_hash": commitmentHash})
	if err != nil {
		return "", fmt.Errorf("deletion: confirmFileDeletion: %w", err)
	}
	log.Printf("[deletion] confirmFileDeletion mined  commitmentHash=%s  tx=%s",
		truncate(commitmentHash, 18), txHash)
	return txHash, nil
}

// claimEscrowOnDeletionChain sends claimEscrowOnDeletion(nullifier, secret,
// regNullifier, regSecret, linkNonce) to VKEscrow and returns the tx hash.
// All five arguments are 0x-prefixed 32-byte hex strings.
func claimEscrowOnDeletionChain(
	cfg ServerConfig,
	nullifier, secret, regNullifier, regSecret, linkNonce string,
) (string, error) {
	if cfg.VKEscrowContract == "" {
		return "", fmt.Errorf("deletion: VKEscrowContract not configured")
	}
	if cfg.RPCURL == "" {
		return "", fmt.Errorf("deletion: RPCURL not configured")
	}
	if cfg.VKPrivKeyHex == "" {
		return "", fmt.Errorf("deletion: VKPrivKeyHex not configured")
	}

	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.VKEscrowContract)

	// Derive the same private payment commitment used by VKEscrow, then check
	// authoritative settlement state before sending.  This makes lifecycle
	// replay/restart idempotent without hiding unrelated contract failures.
	paymentCommitment := ethcrypto.Keccak256(
		append(hexToBytes32(nullifier), hexToBytes32(secret)...),
	)
	alreadySettled, err := escrowClaimAlreadySettled(cfg, paymentCommitment)
	if err != nil {
		return "", fmt.Errorf("deletion: read escrow settlement state: %w", err)
	}
	if alreadySettled {
		log.Printf("[deletion] escrow already settled; claim replay skipped")
		return "", nil
	}

	// calldata: selector (4) + 5×bytes32 (160) = 164 bytes
	calldata := make([]byte, 0, 164)
	calldata = append(calldata, claimEscrowOnDeletionSelector...)
	calldata = append(calldata, hexToBytes32(nullifier)...)
	calldata = append(calldata, hexToBytes32(secret)...)
	calldata = append(calldata, hexToBytes32(regNullifier)...)
	calldata = append(calldata, hexToBytes32(regSecret)...)
	calldata = append(calldata, hexToBytes32(linkNonce)...)

	txHash, err := sendDeletionTx(cfg, fromAddr, toAddr, calldata,
		"VKEscrow", "claimEscrowOnDeletion",
		map[string]any{"nullifier": truncate(nullifier, 12)})
	if err != nil {
		return "", fmt.Errorf("deletion: claimEscrowOnDeletion: %w", err)
	}
	log.Printf("[deletion] claimEscrowOnDeletion mined  tx=%s", txHash)
	return txHash, nil
}

func escrowClaimAlreadySettled(cfg ServerConfig, paymentCommitment []byte) (bool, error) {
	if len(paymentCommitment) != 32 {
		return false, fmt.Errorf("payment commitment must be 32 bytes")
	}
	calldata := make([]byte, 0, 36)
	calldata = append(calldata, escrowStatusSelector...)
	calldata = append(calldata, paymentCommitment...)
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.VKEscrowContract).Hex(),
			"data": "0x" + hex.EncodeToString(calldata),
		},
		"latest",
	})
	if err != nil {
		return false, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil {
		return false, fmt.Errorf("decode escrowStatus: %w", err)
	}
	// escrowStatus returns eight ABI words. claimedAmount is word index 5.
	if len(raw) < 6*32 {
		return false, fmt.Errorf("short escrowStatus response: %d bytes", len(raw))
	}
	totalAmount := new(big.Int).SetBytes(raw[0:32])
	claimedAmount := new(big.Int).SetBytes(raw[5*32 : 6*32])
	return totalAmount.Sign() > 0 && claimedAmount.Cmp(totalAmount) >= 0, nil
}

// sendDeletionTx is a shared helper: signs and sends a tx, waits for receipt,
// then logs via logMinedTx. Uses fileRegMu to avoid nonce races.
func sendDeletionTx(
	cfg ServerConfig,
	fromAddr, toAddr common.Address,
	calldata []byte,
	contractName, funcName string,
	details map[string]any,
) (string, error) {
	return sendDeletionTxCtx(context.Background(), cfg, fromAddr, toAddr, calldata, contractName, funcName, details)
}

// sendDeletionTxCtx honours ctx: no RPC step begins after cancellation, each step's HTTP
// request aborts on cancel, and the post-broadcast receipt wait is interruptible. Note the
// broadcast point is rpcSendRawTransactionCtx — once that returns success the transaction
// exists on-chain regardless of any later cancellation, which is why the declaration claim
// re-checks chain state before ever re-broadcasting.
func sendDeletionTxCtx(
	ctx context.Context,
	cfg ServerConfig,
	fromAddr, toAddr common.Address,
	calldata []byte,
	contractName, funcName string,
	details map[string]any,
) (string, error) {
	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return "", fmt.Errorf("parse privkey: %w", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", fmt.Errorf("deletion tx cancelled before start: %w", ctxErr)
	}

	fileRegMu.Lock()
	defer fileRegMu.Unlock()
	accountLock, err := acquireAccountTxLock(fromAddr.Hex())
	if err != nil {
		return "", err
	}
	defer accountLock.Release()

	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", fmt.Errorf("deletion tx cancelled before nonce fetch: %w", ctxErr)
	}
	nonce, err := rpcAccountTransactionCountCtx(ctx, cfg, fromAddr.Hex())
	logEthCall("vk:eth.getTransactionCount", cfg.RPCURL, cfg.ChainID, "eth", "getTransactionCount", "", fromAddr.Hex(), statusFromErr(err), map[string]any{
		"nonce":           nonce,
		"target_function": funcName,
	})
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	logEthCall("vk:eth.gasPrice", cfg.RPCURL, cfg.ChainID, "eth", "gasPrice", "", fromAddr.Hex(), "success", map[string]any{
		"result":          gasPrice.String(),
		"target_function": funcName,
	})

	gasLimit, err := rpcEstimateGasCtx(ctx, cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, nil)
	logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(err), map[string]any{
		"gas_estimate":    gasLimit,
		"target_function": funcName,
	})
	if err != nil {
		return "", fmt.Errorf("estimateGas: %w", err)
	}
	gasLimit = gasLimit * 12 / 10 // +20% buffer

	chainID := big.NewInt(cfg.ChainID)
	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signer := types.NewEIP155Signer(chainID)
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}
	rawBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", fmt.Errorf("deletion tx cancelled before broadcast: %w", ctxErr)
	}
	txHash, err := rpcSendRawTransactionCtx(ctx, cfg.RPCURL, rawBytes)
	if err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	if receipt, receiptErr := rpcWaitTransactionReceiptCtx(ctx, cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
		logMinedTx("vk:"+contractName+"."+funcName, cfg.RPCURL, cfg.ChainID,
			fromAddr.Hex(), contractName, funcName, toAddr.Hex(), signedTx, receipt, details)
	} else {
		if receiptErr != nil {
			log.Printf("[deletion] receipt wait failed for %s.%s; tx submitted: %s: %v",
				contractName, funcName, txHash, receiptErr)
		}
		logSubmittedTx("vk:"+contractName+"."+funcName, cfg.RPCURL, cfg.ChainID,
			fromAddr.Hex(), contractName, funcName, toAddr.Hex(), signedTx, txHash, details)
	}

	return txHash, nil
}
