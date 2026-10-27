package main

import (
	"crypto/ecdsa"
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

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// ─── Renewal: serving a longer term for a piece already stored ────────────────
//
// A renewal has two halves and they must move together. The escrow's serviceEnd
// decides what the VK is paid for; the FileRegistrationSC record's serviceEnd
// decides how long the VK can be disputed. assessSectorRisk stops holding a VK
// liable once the registered term lapses, so extending only the escrow would pay
// for a window nobody could challenge.
//
// The VK therefore takes on the obligation FIRST (extendServiceEnd), and only
// then proves consent to the escrow (confirmExtension). VKEscrow.claimEscrow
// independently re-checks that the registration covers the escrow term, so a VK
// that confirms but never extends simply cannot collect.
//
// Privacy: the DO's extendEscrow call names only paymentCommitment. The VK
// authenticates by opening extensionCommitment — a fresh keccak256 preimage it
// generated for the signed quote. No VK address and no registrationCommitment
// ever appear in a DO transaction, so the pair stays hidden as before.

const renewalQuoteDomain = "FileTrust VK Renewal Quote v1"

// extensionConfirmWindow is how long the VK promises to stand behind a renewal
// quote. It bounds how long DO funds may sit parked awaiting confirmation.
const extensionConfirmWindow = 30 * time.Minute

var (
	// extendServiceEnd(bytes32,uint64)
	extendServiceEndSelector = ethcrypto.Keccak256(
		[]byte("extendServiceEnd(bytes32,uint64)"),
	)[:4]

	// confirmExtension(bytes32,bytes32,bytes32)
	confirmExtensionSelector = ethcrypto.Keccak256(
		[]byte("confirmExtension(bytes32,bytes32,bytes32)"),
	)[:4]

	// extensionStatus(bytes32) → (uint256,uint64,uint64,bytes32,uint64,bool)
	extensionStatusSelector = ethcrypto.Keccak256(
		[]byte("extensionStatus(bytes32)"),
	)[:4]
)

// GenerateExtensionCommitment creates the VK's renewal consent secret:
//
//	extensionCommitment = keccak256(abi.encodePacked(extNullifier, extSecret))
//
// Only the VK can open it, which is what makes it a consent proof.
func GenerateExtensionCommitment() (extNullifier, extSecret, extensionCommitment string, err error) {
	nullifierBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", "", fmt.Errorf("renewal: generate extNullifier: %w", genErr)
	}
	secretBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", "", fmt.Errorf("renewal: generate extSecret: %w", genErr)
	}
	hash := ethcrypto.Keccak256Hash(append(nullifierBytes, secretBytes...))
	return "0x" + hex.EncodeToString(nullifierBytes),
		"0x" + hex.EncodeToString(secretBytes),
		"0x" + hex.EncodeToString(hash[:]), nil
}

// signRenewalQuote binds the VK to the extension terms it offered. The DO checks
// this off-chain before parking any money; the chain never sees it.
func signRenewalQuote(
	privKey *ecdsa.PrivateKey,
	chainID int64,
	vkAddress, escrowAddress, paymentCommitment, extensionCommitment, addedPriceWei string,
	currentServiceEnd, newServiceEnd, confirmBy, quoteValidUntil int64,
) (string, error) {
	if privKey == nil || chainID <= 0 || newServiceEnd <= currentServiceEnd ||
		confirmBy <= 0 || quoteValidUntil <= 0 {
		return "", fmt.Errorf("invalid renewal quote signing parameters")
	}
	price, ok := new(big.Int).SetString(strings.TrimSpace(addedPriceWei), 10)
	if !ok || price.Sign() <= 0 || price.BitLen() > 256 {
		return "", fmt.Errorf("invalid renewal quote price")
	}
	buf := make([]byte, 0, len(renewalQuoteDomain)+32+20+20+32+32+32+8*4)
	buf = append(buf, []byte(renewalQuoteDomain)...)
	buf = append(buf, common.LeftPadBytes(big.NewInt(chainID).Bytes(), 32)...)
	buf = append(buf, common.HexToAddress(vkAddress).Bytes()...)
	buf = append(buf, common.HexToAddress(escrowAddress).Bytes()...)
	buf = append(buf, hexToBytes32(paymentCommitment)...)
	buf = append(buf, hexToBytes32(extensionCommitment)...)
	buf = append(buf, common.LeftPadBytes(price.Bytes(), 32)...)
	u64 := make([]byte, 8)
	for _, value := range []int64{currentServiceEnd, newServiceEnd, confirmBy, quoteValidUntil} {
		binary.BigEndian.PutUint64(u64, uint64(value))
		buf = append(buf, u64...)
	}
	digest := ethcrypto.Keccak256Hash(buf)
	sig, err := ethcrypto.Sign(accounts.TextHash(digest[:]), privKey)
	if err != nil {
		return "", err
	}
	sig[64] += 27
	return "0x" + hex.EncodeToString(sig), nil
}

// ─── Credential lookup by paymentCommitment ───────────────────────────────────

// findCredentialsByPaymentCommitment locates a stored piece's credentials from
// the paymentCommitment the DO knows. Quote-only records (no commitmentHash yet)
// are ignored: nothing is stored for them, so nothing can be renewed.
func findCredentialsByPaymentCommitment(storage, paymentCommitment string) (PaymentCredentials, bool, error) {
	var empty PaymentCredentials
	target := strings.ToLower(strings.TrimSpace(paymentCommitment))
	if target == "" {
		return empty, false, nil
	}
	entries, err := os.ReadDir(paymentDir(storage))
	if os.IsNotExist(err) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
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
		if strings.EqualFold(strings.TrimSpace(creds.PaymentCommitment), target) {
			return creds, true, nil
		}
	}
	return empty, false, nil
}

// ─── Chain writes ─────────────────────────────────────────────────────────────

// sendVKTransaction builds, signs and submits a VK transaction, sharing the
// registration mutex so concurrent senders cannot collide on nonces.
func sendVKTransaction(
	cfg ServerConfig, label, contractName, functionName, contractAddr string,
	calldata []byte, details map[string]any,
) (string, error) {
	noteLockConfinedWork(label)
	if cfg.RPCURL == "" {
		return "", fmt.Errorf("%s: RPCURL not configured", label)
	}
	if cfg.VKPrivKeyHex == "" {
		return "", fmt.Errorf("%s: VKPrivKeyHex not configured", label)
	}
	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return "", fmt.Errorf("%s: parse privkey: %w", label, err)
	}
	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(contractAddr)

	fileRegMu.Lock()
	defer fileRegMu.Unlock()
	accountLock, lockErr := acquireAccountTxLock(fromAddr.Hex())
	if lockErr != nil {
		return "", fmt.Errorf("%s: %w", label, lockErr)
	}
	defer accountLock.Release()

	// estimateGas is also the precondition check: a call that would revert never
	// reaches the mempool.
	gasLimit, gasErr := rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, nil)
	logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(gasErr), map[string]any{
		"gas_estimate":    gasLimit,
		"target_function": functionName,
	})
	if gasErr != nil {
		return "", fmt.Errorf("%s: estimateGas: %w", label, gasErr)
	}
	gasLimit = gasLimit * 12 / 10

	nonce, nonceErr := rpcGetTransactionCount(cfg.RPCURL, fromAddr.Hex())
	logEthCall("vk:eth.getTransactionCount", cfg.RPCURL, cfg.ChainID, "eth", "getTransactionCount", "", fromAddr.Hex(), statusFromErr(nonceErr), map[string]any{
		"nonce":           nonce,
		"target_function": functionName,
	})
	if nonceErr != nil {
		return "", fmt.Errorf("%s: get nonce: %w", label, nonceErr)
	}

	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signedTx, signErr := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(cfg.ChainID)), privKey)
	if signErr != nil {
		return "", fmt.Errorf("%s: sign tx: %w", label, signErr)
	}
	rawBytes, marshalErr := signedTx.MarshalBinary()
	if marshalErr != nil {
		return "", fmt.Errorf("%s: marshal tx: %w", label, marshalErr)
	}
	txHash, sendErr := rpcSendRawTransaction(cfg.RPCURL, rawBytes)
	if sendErr == nil {
		if receipt, receiptErr := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
			logMinedTx("vk:"+contractName+"."+functionName, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), contractName, functionName, toAddr.Hex(), signedTx, receipt, details)
		} else {
			logSubmittedTx("vk:"+contractName+"."+functionName, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), contractName, functionName, toAddr.Hex(), signedTx, txHash, details)
		}
	}
	if sendErr != nil {
		return "", fmt.Errorf("%s: send tx: %w", label, sendErr)
	}
	return txHash, nil
}

// extendServiceEndOnChain accepts the longer storage obligation. This is the
// liability half and must land before the escrow is confirmed.
func extendServiceEndOnChain(cfg ServerConfig, commitmentHash string, newServiceEnd int64) (string, error) {
	if cfg.FileRegistrationContract == "" {
		return "", fmt.Errorf("renewal: FileRegistrationContract not configured")
	}
	calldata := make([]byte, 0, 4+64)
	calldata = append(calldata, extendServiceEndSelector...)
	calldata = append(calldata, hexToBytes32(commitmentHash)...)
	sePad := make([]byte, 32)
	big.NewInt(newServiceEnd).FillBytes(sePad)
	calldata = append(calldata, sePad...)

	return sendVKTransaction(
		cfg, "renewal-extend-service-end", "FileRegistrationSC", "extendServiceEnd",
		cfg.FileRegistrationContract, calldata,
		map[string]any{"commitment_hash": commitmentHash, "service_end": newServiceEnd},
	)
}

// confirmExtensionOnChain opens the VK's consent secret, committing the escrow
// to the longer term and making the parked funds earnable.
func confirmExtensionOnChain(cfg ServerConfig, paymentCommitment, extNullifier, extSecret string) (string, error) {
	if cfg.VKEscrowContract == "" {
		return "", fmt.Errorf("renewal: VKEscrowContract not configured")
	}
	calldata := make([]byte, 0, 4+96)
	calldata = append(calldata, confirmExtensionSelector...)
	calldata = append(calldata, hexToBytes32(paymentCommitment)...)
	calldata = append(calldata, hexToBytes32(extNullifier)...)
	calldata = append(calldata, hexToBytes32(extSecret)...)

	return sendVKTransaction(
		cfg, "renewal-confirm-extension", "VKEscrow", "confirmExtension",
		cfg.VKEscrowContract, calldata,
		map[string]any{"payment_commitment": paymentCommitment},
	)
}

// ─── Chain reads ──────────────────────────────────────────────────────────────

type onChainExtension struct {
	PendingAmount       *big.Int
	PendingServiceEnd   int64
	ConfirmBy           int64
	ExtensionCommitment string
	ServiceEnd          int64
	ConfirmWindowOpen   bool
}

func readExtensionStatus(cfg ServerConfig, paymentCommitment string) (onChainExtension, error) {
	var status onChainExtension
	if cfg.VKEscrowContract == "" {
		return status, fmt.Errorf("renewal: VKEscrowContract not configured")
	}
	calldata := append(append([]byte{}, extensionStatusSelector...), hexToBytes32(paymentCommitment)...)
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]any{"to": cfg.VKEscrowContract, "data": "0x" + hex.EncodeToString(calldata)},
		"latest",
	})
	if err != nil {
		return status, err
	}
	raw := strings.TrimPrefix(strings.TrimSpace(result), "0x")
	if len(raw) < 6*64 {
		return status, fmt.Errorf("renewal: short extensionStatus result")
	}
	slot := func(i int) string { return raw[i*64 : (i+1)*64] }
	toInt := func(i int) *big.Int {
		n, _ := new(big.Int).SetString(slot(i), 16)
		if n == nil {
			return big.NewInt(0)
		}
		return n
	}
	status.PendingAmount = toInt(0)
	status.PendingServiceEnd = toInt(1).Int64()
	status.ConfirmBy = toInt(2).Int64()
	status.ExtensionCommitment = "0x" + slot(3)
	status.ServiceEnd = toInt(4).Int64()
	status.ConfirmWindowOpen = toInt(5).Sign() != 0
	return status, nil
}

// ─── Sector keep-alive ────────────────────────────────────────────────────────

// extendSectorForRenewal pushes the piece's sector expiration out to cover the
// new term, so the expired-sector GC does not collect a piece that is now paid
// for further. In escrow-backed mode a sector holds exactly one piece, so this
// cannot affect another DO's data.
func extendSectorForRenewal(cfg ServerConfig, sectorID string, newServiceEnd int64) error {
	if strings.TrimSpace(sectorID) == "" {
		return fmt.Errorf("renewal: piece has no sector")
	}
	sector, err := readSector(cfg.Storage, sectorID)
	if err != nil {
		return fmt.Errorf("renewal: read sector: %w", err)
	}
	if sector.Expiration >= newServiceEnd {
		return nil // already covers the new term
	}
	sector.Expiration = newServiceEnd
	if sector.MaxServiceEnd < newServiceEnd {
		sector.MaxServiceEnd = newServiceEnd
	}
	if err := writeSector(cfg.Storage, sector); err != nil {
		return fmt.Errorf("renewal: persist sector expiration: %w", err)
	}
	log.Printf("[renewal] sector %s kept alive until %d", truncate(sectorID, 18), newServiceEnd)
	return nil
}

// ─── Reconciler: complete funded renewals ─────────────────────────────────────

// maxRenewalsPerSweep bounds one reconciler tick.
const maxRenewalsPerSweep = 16

// reconcileEscrowExtensions finishes every renewal the DO has funded: keep the
// sector alive, accept the longer obligation on-chain, then confirm the escrow.
//
// Order matters and is not an optimisation. If the process dies between the two
// chain calls, the VK is left holding a longer obligation than it is paid for —
// safe for the DO — and the next sweep confirms. The reverse order could pay a
// VK for an undisputable window.
func reconcileEscrowExtensions(cfg ServerConfig) {
	if cfg.VKEscrowContract == "" || cfg.FileRegistrationContract == "" {
		return
	}
	entries, err := os.ReadDir(paymentDir(cfg.Storage))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Printf("[renewal] list credentials failed: %v", err)
		return
	}

	handled := 0
	for _, entry := range entries {
		if handled >= maxRenewalsPerSweep {
			return
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(paymentDir(cfg.Storage), entry.Name()))
		if readErr != nil {
			continue
		}
		var creds PaymentCredentials
		if json.Unmarshal(payload, &creds) != nil {
			continue
		}
		// Only pieces this VK quoted a renewal for can be confirmed: the secret
		// is the consent proof and lives nowhere else.
		if creds.ExtensionCommitment == "" || creds.CommitmentHash == "" ||
			creds.PendingServiceEnd <= 0 {
			continue
		}

		status, statusErr := readExtensionStatus(cfg, creds.PaymentCommitment)
		if statusErr != nil {
			log.Printf("[renewal] read extension status failed pc=%s: %v",
				truncate(creds.PaymentCommitment, 18), statusErr)
			continue
		}
		if status.PendingServiceEnd == 0 {
			// Nothing parked: either the DO has not funded it yet, or it is
			// already confirmed. Clear a quote the chain has moved past.
			if status.ServiceEnd >= creds.PendingServiceEnd {
				creds.ServiceEnd = status.ServiceEnd
				clearRenewalQuote(&creds)
				if saveErr := SavePaymentCredentials(cfg.Storage, creds); saveErr != nil {
					log.Printf("[renewal] clear confirmed quote failed: %v", saveErr)
				}
			}
			continue
		}
		if !strings.EqualFold(status.ExtensionCommitment, creds.ExtensionCommitment) {
			log.Printf("[renewal] on-chain commitment does not match our quote pc=%s — ignoring",
				truncate(creds.PaymentCommitment, 18))
			continue
		}
		if !status.ConfirmWindowOpen {
			log.Printf("[renewal] confirm window closed pc=%s — DO may reclaim",
				truncate(creds.PaymentCommitment, 18))
			clearRenewalQuote(&creds)
			_ = SavePaymentCredentials(cfg.Storage, creds)
			continue
		}

		handled++
		newServiceEnd := status.PendingServiceEnd

		pieceMeta, metaErr := readMeta(cfg.Storage, creds.PieceRoot)
		if metaErr != nil {
			log.Printf("[renewal] piece meta unavailable pc=%s: %v",
				truncate(creds.PaymentCommitment, 18), metaErr)
			continue
		}
		if keepErr := extendSectorForRenewal(cfg, pieceMeta.SectorID, newServiceEnd); keepErr != nil {
			log.Printf("[renewal] sector keep-alive failed pc=%s: %v",
				truncate(creds.PaymentCommitment, 18), keepErr)
			continue
		}

		// Liability first.
		if _, extendErr := extendServiceEndOnChain(cfg, creds.CommitmentHash, newServiceEnd); extendErr != nil {
			if !strings.Contains(extendErr.Error(), "serviceEnd not later") {
				log.Printf("[renewal] accept obligation failed pc=%s: %v",
					truncate(creds.PaymentCommitment, 18), extendErr)
				continue
			}
			// Already accepted on a previous sweep — fall through and confirm.
		}

		// Payment second.
		txHash, confirmErr := confirmExtensionOnChain(
			cfg, creds.PaymentCommitment, creds.ExtNullifier, creds.ExtSecret,
		)
		if confirmErr != nil {
			log.Printf("[renewal] confirm failed pc=%s: %v",
				truncate(creds.PaymentCommitment, 18), confirmErr)
			continue
		}

		creds.ServiceEnd = newServiceEnd
		clearRenewalQuote(&creds)
		if saveErr := SavePaymentCredentials(cfg.Storage, creds); saveErr != nil {
			log.Printf("[renewal] persist confirmed renewal failed: %v", saveErr)
		}
		log.Printf("[renewal] confirmed pc=%s newServiceEnd=%d tx=%s",
			truncate(creds.PaymentCommitment, 18), newServiceEnd, txHash)

		reissueRenewedReceipt(cfg, creds)
	}
}

func clearRenewalQuote(creds *PaymentCredentials) {
	creds.ExtNullifier = ""
	creds.ExtSecret = ""
	creds.ExtensionCommitment = ""
	creds.PendingServiceEnd = 0
	creds.ExtensionConfirmBy = 0
	creds.ExtensionPriceWei = ""
	creds.ExtensionQuotedAt = ""
}

// reissueRenewedReceipt writes a fresh signed receipt carrying the new term. The
// DO's dispute evidence binds serviceEnd, so a stale receipt would understate
// the obligation the VK now actually carries.
func reissueRenewedReceipt(cfg ServerConfig, creds PaymentCredentials) {
	if strings.TrimSpace(creds.PieceRoot) == "" {
		return
	}
	meta, err := readMeta(cfg.Storage, creds.PieceRoot)
	if err != nil {
		log.Printf("[renewal] receipt reissue skipped, piece meta unavailable: %v", err)
		return
	}
	meta.ServiceEnd = creds.ServiceEnd
	if err := writeMeta(cfg.Storage, meta); err != nil {
		log.Printf("[renewal] receipt reissue skipped, piece meta not persisted: %v", err)
		return
	}
	log.Printf("[renewal] piece %s now serves until %d; DO should re-fetch its receipt",
		truncate(creds.PieceRoot, 18), creds.ServiceEnd)
}
