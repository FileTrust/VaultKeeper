package main

import (
	"crypto/ecdsa"
	"crypto/rand"
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
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func receiptDir(storage string) string {
	return filepath.Join(storage, "receipts")
}

// packReceiptForHashing produces the deterministic byte sequence that both
// Go and Solidity (abi.encodePacked) must agree on. Order and widths must
// exactly match _computeReceiptDigest in StorageReceiptDispute.sol.
//
//	uint16  receiptVersion          2 bytes
//	bytes32 receiptNonce           32 bytes
//	address vkAddress              20 bytes
//	bytes32 pieceRoot              32 bytes
//	uint64  pieceSize               8 bytes
//	bytes32 keccak256(sectorId)    32 bytes
//	bytes32 sectorRoot             32 bytes
//	uint8   deadlineIndex           1 byte
//	uint8   partitionIndex          1 byte
//	bytes32 partitionRoot          32 bytes  (zero if empty)
//	uint64  serviceEnd              8 bytes
//	uint64  timestamp               8 bytes
//	uint64  chainId                 8 bytes
//	address storageProofContract   20 bytes
func packReceiptForHashing(r PrivateReceiptV1) []byte {
	var buf []byte

	// uint16 receiptVersion
	ver := make([]byte, 2)
	binary.BigEndian.PutUint16(ver, uint16(r.ReceiptVersion))
	buf = append(buf, ver...)

	// bytes32 receiptNonce
	buf = append(buf, hexToBytes32(r.ReceiptNonce)...)

	// address vkAddress (20 bytes)
	buf = append(buf, common.HexToAddress(r.VKAddress).Bytes()...)

	// bytes32 pieceRoot
	buf = append(buf, hexToBytes32(r.PieceRoot)...)

	// uint64 pieceSize
	sz := make([]byte, 8)
	binary.BigEndian.PutUint64(sz, uint64(r.PieceSize))
	buf = append(buf, sz...)

	// bytes32 keccak256(sectorId as bytes)
	sectorIDHash := ethcrypto.Keccak256Hash([]byte(r.SectorID))
	buf = append(buf, sectorIDHash[:]...)

	// bytes32 sectorRoot
	buf = append(buf, hexToBytes32(r.SectorRoot)...)

	// uint8 deadlineIndex
	buf = append(buf, byte(r.DeadlineIndex))

	// uint8 partitionIndex
	buf = append(buf, byte(r.PartitionIndex))

	// bytes32 partitionRoot (zero if empty)
	buf = append(buf, hexToBytes32OrZero(r.PartitionRoot)...)

	// uint64 serviceEnd
	se := make([]byte, 8)
	binary.BigEndian.PutUint64(se, uint64(r.ServiceEnd))
	buf = append(buf, se...)

	// uint64 timestamp
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(r.Timestamp))
	buf = append(buf, ts...)

	// uint64 chainId
	cid := make([]byte, 8)
	binary.BigEndian.PutUint64(cid, uint64(r.ChainID))
	buf = append(buf, cid...)

	// address storageProofContract (20 bytes)
	buf = append(buf, common.HexToAddress(r.StorageProofContract).Bytes()...)

	return buf
}

// computeReceiptDigest returns keccak256(packReceiptForHashing(r)).
func computeReceiptDigest(r PrivateReceiptV1) common.Hash {
	return ethcrypto.Keccak256Hash(packReceiptForHashing(r))
}

// hexToBytes32 decodes a 0x-prefixed hex string to exactly 32 bytes.
// Shorter values are right-padded with zeros; longer values are truncated.
func hexToBytes32(h string) []byte {
	h = strings.TrimPrefix(strings.TrimSpace(h), "0x")
	out := make([]byte, 32)
	if h == "" {
		return out
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return out
	}
	if len(b) >= 32 {
		copy(out, b[:32])
	} else {
		copy(out[32-len(b):], b)
	}
	return out
}

// hexToBytes32OrZero returns 32 zero bytes when h is empty or "0x".
func hexToBytes32OrZero(h string) []byte {
	if strings.TrimSpace(h) == "" || strings.TrimPrefix(strings.TrimSpace(h), "0x") == "" {
		return make([]byte, 32)
	}
	return hexToBytes32(h)
}

// signReceipt signs the receipt digest with Ethereum personal_sign (EIP-191).
// The returned signature has v ∈ {27, 28} per Ethereum convention.
func signReceipt(privKey *ecdsa.PrivateKey, r PrivateReceiptV1) (string, error) {
	digest := computeReceiptDigest(r)
	// accounts.TextHash applies "\x19Ethereum Signed Message:\n32" prefix.
	signedHash := accounts.TextHash(digest[:])
	sig, err := ethcrypto.Sign(signedHash, privKey)
	if err != nil {
		return "", err
	}
	sig[64] += 27 // Ethereum convention: v += 27
	return "0x" + hex.EncodeToString(sig), nil
}

const admissionQuoteDomain = "FileTrustAdmissionQuoteV1"
const admissionQuoteDomainV2 = "FileTrustAdmissionQuoteV2"
const admissionFailureDomain = "FileTrustAdmissionFailureV1"

// signAdmissionQuote signs the exact escrow terms later verified by
// StorageReceiptDispute. Fixed-width packing mirrors Solidity abi.encodePacked.
func signAdmissionQuote(
	privKey *ecdsa.PrivateKey,
	chainID int64,
	vkAddress, escrowAddress, paymentCommitment, registrationCommitment,
	sizeCommitment, linkCommitment, agreedPriceWei string,
	serviceEnd, quoteValidUntil int64,
) (string, error) {
	if privKey == nil || chainID <= 0 || serviceEnd <= 0 || quoteValidUntil <= 0 {
		return "", fmt.Errorf("invalid admission quote signing parameters")
	}
	price, ok := new(big.Int).SetString(strings.TrimSpace(agreedPriceWei), 10)
	if !ok || price.Sign() <= 0 || price.BitLen() > 256 {
		return "", fmt.Errorf("invalid admission quote price")
	}
	buf := make([]byte, 0, len(admissionQuoteDomain)+8+20+20+32*5+8+8)
	buf = append(buf, []byte(admissionQuoteDomain)...)
	u64 := make([]byte, 8)
	binary.BigEndian.PutUint64(u64, uint64(chainID))
	buf = append(buf, u64...)
	buf = append(buf, common.HexToAddress(vkAddress).Bytes()...)
	buf = append(buf, common.HexToAddress(escrowAddress).Bytes()...)
	buf = append(buf, hexToBytes32(paymentCommitment)...)
	buf = append(buf, hexToBytes32(registrationCommitment)...)
	buf = append(buf, hexToBytes32(sizeCommitment)...)
	buf = append(buf, hexToBytes32(linkCommitment)...)
	buf = append(buf, common.LeftPadBytes(price.Bytes(), 32)...)
	binary.BigEndian.PutUint64(u64, uint64(serviceEnd))
	buf = append(buf, u64...)
	binary.BigEndian.PutUint64(u64, uint64(quoteValidUntil))
	buf = append(buf, u64...)
	digest := ethcrypto.Keccak256Hash(buf)
	sig, err := ethcrypto.Sign(accounts.TextHash(digest[:]), privKey)
	if err != nil {
		return "", err
	}
	sig[64] += 27
	return "0x" + hex.EncodeToString(sig), nil
}

// signAdmissionQuoteV2 additionally binds the absolute registration/transfer
// deadline used by VKEscrowV2 and CapacityProofSC activation. This prevents a
// DO or intermediary from extending the VK's obligation after signature.
func signAdmissionQuoteV2(
	privKey *ecdsa.PrivateKey,
	chainID int64,
	vkAddress, escrowAddress, paymentCommitment, registrationCommitment,
	sizeCommitment, linkCommitment, agreedPriceWei string,
	serviceEnd, quoteValidUntil, transferDeadline int64,
) (string, error) {
	if privKey == nil || chainID <= 0 || serviceEnd <= 0 || quoteValidUntil <= 0 ||
		transferDeadline < quoteValidUntil {
		return "", fmt.Errorf("invalid admission quote V2 signing parameters")
	}
	price, ok := new(big.Int).SetString(strings.TrimSpace(agreedPriceWei), 10)
	if !ok || price.Sign() <= 0 || price.BitLen() > 256 {
		return "", fmt.Errorf("invalid admission quote price")
	}
	buf := make([]byte, 0, len(admissionQuoteDomainV2)+8+20+20+32*5+8+8+8)
	buf = append(buf, []byte(admissionQuoteDomainV2)...)
	// uint64(block.chainid), which is what the only on-chain verifier of this
	// digest actually packs: StorageRegistrationTimeout.resolveRegistrationTimeout.
	// V1 uses uint64 on both sides, in that contract and in StorageReceiptDispute.
	//
	// This previously packed uint256, under a comment asserting that matched the
	// contract. It did not, and nothing anywhere pinned the V2 layout, so the
	// mismatch shipped: every V2 signature recovered to an unrelated address and
	// the contract rejected it with InvalidSignature.
	//
	// Live on 2026-10-01: a data owner retried resolveRegistrationTimeout for one
	// piece every ninety seconds for over half an hour, each attempt mined and
	// reverted with 0x8baa579f. Recovering that exact signature off-chain against
	// both widths proved it: uint256 recovered the keeper, uint64 recovered
	// 0xb904F9d3..., and the contract packs uint64.
	u64 := make([]byte, 8)
	binary.BigEndian.PutUint64(u64, uint64(chainID))
	buf = append(buf, u64...)
	buf = append(buf, common.HexToAddress(vkAddress).Bytes()...)
	buf = append(buf, common.HexToAddress(escrowAddress).Bytes()...)
	buf = append(buf, hexToBytes32(paymentCommitment)...)
	buf = append(buf, hexToBytes32(registrationCommitment)...)
	buf = append(buf, hexToBytes32(sizeCommitment)...)
	buf = append(buf, hexToBytes32(linkCommitment)...)
	buf = append(buf, common.LeftPadBytes(price.Bytes(), 32)...)
	binary.BigEndian.PutUint64(u64, uint64(serviceEnd))
	buf = append(buf, u64...)
	binary.BigEndian.PutUint64(u64, uint64(quoteValidUntil))
	buf = append(buf, u64...)
	binary.BigEndian.PutUint64(u64, uint64(transferDeadline))
	buf = append(buf, u64...)
	digest := ethcrypto.Keccak256Hash(buf)
	sig, err := ethcrypto.Sign(accounts.TextHash(digest[:]), privKey)
	if err != nil {
		return "", err
	}
	sig[64] += 27
	return "0x" + hex.EncodeToString(sig), nil
}

func signAdmissionFailure(
	privKey *ecdsa.PrivateKey,
	chainID int64,
	vkAddress, escrowAddress, paymentCommitment, registrationCommitment string,
) (string, error) {
	if privKey == nil || chainID <= 0 ||
		common.HexToAddress(vkAddress) == (common.Address{}) ||
		common.HexToAddress(escrowAddress) == (common.Address{}) {
		return "", fmt.Errorf("invalid admission failure signing parameters")
	}
	buf := append([]byte{}, []byte(admissionFailureDomain)...)
	u64 := make([]byte, 8)
	binary.BigEndian.PutUint64(u64, uint64(chainID))
	buf = append(buf, u64...)
	buf = append(buf, common.HexToAddress(vkAddress).Bytes()...)
	buf = append(buf, common.HexToAddress(escrowAddress).Bytes()...)
	buf = append(buf, hexToBytes32(paymentCommitment)...)
	buf = append(buf, hexToBytes32(registrationCommitment)...)
	digest := ethcrypto.Keccak256Hash(buf)
	sig, err := ethcrypto.Sign(accounts.TextHash(digest[:]), privKey)
	if err != nil {
		return "", err
	}
	sig[64] += 27
	return "0x" + hex.EncodeToString(sig), nil
}

func randomNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(b), nil
}

// currentPartitionForSector finds the deadline/partition slot for a sector
// given the complete current sector list, and computes the current partitionRoot.
// When partition mode is disabled (cfg.DeadlineCount==0) it returns the sector's
// own DeadlineIndex, partitionIndex=0, and an empty partitionRoot.
func currentPartitionForSector(sector SectorMeta, allSectors []SectorMeta, cfg ServerConfig) (int, int, string, error) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return sector.DeadlineIndex, 0, "", nil
	}

	if p, found := currentPartitionMetaForSector(sector.SectorID, allSectors, cfg); found {
		sectorRoots := make([]string, len(p.Sectors))
		for i, ps := range p.Sectors {
			sectorRoots[i] = ps.SectorRoot
		}
		pRoot, err := computePartitionRoot(sectorRoots, cfg.PartitionMaxSectors)
		if err != nil {
			return p.DeadlineIndex, p.PartitionIndex, "", err
		}
		return p.DeadlineIndex, p.PartitionIndex, pRoot, nil
	}
	// Sector not in any active partition yet; return deadline from sector.
	return sector.DeadlineIndex, 0, "", nil
}

// buildPrivateReceipt creates, signs, and returns a PrivateReceiptV1 for the
// given piece/sector. allSectors must include the just-updated sector so the
// partition root reflects the current state.
//
// commitmentHash, commitmentNonce, registrationTxHash, paymentCommitment,
// sizeCommitment, sizeNonce, agreedPriceWei, and deletionAuthHash are appended
// AFTER the ECDSA digest is computed so StorageReceiptDispute signature
// verification continues to work without changes.
func buildPrivateReceipt(
	storage string,
	privKey *ecdsa.PrivateKey,
	vkAddress string,
	chainID int64,
	storageProofContract string,
	meta PieceMeta,
	sector SectorMeta,
	allSectors []SectorMeta,
	cfg ServerConfig,
	commitmentHash string,
	commitmentNonce string,
	registrationTxHash string,
	paymentCommitment string,
	sizeCommitment string,
	sizeNonce string,
	agreedPriceWei string,
	registrationCommitment string,
	linkCommitment string,
	deletionAuthHash string,
) (PrivateReceiptV1, error) {
	nonce, err := randomNonce()
	if err != nil {
		return PrivateReceiptV1{}, fmt.Errorf("receipt nonce: %w", err)
	}

	dl, pt, pRoot, err := currentPartitionForSector(sector, allSectors, cfg)
	if err != nil {
		// Non-fatal: log and carry on with empty partitionRoot.
		log.Printf("[receipt] partition root warning for sector %s: %v", sector.SectorID, err)
		pRoot = ""
	}

	serviceEnd := meta.ServiceEnd
	if serviceEnd <= 0 {
		serviceEnd = sector.Expiration
	}

	// Build the signable fields first (unchanged layout — keeps StorageReceiptDispute
	// signature verification compatible).
	r := PrivateReceiptV1{
		ReceiptVersion:       1,
		ReceiptNonce:         nonce,
		VKAddress:            vkAddress,
		PieceRoot:            meta.PieceRoot,
		PieceSize:            meta.Size,
		SectorID:             sector.SectorID,
		SectorRoot:           sector.SectorRoot,
		DeadlineIndex:        dl,
		PartitionIndex:       pt,
		PartitionRoot:        pRoot,
		ServiceEnd:           serviceEnd,
		Timestamp:            time.Now().UTC().Unix(),
		ChainID:              chainID,
		StorageProofContract: storageProofContract,
	}

	sig, err := signReceipt(privKey, r)
	if err != nil {
		return PrivateReceiptV1{}, fmt.Errorf("sign receipt: %w", err)
	}
	r.VKSignature = sig

	// Attach commitment and registration fields after signing.
	// None of these are part of the signed digest; StorageReceiptDispute remains compatible.
	r.CommitmentHash = commitmentHash
	r.CommitmentNonce = commitmentNonce
	r.RegistrationTxHash = registrationTxHash
	r.DeletionAuthHash = deletionAuthHash

	// Attach payment commitment fields (VKEscrow). Also not part of the signed digest.
	r.PaymentCommitment = paymentCommitment
	r.SizeCommitment = sizeCommitment
	r.SizeNonce = sizeNonce
	r.AgreedPriceWei = agreedPriceWei
	r.RegistrationCommitment = registrationCommitment
	r.LinkCommitment = linkCommitment

	return r, nil
}

// saveIssuedReceipt writes a local audit copy of the issued receipt.
func saveIssuedReceipt(storage string, receipt PrivateReceiptV1) {
	if err := os.MkdirAll(receiptDir(storage), 0700); err != nil {
		log.Printf("[receipt] mkdir failed: %v", err)
		return
	}
	// File name: pieceRoot-sectorId.json (both sanitized)
	name := safeID(receipt.PieceRoot) + "-" + safeID(receipt.SectorID) + ".json"
	path := filepath.Join(receiptDir(storage), name)
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		log.Printf("[receipt] marshal failed: %v", err)
		return
	}
	if err := atomicWriteFile(path, b, 0600); err != nil {
		log.Printf("[receipt] save failed: %v", err)
		return
	}
	pRoot := receipt.PartitionRoot
	if len(pRoot) > 10 {
		pRoot = pRoot[:10] + "..."
	}
	cHash := receipt.CommitmentHash
	if len(cHash) > 18 {
		cHash = cHash[:18] + "..."
	}
	log.Printf("[receipt] issued  pieceRoot=%s sectorId=%s dl=%d pt=%d partitionRoot=%s commitmentHash=%s",
		receipt.PieceRoot[:min(16, len(receipt.PieceRoot))],
		receipt.SectorID[:min(24, len(receipt.SectorID))],
		receipt.DeadlineIndex,
		receipt.PartitionIndex,
		pRoot,
		cHash,
	)
}

// ParseVKPrivKey parses a hex Ethereum private key string (with or without 0x prefix).
func ParseVKPrivKey(hexKey string) (*ecdsa.PrivateKey, error) {
	return ethcrypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(hexKey), "0x"))
}

// VKAddressFromKey derives the Ethereum address from a private key.
func VKAddressFromKey(privKey *ecdsa.PrivateKey) string {
	return ethcrypto.PubkeyToAddress(privKey.PublicKey).Hex()
}
