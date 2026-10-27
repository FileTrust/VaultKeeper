package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// paymentDir returns the path to the local payment credentials directory.
func paymentDir(storage string) string {
	return filepath.Join(storage, "payment")
}

// paymentCredPath returns the path for a specific commitmentHash's credentials.
func paymentCredPath(storage, commitmentHash string) string {
	return filepath.Join(paymentDir(storage), safeID(commitmentHash)+".json")
}

// GeneratePaymentCommitment creates a new (nullifier, secret) pair and computes:
//
//	paymentCommitment = keccak256(abi.encodePacked(nullifier, secret))
//
// Returns (nullifier, secret, paymentCommitment) as 0x-prefixed hex strings.
func GeneratePaymentCommitment() (nullifier, secret, paymentCommitment string, err error) {
	nullifierBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", "", fmt.Errorf("payment: generate nullifier: %w", genErr)
	}
	secretBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", "", fmt.Errorf("payment: generate secret: %w", genErr)
	}

	combined := append(nullifierBytes, secretBytes...)
	hash := ethcrypto.Keccak256Hash(combined)

	nullifier = "0x" + fmt.Sprintf("%x", nullifierBytes)
	secret = "0x" + fmt.Sprintf("%x", secretBytes)
	paymentCommitment = "0x" + fmt.Sprintf("%x", hash[:])
	return nullifier, secret, paymentCommitment, nil
}

// GenerateSizeCommitment creates a random sizeNonce and computes:
//
//	sizeCommitment = keccak256(abi.encodePacked(uint64(pieceSize), bytes32(sizeNonce)))
//
// Encoding matches Solidity abi.encodePacked(uint64, bytes32) = 8 + 32 = 40 bytes.
// Returns (sizeNonce, sizeCommitment) as 0x-prefixed hex strings.
func GenerateSizeCommitment(pieceSize int64) (sizeNonce, sizeCommitment string, err error) {
	nonceBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", fmt.Errorf("payment: generate sizeNonce: %w", genErr)
	}

	// Pack uint64(pieceSize) big-endian (8 bytes) || bytes32(sizeNonce) (32 bytes).
	buf := make([]byte, 8+32)
	binary.BigEndian.PutUint64(buf[:8], uint64(pieceSize))
	copy(buf[8:], nonceBytes)

	hash := ethcrypto.Keccak256Hash(buf)
	sizeNonce = "0x" + fmt.Sprintf("%x", nonceBytes)
	sizeCommitment = "0x" + fmt.Sprintf("%x", hash[:])
	return sizeNonce, sizeCommitment, nil
}

// VerifySizeCommitment recomputes keccak256(uint64(pieceSize) || bytes32(sizeNonce))
// and checks it equals the expected sizeCommitment. Used by DO off-chain.
func VerifySizeCommitment(pieceSize int64, sizeNonce, expectedCommitment string) bool {
	nonceBytes := hexToBytes32(sizeNonce)
	buf := make([]byte, 8+32)
	binary.BigEndian.PutUint64(buf[:8], uint64(pieceSize))
	copy(buf[8:], nonceBytes)
	hash := ethcrypto.Keccak256Hash(buf)
	computed := "0x" + fmt.Sprintf("%x", hash[:])
	return computed == expectedCommitment
}

// SavePaymentCredentials writes the private payment credentials to local storage.
// These are never sent to DO or stored on-chain — VK uses them to call claimEscrow().
func SavePaymentCredentials(storage string, creds PaymentCredentials) error {
	if err := os.MkdirAll(paymentDir(storage), 0700); err != nil {
		return fmt.Errorf("payment: mkdir: %w", err)
	}
	creds.CreatedAt = time.Now().Format(time.RFC3339)
	b, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("payment: marshal: %w", err)
	}
	path := paymentCredPath(storage, creds.CommitmentHash)
	return atomicWriteFile(path, b, 0600)
}

// SaveQuoteCredentials writes quote credentials keyed by paymentCommitment.
// Used when commitmentHash is not yet known (before the file is actually stored).
// After file storage, SavePaymentCredentials is called again with the resolved commitmentHash.
func SaveQuoteCredentials(storage string, creds PaymentCredentials) error {
	if err := os.MkdirAll(paymentDir(storage), 0700); err != nil {
		return fmt.Errorf("payment: mkdir: %w", err)
	}
	creds.CreatedAt = time.Now().Format(time.RFC3339)
	b, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("payment: marshal: %w", err)
	}
	path := paymentCredPath(storage, creds.PaymentCommitment) // key by paymentCommitment
	return atomicWriteFile(path, b, 0600)
}

// LoadPaymentCredentials reads the saved credentials for a commitmentHash.
func LoadPaymentCredentials(storage, commitmentHash string) (PaymentCredentials, error) {
	var creds PaymentCredentials
	b, err := os.ReadFile(paymentCredPath(storage, commitmentHash))
	if err != nil {
		return creds, fmt.Errorf("payment: read creds: %w", err)
	}
	if err := json.Unmarshal(b, &creds); err != nil {
		return creds, fmt.Errorf("payment: unmarshal creds: %w", err)
	}
	return creds, nil
}

// GenerateRegistrationCommitment creates a new (regNullifier, regSecret) pair and computes:
//
//	registrationCommitment = keccak256(abi.encodePacked(regNullifier, regSecret))
//
// This commitment is registered on FileRegistrationSC and is completely independent of
// paymentCommitment — the link is hidden from observers by linkNonce.
func GenerateRegistrationCommitment() (regNullifier, regSecret, registrationCommitment string, err error) {
	regNullifierBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", "", fmt.Errorf("payment: generate regNullifier: %w", genErr)
	}
	regSecretBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", "", fmt.Errorf("payment: generate regSecret: %w", genErr)
	}

	combined := append(regNullifierBytes, regSecretBytes...)
	hash := ethcrypto.Keccak256Hash(combined)

	regNullifier = "0x" + fmt.Sprintf("%x", regNullifierBytes)
	regSecret = "0x" + fmt.Sprintf("%x", regSecretBytes)
	registrationCommitment = "0x" + fmt.Sprintf("%x", hash[:])
	return regNullifier, regSecret, registrationCommitment, nil
}

// GenerateLinkCommitment creates a random linkNonce and computes:
//
//	linkCommitment = keccak256(paymentCommitment || registrationCommitment || linkNonce)
//
// The linkNonce stays off chain so observers cannot link paymentCommitment
// (visible in VKEscrow) to registrationCommitment (visible in FileRegistrationSC)
// before service end. The VK gives it to the data owner with the quote (the data
// owner knows both commitments already): only with it can the owner prove on chain
// which registration its escrow pays for. It is published at claimEscrow time, or
// when the owner settles or refunds the escrow.
func GenerateLinkCommitment(paymentCommitment, registrationCommitment string) (linkNonce, linkCommitment string, err error) {
	linkNonceBytes, genErr := randomBytes32()
	if genErr != nil {
		return "", "", fmt.Errorf("payment: generate linkNonce: %w", genErr)
	}

	pc := hexToBytes32(paymentCommitment)
	rc := hexToBytes32(registrationCommitment)
	combined := make([]byte, 0, 96)
	combined = append(combined, pc...)
	combined = append(combined, rc...)
	combined = append(combined, linkNonceBytes...)
	hash := ethcrypto.Keccak256Hash(combined)

	linkNonce = "0x" + fmt.Sprintf("%x", linkNonceBytes)
	linkCommitment = "0x" + fmt.Sprintf("%x", hash[:])
	return linkNonce, linkCommitment, nil
}

// randomBytes32 generates 32 cryptographically random bytes.
func randomBytes32() ([]byte, error) {
	nonce, err := randomNonce() // defined in receipt.go: generates 32 random bytes as 0x hex
	if err != nil {
		return nil, err
	}
	return hexToBytes32(nonce), nil
}
