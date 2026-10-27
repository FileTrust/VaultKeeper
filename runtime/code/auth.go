package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// accessControlConfigured reports whether this keeper can answer the question
// "is this requester allowed to read this file" at all. Without both an RPC URL
// and an ACL contract it cannot, and a keeper that cannot answer must not guess.
func accessControlConfigured(cfg ServerConfig) bool {
	return strings.TrimSpace(cfg.RPCURL) != "" && strings.TrimSpace(cfg.ACLAddress) != ""
}

// escrowVerificationConfigured reports whether this keeper can confirm that an
// upload was paid for. Without both an escrow contract and an RPC URL it cannot,
// and a keeper that cannot check payment must not assume it.
func escrowVerificationConfigured(cfg ServerConfig) bool {
	return strings.TrimSpace(cfg.VKEscrowContract) != "" && strings.TrimSpace(cfg.RPCURL) != ""
}

func authorizeStoreRequest(cfg ServerConfig, req StoreReq, allowExpired bool) error {
	rpcURL, aclAddress := cfg.RPCURL, cfg.ACLAddress
	if !validTransferID(req.TransferID) {
		return fmt.Errorf("missing or invalid transferId")
	}
	if strings.TrimSpace(req.FileID) == "" {
		return fmt.Errorf("missing fileId")
	}
	if !common.IsHexAddress(req.Uploader) {
		return fmt.Errorf("missing or invalid uploader")
	}
	if strings.TrimSpace(req.TransferSignature) == "" || req.TransferIssuedAt <= 0 {
		return fmt.Errorf("missing upload authorization signature")
	}
	// Every authenticated production upload must bind the exact bytes that the
	// DO authorized.  The unauthenticated /store/2 endpoint is the isolated
	// legacy protocol; accepting an unsigned content commitment on /store/3
	// would let a compromised transport or VK substitute different bytes while
	// retaining otherwise valid transfer metadata.
	if strings.TrimSpace(req.ExpectedPieceRoot) == "" {
		return fmt.Errorf("missing expectedPieceRoot")
	}
	if err := validateRoot(req.ExpectedPieceRoot); err != nil {
		return fmt.Errorf("invalid expectedPieceRoot: %w", err)
	}
	if req.ExpectedPieceBlockSize <= 0 {
		return fmt.Errorf("missing expectedPieceBlockSize")
	}
	now := time.Now().Unix()
	if (!allowExpired && req.TransferIssuedAt < now-600) || req.TransferIssuedAt > now+120 {
		return fmt.Errorf("upload authorization signature expired or from the future")
	}
	recovered, err := recoverStoreUploaderAddress(req)
	if err != nil {
		return err
	}
	claimed := common.HexToAddress(req.Uploader).Hex()
	if !strings.EqualFold(recovered, claimed) {
		return fmt.Errorf("signature does not match uploader")
	}
	// A valid signature proves who is asking, not that they own the file. The
	// second question can only be answered on chain, and a keeper that cannot
	// ask it used to skip it -- so any key with a well-formed signature could
	// write pieces into any file's storage. Not asking is not an answer.
	if !accessControlConfigured(cfg) {
		if cfg.AllowUnauthenticatedWrites {
			return nil
		}
		return fmt.Errorf("access control is not configured on this vault keeper")
	}
	allowed, err := aclIsDataOwnerForFile(rpcURL, aclAddress, req.FileID, recovered)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("uploader is not the data owner for this file policy")
	}
	return nil
}

func vaultmeshStoreAuthMessage(req StoreReq) string {
	message := fmt.Sprintf(
		"FileTrust VaultMesh STORE\ntransferId=%s\nfileId=%s\npieceIndex=%d\nname=%s\nsize=%d\nserviceEnd=%d\ncommitmentNonce=%s\npaymentCommitment=%s\ndeletionAuthHash=%s\nfileFormat=%s\nuploader=%s\nissuedAt=%d",
		req.TransferID,
		normalizeFileID(req.FileID),
		req.PieceIndex,
		filepath.Base(req.Name),
		req.Size,
		req.ServiceEnd,
		strings.ToLower(strings.TrimSpace(req.CommitmentNonce)),
		strings.ToLower(strings.TrimSpace(req.PaymentCommitment)),
		strings.ToLower(strings.TrimSpace(req.DeletionAuthHash)),
		req.FileFormat,
		common.HexToAddress(req.Uploader).Hex(),
		req.TransferIssuedAt,
	)
	if strings.TrimSpace(req.ExpectedPieceRoot) == "" {
		return message
	}
	// V2 authorization inserts the locally known content commitment before the
	// uploader/timestamp suffix. This preserves verification of legacy signed
	// requests while binding every new production upload to its exact bytes.
	prefix := fmt.Sprintf(
		"FileTrust VaultMesh STORE\ntransferId=%s\nfileId=%s\npieceIndex=%d\nname=%s\nsize=%d\nserviceEnd=%d\ncommitmentNonce=%s\npaymentCommitment=%s\ndeletionAuthHash=%s\nfileFormat=%s",
		req.TransferID, normalizeFileID(req.FileID), req.PieceIndex,
		filepath.Base(req.Name), req.Size, req.ServiceEnd,
		strings.ToLower(strings.TrimSpace(req.CommitmentNonce)),
		strings.ToLower(strings.TrimSpace(req.PaymentCommitment)),
		strings.ToLower(strings.TrimSpace(req.DeletionAuthHash)), req.FileFormat,
	)
	return fmt.Sprintf(
		"%s\nexpectedPieceRoot=%s\npieceBlockSize=%d\nuploader=%s\nissuedAt=%d",
		prefix, strings.ToLower(strings.TrimSpace(req.ExpectedPieceRoot)),
		req.ExpectedPieceBlockSize, common.HexToAddress(req.Uploader).Hex(),
		req.TransferIssuedAt,
	)
}

func recoverStoreUploaderAddress(req StoreReq) (string, error) {
	sigHex := strings.TrimPrefix(strings.TrimSpace(req.TransferSignature), "0x")
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != 65 {
		return "", fmt.Errorf("invalid upload signature")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return "", fmt.Errorf("bad upload signature recovery id")
	}
	hash := accounts.TextHash([]byte(vaultmeshStoreAuthMessage(req)))
	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		return "", fmt.Errorf("upload signature recovery failed")
	}
	return ethcrypto.PubkeyToAddress(*pub).Hex(), nil
}

func aclIsDataOwnerForFile(rpcURL, aclAddress, fileID, uploader string) (bool, error) {
	selector := ethcrypto.Keccak256([]byte("isFileDataOwner(bytes32,address)"))[:4]
	fid, err := fileIDBytes32(fileID)
	if err != nil {
		return false, err
	}
	account := common.HexToAddress(uploader)
	calldata := make([]byte, 0, 4+32+32)
	calldata = append(calldata, selector...)
	calldata = append(calldata, fid...)
	calldata = append(calldata, make([]byte, 12)...)
	calldata = append(calldata, account.Bytes()...)
	payload := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "eth_call",
		"params": []any{map[string]string{
			"to":   common.HexToAddress(aclAddress).Hex(),
			"data": "0x" + hex.EncodeToString(calldata),
		}, "latest"},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("ACL data-owner RPC call failed: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("ACL data-owner response decode failed: %w", err)
	}
	if out.Error != nil {
		return false, fmt.Errorf("ACL data-owner RPC error: %s", out.Error.Message)
	}
	result := strings.TrimPrefix(out.Result, "0x")
	if len(result) < 64 {
		return false, nil
	}
	value, ok := new(big.Int).SetString(result[len(result)-64:], 16)
	return ok && value.Sign() != 0, nil
}

func authorizeGetRequest(rpcURL, aclAddress, storage string, req GetReq) error {
	pieceRoot := requestPieceRoot(req)
	if strings.TrimSpace(pieceRoot) == "" {
		return fmt.Errorf("missing pieceRoot")
	}
	if strings.TrimSpace(req.FileID) == "" {
		return fmt.Errorf("missing fileId")
	}
	if strings.TrimSpace(req.Requester) == "" {
		return fmt.Errorf("missing requester")
	}
	if strings.TrimSpace(req.Signature) == "" {
		return fmt.Errorf("missing signature")
	}
	if req.IssuedAt <= 0 {
		return fmt.Errorf("missing issuedAt")
	}

	now := time.Now().Unix()
	if req.IssuedAt < now-600 || req.IssuedAt > now+120 {
		return fmt.Errorf("authorization signature expired or from the future")
	}

	meta, err := readMeta(storage, pieceRoot)
	if err != nil {
		return fmt.Errorf("piece metadata not found")
	}
	if meta.FileID != "" && !sameFileID(meta.FileID, req.FileID) {
		return fmt.Errorf("fileId does not match stored piece metadata")
	}
	if meta.ServiceEnd > 0 && now > meta.ServiceEnd {
		return fmt.Errorf("piece service period has ended")
	}

	recovered, err := recoverRequesterAddress(req)
	if err != nil {
		return err
	}
	claimed := common.HexToAddress(req.Requester).Hex()
	if !strings.EqualFold(recovered, claimed) {
		return fmt.Errorf("signature does not match requester")
	}

	allowed, err := aclIsRequesterForFile(rpcURL, aclAddress, req.FileID, recovered)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("requester is not allowed for this file policy")
	}
	return nil
}

// The message a data owner signs to authorize a deletion. It names the exact
// commitment, so one signature cannot be moved to another piece, and the moment
// it was issued, so a captured one stops working.
func vaultmeshDeleteAuthMessage(req DeleteReq) string {
	return fmt.Sprintf(
		"FileTrust VaultMesh DELETE\ncommitmentHash=%s\nrequester=%s\nissuedAt=%d",
		strings.ToLower(strings.TrimSpace(req.CommitmentHash)),
		common.HexToAddress(req.Requester).Hex(),
		req.IssuedAt,
	)
}

func recoverDeleteRequesterAddress(req DeleteReq) (string, error) {
	sigHex := strings.TrimPrefix(strings.TrimSpace(req.Signature), "0x")
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return "", fmt.Errorf("bad deletion signature encoding")
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("bad deletion signature length")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return "", fmt.Errorf("bad deletion signature recovery id")
	}
	pub, err := ethcrypto.SigToPub(accounts.TextHash([]byte(vaultmeshDeleteAuthMessage(req))), sig)
	if err != nil {
		return "", fmt.Errorf("deletion signature recovery failed")
	}
	return ethcrypto.PubkeyToAddress(*pub).Hex(), nil
}

// authorizeDeleteRequest answers the question the deletion secret never could:
// is the sender the owner of this file, and is this request current?
//
// The secret proves possession and nothing else. Anyone who ever saw it -- in a
// log, in transit, in an old backup -- could destroy the data with it, forever.
// This binds the deletion to an on-chain identity and to a moment in time.
func authorizeDeleteRequest(cfg ServerConfig, req DeleteReq, fileID string) error {
	if strings.TrimSpace(req.Requester) == "" {
		return fmt.Errorf("missing requester")
	}
	if strings.TrimSpace(req.Signature) == "" {
		return fmt.Errorf("missing deletion authorization signature")
	}
	if req.IssuedAt <= 0 {
		return fmt.Errorf("missing issuedAt")
	}
	now := time.Now().Unix()
	if req.IssuedAt < now-600 || req.IssuedAt > now+120 {
		return fmt.Errorf("deletion authorization expired or from the future")
	}

	recovered, err := recoverDeleteRequesterAddress(req)
	if err != nil {
		return err
	}
	if !strings.EqualFold(recovered, common.HexToAddress(req.Requester).Hex()) {
		return fmt.Errorf("signature does not match requester")
	}

	if !accessControlConfigured(cfg) {
		if cfg.AllowUnauthenticatedWrites {
			return nil
		}
		return fmt.Errorf("access control is not configured on this vault keeper")
	}
	if strings.TrimSpace(fileID) == "" {
		return fmt.Errorf("stored piece has no fileId to check ownership against")
	}
	owner, err := aclIsDataOwnerForFile(cfg.RPCURL, cfg.ACLAddress, fileID, recovered)
	if err != nil {
		return err
	}
	if !owner {
		return fmt.Errorf("requester is not the data owner for this file")
	}
	return nil
}

func vaultmeshAuthMessage(req GetReq) string {
	return fmt.Sprintf(
		"FileTrust VaultMesh GET\nfileId=%s\npieceRoot=%s\nrequester=%s\nissuedAt=%d",
		normalizeFileID(req.FileID),
		normalizeRoot(requestPieceRoot(req)),
		common.HexToAddress(req.Requester).Hex(),
		req.IssuedAt,
	)
}

func recoverRequesterAddress(req GetReq) (string, error) {
	sigHex := strings.TrimPrefix(strings.TrimSpace(req.Signature), "0x")
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return "", fmt.Errorf("bad signature hex")
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("signature must be 65 bytes")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return "", fmt.Errorf("bad recovery id")
	}
	hash := accounts.TextHash([]byte(vaultmeshAuthMessage(req)))
	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		return "", fmt.Errorf("signature recovery failed")
	}
	return ethcrypto.PubkeyToAddress(*pub).Hex(), nil
}

func aclIsRequesterForFile(rpcURL, aclAddress, fileID, requester string) (bool, error) {
	selector := ethcrypto.Keccak256([]byte("isRequesterForFile(bytes32,address)"))[:4]
	fid, err := fileIDBytes32(fileID)
	if err != nil {
		return false, err
	}
	reqAddr := common.HexToAddress(requester)
	calldata := make([]byte, 0, 4+32+32)
	calldata = append(calldata, selector...)
	calldata = append(calldata, fid...)
	calldata = append(calldata, make([]byte, 12)...)
	calldata = append(calldata, reqAddr.Bytes()...)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": common.HexToAddress(aclAddress).Hex(), "data": "0x" + hex.EncodeToString(calldata)},
			"latest",
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		logEthCall("vk:AccessControlFT.isRequesterForFile", rpcURL, 0, "AccessControlFT", "isRequesterForFile", common.HexToAddress(aclAddress).Hex(), requester, "failed", map[string]any{"error": err.Error(), "file_id": fileID})
		return false, fmt.Errorf("ACL RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		logEthCall("vk:AccessControlFT.isRequesterForFile", rpcURL, 0, "AccessControlFT", "isRequesterForFile", common.HexToAddress(aclAddress).Hex(), requester, "failed", map[string]any{"error": err.Error(), "file_id": fileID})
		return false, fmt.Errorf("ACL RPC response decode failed: %w", err)
	}
	if out.Error != nil {
		logEthCall("vk:AccessControlFT.isRequesterForFile", rpcURL, 0, "AccessControlFT", "isRequesterForFile", common.HexToAddress(aclAddress).Hex(), requester, "failed", map[string]any{"error": out.Error.Message, "file_id": fileID})
		return false, fmt.Errorf("ACL RPC error: %s", out.Error.Message)
	}
	result := strings.TrimPrefix(out.Result, "0x")
	if len(result) == 0 {
		logEthCall("vk:AccessControlFT.isRequesterForFile", rpcURL, 0, "AccessControlFT", "isRequesterForFile", common.HexToAddress(aclAddress).Hex(), requester, "success", map[string]any{"file_id": fileID, "result": false})
		return false, nil
	}
	v, err := strconv.ParseInt(result[len(result)-1:], 16, 64)
	if err != nil {
		logEthCall("vk:AccessControlFT.isRequesterForFile", rpcURL, 0, "AccessControlFT", "isRequesterForFile", common.HexToAddress(aclAddress).Hex(), requester, "failed", map[string]any{"error": "bad ACL result", "file_id": fileID})
		return false, fmt.Errorf("bad ACL result")
	}
	ok := v != 0
	logEthCall("vk:AccessControlFT.isRequesterForFile", rpcURL, 0, "AccessControlFT", "isRequesterForFile", common.HexToAddress(aclAddress).Hex(), requester, "success", map[string]any{"file_id": fileID, "result": ok})
	return ok, nil
}

// aclFilePolicyExists returns true if fileId has an existing policy in AccessControlFT.
// Uses getFilePolicy(bytes32) and reads the first return slot (the `exists` bool).
func aclFilePolicyExists(rpcURL, aclAddress, fileID string) (bool, error) {
	selector := ethcrypto.Keccak256([]byte("getFilePolicy(bytes32)"))[:4]
	fid, err := fileIDBytes32(fileID)
	if err != nil {
		return false, err
	}
	calldata := make([]byte, 0, 4+32)
	calldata = append(calldata, selector...)
	calldata = append(calldata, fid...)

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": common.HexToAddress(aclAddress).Hex(), "data": "0x" + hex.EncodeToString(calldata)},
			"latest",
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		logEthCall("vk:AccessControlFT.getFilePolicy", rpcURL, 0, "AccessControlFT", "getFilePolicy", common.HexToAddress(aclAddress).Hex(), "", "failed", map[string]any{"error": err.Error(), "file_id": fileID})
		return false, fmt.Errorf("ACL RPC call failed: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		logEthCall("vk:AccessControlFT.getFilePolicy", rpcURL, 0, "AccessControlFT", "getFilePolicy", common.HexToAddress(aclAddress).Hex(), "", "failed", map[string]any{"error": err.Error(), "file_id": fileID})
		return false, fmt.Errorf("ACL RPC response decode failed: %w", err)
	}
	if out.Error != nil {
		logEthCall("vk:AccessControlFT.getFilePolicy", rpcURL, 0, "AccessControlFT", "getFilePolicy", common.HexToAddress(aclAddress).Hex(), "", "failed", map[string]any{"error": out.Error.Message, "file_id": fileID})
		return false, fmt.Errorf("ACL RPC error: %s", out.Error.Message)
	}
	result := strings.TrimPrefix(out.Result, "0x")
	// First 32 bytes (64 hex chars) is the `exists` bool — non-zero means true.
	if len(result) < 64 {
		logEthCall("vk:AccessControlFT.getFilePolicy", rpcURL, 0, "AccessControlFT", "getFilePolicy", common.HexToAddress(aclAddress).Hex(), "", "success", map[string]any{"file_id": fileID, "exists": false})
		return false, nil
	}
	exists := result[:64] != strings.Repeat("0", 64)
	logEthCall("vk:AccessControlFT.getFilePolicy", rpcURL, 0, "AccessControlFT", "getFilePolicy", common.HexToAddress(aclAddress).Hex(), "", "success", map[string]any{"file_id": fileID, "exists": exists})
	return exists, nil
}

func fileIDBytes32(fileID string) ([]byte, error) {
	clean := strings.TrimSpace(fileID)
	if len(clean) >= 2 && strings.EqualFold(clean[:2], "0x") {
		clean = clean[2:]
	}
	if len(clean) != 64 {
		return nil, fmt.Errorf("bad fileId length")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("bad fileId hex")
	}
	return b, nil
}

func normalizeFileID(fileID string) string {
	clean := strings.TrimSpace(fileID)
	if len(clean) >= 2 && strings.EqualFold(clean[:2], "0x") {
		clean = clean[2:]
	}
	clean = strings.ToLower(clean)
	return "0x" + clean
}

func sameFileID(a, b string) bool {
	return strings.EqualFold(normalizeFileID(a), normalizeFileID(b))
}
