package main

// owner_recovery.go — what a data owner can ask for after losing its records.
//
// Two requests, both answered only to the owner of the file in question:
//
//	recovery-receipt  return the private receipt this keeper signed for a
//	                  piece. The keeper already keeps a copy (saveIssuedReceipt);
//	                  until now there was no way to ask for it.
//	recovery-vault    store, and later return, one sealed blob per upload. The
//	                  keeper cannot read it: it is encrypted to the owner's own
//	                  key, and this node only holds the bytes.
//
// Why a keeper should serve these at all. The receipt is the owner's only
// evidence in a storage dispute, and it lives on the disk of the party it
// might be used against. An owner who reinstalls has no copy, so a keeper that
// stays silent can never be challenged -- refusing is free. An honest keeper
// loses nothing by answering: the receipt is already in the owner's hands by
// design, and the sealed blob is noise to everyone but its owner.
//
// The sealed blob is small, bounded, and stored per (owner, upload). It is not
// a general file store: oversized or unsigned requests are refused, and the
// keeper never parses the contents.

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/network"
)

const (
	// A sealed copy holds receipts and per-piece secrets for one upload.
	// 256 KB is far above what that needs and far below anything worth
	// abusing as storage.
	maxRecoveryVaultBytes = 256 * 1024

	// The same freshness window the deletion path uses: long enough for a
	// slow link, short enough that a captured request stops working.
	recoveryAuthSkewPast   = 600
	recoveryAuthSkewFuture = 120
)

// ── the requests ─────────────────────────────────────────────────────────────

// RecoveryReceiptReq asks for the receipt this keeper signed for one piece.
type RecoveryReceiptReq struct {
	FileID    string `json:"fileId"`
	PieceRoot string `json:"pieceRoot"`
	Requester string `json:"requester"`
	IssuedAt  int64  `json:"issuedAt"`
	Signature string `json:"sig"`
}

type RecoveryReceiptResp struct {
	Found   bool              `json:"found"`
	Receipt *PrivateReceiptV1 `json:"receipt,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// RecoveryVaultReq both stores and fetches. Sealed empty means "give it back".
type RecoveryVaultReq struct {
	FileID    string `json:"fileId"`
	UploadID  string `json:"uploadId"`
	Sealed    string `json:"sealed,omitempty"` // base64, opaque to this node
	Requester string `json:"requester"`
	IssuedAt  int64  `json:"issuedAt"`
	Signature string `json:"sig"`
}

type RecoveryVaultResp struct {
	Stored bool   `json:"stored,omitempty"`
	Found  bool   `json:"found,omitempty"`
	Sealed string `json:"sealed,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ── what the owner signs ─────────────────────────────────────────────────────
//
// One message shape per action, each naming the exact thing it covers, so a
// signature for one piece or one upload cannot be moved to another.

func recoveryReceiptAuthMessage(req RecoveryReceiptReq) string {
	return fmt.Sprintf(
		"FileTrust VaultMesh RECOVERY-RECEIPT\nfileId=%s\npieceRoot=%s\nrequester=%s\nissuedAt=%d",
		normalizeFileID(req.FileID),
		normalizeRoot(req.PieceRoot),
		common.HexToAddress(req.Requester).Hex(),
		req.IssuedAt,
	)
}

func recoveryVaultAuthMessage(req RecoveryVaultReq, action string) string {
	return fmt.Sprintf(
		"FileTrust VaultMesh RECOVERY-VAULT\naction=%s\nfileId=%s\nuploadId=%s\nrequester=%s\nissuedAt=%d",
		action,
		normalizeFileID(req.FileID),
		strings.ToLower(strings.TrimSpace(req.UploadID)),
		common.HexToAddress(req.Requester).Hex(),
		req.IssuedAt,
	)
}

func recoverSigner(message, sigHex string) (string, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(sigHex), "0x")
	sig, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("bad signature encoding")
	}
	if len(sig) != 65 {
		return "", fmt.Errorf("bad signature length")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return "", fmt.Errorf("bad signature recovery id")
	}
	pub, err := ethcrypto.SigToPub(accounts.TextHash([]byte(message)), sig)
	if err != nil {
		return "", fmt.Errorf("signature recovery failed")
	}
	return ethcrypto.PubkeyToAddress(*pub).Hex(), nil
}

// authorizeRecoveryRequest proves three things before anything is served: the
// signature is this requester's, the request is current, and the chain agrees
// that this address owns the file.
func authorizeRecoveryRequest(cfg ServerConfig, message, requester, sigHex string,
	issuedAt int64, fileID string) error {
	if strings.TrimSpace(requester) == "" {
		return fmt.Errorf("missing requester")
	}
	if strings.TrimSpace(sigHex) == "" {
		return fmt.Errorf("missing signature")
	}
	if issuedAt <= 0 {
		return fmt.Errorf("missing issuedAt")
	}
	now := time.Now().Unix()
	if issuedAt < now-recoveryAuthSkewPast || issuedAt > now+recoveryAuthSkewFuture {
		return fmt.Errorf("authorization expired or from the future")
	}
	recovered, err := recoverSigner(message, sigHex)
	if err != nil {
		return err
	}
	if !strings.EqualFold(recovered, common.HexToAddress(requester).Hex()) {
		return fmt.Errorf("signature does not match requester")
	}
	if strings.TrimSpace(fileID) == "" {
		return fmt.Errorf("missing fileId")
	}
	if !accessControlConfigured(cfg) {
		if cfg.AllowUnauthenticatedWrites {
			return nil
		}
		return fmt.Errorf("access control is not configured on this vault keeper")
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

// ── the sealed copies on disk ────────────────────────────────────────────────

func recoveryVaultDir(storage string) string {
	return filepath.Join(storage, "recovery_vault")
}

// recoveryVaultPath keeps one file per (owner, file, upload). The owner is in
// the name so one owner's sealed copy can never be served to another, even if
// two of them chose the same upload id.
func recoveryVaultPath(storage, owner, fileID, uploadID string) string {
	name := fmt.Sprintf(
		"%s-%s-%s.sealed",
		safeID(strings.ToLower(common.HexToAddress(owner).Hex())),
		safeID(normalizeFileID(fileID)),
		safeID(strings.ToLower(strings.TrimSpace(uploadID))),
	)
	return filepath.Join(recoveryVaultDir(storage), name)
}

func storeRecoveryVault(storage, owner, fileID, uploadID string, sealed []byte) error {
	if len(sealed) == 0 {
		return fmt.Errorf("empty sealed copy")
	}
	if len(sealed) > maxRecoveryVaultBytes {
		return fmt.Errorf("sealed copy too large")
	}
	if err := os.MkdirAll(recoveryVaultDir(storage), 0700); err != nil {
		return fmt.Errorf("create recovery vault dir: %w", err)
	}
	return atomicWriteFile(recoveryVaultPath(storage, owner, fileID, uploadID), sealed, 0600)
}

func loadRecoveryVault(storage, owner, fileID, uploadID string) ([]byte, bool) {
	data, err := os.ReadFile(recoveryVaultPath(storage, owner, fileID, uploadID))
	if err != nil {
		return nil, false
	}
	return data, true
}

// findIssuedReceipt looks through this keeper's own copies for the receipt it
// signed for a piece. The file name carries the sector id as well, which the
// asker does not know, so the match is on the piece root inside each file.
func findIssuedReceipt(storage, pieceRoot string) (*PrivateReceiptV1, bool) {
	wanted := normalizeRoot(pieceRoot)
	entries, err := os.ReadDir(receiptDir(storage))
	if err != nil {
		return nil, false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(receiptDir(storage), entry.Name()))
		if err != nil {
			continue
		}
		var receipt PrivateReceiptV1
		if err := json.Unmarshal(raw, &receipt); err != nil {
			continue
		}
		if normalizeRoot(receipt.PieceRoot) == wanted {
			return &receipt, true
		}
	}
	return nil, false
}

// ── the handlers ─────────────────────────────────────────────────────────────

func handleRecoveryReceipt(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	var req RecoveryReceiptReq
	if err := json.NewDecoder(bufio.NewReader(s)).Decode(&req); err != nil {
		writeJSON(s, RecoveryReceiptResp{Error: "decode request: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.PieceRoot) == "" {
		writeJSON(s, RecoveryReceiptResp{Error: "pieceRoot required"})
		return
	}
	if err := authorizeRecoveryRequest(cfg, recoveryReceiptAuthMessage(req),
		req.Requester, req.Signature, req.IssuedAt, req.FileID); err != nil {
		writeJSON(s, RecoveryReceiptResp{Error: err.Error()})
		return
	}
	receipt, found := findIssuedReceipt(cfg.Storage, req.PieceRoot)
	if !found {
		writeJSON(s, RecoveryReceiptResp{Found: false})
		return
	}
	writeJSON(s, RecoveryReceiptResp{Found: true, Receipt: receipt})
}

func handleRecoveryVault(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	var req RecoveryVaultReq
	if err := json.NewDecoder(bufio.NewReader(s)).Decode(&req); err != nil {
		writeJSON(s, RecoveryVaultResp{Error: "decode request: " + err.Error()})
		return
	}
	if strings.TrimSpace(req.UploadID) == "" {
		writeJSON(s, RecoveryVaultResp{Error: "uploadId required"})
		return
	}

	action := "fetch"
	if strings.TrimSpace(req.Sealed) != "" {
		action = "store"
	}
	if err := authorizeRecoveryRequest(cfg, recoveryVaultAuthMessage(req, action),
		req.Requester, req.Signature, req.IssuedAt, req.FileID); err != nil {
		writeJSON(s, RecoveryVaultResp{Error: err.Error()})
		return
	}

	if action == "store" {
		sealed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.Sealed))
		if err != nil {
			writeJSON(s, RecoveryVaultResp{Error: "sealed copy is not base64"})
			return
		}
		if len(sealed) > maxRecoveryVaultBytes {
			writeJSON(s, RecoveryVaultResp{Error: "sealed copy too large"})
			return
		}
		if err := storeRecoveryVault(cfg.Storage, req.Requester, req.FileID,
			req.UploadID, sealed); err != nil {
			writeJSON(s, RecoveryVaultResp{Error: err.Error()})
			return
		}
		writeJSON(s, RecoveryVaultResp{Stored: true})
		return
	}

	sealed, found := loadRecoveryVault(cfg.Storage, req.Requester, req.FileID, req.UploadID)
	if !found {
		writeJSON(s, RecoveryVaultResp{Found: false})
		return
	}
	writeJSON(s, RecoveryVaultResp{
		Found:  true,
		Sealed: base64.StdEncoding.EncodeToString(sealed),
	})
}
