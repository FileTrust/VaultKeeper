package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// A quote holds keeper capacity, on chain and locally, before any payment. It
// used to be issued to anyone who could open a stream: no wallet, no file, no
// proof. A requester could therefore hold capacity on every keeper for free,
// repeat it after each expiry, and make the keeper pay the chain fees for both
// the hold and its release.
//
// A quote is now issued only to the data owner of a real file whose key
// generation has finished on chain. Key generation pays the guardians out of
// the data owner's own escrow, and that money does not come back, so every
// file a requester uses to hold capacity costs it real money first. Both the
// real data owner app and the load test already finish key generation before
// asking any keeper for a quote, because the pieces are encrypted under that key.
//
// The keeper learns nothing new from this: the store request that follows a
// quote already names the file and the uploader, and the keeper already checks
// ownership on chain at that point. Every check here is a read; nothing is
// written on chain, so no observer can link the data owner to the keeper.

// errQuoteNotAuthorized marks a refusal that retrying the same request cannot
// change, as opposed to a chain read that may succeed on the next attempt.
var errQuoteNotAuthorized = errors.New("quote not authorized")

var (
	aclIsFilePolicyActiveSelector = ethcrypto.Keccak256([]byte("isFilePolicyActive(bytes32)"))[:4]
	aclDkgV2Selector              = ethcrypto.Keccak256([]byte("dkgV2()"))[:4]
	dkgV2GetKeySelector           = ethcrypto.Keccak256([]byte("getV2Key(bytes32)"))[:4]
)

// vaultmeshQuoteAuthMessage is the exact text the data owner signs. It names the
// keeper being asked, so a keeper that receives a signed request cannot replay
// it to another keeper to hold capacity there in the data owner's name. The
// data owner builds the same text in do_vaultmesh.quote_authorization_message;
// both sides pin it in a test, because a silent difference between them refuses
// every quote.
func vaultmeshQuoteAuthMessage(req QuoteReq, vkAddress string) string {
	return fmt.Sprintf(
		"FileTrust VaultMesh QUOTE\ntransferId=%s\nfileId=%s\nsize=%d\nserviceEnd=%d\nvaultKeeper=%s\nuploader=%s\nissuedAt=%d",
		req.TransferID,
		normalizeFileID(req.FileID),
		req.Size,
		req.ServiceEnd,
		common.HexToAddress(vkAddress).Hex(),
		common.HexToAddress(req.Uploader).Hex(),
		req.IssuedAt,
	)
}

// verifyQuoteSignature checks everything that needs no chain read: the fields
// are present and well formed, the request is current, and the signature was
// made by the claimed uploader for this keeper.
func verifyQuoteSignature(req QuoteReq, vkAddress string, now time.Time) error {
	if !validTransferID(req.TransferID) {
		return fmt.Errorf("%w: missing or invalid transferId", errQuoteNotAuthorized)
	}
	if _, err := fileIDBytes32(req.FileID); err != nil {
		return fmt.Errorf("%w: invalid fileId: %v", errQuoteNotAuthorized, err)
	}
	if !common.IsHexAddress(req.Uploader) {
		return fmt.Errorf("%w: missing or invalid uploader", errQuoteNotAuthorized)
	}
	if !common.IsHexAddress(vkAddress) {
		return fmt.Errorf("%w: this vault keeper has no address to bind the request to", errQuoteNotAuthorized)
	}
	// Same window as a store authorization.
	unix := now.Unix()
	if req.IssuedAt <= 0 || req.IssuedAt < unix-600 || req.IssuedAt > unix+120 {
		return fmt.Errorf("%w: quote authorization expired or from the future", errQuoteNotAuthorized)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(req.Signature), "0x"))
	if err != nil || len(sig) != 65 {
		return fmt.Errorf("%w: invalid quote signature", errQuoteNotAuthorized)
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return fmt.Errorf("%w: bad quote signature recovery id", errQuoteNotAuthorized)
	}
	hash := accounts.TextHash([]byte(vaultmeshQuoteAuthMessage(req, vkAddress)))
	pub, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		return fmt.Errorf("%w: quote signature recovery failed", errQuoteNotAuthorized)
	}
	if !strings.EqualFold(ethcrypto.PubkeyToAddress(*pub).Hex(), common.HexToAddress(req.Uploader).Hex()) {
		return fmt.Errorf("%w: quote signature does not match uploader for this vault keeper", errQuoteNotAuthorized)
	}
	return nil
}

// quoteFileOnChain is what the chain says about the file a quote is asked for.
type quoteFileOnChain struct {
	Owner        bool
	PolicyActive bool
	KeyExists    bool
	KeyFinalized bool
	KeyOwner     string
}

// readQuoteFileOnChain reads the three facts a quote depends on. Any read that
// fails is returned wrapped in ErrRPCUnavailable: an unreadable chain is a
// reason to retry, never a reason to issue the quote.
func readQuoteFileOnChain(cfg ServerConfig, fileID, uploader string) (quoteFileOnChain, error) {
	var out quoteFileOnChain
	fid, err := fileIDBytes32(fileID)
	if err != nil {
		return out, fmt.Errorf("%w: invalid fileId: %v", errQuoteNotAuthorized, err)
	}
	owner, err := aclIsDataOwnerForFile(cfg.RPCURL, cfg.ACLAddress, fileID, uploader)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrRPCUnavailable, err)
	}
	out.Owner = owner

	active, err := ethCallWords(cfg.RPCURL, cfg.ACLAddress,
		append(append([]byte{}, aclIsFilePolicyActiveSelector...), fid...), 1, "ACL.isFilePolicyActive")
	if err != nil {
		return out, err
	}
	out.PolicyActive = !isZeroWord(active[0:32])

	coordinatorWord, err := ethCallWords(cfg.RPCURL, cfg.ACLAddress, aclDkgV2Selector, 1, "ACL.dkgV2")
	if err != nil {
		return out, err
	}
	coordinator := common.BytesToAddress(coordinatorWord[12:32])
	if coordinator == (common.Address{}) {
		// No key generation contract means no file can have a finished key.
		return out, nil
	}
	key, err := ethCallWords(cfg.RPCURL, coordinator.Hex(),
		append(append([]byte{}, dkgV2GetKeySelector...), fid...), 3, "ZkDkgCoordinatorV2.getV2Key")
	if err != nil {
		return out, err
	}
	out.KeyExists = !isZeroWord(key[0:32])
	out.KeyFinalized = !isZeroWord(key[32:64])
	out.KeyOwner = common.BytesToAddress(key[76:96]).Hex()
	return out, nil
}

// authorizeQuoteRequest decides whether a quote may be issued at all, before any
// capacity is held. A refusal wraps errQuoteNotAuthorized; a chain read that
// failed wraps ErrRPCUnavailable so the caller answers busy instead.
func authorizeQuoteRequest(cfg ServerConfig, req QuoteReq, now time.Time) error {
	if !accessControlConfigured(cfg) {
		// The same explicit test-only opening the store path honours. Without it,
		// a keeper that cannot ask the chain who owns a file must not guess.
		if cfg.AllowUnauthenticatedWrites {
			return nil
		}
		return fmt.Errorf("%w: access control is not configured on this vault keeper", errQuoteNotAuthorized)
	}
	if err := verifyQuoteSignature(req, cfg.VKAddress, now); err != nil {
		return err
	}
	facts, err := readQuoteFileOnChain(cfg, req.FileID, req.Uploader)
	if err != nil {
		return err
	}
	switch {
	case !facts.Owner:
		return fmt.Errorf("%w: uploader is not the data owner for this file policy", errQuoteNotAuthorized)
	case !facts.PolicyActive:
		return fmt.Errorf("%w: file policy is not active", errQuoteNotAuthorized)
	case !facts.KeyExists || !facts.KeyFinalized:
		return fmt.Errorf("%w: key generation for this file is not finished", errQuoteNotAuthorized)
	case !strings.EqualFold(facts.KeyOwner, common.HexToAddress(req.Uploader).Hex()):
		return fmt.Errorf("%w: the file key belongs to another data owner", errQuoteNotAuthorized)
	}
	return nil
}

// quoteFileHash is the only form in which a quote record keeps the file. The
// keeper stores the file id itself once a piece is stored; a quote that never
// becomes a stored piece leaves only this.
//
// An explicitly open test keeper may take a quote with no file at all; that
// gets no hash, so unrelated anonymous quotes are not counted as one file.
func quoteFileHash(fileID string) string {
	if strings.TrimSpace(fileID) == "" {
		return ""
	}
	sum := ethcrypto.Keccak256([]byte("FileTrustQuoteFileV1\x00" + normalizeFileID(fileID)))
	return hex.EncodeToString(sum)
}

// ethCallWords performs a read-only call and returns at least `words` ABI words.
func ethCallWords(rpcURL, contract string, calldata []byte, words int, label string) ([]byte, error) {
	if !common.IsHexAddress(contract) {
		return nil, fmt.Errorf("%w: %s contract is not configured", errQuoteNotAuthorized, label)
	}
	result, err := rpcCall(rpcURL, "eth_call", []any{
		map[string]string{"to": common.HexToAddress(contract).Hex(), "data": "0x" + hex.EncodeToString(calldata)},
		"latest",
	})
	if err != nil {
		if errors.Is(err, ErrRPCUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrRPCUnavailable, label, err)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil || len(raw) < 32*words {
		return nil, fmt.Errorf("%w: invalid %s response", ErrRPCUnavailable, label)
	}
	return raw, nil
}

func isZeroWord(word []byte) bool {
	for _, b := range word {
		if b != 0 {
			return false
		}
	}
	return true
}
