package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// handleRenew quotes a longer service term for a piece this VK already stores.
//
// The DO names the piece by paymentCommitment only. That is safe: the DO already
// knows it, it identifies nothing on its own, and nothing about the VK-DO pair is
// published by answering. The VK's consent travels as extensionCommitment — a
// fresh secret only this VK can later open on-chain.
//
// Refusing is always allowed. A VK that is short on space, or whose policy caps
// the term, simply declines and the DO renews elsewhere or lets the term lapse.
func handleRenew(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	requesterID := requesterIDFromStream(s)
	now := time.Now().UTC()
	if blocked, until := requesterBlockedUntil(requesterID, now); blocked {
		writeJSON(s, RenewResp{OK: false, Err: fmt.Sprintf("requester temporarily blocked until %s", until.Format(time.RFC3339))})
		return
	}

	var req RenewReq
	if err := json.NewDecoder(bufio.NewReader(s)).Decode(&req); err != nil {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, RenewResp{OK: false, Err: err.Error()})
		return
	}
	if strings.TrimSpace(req.PaymentCommitment) == "" || req.NewServiceEnd <= 0 {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, RenewResp{OK: false, Err: "paymentCommitment and newServiceEnd are required"})
		return
	}

	creds, found, err := findCredentialsByPaymentCommitment(cfg.Storage, req.PaymentCommitment)
	if err != nil {
		writeJSON(s, RenewResp{OK: false, Err: "credential lookup failed"})
		return
	}
	if !found {
		// Do not distinguish "not ours" from "never existed": either way this VK
		// has nothing to renew, and saying more would answer probes about which
		// commitments a VK holds.
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, RenewResp{OK: false, Err: "no renewable agreement for this commitment"})
		return
	}

	chainNow, err := rpcLatestBlockTimestamp(cfg.RPCURL)
	if err != nil {
		writeJSON(s, RenewResp{OK: false, Err: "chain time unavailable"})
		return
	}

	// The term must still be running. Once it lapses the piece may already be
	// collected, so a renewal would promise something we cannot guarantee.
	if creds.ServiceEnd <= chainNow {
		writeJSON(s, RenewResp{OK: false, Err: "service period already ended; a new agreement is required"})
		return
	}
	if req.NewServiceEnd <= creds.ServiceEnd {
		writeJSON(s, RenewResp{OK: false, Err: "newServiceEnd must be later than the current term"})
		return
	}
	if cfg.MaxServiceDays > 0 {
		maxEnd := chainNow + int64(cfg.MaxServiceDays)*86400
		if req.NewServiceEnd > maxEnd {
			writeJSON(s, RenewResp{OK: false, Err: fmt.Sprintf("newServiceEnd exceeds VK maxServiceDays (%d)", cfg.MaxServiceDays)})
			return
		}
	}
	if cfg.VKEscrowContract == "" || cfg.FileRegistrationContract == "" ||
		strings.TrimSpace(cfg.VKPrivKeyHex) == "" || cfg.ChainID <= 0 {
		writeJSON(s, RenewResp{OK: false, Err: "VK renewal is not configured"})
		return
	}

	// Price only the ADDED days, at the VK's current rate.
	addedSeconds := req.NewServiceEnd - creds.ServiceEnd
	addedDays := (addedSeconds + 86399) / 86400
	price := storagePriceWeiForBytes(cfg.StorageFee, creds.PieceSize, addedDays, cfg.SuToWeiRate)
	if price.Sign() <= 0 {
		writeJSON(s, RenewResp{OK: false, Err: "cannot issue enforceable renewal quote with zero price"})
		return
	}

	// Reuse an outstanding quote so a DO retry cannot strand the first secret.
	extNullifier, extSecret, extensionCommitment := creds.ExtNullifier, creds.ExtSecret, creds.ExtensionCommitment
	reusable := extensionCommitment != "" &&
		creds.PendingServiceEnd == req.NewServiceEnd &&
		creds.ExtensionConfirmBy > chainNow
	if !reusable {
		extNullifier, extSecret, extensionCommitment, err = GenerateExtensionCommitment()
		if err != nil {
			writeJSON(s, RenewResp{OK: false, Err: "generate extension commitment"})
			return
		}
	}

	confirmBy := chainNow + int64(extensionConfirmWindow.Seconds())
	if confirmBy >= creds.ServiceEnd {
		// The escrow refuses a confirm deadline past the running term.
		confirmBy = creds.ServiceEnd - 1
	}
	if confirmBy <= chainNow {
		writeJSON(s, RenewResp{OK: false, Err: "too close to service end to renew safely"})
		return
	}
	if reusable {
		confirmBy = creds.ExtensionConfirmBy
	}

	privKey, keyErr := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if keyErr != nil {
		writeJSON(s, RenewResp{OK: false, Err: "invalid VK signing key"})
		return
	}
	quoteValidUntil := chainNow + 300
	signature, signErr := signRenewalQuote(
		privKey, cfg.ChainID, cfg.VKAddress, cfg.VKEscrowContract,
		creds.PaymentCommitment, extensionCommitment, price.String(),
		creds.ServiceEnd, req.NewServiceEnd, confirmBy, quoteValidUntil,
	)
	if signErr != nil {
		writeJSON(s, RenewResp{OK: false, Err: "sign renewal quote: " + signErr.Error()})
		return
	}

	// Persist the secret BEFORE answering. If we answered first and then failed
	// to save, the DO could fund an extension we could never confirm — money
	// parked against a promise we lost the proof for.
	creds.ExtNullifier = extNullifier
	creds.ExtSecret = extSecret
	creds.ExtensionCommitment = extensionCommitment
	creds.PendingServiceEnd = req.NewServiceEnd
	creds.ExtensionConfirmBy = confirmBy
	creds.ExtensionPriceWei = price.String()
	creds.ExtensionQuotedAt = nowRFC3339()
	if saveErr := SavePaymentCredentials(cfg.Storage, creds); saveErr != nil {
		log.Printf("[renewal] save extension credentials failed: %v", saveErr)
		writeJSON(s, RenewResp{OK: false, Err: "failed to save renewal credentials"})
		return
	}

	log.Printf("[renewal] quoted pc=%s %d→%d addedDays=%d price=%s",
		truncate(creds.PaymentCommitment, 18), creds.ServiceEnd, req.NewServiceEnd,
		addedDays, price.String())

	writeJSON(s, RenewResp{
		OK:                  true,
		PaymentCommitment:   creds.PaymentCommitment,
		ExtensionCommitment: extensionCommitment,
		CurrentServiceEnd:   creds.ServiceEnd,
		NewServiceEnd:       req.NewServiceEnd,
		AddedPriceWei:       price.String(),
		ConfirmBy:           confirmBy,
		QuoteValidUntil:     quoteValidUntil,
		VKEscrowContract:    cfg.VKEscrowContract,
		VKAddress:           cfg.VKAddress,
		VKSignature:         signature,
	})
}

// renewalPriceForDays is exposed for tests: the added term is priced at the
// VK's ordinary rate, over the added days only.
func renewalPriceForDays(cfg ServerConfig, sizeBytes, addedDays int64) *big.Int {
	return storagePriceWeiForBytes(cfg.StorageFee, sizeBytes, addedDays, cfg.SuToWeiRate)
}
