package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type DiscoveryRecord struct {
	Version      int    `json:"version"`
	PeerID       string `json:"peerId"`
	Multiaddr    string `json:"multiaddr"`
	VKAddress    string `json:"vkAddress"`
	Seq          int64  `json:"seq"`
	EndpointHash string `json:"endpointHash,omitempty"`
	ExpiresAt    int64  `json:"expiresAt"`
	Signature    string `json:"signature"`
}

type DiscoveryEndpointState struct {
	PeerID       string `json:"peerId"`
	Multiaddr    string `json:"multiaddr"`
	VKAddress    string `json:"vkAddress"`
	Seq          int64  `json:"seq"`
	EndpointHash string `json:"endpointHash"`
	UpdatedAt    int64  `json:"updatedAt"`
}

func discoveryEndpointCanonicalMessage(record DiscoveryRecord) string {
	return strings.Join([]string{
		"FileTrust VK Discovery Endpoint",
		"version=1",
		"peerId=" + record.PeerID,
		"multiaddr=" + record.Multiaddr,
		"vkAddress=" + record.VKAddress,
		fmt.Sprintf("seq=%d", record.Seq),
	}, "\n")
}

func discoveryEndpointHash(record DiscoveryRecord) string {
	return ethcrypto.Keccak256Hash([]byte(discoveryEndpointCanonicalMessage(record))).Hex()
}

func discoveryCanonicalMessage(record DiscoveryRecord) string {
	return strings.Join([]string{
		"FileTrust VK Discovery Record",
		"version=1",
		"peerId=" + record.PeerID,
		"multiaddr=" + record.Multiaddr,
		"vkAddress=" + record.VKAddress,
		fmt.Sprintf("seq=%d", record.Seq),
		fmt.Sprintf("expiresAt=%d", record.ExpiresAt),
	}, "\n")
}

func endpointStatePath(cfg ServerConfig) string {
	return filepath.Join(cfg.Storage, "discovery_endpoint.json")
}

func loadDiscoveryEndpointState(cfg ServerConfig) DiscoveryEndpointState {
	path := endpointStatePath(cfg)
	raw, err := os.ReadFile(path)
	if err != nil {
		return DiscoveryEndpointState{}
	}
	var state DiscoveryEndpointState
	if err := json.Unmarshal(raw, &state); err != nil {
		log.Printf("[discovery] endpoint state ignored path=%s err=%v", path, err)
		return DiscoveryEndpointState{}
	}
	return state
}

func saveDiscoveryEndpointState(cfg ServerConfig, state DiscoveryEndpointState) {
	path := endpointStatePath(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Printf("[discovery] endpoint state mkdir failed: %v", err)
		return
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("[discovery] endpoint state marshal failed: %v", err)
		return
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0644); err != nil {
		log.Printf("[discovery] endpoint state write failed: %v", err)
	}
}

func buildDiscoveryEndpointState(cfg ServerConfig, peerID, multiaddr string) DiscoveryEndpointState {
	state := loadDiscoveryEndpointState(cfg)
	if state.PeerID != peerID || state.VKAddress != cfg.VKAddress || state.Multiaddr != multiaddr || state.Seq <= 0 {
		state = DiscoveryEndpointState{
			PeerID:    peerID,
			Multiaddr: multiaddr,
			VKAddress: cfg.VKAddress,
			Seq:       time.Now().UTC().UnixNano(),
			UpdatedAt: time.Now().UTC().Unix(),
		}
	}
	record := DiscoveryRecord{
		Version:   1,
		PeerID:    peerID,
		Multiaddr: multiaddr,
		VKAddress: cfg.VKAddress,
		Seq:       state.Seq,
	}
	state.EndpointHash = discoveryEndpointHash(record)
	saveDiscoveryEndpointState(cfg, state)
	return state
}

func signDiscoveryRecord(cfg ServerConfig, peerID, multiaddr string, seq int64, endpointHash string, now int64) (DiscoveryRecord, error) {
	if cfg.VKPrivKeyHex == "" {
		return DiscoveryRecord{}, fmt.Errorf("missing VK private key")
	}
	if cfg.VKAddress == "" {
		return DiscoveryRecord{}, fmt.Errorf("missing VK address")
	}
	ttl := cfg.DiscoveryTTLSeconds
	if ttl <= 0 {
		ttl = DefaultDiscoveryTTLSeconds
	}

	record := DiscoveryRecord{
		Version:      1,
		PeerID:       peerID,
		Multiaddr:    multiaddr,
		VKAddress:    cfg.VKAddress,
		Seq:          seq,
		EndpointHash: endpointHash,
		ExpiresAt:    now + ttl,
	}
	computedHash := discoveryEndpointHash(record)
	if record.EndpointHash == "" {
		record.EndpointHash = computedHash
	} else if !strings.EqualFold(record.EndpointHash, computedHash) {
		return DiscoveryRecord{}, fmt.Errorf("endpoint hash mismatch: state=%s computed=%s", record.EndpointHash, computedHash)
	}

	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		return DiscoveryRecord{}, err
	}
	hash := accounts.TextHash([]byte(discoveryCanonicalMessage(record)))
	signature, err := ethcrypto.Sign(hash, privKey)
	if err != nil {
		return DiscoveryRecord{}, err
	}
	if len(signature) == 65 && signature[64] < 27 {
		signature[64] += 27
	}
	record.Signature = "0x" + hex.EncodeToString(signature)
	return record, nil
}

func announceDiscoveryRecord(ctx context.Context, url string, record DiscoveryRecord) error {
	endpoint := strings.TrimRight(url, "/") + "/v1/announce"
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("status %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func discoveryRetryInterval(refresh time.Duration) time.Duration {
	return discoveryRetryDelay(refresh, 1)
}

func discoveryRetryDelay(refresh time.Duration, consecutiveFailures int) time.Duration {
	maxRetry := 5 * time.Minute
	if refresh > 0 && refresh/6 < maxRetry {
		maxRetry = refresh / 6
	}
	if maxRetry < 10*time.Second {
		maxRetry = 10 * time.Second
	}
	if consecutiveFailures < 1 {
		consecutiveFailures = 1
	}
	retry := 10 * time.Second
	for i := 1; i < consecutiveFailures && retry < maxRetry; i++ {
		retry *= 2
	}
	if retry > maxRetry {
		retry = maxRetry
	}
	return retry
}

func announceDiscoveryURLs(ctx context.Context, record DiscoveryRecord, urls []string) (int, []string) {
	succeeded := 0
	failed := make([]string, 0)
	for _, rawURL := range urls {
		url := strings.TrimSpace(rawURL)
		if url == "" {
			continue
		}
		announceCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := announceDiscoveryRecord(announceCtx, url, record)
		cancel()
		if err != nil {
			log.Printf("[discovery] announce failed url=%s err=%v", url, err)
			failed = append(failed, url)
			continue
		}
		succeeded++
	}
	return succeeded, failed
}

func startDiscoveryHeartbeat(ctx context.Context, cfg ServerConfig, peerID string, multiaddrSource func() string) {
	if len(cfg.DiscoveryURLs) == 0 {
		return
	}
	if cfg.VKPrivKeyHex == "" || cfg.VKAddress == "" {
		log.Printf("[discovery] skipped: --vk-private-key is required for signed announcements")
		return
	}

	heartbeat := cfg.DiscoveryHeartbeatSeconds
	if heartbeat <= 0 {
		heartbeat = DefaultDiscoveryHeartbeatSeconds
	}
	ttl := cfg.DiscoveryTTLSeconds
	if ttl <= 0 {
		ttl = DefaultDiscoveryTTLSeconds
	}
	if ttl <= heartbeat {
		log.Printf("[discovery] not started: ttl=%ds must be greater than refresh=%ds", ttl, heartbeat)
		return
	}
	refreshInterval := time.Duration(heartbeat) * time.Second
	checkInterval := time.Minute
	if refreshInterval/12 > 0 && refreshInterval/12 < checkInterval {
		checkInterval = refreshInterval / 12
	}
	if checkInterval < time.Second {
		checkInterval = time.Second
	}

	currentMultiaddr := strings.TrimSpace(multiaddrSource())
	if currentMultiaddr == "" {
		// An automatic address (--advertise-ip auto) exists only once it is
		// proven. Wait for it rather than never announcing at all.
		log.Printf("[discovery] waiting for an address to announce")
		currentMultiaddr = waitForMultiaddr(ctx, multiaddrSource, 5*time.Second)
		if currentMultiaddr == "" {
			return
		}
	}
	endpointState := buildDiscoveryEndpointState(cfg, peerID, currentMultiaddr)
	var pendingRecord *DiscoveryRecord
	var pendingURLs []string
	var nextRetry time.Time
	var nextRefresh time.Time
	retryFailures := 0
	scheduleRetry := func() time.Duration {
		retryFailures++
		delay := discoveryRetryDelay(refreshInterval, retryFailures)
		nextRetry = time.Now().Add(delay)
		return delay
	}
	resetRetry := func() {
		retryFailures = 0
		nextRetry = time.Time{}
	}

	announceFresh := func(reason string) {
		currentMultiaddr = strings.TrimSpace(multiaddrSource())
		if currentMultiaddr == "" {
			log.Printf("[discovery] announcement deferred reason=%s: advertised multiaddr is empty", reason)
			scheduleRetry()
			return
		}
		endpointState = buildDiscoveryEndpointState(cfg, peerID, currentMultiaddr)
		if cfg.VKRegistryContract != "" && cfg.VKRegistryABIPath != "" {
			seq, endpointHash, ok := syncRegistryEndpoint(cfg, peerID, currentMultiaddr, endpointState.Seq)
			if !ok {
				log.Printf("[discovery] announcement deferred reason=%s: registry endpoint update/check failed", reason)
				scheduleRetry()
				return
			}
			if seq != endpointState.Seq || !strings.EqualFold(endpointHash, endpointState.EndpointHash) {
				endpointState.Seq = seq
				endpointState.EndpointHash = endpointHash
				endpointState.UpdatedAt = time.Now().UTC().Unix()
				saveDiscoveryEndpointState(cfg, endpointState)
			}
		}
		now := time.Now().UTC().Unix()
		record, err := signDiscoveryRecord(cfg, peerID, currentMultiaddr, endpointState.Seq, endpointState.EndpointHash, now)
		if err != nil {
			log.Printf("[discovery] sign record failed: %v", err)
			scheduleRetry()
			return
		}
		succeeded, failed := announceDiscoveryURLs(ctx, record, cfg.DiscoveryURLs)
		if len(failed) > 0 {
			pendingCopy := record
			pendingRecord = &pendingCopy
			pendingURLs = failed
			retryDelay := scheduleRetry()
			log.Printf("[discovery] announcement partial reason=%s nodes=%d/%d retryIn=%s",
				reason, succeeded, succeeded+len(failed), retryDelay)
			return
		}
		pendingRecord = nil
		pendingURLs = nil
		resetRetry()
		nextRefresh = nextHeartbeatSlot(time.Now(), cfg.ChainID, cfg.VKAddress, "discovery-announcement", refreshInterval)
		log.Printf("[discovery] announcement complete reason=%s nodes=%d endpoint=%s expiresAt=%d nextRefresh=%s",
			reason, succeeded, currentMultiaddr, record.ExpiresAt, refreshInterval)
	}

	retryPending := func() {
		if pendingRecord == nil || len(pendingURLs) == 0 {
			announceFresh("retry")
			return
		}
		succeeded, failed := announceDiscoveryURLs(ctx, *pendingRecord, pendingURLs)
		if len(failed) > 0 {
			pendingURLs = failed
			retryDelay := scheduleRetry()
			log.Printf("[discovery] retry partial nodes=%d/%d remaining=%d retryIn=%s",
				succeeded, succeeded+len(failed), len(failed), retryDelay)
			return
		}
		log.Printf("[discovery] retry complete nodes=%d endpoint=%s", succeeded, currentMultiaddr)
		pendingRecord = nil
		pendingURLs = nil
		resetRetry()
		nextRefresh = nextHeartbeatSlot(time.Now(), cfg.ChainID, cfg.VKAddress, "discovery-announcement", refreshInterval)
	}

	announceFresh("startup")
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			candidate := strings.TrimSpace(multiaddrSource())
			if candidate != "" && candidate != currentMultiaddr {
				currentMultiaddr = candidate
				pendingRecord = nil
				pendingURLs = nil
				resetRetry()
				announceFresh("endpoint-change")
				continue
			}
			now := time.Now()
			if !nextRetry.IsZero() && !now.Before(nextRetry) {
				retryPending()
				continue
			}
			if !nextRefresh.IsZero() && !now.Before(nextRefresh) {
				announceFresh("renewal")
			}
		}
	}
}

// waitForMultiaddr polls source until it is non-empty; empty means ctx ended.
func waitForMultiaddr(ctx context.Context, source func() string, every time.Duration) string {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		if addr := strings.TrimSpace(source()); addr != "" {
			return addr
		}
		select {
		case <-ctx.Done():
			return ""
		case <-ticker.C:
		}
	}
}

func parseDiscoveryURLs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]bool{}
	var urls []string
	for _, part := range strings.Split(raw, ",") {
		url := strings.TrimSpace(part)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		urls = append(urls, url)
	}
	return urls
}
