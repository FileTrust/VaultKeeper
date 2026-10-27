package main

// Choosing the keepers that check this keeper's public address (see
// reach_protocol.go). They come from discovery, which is not trusted: every
// record must be signed by its keeper and match the endpoint hash that keeper
// put on chain, exactly as a data owner checks it before storing. Discovery can
// withhold keepers, never invent them. Helpers are picked at random, one per
// address, and never from this keeper's own address, so keepers sharing a
// machine with it cannot vouch for it.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

type reachHelper struct {
	VKAddress string
	PeerID    peer.ID
	Addr      ma.Multiaddr // /ip4/<ip>/tcp/<port>, without /p2p
	IP        netip.Addr
}

// fetchDiscoveryRecords lists every record the discovery nodes hold. It fails
// only when no node answered. Connections are not reused: after this machine's
// address changes, a kept-alive connection from the old address hangs until it
// times out.
func fetchDiscoveryRecords(ctx context.Context, urls []string) ([]DiscoveryRecord, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	var out []DiscoveryRecord
	answered := 0
	var lastErr error
	for _, raw := range urls {
		url := strings.TrimRight(strings.TrimSpace(raw), "/")
		if url == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/v1/records", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[public-addr] discovery record list failed url=%s err=%v", url, err)
			lastErr = err
			continue
		}
		var body struct {
			OK      bool              `json:"ok"`
			Records []DiscoveryRecord `json:"records"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body)
		resp.Body.Close()
		if err != nil || !body.OK {
			lastErr = fmt.Errorf("%s: bad answer", url)
			continue
		}
		answered++
		out = append(out, body.Records...)
	}
	if answered == 0 && lastErr != nil {
		return nil, fmt.Errorf("no discovery node answered: %w", lastErr)
	}
	return out, nil
}

// verifyDiscoveryRecordSignature checks the keeper's own signature over the
// record, the same message a data owner checks.
func verifyDiscoveryRecordSignature(record DiscoveryRecord) error {
	sig, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(record.Signature), "0x"))
	if err != nil || len(sig) != 65 {
		return errors.New("invalid signature")
	}
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return errors.New("bad signature recovery id")
	}
	pub, err := ethcrypto.SigToPub(accounts.TextHash([]byte(discoveryCanonicalMessage(record))), sig)
	if err != nil {
		return err
	}
	if !strings.EqualFold(ethcrypto.PubkeyToAddress(*pub).Hex(), record.VKAddress) {
		return errors.New("signed by another key")
	}
	return nil
}

// reachHelperFromRecord does every check that needs no chain call.
func reachHelperFromRecord(cfg ServerConfig, record DiscoveryRecord, now time.Time) (reachHelper, error) {
	if !common.IsHexAddress(record.VKAddress) {
		return reachHelper{}, errors.New("bad keeper address")
	}
	if strings.EqualFold(record.VKAddress, cfg.VKAddress) {
		return reachHelper{}, errors.New("this keeper")
	}
	if record.ExpiresAt <= now.Unix() {
		return reachHelper{}, errors.New("expired")
	}
	pid, err := peer.Decode(record.PeerID)
	if err != nil {
		return reachHelper{}, errors.New("bad peer id")
	}
	full, err := ma.NewMultiaddr(record.Multiaddr)
	if err != nil {
		return reachHelper{}, errors.New("bad multiaddr")
	}
	ipText, err := full.ValueForProtocol(ma.P_IP4)
	if err != nil {
		return reachHelper{}, errors.New("not an IPv4 address")
	}
	portText, err := full.ValueForProtocol(ma.P_TCP)
	if err != nil {
		return reachHelper{}, errors.New("not a TCP address")
	}
	p2p, err := full.ValueForProtocol(ma.P_P2P)
	if err != nil || p2p != record.PeerID {
		return reachHelper{}, errors.New("multiaddr does not name the record's peer id")
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return reachHelper{}, errors.New("bad IPv4 address")
	}
	addr, err := ma.NewMultiaddr("/ip4/" + ipText + "/tcp/" + portText)
	if err != nil {
		return reachHelper{}, errors.New("bad transport address")
	}
	if record.EndpointHash != "" && !strings.EqualFold(record.EndpointHash, discoveryEndpointHash(record)) {
		return reachHelper{}, errors.New("endpoint hash does not match the record")
	}
	if err := verifyDiscoveryRecordSignature(record); err != nil {
		return reachHelper{}, err
	}
	return reachHelper{VKAddress: record.VKAddress, PeerID: pid, Addr: addr, IP: ip}, nil
}

func loadVKRegistryABI(path string) (abi.ABI, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return abi.ABI{}, err
	}
	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	abiJSON := raw
	if json.Unmarshal(raw, &artifact) == nil && len(artifact.ABI) > 2 {
		abiJSON = artifact.ABI
	}
	return abi.JSON(strings.NewReader(string(abiJSON)))
}

// findReachHelpers returns up to 3*want verified helpers in random order, so
// helpers that do not answer can be replaced. exclude holds this keeper's own
// addresses. An error means the helpers could not be looked up -- which is not
// the same as "there are none", and must not lead to the weaker self check.
func findReachHelpers(ctx context.Context, cfg ServerConfig, exclude map[netip.Addr]bool, want int) ([]reachHelper, error) {
	if want <= 0 || len(cfg.DiscoveryURLs) == 0 {
		return nil, nil
	}
	if cfg.VKRegistryContract == "" || cfg.VKRegistryABIPath == "" || cfg.RPCURL == "" {
		return nil, errors.New("the registry contract, its ABI and an RPC URL are needed to check helpers")
	}
	parsedABI, err := loadVKRegistryABI(cfg.VKRegistryABIPath)
	if err != nil {
		return nil, fmt.Errorf("registry ABI: %w", err)
	}
	registry := common.HexToAddress(cfg.VKRegistryContract)

	all, err := fetchDiscoveryRecords(ctx, cfg.DiscoveryURLs)
	if err != nil {
		return nil, err
	}
	newest := map[string]DiscoveryRecord{}
	for _, record := range all {
		key := strings.ToLower(record.VKAddress)
		if old, ok := newest[key]; !ok || record.Seq > old.Seq {
			newest[key] = record
		}
	}
	records := make([]DiscoveryRecord, 0, len(newest))
	for _, record := range newest {
		records = append(records, record)
	}
	mrand.Shuffle(len(records), func(i, j int) { records[i], records[j] = records[j], records[i] })

	limit := 3 * want
	chainChecks, chainErrors := 0, 0
	var chainErr error
	used := map[netip.Addr]bool{}
	var out []reachHelper
	now := time.Now()
	for _, record := range records {
		if len(out) >= limit || chainChecks >= 6*want || ctx.Err() != nil {
			break
		}
		helper, err := reachHelperFromRecord(cfg, record, now)
		if err != nil {
			continue
		}
		if exclude[helper.IP] || used[helper.IP] {
			continue
		}
		if !cfg.PublicAddrAllowPrivate && !isPublicIPv4(helper.IP) {
			continue
		}
		chainChecks++
		onChain, supported, err := readRegistryEndpoint(cfg, parsedABI, registry, common.HexToAddress(record.VKAddress))
		if err != nil {
			chainErrors++
			chainErr = err
			continue
		}
		if !supported {
			continue
		}
		if onChain.Seq == 0 || onChain.Seq != uint64(record.Seq) ||
			!strings.EqualFold(onChain.EndpointHash, discoveryEndpointHash(record)) {
			continue
		}
		used[helper.IP] = true
		out = append(out, helper)
	}
	if len(out) == 0 && chainErrors > 0 {
		return nil, fmt.Errorf("could not check keepers on chain: %w", chainErr)
	}
	if len(out) == 0 && len(records) > 0 {
		log.Printf("[public-addr] none of %d discovery records is a usable independent helper", len(records))
	}
	return out, nil
}

func (h reachHelper) String() string {
	return fmt.Sprintf("%s@%s", h.VKAddress, h.IP)
}
