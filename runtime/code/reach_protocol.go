package main

// Call-back proof for the automatic public address (see public_address.go).
//
// A keeper cannot see its own internet address from the inside, and no single
// outside party is trusted to tell it. Two small protocols let other keepers
// check it instead:
//
//	ReachRequestProtocol  the asking keeper opens it to a helper keeper and sends
//	                      a port, its own peer id and a fresh random nonce.
//	ReachBackProtocol     the helper dials back, from a brand-new host, to the
//	                      address the request CAME FROM (never one the asker
//	                      names) and hands the nonce over that new connection.
//
// The libp2p handshake only completes if the far end holds the asking keeper's
// key, so a completed call means "this address reaches that keeper". The nonce
// arriving at the asker proves the helper really made the call: a helper that
// only says "reached" is not believed. Dialing only the observed address means
// nobody can point a helper at a third party.
//
// The asker sends its request from a separate short-lived host, never from its
// listening host. libp2p reuses the listening port for outgoing connections, and
// on many home routers such a connection briefly opens that port from outside:
// a call-back would then succeed now and fail for every data owner later.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

const (
	ReachRequestProtocol protocol.ID = "/filetrust/vk/reach/1.0.0"
	ReachBackProtocol    protocol.ID = "/filetrust/vk/reach-back/1.0.0"

	reachDialTimeout    = 10 * time.Second
	reachRequestTimeout = 45 * time.Second
	// Keepers on one machine share an address, so the per-address budget is
	// generous; the global in-flight cap bounds the work one helper does.
	reachPerIPPerMinute = 20
	reachMaxInflight    = 8
	reachReasonBusy     = "busy"
)

type reachRequest struct {
	Target string `json:"target"` // peer id the helper must reach
	Port   int    `json:"port"`
	Nonce  string `json:"nonce"`
}

type reachResponse struct {
	ObservedIP string `json:"observedIp"`
	Port       int    `json:"port"`
	Reached    bool   `json:"reached"`
	Reason     string `json:"reason,omitempty"`
}

func newReachNonce() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func validReachNonce(nonce string) bool {
	if len(nonce) != 64 {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil
}

// observedIPv4 is the IPv4 address a connection came from, as this side sees it.
func observedIPv4(c network.Conn) (netip.Addr, error) {
	remote := c.RemoteMultiaddr()
	if _, err := remote.ValueForProtocol(ma.P_CIRCUIT); err == nil {
		return netip.Addr{}, errors.New("relayed connection")
	}
	ip, err := manet.ToIP(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("bad address %s", ip)
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("not IPv4: %s", addr)
	}
	return addr, nil
}

func writeJSONLine(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

func shortReachError(err error) string {
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return msg
}

// newEphemeralDialHost is a throw-away TCP-only host with a fresh identity and
// no listener, so every dial it makes is a new connection from a random port.
func newEphemeralDialHost() (host.Host, error) {
	return libp2p.New(
		libp2p.NoListenAddrs,
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.DisableRelay(),
		libp2p.DisableIdentifyAddressDiscovery(),
		libp2p.Ping(false),
	)
}

// dialBackOverTCP calls target at addr from a new host and hands over nonce.
// It returns true only when the keeper there accepted the nonce.
func dialBackOverTCP(ctx context.Context, addr netip.AddrPort, target peer.ID, nonce string) (bool, string) {
	h, err := newEphemeralDialHost()
	if err != nil {
		return false, "could not start a dialer: " + shortReachError(err)
	}
	defer h.Close()
	maddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", addr.Addr(), addr.Port()))
	if err != nil {
		return false, "bad address: " + shortReachError(err)
	}
	h.Peerstore().AddAddr(target, maddr, time.Minute)
	dctx, cancel := context.WithTimeout(ctx, reachDialTimeout)
	defer cancel()
	st, err := h.NewStream(dctx, target, ReachBackProtocol)
	if err != nil {
		return false, "could not connect to " + addr.String() + ": " + shortReachError(err)
	}
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(reachDialTimeout))
	if _, err := io.WriteString(st, nonce+"\n"); err != nil {
		return false, "could not send the proof: " + shortReachError(err)
	}
	reply, _ := bufio.NewReader(io.LimitReader(st, 16)).ReadString('\n')
	if strings.TrimSpace(reply) != "ok" {
		return false, "the keeper at " + addr.String() + " did not accept the proof"
	}
	return true, ""
}

// reachHelperService answers other keepers' call-back requests.
type reachHelperService struct {
	allowPrivate bool
	now          func() time.Time
	dialBack     func(ctx context.Context, addr netip.AddrPort, target peer.ID, nonce string) (bool, string)

	mu       sync.Mutex
	recent   map[netip.Addr][]time.Time
	inflight int
}

func newReachHelperService(allowPrivate bool) *reachHelperService {
	return &reachHelperService{
		allowPrivate: allowPrivate,
		now:          time.Now,
		dialBack:     dialBackOverTCP,
		recent:       map[netip.Addr][]time.Time{},
	}
}

func (s *reachHelperService) acquire(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	kept := s.recent[ip][:0]
	for _, at := range s.recent[ip] {
		if now.Sub(at) < time.Minute {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(s.recent, ip)
	} else {
		s.recent[ip] = kept
	}
	if len(kept) >= reachPerIPPerMinute || s.inflight >= reachMaxInflight {
		return false
	}
	s.recent[ip] = append(kept, now)
	s.inflight++
	return true
}

func (s *reachHelperService) release() {
	s.mu.Lock()
	s.inflight--
	s.mu.Unlock()
}

func (s *reachHelperService) handle(st network.Stream) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(reachRequestTimeout))
	var req reachRequest
	if err := json.NewDecoder(io.LimitReader(st, 1024)).Decode(&req); err != nil {
		_ = st.Reset()
		return
	}
	resp := reachResponse{Port: req.Port}
	ip, err := observedIPv4(st.Conn())
	if err != nil {
		resp.Reason = "no IPv4 address seen: " + shortReachError(err)
		_ = writeJSONLine(st, resp)
		return
	}
	resp.ObservedIP = ip.String()
	target, perr := peer.Decode(req.Target)
	switch {
	case perr != nil:
		resp.Reason = "invalid target peer id"
	case req.Port < 1 || req.Port > 65535:
		resp.Reason = "invalid port"
	case !validReachNonce(req.Nonce):
		resp.Reason = "invalid nonce"
	case !s.allowPrivate && !isPublicIPv4(ip):
		resp.Reason = "the request came from " + ip.String() + ", which is not a public internet address"
	case !s.acquire(ip):
		resp.Reason = reachReasonBusy
	default:
		ctx, cancel := context.WithTimeout(context.Background(), reachDialTimeout+5*time.Second)
		resp.Reached, resp.Reason = s.dialBack(ctx, netip.AddrPortFrom(ip, uint16(req.Port)), target, req.Nonce)
		cancel()
		s.release()
	}
	_ = writeJSONLine(st, resp)
}

// reachNonceBook is the asking side: it knows which nonces it is waiting for and
// answers ReachBackProtocol calls that bring one of them.
type reachNonceBook struct {
	mu      sync.Mutex
	waiting map[string]chan struct{}
}

func newReachNonceBook() *reachNonceBook {
	return &reachNonceBook{waiting: map[string]chan struct{}{}}
}

func (b *reachNonceBook) expect(nonce string) <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan struct{})
	b.waiting[nonce] = ch
	return ch
}

func (b *reachNonceBook) forget(nonce string) {
	b.mu.Lock()
	delete(b.waiting, nonce)
	b.mu.Unlock()
}

// deliver marks nonce as arrived. Only a nonce this keeper is waiting for counts,
// and each counts once.
func (b *reachNonceBook) deliver(nonce string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch, ok := b.waiting[nonce]
	if !ok {
		return false
	}
	delete(b.waiting, nonce)
	close(ch)
	return true
}

func (b *reachNonceBook) handle(st network.Stream) {
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(reachDialTimeout))
	line, _ := bufio.NewReader(io.LimitReader(st, 128)).ReadString('\n')
	if b.deliver(strings.TrimSpace(line)) {
		_, _ = io.WriteString(st, "ok\n")
		return
	}
	_, _ = io.WriteString(st, "no\n")
}

// askReachHelper asks one helper to call this keeper (target) back at port, from
// a fresh host. seen reports whether the helper's call really arrived.
func askReachHelper(ctx context.Context, book *reachNonceBook, helper reachHelper, target peer.ID, port int) (resp reachResponse, seen bool, err error) {
	nonce, err := newReachNonce()
	if err != nil {
		return reachResponse{}, false, err
	}
	arrived := book.expect(nonce)
	defer book.forget(nonce)

	dialer, err := newEphemeralDialHost()
	if err != nil {
		return reachResponse{}, false, err
	}
	defer dialer.Close()
	dialer.Peerstore().AddAddr(helper.PeerID, helper.Addr, time.Minute)
	sctx, cancel := context.WithTimeout(ctx, reachRequestTimeout)
	defer cancel()
	st, err := dialer.NewStream(sctx, helper.PeerID, ReachRequestProtocol)
	if err != nil {
		return reachResponse{}, false, err
	}
	defer st.Close()
	_ = st.SetDeadline(time.Now().Add(reachRequestTimeout))
	if err := writeJSONLine(st, reachRequest{Target: target.String(), Port: port, Nonce: nonce}); err != nil {
		return reachResponse{}, false, err
	}
	if err := json.NewDecoder(io.LimitReader(st, 4096)).Decode(&resp); err != nil {
		return reachResponse{}, false, err
	}
	select {
	case <-arrived:
		return resp, true, nil
	default:
	}
	if resp.Reached {
		// The helper waits for our "ok" before answering, so the nonce is normally
		// here already; allow a moment for scheduling.
		select {
		case <-arrived:
			return resp, true, nil
		case <-time.After(2 * time.Second):
		}
	}
	return resp, false, nil
}

// selfReachCheck dials this keeper's own candidate address from a fresh host.
// It proves the address leads to this keeper's key from here; it cannot see a
// firewall that only filters traffic from outside, which is why independent
// helpers are preferred whenever there are any.
func selfReachCheck(ctx context.Context, book *reachNonceBook, addr netip.AddrPort, self peer.ID) error {
	nonce, err := newReachNonce()
	if err != nil {
		return err
	}
	arrived := book.expect(nonce)
	defer book.forget(nonce)
	ok, reason := dialBackOverTCP(ctx, addr, self, nonce)
	if !ok {
		return errors.New(reason)
	}
	select {
	case <-arrived:
		return nil
	default:
		return errors.New("the call to " + addr.String() + " was answered without the proof")
	}
}
