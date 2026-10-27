package main

// Automatic public address: --advertise-ip auto.
//
// The address a keeper publishes (in its signed discovery record and, as a hash,
// on chain) must be one the internet can really reach it on, and no single party
// -- discovery included -- is trusted to say what that is. So the keeper:
//
//  1. Collects votes for its internet address from independent sources: its own
//     network card (only when that holds a public address), its home router
//     (UPnP / NAT-PMP, which also opens the port), several "what is my IP"
//     services run by different companies, and the keepers it asks in step 2.
//     An address wins only with at least two votes and more than half of all.
//  2. Proves it. Independent keepers, picked at random from discovery and checked
//     against the chain, call it back at that address (reach_protocol.go). With
//     three or more, a majority must succeed; with one or two, all must. Only in
//     a network with no independent keeper yet does it call itself.
//  3. Publishes only a proven address. Until then it publishes nothing.
//
// It checks again every few minutes. A light check (no helpers) only looks for a
// new address; a change, or the hourly timer, runs the full proof. A new address
// is published only after it is proven, at most once per
// PublicAddrMinChangeSeconds, because each one is an on-chain update. An address
// that is no longer the keeper's, or that fails its proof twice, is withdrawn:
// the keeper stops renewing its discovery record instead of pointing data owners
// at a dead address.
//
// A wrong address can never let someone else pose as this keeper -- every
// connection checks the keeper's key -- it can only make the keeper unreachable.
// That is what this file prevents.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	natpkg "github.com/libp2p/go-libp2p/p2p/net/nat"
)

const (
	// With fewer independent helpers than this, every one must succeed.
	publicAddrMajorityHelpers = 3
	// A failed full proof of the published address is retried once before the
	// address is withdrawn.
	publicAddrWithdrawAfterFailures = 2
	publicAddrMapperRetry           = 30 * time.Minute
	publicAddrEventDebounce         = 30 * time.Second
)

var nonPublicIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var carrierNATPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isPublicIPv4 reports whether the internet at large can route to ip.
func isPublicIPv4(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return false
	}
	for _, prefix := range nonPublicIPv4Prefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func isAutoAdvertise(cfg ServerConfig) bool {
	return strings.EqualFold(strings.TrimSpace(cfg.AdvertiseIP), "auto")
}

type addrVote struct {
	Source string
	IP     netip.Addr
}

// decidePublicIP picks the address with the most votes. It needs at least two
// votes and more than half of all votes, and a tie decides nothing.
func decidePublicIP(votes []addrVote) (netip.Addr, string) {
	if len(votes) == 0 {
		return netip.Addr{}, "no source answered"
	}
	counts := map[netip.Addr]int{}
	for _, v := range votes {
		counts[v.IP]++
	}
	var best netip.Addr
	bestCount, tie := 0, false
	for ip, n := range counts {
		switch {
		case n > bestCount:
			best, bestCount, tie = ip, n, false
		case n == bestCount:
			tie = true
		}
	}
	if tie {
		return netip.Addr{}, fmt.Sprintf("sources disagree: %s", formatVotes(votes))
	}
	if bestCount < 2 {
		return netip.Addr{}, fmt.Sprintf("only one source answered: %s", formatVotes(votes))
	}
	if bestCount*2 <= len(votes) {
		return netip.Addr{}, fmt.Sprintf("no majority: %s", formatVotes(votes))
	}
	return best, ""
}

func formatVotes(votes []addrVote) string {
	parts := make([]string, 0, len(votes))
	for _, v := range votes {
		parts = append(parts, v.Source+"="+v.IP.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// echoHTTPClient talks to "what is my IP" services directly over IPv4. A proxy
// would answer with its own address, so none is used even if one is configured.
func echoHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp4", addr)
			},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

func fetchEchoIP(ctx context.Context, client *http.Client, rawURL string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, errors.New("answer is not an address")
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return netip.Addr{}, errors.New("answer is not an IPv4 address")
	}
	return ip, nil
}

// fetchEchoVotes asks every service at once; each host votes at most once.
func fetchEchoVotes(ctx context.Context, urls []string, allowPrivate bool) ([]addrVote, []string) {
	client := echoHTTPClient()
	type answer struct {
		source string
		ip     netip.Addr
		err    error
	}
	seen := map[string]bool{}
	answers := make(chan answer, len(urls))
	asked := 0
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		parsed, err := url.Parse(raw)
		if raw == "" || err != nil || parsed.Host == "" || seen[parsed.Host] {
			continue
		}
		seen[parsed.Host] = true
		asked++
		go func(rawURL, source string) {
			ip, err := fetchEchoIP(ctx, client, rawURL)
			answers <- answer{source: source, ip: ip, err: err}
		}(raw, "echo:"+parsed.Host)
	}
	var votes []addrVote
	var problems []string
	for i := 0; i < asked; i++ {
		a := <-answers
		switch {
		case a.err != nil:
			problems = append(problems, fmt.Sprintf("%s did not answer: %s", a.source, shortReachError(a.err)))
		case !allowPrivate && !isPublicIPv4(a.ip):
			problems = append(problems, fmt.Sprintf("%s answered %s, which is not a public address", a.source, a.ip))
		default:
			votes = append(votes, addrVote{Source: a.source, IP: a.ip})
		}
	}
	return votes, problems
}

// localPublicIPv4s lists the public IPv4 addresses on this machine's own
// network cards (a server with a public address has one; a home machine has none).
func localPublicIPv4s() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if isPublicIPv4(ip) {
			out = append(out, ip)
		}
	}
	return out
}

// portMapper is a home router that opens a port on request (UPnP / NAT-PMP).
// libp2p's nat.NAT implements it and keeps the mapping renewed.
type portMapper interface {
	AddMapping(ctx context.Context, protocol string, port int) error
	GetMapping(protocol string, port int) (netip.AddrPort, bool)
	Close() error
}

func discoverPortMapper(ctx context.Context) (portMapper, error) {
	n, err := natpkg.DiscoverNAT(ctx)
	if err != nil {
		return nil, err
	}
	return n, nil
}

// publicAddrCheck is the last check, as written to public_address.json.
type publicAddrCheck struct {
	At            int64    `json:"at"`
	Kind          string   `json:"kind"`
	Why           string   `json:"why"`
	Votes         []string `json:"votes"`
	Decided       string   `json:"decided,omitempty"`
	Port          int      `json:"port,omitempty"`
	HelpersAsked  int      `json:"helpersAsked"`
	Confirmations int      `json:"confirmations"`
	Proven        bool     `json:"proven"`
	Method        string   `json:"method,omitempty"`
	Problems      []string `json:"problems,omitempty"`
}

type publicAddrRound struct {
	Full          bool
	Why           string
	Votes         []addrVote
	Decided       netip.Addr
	Port          int
	HelpersAsked  int
	Confirmations int
	Proven        bool
	Method        string
	Problems      []string
}

type publicAddrDetector struct {
	cfg        ServerConfig
	host       host.Host
	listenPort int
	book       *reachNonceBook

	// Sources and proofs; tests replace them.
	now            func() time.Time
	echoVotes      func(ctx context.Context) ([]addrVote, []string)
	interfaceIPs   func() []netip.Addr
	findHelpers    func(ctx context.Context, exclude map[netip.Addr]bool, want int) ([]reachHelper, error)
	askHelper      func(ctx context.Context, helper reachHelper, port int) (reachResponse, bool, error)
	selfCheck      func(ctx context.Context, addr netip.AddrPort) error
	discoverMapper func(ctx context.Context) (portMapper, error)

	mu              sync.Mutex
	published       netip.AddrPort
	publishedAt     time.Time
	lastAnnounced   netip.AddrPort
	lastChangeAt    time.Time
	fullFailures    int
	nextFull        time.Time
	lastFullResult  netip.AddrPort // decided address and port of the last full round
	mapper          portMapper
	mapperTriedAt   time.Time
	mapperLoggedErr bool
	last            publicAddrCheck
}

func newPublicAddrDetector(cfg ServerConfig, h host.Host, listenPort int) *publicAddrDetector {
	d := &publicAddrDetector{
		cfg:        cfg,
		host:       h,
		listenPort: listenPort,
		book:       newReachNonceBook(),
		now:        time.Now,
	}
	d.echoVotes = func(ctx context.Context) ([]addrVote, []string) {
		return fetchEchoVotes(ctx, d.cfg.PublicAddrEchoURLs, d.cfg.PublicAddrAllowPrivate)
	}
	d.interfaceIPs = localPublicIPv4s
	d.findHelpers = func(ctx context.Context, exclude map[netip.Addr]bool, want int) ([]reachHelper, error) {
		return findReachHelpers(ctx, d.cfg, exclude, want)
	}
	d.askHelper = func(ctx context.Context, helper reachHelper, port int) (reachResponse, bool, error) {
		return askReachHelper(ctx, d.book, helper, d.host.ID(), port)
	}
	d.selfCheck = func(ctx context.Context, addr netip.AddrPort) error {
		return selfReachCheck(ctx, d.book, addr, d.host.ID())
	}
	d.discoverMapper = discoverPortMapper
	return d
}

func (d *publicAddrDetector) seconds(v, def int64) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Second
}

func (d *publicAddrDetector) checkInterval() time.Duration {
	return d.seconds(d.cfg.PublicAddrCheckSeconds, DefaultPublicAddrCheckSeconds)
}

func (d *publicAddrDetector) fullInterval() time.Duration {
	return d.seconds(d.cfg.PublicAddrFullCheckSeconds, DefaultPublicAddrFullCheckSeconds)
}

func (d *publicAddrDetector) minChange() time.Duration {
	return d.seconds(d.cfg.PublicAddrMinChangeSeconds, DefaultPublicAddrMinChangeSeconds)
}

func (d *publicAddrDetector) usable(ip netip.Addr) bool {
	if d.cfg.PublicAddrAllowPrivate {
		return ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return isPublicIPv4(ip)
}

// Published is the proven address, or the zero value while there is none.
func (d *publicAddrDetector) Published() netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.published
}

// Multiaddr is what the keeper advertises: empty until an address is proven.
func (d *publicAddrDetector) Multiaddr() string {
	p := d.Published()
	if !p.IsValid() {
		return ""
	}
	return fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", p.Addr(), p.Port(), d.host.ID())
}

func (d *publicAddrDetector) currentMapper() portMapper {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.mapper
}

// ensureMapper looks for a home router that can open the port, at start and
// then every half hour while there is none.
func (d *publicAddrDetector) ensureMapper(ctx context.Context) {
	if !d.cfg.PublicAddrPortMapping || d.discoverMapper == nil {
		return
	}
	d.mu.Lock()
	if d.mapper != nil || (!d.mapperTriedAt.IsZero() && d.now().Sub(d.mapperTriedAt) < publicAddrMapperRetry) {
		d.mu.Unlock()
		return
	}
	d.mapperTriedAt = d.now()
	logErr := !d.mapperLoggedErr
	d.mu.Unlock()

	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	m, err := d.discoverMapper(dctx)
	if err != nil {
		if logErr {
			log.Printf("[public-addr] no router that opens ports (UPnP / NAT-PMP): %v", err)
			d.mu.Lock()
			d.mapperLoggedErr = true
			d.mu.Unlock()
		}
		return
	}
	if err := m.AddMapping(dctx, "tcp", d.listenPort); err != nil {
		log.Printf("[public-addr] the router refused to open TCP port %d: %v", d.listenPort, err)
		_ = m.Close()
		return
	}
	d.mu.Lock()
	d.mapper = m
	d.mu.Unlock()
	log.Printf("[public-addr] router found (UPnP / NAT-PMP); asked it to open TCP port %d", d.listenPort)
}

// collectBaseVotes gathers every vote that needs no helper, and the port the
// internet should use (the router's outside port when it opened one).
func (d *publicAddrDetector) collectBaseVotes(ctx context.Context) ([]addrVote, int, []string) {
	port := d.listenPort
	var votes []addrVote
	var problems []string

	switch ips := d.interfaceIPs(); {
	case len(ips) == 1:
		votes = append(votes, addrVote{Source: "this-machine", IP: ips[0]})
	case len(ips) > 1:
		problems = append(problems, fmt.Sprintf("this machine has %d public addresses, so it does not vote", len(ips)))
	}

	if m := d.currentMapper(); m != nil {
		if ext, ok := m.GetMapping("tcp", d.listenPort); ok {
			ip := ext.Addr().Unmap()
			switch {
			case d.usable(ip) && ext.Port() != 0:
				votes = append(votes, addrVote{Source: "router", IP: ip})
				port = int(ext.Port())
			case carrierNATPrefix.Contains(ip):
				problems = append(problems, fmt.Sprintf(
					"the router's own internet address %s is shared by the internet provider (carrier-grade NAT): nobody outside can call this keeper", ip))
			default:
				problems = append(problems, fmt.Sprintf(
					"the router's own internet address %s is not public: another router sits in front of it", ip))
			}
		} else {
			problems = append(problems, fmt.Sprintf("the router has not opened TCP port %d", d.listenPort))
		}
	}

	if d.echoVotes != nil {
		echo, echoProblems := d.echoVotes(ctx)
		votes = append(votes, echo...)
		problems = append(problems, echoProblems...)
	}
	return votes, port, problems
}

func (d *publicAddrDetector) lightRound(ctx context.Context, why string) publicAddrRound {
	votes, port, problems := d.collectBaseVotes(ctx)
	round := publicAddrRound{Why: why, Votes: votes, Port: port, Problems: problems}
	if decided, reason := decidePublicIP(votes); decided.IsValid() {
		round.Decided = decided
	} else {
		round.Problems = append(round.Problems, reason)
	}
	return round
}

type helperAnswer struct {
	helper reachHelper
	resp   reachResponse
	ip     netip.Addr
	seen   bool
}

// askHelpers asks independent keepers to call back. candidates is how many
// were found; lookupErr means they could not be looked up at all.
func (d *publicAddrDetector) askHelpers(ctx context.Context, exclude map[netip.Addr]bool, port int) (answers []helperAnswer, candidates int, problems []string, lookupErr error) {
	want := d.cfg.PublicAddrHelpers
	if want <= 0 || d.findHelpers == nil {
		return nil, 0, nil, nil
	}
	found, err := d.findHelpers(ctx, exclude, want)
	if err != nil {
		return nil, 0, nil, err
	}
	type result struct {
		helper reachHelper
		resp   reachResponse
		seen   bool
		err    error
	}
	next := 0
	for len(answers) < want && next < len(found) && ctx.Err() == nil {
		batch := found[next:min(len(found), next+want-len(answers))]
		next += len(batch)
		results := make(chan result, len(batch))
		for _, h := range batch {
			go func(h reachHelper) {
				resp, seen, err := d.askHelper(ctx, h, port)
				results <- result{helper: h, resp: resp, seen: seen, err: err}
			}(h)
		}
		for range batch {
			r := <-results
			if r.err != nil {
				problems = append(problems, fmt.Sprintf("helper %s did not answer: %s", r.helper, shortReachError(r.err)))
				continue
			}
			if r.resp.Reason == reachReasonBusy {
				continue
			}
			ip, err := netip.ParseAddr(r.resp.ObservedIP)
			if err != nil || !d.usable(ip.Unmap()) {
				problems = append(problems, fmt.Sprintf("helper %s saw no usable address: %s", r.helper, r.resp.Reason))
				continue
			}
			answers = append(answers, helperAnswer{helper: r.helper, resp: r.resp, ip: ip.Unmap(), seen: r.seen})
		}
	}
	return answers, len(found), problems, nil
}

func (d *publicAddrDetector) fullRound(ctx context.Context, why string) publicAddrRound {
	votes, port, problems := d.collectBaseVotes(ctx)
	exclude := map[netip.Addr]bool{}
	for _, v := range votes {
		exclude[v.IP] = true
	}
	for _, ip := range d.interfaceIPs() {
		exclude[ip] = true
	}
	if pub := d.Published(); pub.IsValid() {
		exclude[pub.Addr()] = true
	}
	answers, candidates, helperProblems, lookupErr := d.askHelpers(ctx, exclude, port)
	problems = append(problems, helperProblems...)
	for _, a := range answers {
		votes = append(votes, addrVote{Source: "helper:" + a.helper.VKAddress, IP: a.ip})
	}
	round := publicAddrRound{Full: true, Why: why, Votes: votes, Port: port, HelpersAsked: len(answers), Problems: problems}
	decided, reason := decidePublicIP(votes)
	if !decided.IsValid() {
		round.Problems = append(round.Problems, reason)
		return round
	}
	round.Decided = decided

	for _, a := range answers {
		switch {
		case a.resp.Reached && a.seen && a.ip == decided && a.resp.Port == port:
			round.Confirmations++
		case a.resp.Reached && !a.seen:
			round.Problems = append(round.Problems, fmt.Sprintf("helper %s said it called back, but its call never arrived", a.helper))
		case a.ip != decided:
			round.Problems = append(round.Problems, fmt.Sprintf("helper %s saw this keeper as %s", a.helper, a.ip))
		default:
			round.Problems = append(round.Problems, fmt.Sprintf("helper %s could not call back: %s", a.helper, a.resp.Reason))
		}
	}
	target := netip.AddrPortFrom(decided, uint16(port))
	switch n := len(answers); {
	case n >= publicAddrMajorityHelpers:
		round.Proven = round.Confirmations*2 > n
		round.Method = fmt.Sprintf("%d of %d independent keepers called it back", round.Confirmations, n)
	case n > 0:
		round.Proven = round.Confirmations == n
		round.Method = fmt.Sprintf("%d of %d independent keepers called it back (all must, with fewer than %d)",
			round.Confirmations, n, publicAddrMajorityHelpers)
	case lookupErr != nil:
		// "Could not look" is not "there are none": no weaker self check.
		round.Problems = append(round.Problems, "could not look up independent keepers, trying again soon: "+shortReachError(lookupErr))
		return round
	case candidates > 0:
		round.Problems = append(round.Problems, fmt.Sprintf("none of %d independent keepers answered; trying again soon", candidates))
		return round
	default:
		round.Method = "it called itself (no independent keeper exists yet)"
		if d.selfCheck == nil {
			round.Problems = append(round.Problems, "no way to check the address")
		} else if err := d.selfCheck(ctx, target); err != nil {
			round.Problems = append(round.Problems, "it could not call itself: "+shortReachError(err))
		} else {
			round.Proven = true
		}
	}
	if !round.Proven {
		round.Problems = append(round.Problems, d.unreachableHint(decided, port))
	}
	return round
}

// unreachableHint says, in operator terms, what usually blocks the address.
func (d *publicAddrDetector) unreachableHint(decided netip.Addr, port int) string {
	for _, ip := range d.interfaceIPs() {
		if ip == decided {
			return fmt.Sprintf("this machine owns %s: check that its firewall lets TCP port %d in", decided, port)
		}
	}
	if m := d.currentMapper(); m != nil {
		if ext, ok := m.GetMapping("tcp", d.listenPort); ok && ext.Addr().Unmap() == decided {
			return fmt.Sprintf("the router opened %s:%d but calls still do not arrive", decided, port)
		}
	}
	return fmt.Sprintf("this machine is behind a router: turn on UPnP / NAT-PMP there, or forward TCP port %d to this machine; "+
		"if the provider shares one address among many customers (carrier-grade NAT), outside calls cannot arrive at all", port)
}

func (r publicAddrRound) check(at time.Time) publicAddrCheck {
	c := publicAddrCheck{
		At:            at.Unix(),
		Kind:          "light",
		Why:           r.Why,
		Votes:         strings.Split(formatVotes(r.Votes), ", "),
		Port:          r.Port,
		HelpersAsked:  r.HelpersAsked,
		Confirmations: r.Confirmations,
		Proven:        r.Proven,
		Method:        r.Method,
		Problems:      r.Problems,
	}
	if len(r.Votes) == 0 {
		c.Votes = nil
	}
	if r.Full {
		c.Kind = "full"
	}
	if r.Decided.IsValid() {
		c.Decided = r.Decided.String()
	}
	return c
}

// apply turns a round into the published address. For a light round it only
// reports whether a full round is needed.
func (d *publicAddrDetector) apply(r publicAddrRound) (needFull bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.last = r.check(now)
	defer d.writeStatusLocked()

	if !r.Full {
		if !r.Decided.IsValid() {
			return false
		}
		seen := netip.AddrPortFrom(r.Decided, uint16(r.Port))
		if d.published.IsValid() {
			return seen != d.published
		}
		// Nothing published: re-prove at once only if something changed since
		// the last full round; otherwise wait for the backed-off schedule.
		return seen != d.lastFullResult
	}

	if r.Decided.IsValid() {
		d.lastFullResult = netip.AddrPortFrom(r.Decided, uint16(r.Port))
	}

	if r.Proven {
		d.fullFailures = 0
		candidate := netip.AddrPortFrom(r.Decided, uint16(r.Port))
		switch {
		case d.published == candidate:
			d.nextFull = now.Add(d.fullInterval())
		case !d.lastAnnounced.IsValid() || d.lastAnnounced == candidate || now.Sub(d.lastChangeAt) >= d.minChange():
			d.publishLocked(candidate, now, r.Method)
		default:
			wait := d.lastChangeAt.Add(d.minChange())
			d.nextFull = wait
			log.Printf("[public-addr] new address %s is proven; publishing it at %s (at most one change per %s)",
				candidate, wait.Format(time.RFC3339), d.minChange())
		}
		return false
	}

	d.fullFailures++
	d.nextFull = now.Add(d.checkInterval())
	problems := strings.Join(r.Problems, "; ")
	if !d.published.IsValid() {
		// A keeper that cannot be reached (carrier-grade NAT, closed port) would
		// otherwise ask helpers every few minutes forever: back off to hourly.
		wait := d.checkInterval()
		for i := 1; i < d.fullFailures && wait < d.fullInterval(); i++ {
			wait *= 2
		}
		if wait > d.fullInterval() {
			wait = d.fullInterval()
		}
		d.nextFull = now.Add(wait)
		log.Printf("[public-addr] no proven address yet (next full check in %s): %s", wait, problems)
		return false
	}
	switch {
	case r.Decided.IsValid() && r.Decided != d.published.Addr():
		d.withdrawLocked(fmt.Sprintf("the internet address is now %s, not %s, and it is not proven yet: %s",
			r.Decided, d.published.Addr(), problems))
	case d.fullFailures >= publicAddrWithdrawAfterFailures:
		d.withdrawLocked(fmt.Sprintf("%s could not be proven %d times in a row: %s", d.published, d.fullFailures, problems))
	default:
		log.Printf("[public-addr] %s could not be proven; trying again in %s: %s", d.published, d.checkInterval(), problems)
	}
	return false
}

func (d *publicAddrDetector) publishLocked(addr netip.AddrPort, now time.Time, method string) {
	if d.lastAnnounced != addr {
		d.lastChangeAt = now
	}
	old := d.published
	d.published = addr
	d.publishedAt = now
	d.lastAnnounced = addr
	d.nextFull = now.Add(d.fullInterval())
	if old.IsValid() {
		log.Printf("[public-addr] address changed %s -> %s (proof: %s)", old, addr, method)
	} else {
		log.Printf("[public-addr] address %s proven and published (proof: %s)", addr, method)
	}
}

func (d *publicAddrDetector) withdrawLocked(reason string) {
	log.Printf("[public-addr] address %s withdrawn: %s", d.published, reason)
	d.published = netip.AddrPort{}
}

func (d *publicAddrDetector) statusPath() string {
	if d.cfg.Storage == "" {
		return ""
	}
	return filepath.Join(d.cfg.Storage, "public_address.json")
}

func (d *publicAddrDetector) writeStatusLocked() {
	path := d.statusPath()
	if path == "" {
		return
	}
	status := map[string]any{
		"mode":      "auto",
		"published": "",
		"lastCheck": d.last,
	}
	if d.published.IsValid() {
		status["published"] = d.published.String()
		status["publishedAt"] = d.publishedAt.Unix()
	}
	raw, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// due reports whether the next tick must run a full round.
func (d *publicAddrDetector) due() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nextFull.IsZero() || !d.now().Before(d.nextFull)
}

// tick runs one regular check.
func (d *publicAddrDetector) tick(ctx context.Context, why string) {
	d.ensureMapper(ctx)
	if d.due() {
		d.apply(d.fullRound(ctx, why))
		return
	}
	if d.apply(d.lightRound(ctx, why)) {
		d.apply(d.fullRound(ctx, why+": address changed"))
	}
}

func (d *publicAddrDetector) close() {
	d.mu.Lock()
	m := d.mapper
	d.mapper = nil
	d.mu.Unlock()
	if m != nil {
		_ = m.Close()
	}
}

// interfaceSignature lists every IPv4 address on this machine's network cards,
// private ones included: a new lease or a new network changes it.
func interfaceSignature() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var parts []string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
			parts = append(parts, ipnet.IP.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// run checks at start, then every PublicAddrCheckSeconds, and soon after this
// machine joins another network.
func (d *publicAddrDetector) run(ctx context.Context) {
	defer d.close()
	var changes <-chan any
	if d.host != nil {
		if sub, err := d.host.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated)); err == nil {
			defer sub.Close()
			changes = sub.Out()
		}
	}
	d.tick(ctx, "startup")
	ticker := time.NewTicker(d.checkInterval())
	defer ticker.Stop()
	lastEvent := time.Time{}
	lastInterfaces := interfaceSignature()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.tick(ctx, "scheduled")
		case <-changes:
			// libp2p also reports addresses other peers observed; only a change
			// of this machine's own network counts.
			current := interfaceSignature()
			if current == lastInterfaces || time.Since(lastEvent) < publicAddrEventDebounce {
				continue
			}
			lastInterfaces, lastEvent = current, time.Now()
			d.tick(ctx, "network changed")
		}
	}
}
