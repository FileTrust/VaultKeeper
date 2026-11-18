package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// Public proof identifiers fit in a few hundred bytes. Bound the control-plane
// work before JSON decoding; silent peers must not hold data-transfer permits.
const (
	publicProofHeaderBytes     = 4096
	publicProofHeaderTimeout   = 15 * time.Second
	publicProofResponseTimeout = 15 * time.Second
	publicProofRequestsGlobal  = 16
	publicProofRequestsPerPeer = 2
)

type publicProofRequestLease struct {
	controller *transferAdmissionController
	identity   string
	once       sync.Once
}

func (c *transferAdmissionController) acquirePublicProofRequest(identity string) (*publicProofRequestLease, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.publicProofRequests >= publicProofRequestsGlobal || c.publicProofPeers[identity] >= publicProofRequestsPerPeer {
		c.busyResponses++
		return nil, c.retryAfterSeconds, fmt.Errorf("public proof requests are busy")
	}
	if c.publicProofPeers == nil {
		c.publicProofPeers = make(map[string]int)
	}
	c.publicProofRequests++
	c.publicProofPeers[identity]++
	return &publicProofRequestLease{controller: c, identity: identity}, 0, nil
}

func (l *publicProofRequestLease) Release() {
	l.once.Do(func() {
		c := l.controller
		c.mu.Lock()
		defer c.mu.Unlock()
		c.publicProofRequests--
		if c.publicProofPeers[l.identity] <= 1 {
			delete(c.publicProofPeers, l.identity)
		} else {
			c.publicProofPeers[l.identity]--
		}
	})
}

// Reuse the existing shared download/peer work bounds, but do not queue public
// proof work. Otherwise a departed caller can leave a future full-file read in
// the transfer queue. Downloads/uploads retain their existing queue semantics.
func (c *transferAdmissionController) acquirePublicProofWork(identity string) (*transferLease, int64, error) {
	c.mu.Lock()
	if !c.canAdmitLocked("download", identity, "", 0) {
		c.busyResponses++
		retry := c.retryAfterSeconds
		c.mu.Unlock()
		return nil, retry, fmt.Errorf("transfer resources are busy")
	}
	c.activeDownloads++
	c.peerActive[identity]++
	c.acceptedTransfers++
	c.mu.Unlock()
	return &transferLease{controller: c, kind: "download", identity: identity,
		activity: beginForegroundActivity("download")}, 0, nil
}

func writePublicProofResponse(s network.Stream, response ProveResp) {
	// Set this immediately before the response, rather than imposing a new
	// arbitrary time limit on legitimate whole-piece integrity verification.
	if err := s.SetWriteDeadline(time.Now().Add(publicProofResponseTimeout)); err != nil {
		return
	}
	writeJSON(s, response)
}
