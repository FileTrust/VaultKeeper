package main

import (
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Intentional maintenance stops admission, finishes existing work and never
// sends SIGKILL to a proof worker. Durable journals remain in their original paths.
var vkStop = make(chan struct{})
var vkStopOnce sync.Once
var vkSignalsOnce sync.Once

func installVKStopSignals() {
	vkSignalsOnce.Do(func() {
		if expected, err := strconv.Atoi(os.Getenv("FILETRUST_VK_SUPERVISOR_PID")); err == nil && expected > 0 {
			go func() {
				for {
					if os.Getppid() != expected {
						vkStopOnce.Do(func() { close(vkStop) })
						return
					}
					if vkWait(500 * time.Millisecond) {
						return
					}
				}
			}()
		}
		events := make(chan os.Signal, 1)
		signal.Notify(events, syscall.SIGTERM, syscall.SIGINT)
		go func() { <-events; vkStopOnce.Do(func() { close(vkStop) }) }()
	})
}
func vkStopping() bool {
	select {
	case <-vkStop:
		return true
	default:
		return false
	}
}
func vkWait(delay time.Duration) bool {
	select {
	case <-vkStop:
		return true
	case <-time.After(delay):
		return false
	}
}

type maintenanceGate struct {
	mu      sync.Mutex
	closing bool
	active  sync.WaitGroup
}

func (g *maintenanceGate) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return false
	}
	g.active.Add(1)
	return true
}
func (g *maintenanceGate) closeAndWait() {
	g.mu.Lock()
	g.closing = true
	g.mu.Unlock()
	g.active.Wait()
}

var vkStreams maintenanceGate
var vkBackground maintenanceGate

func installVKStreamHandler(h host.Host, id protocol.ID, handler network.StreamHandler) {
	h.SetStreamHandler(id, func(s network.Stream) {
		if vkStopping() || !vkStreams.begin() {
			_ = s.Reset()
			return
		}
		defer vkStreams.active.Done()
		handler(s)
	})
}
func startVKBackground(work func()) {
	if vkStopping() || !vkBackground.begin() {
		return
	}
	go func() { defer vkBackground.active.Done(); work() }()
}
