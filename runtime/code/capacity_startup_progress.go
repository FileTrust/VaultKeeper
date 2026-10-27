package main

// STARTUP PROGRESS FOR ONE KEEPER.
//
// A keeper proves its whole declared capacity before it will admit anything. On the
// 200 MB test profile that is 45-55 minutes; on a 10 TB deployment it is far longer.
// For that entire window the daemon logged only what it happened to be doing, so an
// operator watching a fresh keeper saw a burst of startup lines and then nothing. The
// keeper looked dead exactly when it was busiest, and there was no way to tell a long
// baseline apart from a wedge without reading chain state by hand.
//
// The unit of that work is the partition: one zk proof each, counted on chain as
// ProvenPartitions/ExpectedPartitions. This renders that count as a progress bar with
// an elapsed time and a projected finish, and says READY once — when admission opens
// and the keeper will actually take uploads, downloads and deletes.
//
// Progress belongs to one keeper. Each keeper runs its own daemon and writes its own
// log, so this is per-keeper by construction, which is also how production runs: one
// keeper per machine.

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// Heartbeat cadence while the partition count is unchanged. A single partition can take
// many minutes, so silence between counts is the very thing being fixed; this keeps the
// line moving without flooding the log.
const capacityProgressHeartbeat = 30 * time.Second

const capacityProgressBarWidth = 24

type capacityStartupProgress struct {
	mu          sync.Mutex
	startedAt   time.Time
	lastLogAt   time.Time
	lastProven  uint32
	lastTotal   uint32
	readyLogged bool
	started     bool
}

var capacityProgress capacityStartupProgress

// renderCapacityProgressBar draws the bar itself. Exposed separately so tests pin the
// rendering without a scheduler.
func renderCapacityProgressBar(proven, total uint32, width int) string {
	if width <= 0 {
		width = capacityProgressBarWidth
	}
	if total == 0 {
		return strings.Repeat("-", width)
	}
	if proven > total {
		proven = total
	}
	filled := int(uint64(proven) * uint64(width) / uint64(total))
	if filled > width {
		filled = width
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}

func capacityProgressPercent(proven, total uint32) int {
	if total == 0 {
		return 0
	}
	if proven >= total {
		return 100
	}
	return int(uint64(proven) * 100 / uint64(total))
}

// capacityProgressETA projects the remaining time from the average time per proven
// partition. It reports false until at least one partition has completed, because a
// projection from zero samples is not an estimate.
func capacityProgressETA(elapsed time.Duration, proven, total uint32) (time.Duration, bool) {
	if proven == 0 || total == 0 || proven >= total {
		return 0, false
	}
	per := elapsed / time.Duration(proven)
	if per <= 0 {
		return 0, false
	}
	return per * time.Duration(total-proven), true
}

// reportCapacityStartupProgress logs one progress line for this keeper.
//
// It is safe to call on every scan: output is rate-limited to a change in the proven
// count or the heartbeat interval, whichever comes first.
func reportCapacityStartupProgress(proven, total uint32, admissionOpen bool, now time.Time) {
	capacityProgress.report(proven, total, admissionOpen, now)
}

func (p *capacityStartupProgress) report(proven, total uint32, admissionOpen bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Admission open is the only definition of ready that matters to a caller: it is the
	// moment uploads, downloads and deletes are actually accepted.
	if admissionOpen {
		if !p.readyLogged {
			p.readyLogged = true
			// Emit the final observed count before READY. Otherwise the previous
			// 2/3 tick can remain the last percentage an operator ever sees.
			if total > 0 {
				elapsed := time.Duration(0)
				if p.started {
					elapsed = now.Sub(p.startedAt).Round(time.Second)
				}
				log.Printf("[capacity-progress] [%s] %d/%d partitions %d%% elapsed %s",
					renderCapacityProgressBar(proven, total, capacityProgressBarWidth),
					proven, total, capacityProgressPercent(proven, total),
					elapsed)
			}
			if p.started {
				log.Printf(
					"[capacity-progress] READY after %s -- admission open, accepting upload/download/delete",
					now.Sub(p.startedAt).Round(time.Second),
				)
			} else {
				log.Printf("[capacity-progress] READY -- admission open, accepting upload/download/delete")
			}
		}
		return
	}

	// Closed again after being ready (capacity filled, backlog unsafe, proof subsystem
	// down). Start a fresh window so the next READY reports its own duration rather than
	// the age of the process.
	if p.readyLogged {
		p.readyLogged = false
		p.started = false
	}
	if !p.started {
		p.started = true
		p.startedAt = now
		p.lastLogAt = time.Time{}
		p.lastProven = 0
		p.lastTotal = 0
	}

	changed := proven != p.lastProven || total != p.lastTotal
	if !changed && !p.lastLogAt.IsZero() && now.Sub(p.lastLogAt) < capacityProgressHeartbeat {
		return
	}
	p.lastProven, p.lastTotal, p.lastLogAt = proven, total, now

	elapsed := now.Sub(p.startedAt).Round(time.Second)

	// Before the first campaign opens there is no denominator, and a keeper can
	// sit in that phase for many minutes while it builds its baseline. An empty
	// bar over "0/0 partitions 0%" reads as broken, so name the phase instead of
	// drawing a bar against a total nobody has computed yet.
	if total == 0 {
		log.Printf(
			"[capacity-progress] building capacity baseline, elapsed %s "+
				"-- partition count not decided yet, not accepting upload/download/delete",
			elapsed,
		)
		return
	}

	line := fmt.Sprintf(
		"[capacity-progress] [%s] %d/%d partitions %d%% elapsed %s",
		renderCapacityProgressBar(proven, total, capacityProgressBarWidth),
		proven, total, capacityProgressPercent(proven, total), elapsed,
	)
	if eta, ok := capacityProgressETA(now.Sub(p.startedAt), proven, total); ok {
		line += fmt.Sprintf(" eta ~%s", eta.Round(time.Second))
	}
	line += " -- not yet accepting upload/download/delete"
	log.Print(line)
}
