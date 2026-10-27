package main

// Capacity milestones — the few daemon events an operator needs on the console.
//
// Capacity proving happens in the proof daemon, a separate process whose output
// goes only to proof_daemon.log. From the console you could therefore see
// `ADMISSION CLOSED … proof_subsystem_unavailable` and have no way to watch the
// work that would eventually clear it: the cause was visible, the cure was not.
//
// The fix is not to forward the daemon's log. That log reports per-scan
// verdicts, per-partition progress, lock waits and batch bookkeeping, and
// forwarding it would reproduce on the console exactly the flood we just spent
// two changes removing.
//
// Instead the daemon marks the handful of events that change what the keeper
// can DO -- a campaign opening, a campaign completing -- and only those are
// forwarded. Everything else stays in proof_daemon.log at full detail.
//
// The rule for what belongs here: would an operator act differently, or stop
// worrying, on seeing it? A campaign opening explains why admission is closed.
// A campaign completing explains why it reopened. A per-scan verdict explains
// nothing on its own.

import (
	"fmt"
	"log"
)

// Tag recognised by the console follower in vks.py. Changing it requires
// changing CAPACITY_CONSOLE_TAGS there too.
const capacityMilestoneTag = "[capacity-milestone]"

func logCapacityMilestone(format string, args ...any) {
	log.Printf("%s %s", capacityMilestoneTag, fmt.Sprintf(format, args...))
}

// humanBytes keeps milestone lines readable: an operator reads "97.6 MB" at a
// glance and has to stop and count digits for "102367232".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 4 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}
