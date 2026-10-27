package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A.0 drain-before-cutover quiesce mode.
//
// Quiescing does NOT stop the proof workers: reconciliation, proving, submission,
// abandonment, and reanchoring all keep running so every EXISTING frozen snapshot can
// reach its natural terminal state (submit or abandon). What quiesce prevents is the
// creation of NEW on-chain freeze state:
//   - opening a new capacity proof epoch;
//   - creating a new frozen partition snapshot (capacity or deletion freezes alike —
//     both go through prepareFrozenPartitionSnapshot's freeze branch).
//
// The flag is durable (a marker file under the storage lifecycle directory) so it
// survives restarts, and its status — together with the count of locally-known frozen
// snapshots still awaiting resolution — is exposed through the operational metrics as
// the observable `quiesced` / `drained` signals. Workers are only stopped AFTER the
// exhaustive on-chain drain verifier has confirmed the drain.

func freezeQuiescePath(storage string) string {
	return filepath.Join(storage, "lifecycle", "freeze-quiesce")
}

// setFreezeQuiesce durably enables or disables the freeze quiesce.
func setFreezeQuiesce(storage string, enabled bool) error {
	if enabled {
		if err := os.MkdirAll(filepath.Dir(freezeQuiescePath(storage)), 0700); err != nil {
			return err
		}
		return atomicWriteFile(freezeQuiescePath(storage), []byte(nowRFC3339()+"\n"), 0600)
	}
	err := os.Remove(freezeQuiescePath(storage))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// freezeQuiesceActive reports whether the durable freeze quiesce is enabled.
func freezeQuiesceActive(storage string) bool {
	_, err := os.Stat(freezeQuiescePath(storage))
	return err == nil
}

// errFreezeQuiesced marks a freeze attempt refused by the quiesce (non-destructive:
// the local queued generation is preserved and retried after the quiesce lifts).
var errFreezeQuiesced = fmt.Errorf("new on-chain freezes are quiesced for drain-before-cutover")

// countLocalFrozenSnapshots reports how many partitions still hold a locally-known
// frozen snapshot record awaiting submit/abandon. Zero while quiesced is the local
// half of the `drained` signal (the authoritative half is the on-chain exhaustive
// drain verifier).
func countLocalFrozenSnapshots(storage string) (int, error) {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return 0, err
	}
	frozen := 0
	for _, queue := range queues {
		if queue.Frozen != nil {
			frozen++
		}
	}
	return frozen, nil
}

// freezeQuiesceStatus is the observable quiesce/drain state.
type freezeQuiesceStatus struct {
	VKAddress                string `json:"vkAddress,omitempty"`
	Quiesced                 bool   `json:"quiesced"`
	FrozenSnapshotsRemaining int    `json:"frozenSnapshotsRemaining"`
	// DrainedLocal is true when quiesce is active and no locally-known frozen
	// snapshot remains. On-chain drain is verified separately and exhaustively by
	// Blockchain/scripts/verify_snapshot_drain.js.
	DrainedLocal bool `json:"drainedLocal"`
}

func collectFreezeQuiesceStatus(storage string) freezeQuiesceStatus {
	return collectFreezeQuiesceStatusForVK(storage, "")
}

func collectFreezeQuiesceStatusForVK(storage, vkAddress string) freezeQuiesceStatus {
	status := freezeQuiesceStatus{VKAddress: vkAddress, Quiesced: freezeQuiesceActive(storage)}
	if remaining, err := countLocalFrozenSnapshots(storage); err == nil {
		status.FrozenSnapshotsRemaining = remaining
		status.DrainedLocal = status.Quiesced && remaining == 0
	} else {
		// Fail closed: an unreadable queue set is never reported as drained.
		status.FrozenSnapshotsRemaining = -1
		status.DrainedLocal = false
	}
	return status
}

// runFreezeQuiesceCLI implements the `quiesce-freezes` command mode: it toggles or
// reports the durable quiesce state and prints the observable status as JSON.
func runFreezeQuiesceCLI(storage, vkAddress, state string) error {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "on":
		if err := setFreezeQuiesce(storage, true); err != nil {
			return err
		}
	case "off":
		if err := setFreezeQuiesce(storage, false); err != nil {
			return err
		}
	case "", "status":
		// report only
	default:
		return fmt.Errorf("quiesce state must be on, off, or status")
	}
	payload, err := json.Marshal(collectFreezeQuiesceStatusForVK(storage, vkAddress))
	if err != nil {
		return err
	}
	fmt.Println(string(payload))
	return nil
}
