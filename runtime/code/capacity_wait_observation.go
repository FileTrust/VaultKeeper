package main

import "time"

// observeCapacityWaitLag refreshes only the observation used for liveness logs.
// Readiness reconciliation can retire a journal record after the scheduler's
// earlier lag snapshot. Never classify that retired record as unowned work.
// Scheduling, admission, proof counts and durable lag state are unchanged.
// On read failure retain the earlier snapshot rather than report no work.
func observeCapacityWaitLag(storage string, prior capacityProofLagSnapshot) (capacityProofLagSnapshot, error) {
	observed := prior
	err := withCapacityCoordinationLock(storage, func() error {
		records, err := listPendingCapacityMutationJournalRecordsUnlocked(storage)
		if err != nil {
			return err
		}
		observed.PendingMutations = len(records)
		observed.OldestMutationAgeNanos = 0
		now := time.Now() // Journal creation timestamps use the host clock.
		for _, record := range records {
			created, parseErr := time.Parse(time.RFC3339Nano, record.CreatedAt)
			if parseErr != nil {
				// Keep the earlier age if a timestamp cannot be interpreted.
				if prior.OldestMutationAgeNanos > observed.OldestMutationAgeNanos {
					observed.OldestMutationAgeNanos = prior.OldestMutationAgeNanos
				}
				continue
			}
			if age := now.Sub(created); int64(age) > observed.OldestMutationAgeNanos {
				observed.OldestMutationAgeNanos = int64(age)
			}
		}
		return nil
	})
	if err != nil {
		return prior, err
	}
	return observed, nil
}
