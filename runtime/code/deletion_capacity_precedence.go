package main

import (
	"fmt"
	"time"
)

// Two default proof-daemon observations give a newly registered successor a bounded chance to
// acquire qualified G.4B ownership. This is coordination latency, not a proof-duration estimate;
// after it expires, ordinary standalone deletion remains live unless urgency already owns it.
const deletionUrgencyOwnershipWindow = 2 * time.Minute

type deletionProofOwnershipDeferredError struct{ Reason string }

func (e *deletionProofOwnershipDeferredError) Error() string { return e.Reason }

func directDeletionProofOwnershipDeferred(
	storage string, operation DeletionLifecycleOperation, partition PartitionMeta, now time.Time,
) (bool, string, error) {
	urgent, err := qualifiedUrgencyPlanOwnsPartition(storage, partition)
	if err != nil {
		return true, "", err
	}
	if urgent {
		return true, "qualified lifecycle urgency owns successor proof", nil
	}
	registered := operation.SuccessorRegisteredAtUnix
	if registered <= 0 || now.Unix() < registered {
		return true, "successor proof ownership window is not durably anchored", nil
	}
	availableAt := time.Unix(registered, 0).Add(deletionUrgencyOwnershipWindow)
	if now.Before(availableAt) {
		return true, fmt.Sprintf("successor proof ownership window open until %s", availableAt.UTC().Format(time.RFC3339)), nil
	}
	return false, "", nil
}
