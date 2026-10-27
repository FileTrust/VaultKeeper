package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

var ErrPartitionNoLongerActive = errors.New("partition is no longer active locally")

// Capacity proof epochs occupy the low half of the uint64 domain. The high
// bit identifies a one-partition proof that is authorized by an outstanding
// FileRegistration deletion. Keeping the domains disjoint prevents a deletion
// proof from being counted as a complete capacity proof epoch.
const standaloneDeletionProofFlag uint64 = 1 << 63

// capacityAuthorityDomainMask is the pair of bits ProofAuthorityDomains reserves to carry
// the authority domain: bit 62 marks an incremental batch, bit 63 a standalone deletion
// proof. A FULL capacity epoch id must have neither set — the contract enforces
// 0 < id < 1<<62 and reverts FullEpochIdOutOfDomain otherwise.
const capacityAuthorityDomainMask uint64 = incrementalCapacityAuthorityFlag | standaloneDeletionProofFlag

func currentProofRound(periodSeconds int64) uint64 {
	if periodSeconds <= 0 {
		periodSeconds = 24 * 60 * 60
	}
	return uint64(time.Now().UTC().Unix() / periodSeconds)
}

// buildSectorChallenge generates off-chain challenge indexes for the standalone
// sector-proof CLI mode (no chain involved). The proof daemon always uses
// chain-derived indexes from openStorageProofChallenge instead.
func buildSectorChallenge(sector SectorMeta, round uint64, challengeCount int, seed string) (SectorChallenge, error) {
	blockCount := sector.SectorBlockCount
	if blockCount <= 0 {
		return SectorChallenge{}, fmt.Errorf("sector has no ZK sector blocks")
	}
	if challengeCount <= 0 {
		challengeCount = 1
	}
	if challengeCount > blockCount {
		challengeCount = blockCount
	}
	if seed == "" {
		seed = fmt.Sprintf("%s:%d:%d", sector.SectorRoot, round, time.Now().UTC().Unix())
	}
	indexes := make([]uint64, 0, challengeCount)
	seen := map[uint64]bool{}
	counter := uint64(0)
	for len(indexes) < challengeCount && counter < math.MaxUint32 {
		h := sha256.New()
		h.Write([]byte(seed))
		h.Write([]byte(sector.SectorRoot))
		var buf [16]byte
		binary.BigEndian.PutUint64(buf[:8], round)
		binary.BigEndian.PutUint64(buf[8:], counter)
		h.Write(buf[:])
		d := h.Sum(nil)
		idx := binary.BigEndian.Uint64(d[:8]) % uint64(blockCount)
		if !seen[idx] {
			seen[idx] = true
			indexes = append(indexes, idx)
		}
		counter++
	}
	return SectorChallenge{SectorRoot: sector.SectorRoot, Round: round, ChallengeSeed: "0x" + challengeSeedHex(seed), ChallengeIndexes: indexes, CreatedAt: nowRFC3339()}, nil
}

func dueSectors(storage string, round uint64) ([]SectorMeta, error) {
	return dueSectorsAt(storage, round, time.Now().UTC().Unix())
}

func dueSectorsAt(storage string, round uint64, chainTimestamp int64) ([]SectorMeta, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return nil, err
	}
	out := []SectorMeta{}
	for _, s := range sectors {
		if s.Expiration > chainTimestamp && s.LastProofRound < round && s.SectorBlockCount > 0 {
			out = append(out, s)
		}
	}
	return out, nil
}

func challengeSeedHex(seed string) string {
	s := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(s[:])
}

// proveSectorWithChain runs the full per-sector proof cycle (existing path, unchanged).
func proveSectorWithChain(storage string, sector SectorMeta, round uint64, challengeCount int, proverCmd, chainCmd string) error {
	challenge, publicInputs, err := openStorageProofChallenge(chainCmd, sector, round, challengeCount)
	if err != nil {
		return err
	}
	req := ZKProofRequest{Sector: sector, Challenge: challenge, StorageDir: storage, PublicInputs: publicInputs}
	proof, err := runExternalZKProver(proverCmd, req)
	if err != nil {
		return err
	}
	if err := submitStorageProofToChain(chainCmd, sector, challenge, proof); err != nil {
		return err
	}
	return markSectorProofed(storage, sector, round)
}

func refreshPartitionForProof(storage string, requested PartitionMeta, deadlineCount, partitionMaxSectors int, chainTimestamp int64) (PartitionMeta, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return PartitionMeta{}, fmt.Errorf("refresh partition: list sectors: %w", err)
	}
	if deadlineCount <= requested.DeadlineIndex {
		deadlineCount = requested.DeadlineIndex + 1
	}
	if partitionMaxSectors <= 0 {
		return PartitionMeta{}, fmt.Errorf("refresh partition: invalid partition sector limit")
	}
	current, found := currentPartitionMetaByCoordinatesAt(
		sectors,
		ServerConfig{DeadlineCount: deadlineCount, PartitionMaxSectors: partitionMaxSectors},
		requested.DeadlineIndex,
		requested.PartitionIndex,
		requested.PartitionKind,
		chainTimestamp,
	)
	if !found || len(current.Sectors) == 0 {
		return PartitionMeta{}, fmt.Errorf("%w: dl%d-pt%d", ErrPartitionNoLongerActive, requested.DeadlineIndex, requested.PartitionIndex)
	}
	return current, nil
}

func exactPartitionVersionAlreadyProven(status PartitionVersionStatus, partition PartitionMeta, round uint64) bool {
	return status.Active &&
		status.CurrentContentProven &&
		status.LastProofRound >= round &&
		partitionMatchesChainContent(status, partition) &&
		sameRoot(status.LastProvenContentHash, status.ContentHash)
}

func currentPartitionVersionIsProven(status PartitionVersionStatus, partition PartitionMeta) bool {
	return status.Active && status.CurrentContentProven &&
		partitionMatchesChainContent(status, partition) &&
		sameRoot(status.LastProvenContentHash, status.ContentHash)
}

func isContentAlreadyProvenError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "content already proven")
}

type partitionProofDeferredError struct {
	Round      uint64
	RetryRound uint64
	Reason     string
}

func (err *partitionProofDeferredError) Error() string {
	return fmt.Sprintf("partition proof deferred from round %d until round %d: %s", err.Round, err.RetryRound, err.Reason)
}

func legacyChallengeDeferral(status ChainProofCommandResponse, round uint64) error {
	if status.ChallengeExists && status.ChallengeDeadline > 0 &&
		status.ChainTimestamp > status.ChallengeDeadline {
		return &partitionProofDeferredError{
			Round: round, RetryRound: max(round+1, status.CurrentRound+1),
			Reason: "the existing legacy challenge expired; generating another proof in this round cannot succeed",
		}
	}
	return nil
}

// confirmPartitionProofSubmission resolves ambiguous submissions without ever
// treating an error string alone as success. In particular, an older
// StorageProofSC reverts duplicate submissions; RPC gateways may briefly serve
// a stale view immediately afterward. Success requires the chain to report the
// exact local content proved in the requested round.
func confirmPartitionProofSubmission(
	chainCmd string,
	partition PartitionMeta,
	round uint64,
	retryStaleView bool,
) (PartitionVersionStatus, bool, error) {
	attempts := 1
	if retryStaleView {
		attempts = 6
	}
	var lastStatus PartitionVersionStatus
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		status, err := partitionVersionStatusOnChain(chainCmd, partition)
		if err == nil {
			lastStatus = status
			lastErr = nil
			if exactPartitionVersionAlreadyProven(status, partition, round) {
				return status, true, nil
			}
			// A different current content version proves this was not a harmless
			// duplicate of the proof we generated. The caller must refresh.
			if status.ContentHash != "" && !partitionMatchesChainContent(status, partition) {
				return status, false, nil
			}
		} else {
			lastErr = err
		}
		if attempt+1 < attempts {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return lastStatus, false, lastErr
}

// provePartitionWithChain locks the exact partition version from the final
// snapshot through submission. Host-heavy-work is acquired first, so unrelated
// stores do not wait while this proof is queued behind another VK's proof.
func proofRoundDeadline(round uint64, periodSeconds int64) time.Time {
	if periodSeconds <= 0 {
		periodSeconds = 24 * 60 * 60
	}
	return time.Unix(int64(round+1)*periodSeconds, 0)
}

func nextProofWindowDeadline(now time.Time, periodSeconds int64, deadlineCount int) time.Time {
	return nextProofWindowDeadlineAt(now.Unix(), periodSeconds, deadlineCount)
}

// chainDeadlineHostDue converts a chain-domain absolute deadline into a local
// scheduling deadline using only its remaining duration. Validator/host clock
// skew therefore cannot create fake proof slack or premature urgency.
func chainDeadlineHostDue(chainDeadline, chainTimestamp int64, hostNow time.Time) time.Time {
	if chainDeadline <= chainTimestamp {
		return hostNow
	}
	remaining := chainDeadline - chainTimestamp
	const maxDurationSeconds = int64(^uint64(0)>>1) / int64(time.Second)
	if remaining > maxDurationSeconds {
		remaining = maxDurationSeconds
	}
	return hostNow.Add(time.Duration(remaining) * time.Second)
}

func livePartitionProofGeneration(work string, round uint64, contentHash, intent string) string {
	return fmt.Sprintf("partition|%s|%d|%s|%s", work, round, contentHash, intent)
}

func snapshotProofJobScope(snapshot partitionProofSnapshot) string {
	return fmt.Sprintf("snapshot-%s-dl%d-pt%d", snapshot.Partition.PartitionKind,
		snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex)
}

func frozenPartitionProofGeneration(work string, snapshot partitionProofSnapshot, challenge PartitionChallenge) string {
	return fmt.Sprintf("snapshot|%s|%d|%s|%d", work, snapshot.ContentVersion, snapshot.ContentHash, challenge.Round)
}

func schedulerGenerationAuthoritative(scope, generation string) error {
	lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
	if lockPath == "" {
		return nil
	}
	authoritative, err := proofJobGenerationAuthoritative(lockPath, scope, generation)
	if err != nil {
		return fmt.Errorf("read authoritative proof generation: %w", err)
	}
	if !authoritative {
		return fmt.Errorf("%w: generation %s scope %s", ErrProofJobCancelled, generation, scope)
	}
	return nil
}

func validateLiveProofSubmissionAuthority(
	partition PartitionMeta, round uint64, challengedContent, generation, authoritativeGeneration string,
	status PartitionVersionStatus,
) (bool, error) {
	if generation != authoritativeGeneration {
		return false, fmt.Errorf("proof job generation is no longer authoritative")
	}
	if !sameRoot(partitionContentHash(partition), challengedContent) {
		return false, fmt.Errorf("live partition content changed before proof submission")
	}
	if !partitionMatchesChainContent(status, partition) {
		return false, fmt.Errorf("on-chain partition generation changed before proof submission")
	}
	return exactPartitionVersionAlreadyProven(status, partition, round), nil
}

// requireSnapshotNonceIdentity selects the A.0 contract protocol (default): every active
// frozen snapshot MUST carry a positive snapshot nonce locally AND on-chain, and they
// must match, before submit/abandon/reanchor may send a transaction. The pre-A.0
// contract protocol (no nonce) may ONLY be selected explicitly via the
// -legacy-snapshot-protocol flag during deployment preparation; nonce validation is
// never silently skipped because one side omitted it.
var requireSnapshotNonceIdentity = true

// snapshotNonceIdentityError enforces the mandatory post-cutover nonce identity:
// local > 0, chain > 0, and equal. Under the explicit legacy protocol it only rejects
// a mismatch when both sides carry a nonce.
func snapshotNonceIdentityError(localNonce, chainNonce uint64) error {
	if !requireSnapshotNonceIdentity {
		if localNonce != 0 && chainNonce != 0 && localNonce != chainNonce {
			return fmt.Errorf("snapshot nonce mismatch: local %d chain %d", localNonce, chainNonce)
		}
		return nil
	}
	if localNonce == 0 {
		return fmt.Errorf("snapshot nonce identity incomplete: local nonce is zero")
	}
	if chainNonce == 0 {
		return fmt.Errorf("snapshot nonce identity incomplete: chain returned no snapshot nonce (legacy contract? select -legacy-snapshot-protocol explicitly)")
	}
	if localNonce != chainNonce {
		return fmt.Errorf("snapshot nonce mismatch: local %d chain %d", localNonce, chainNonce)
	}
	return nil
}

func validateFrozenProofSubmissionAuthority(
	snapshot partitionProofSnapshot,
	queue partitionProofSnapshotQueue,
	status FrozenPartitionSnapshotStatus,
	epoch CapacityProofEpochStatus,
	requireEpoch bool,
	generation, authoritativeGeneration string,
) (bool, error) {
	if generation != authoritativeGeneration {
		return false, fmt.Errorf("frozen proof job generation is no longer authoritative")
	}
	// A.1 fence: the worker's local generation must still match the live frozen slot.
	// Content-identical records share an ID, so this catches a reanchor/replacement that
	// overtook this worker even when every content field still matches.
	if queue.Frozen == nil || !partitionGenerationIdentityOK(queue.Frozen.Generation, snapshot.Generation) {
		return false, fmt.Errorf("%w: submit blocked", ErrPartitionProofSnapshotSuperseded)
	}
	if queue.Frozen == nil || queue.Frozen.ID != snapshot.ID ||
		queue.Frozen.ProofEpochID != snapshot.ProofEpochID ||
		queue.Frozen.ContentVersion != snapshot.ContentVersion ||
		!sameRoot(queue.Frozen.ContentHash, snapshot.ContentHash) ||
		!sameRoot(queue.Frozen.ChainContentHash, snapshot.ChainContentHash) {
		return false, fmt.Errorf("frozen snapshot is no longer the authoritative queue head")
	}
	if !status.Exists || status.ProofEpochID != snapshot.ProofEpochID ||
		status.ContentVersion != snapshot.ContentVersion || status.Round != snapshot.Round ||
		!sameRoot(status.ContentHash, snapshot.ChainContentHash) {
		return false, fmt.Errorf("frozen snapshot identity changed on-chain before submission")
	}
	if err := snapshotNonceIdentityError(snapshot.SnapshotNonce, status.SnapshotNonce); err != nil {
		return false, fmt.Errorf("frozen snapshot nonce authority: %w", err)
	}
	if requireEpoch && (!epoch.Active || epoch.Invalidated || epoch.ProofEpochID != snapshot.ProofEpochID || epoch.TargetRound != snapshot.Round) {
		return false, fmt.Errorf("capacity epoch changed before frozen proof submission")
	}
	return status.Proven, nil
}

func provePartitionWithChain(storage string, partition PartitionMeta, round uint64, challengeCount, deadlineCount, partitionMaxSectors int, partitionProverCmd, chainCmd string, deterministicChallenge, allowDeletionPending bool, workDeadline time.Time, chainTimestamp int64) (string, error) {
	return provePartitionWithChainIntent(
		storage, partition, round, challengeCount, deadlineCount, partitionMaxSectors,
		partitionProverCmd, chainCmd, deterministicChallenge, allowDeletionPending,
		workDeadline, chainTimestamp, "",
	)
}

// c1DurationClass is the C.1 SCHEDULING duration class decided once by the authoritative
// campaign layer (see provePartitionCandidates). It is deliberately separate from the G.3
// proof-SHAPE key (`capacity-final-nN`) built below: the shape key answers "how long does this
// proof shape take", the C.1 class answers "what type of capacity campaign is this". An empty
// value preserves the historical behaviour of classifying from the shape key.
func provePartitionWithChainIntent(storage string, partition PartitionMeta, round uint64, challengeCount, deadlineCount, partitionMaxSectors int, partitionProverCmd, chainCmd string, deterministicChallenge, allowDeletionPending bool, workDeadline time.Time, chainTimestamp int64, intent string) (string, error) {
	return provePartitionWithChainIntentClass(storage, partition, round, challengeCount, deadlineCount,
		partitionMaxSectors, partitionProverCmd, chainCmd, deterministicChallenge, allowDeletionPending,
		workDeadline, chainTimestamp, intent, "")
}

func provePartitionWithChainIntentClass(storage string, partition PartitionMeta, round uint64, challengeCount, deadlineCount, partitionMaxSectors int, partitionProverCmd, chainCmd string, deterministicChallenge, allowDeletionPending bool, workDeadline time.Time, chainTimestamp int64, intent, c1DurationClass string) (string, error) {
	if len(partition.Sectors) == 0 {
		return "", fmt.Errorf("partition dl%d-pt%d has no sectors", partition.DeadlineIndex, partition.PartitionIndex)
	}
	work := fmt.Sprintf("partition-%s-dl%d-pt%d", partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)
	var lifecycleLock *partitionLifecycleLock
	var challenge PartitionChallenge
	var proof ZKProofResult
	var alreadyProven bool
	var alreadyProvenRound uint64
	var replayedSubmitTx string
	class := fmt.Sprintf("%s-final-n%d", partition.PartitionKind, len(partition.Sectors))
	if intent == "deletion" {
		class = fmt.Sprintf("deletion-final-n%d", len(partition.Sectors))
	}
	releaseLifecycle := func() {
		if lifecycleLock != nil {
			lifecycleLock.Release()
			lifecycleLock = nil
		}
	}
	acquireAndRefresh := func() error {
		lock, lockErr := acquirePartitionLifecycleLock(storage, partition.DeadlineIndex, partition.PartitionIndex)
		if lockErr != nil {
			return lockErr
		}
		lifecycleLock = lock
		if !allowDeletionPending {
			pending, pendingErr := partitionHasPendingDeletion(storage, partition.DeadlineIndex, partition.PartitionIndex)
			if pendingErr != nil {
				return fmt.Errorf("recheck partition deletion: %w", pendingErr)
			}
			if pending {
				return ErrPartitionDeletionInProgress
			}
		}
		refreshed, refreshErr := refreshPartitionForProof(storage, partition, deadlineCount, partitionMaxSectors, chainTimestamp)
		if refreshErr != nil {
			return refreshErr
		}
		if partitionContentHash(refreshed) != partitionContentHash(partition) {
			log.Printf("[partition] dl=%d pt=%d content changed while queued; proving refreshed sectors=%d",
				partition.DeadlineIndex, partition.PartitionIndex, len(refreshed.Sectors))
		}
		partition = refreshed
		return nil
	}

	// Chain reads and replay submissions do not consume the ZK prover. Keep
	// them outside the host-wide prover lock so one slow RPC endpoint cannot
	// stop every VK on this host from proving. The exact partition lifecycle
	// lock still protects this VK's content while the challenge is selected.
	if err := acquireAndRefresh(); err != nil {
		releaseLifecycle()
		return "", err
	}

	// Another process may already have submitted this exact partition version.
	status, statusErr := partitionVersionStatusOnChain(chainCmd, partition)
	if statusErr != nil {
		log.Printf("[partition] dl=%d pt=%d pre-proof status unavailable; continuing safely: %v",
			partition.DeadlineIndex, partition.PartitionIndex, statusErr)
	}

	// A prior submit may have reached the chain before its RPC connection
	// failed. Resolve and replay it before spending shared prover resources.
	replayOps := defaultPartitionReplayOps
	replayGeneration := livePartitionProofGeneration(work, round, partitionContentHash(partition), intent)
	replayOps.authority = func() error {
		lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv))
		if lockPath == "" {
			return nil
		}
		authoritative, found, err := proofJobScopeAuthority(lockPath, work)
		if err != nil {
			return err
		}
		// Queue journals created before Task 5 have no authority pointer; their
		// exact local/challenge/on-chain checks remain a safe migration path.
		if found && authoritative != replayGeneration {
			return ErrProofJobCancelled
		}
		return nil
	}
	replay, replayErr := replayPersistedPartitionProof(
		storage, partition, round, challengeCount, chainCmd,
		deterministicChallenge, replayOps,
	)
	if replayErr != nil {
		releaseLifecycle()
		return "", replayErr
	}
	if replay.Confirmed {
		alreadyProven = true
		alreadyProvenRound = replay.ConfirmedRound
		replayedSubmitTx = replay.SubmitTx
	}
	if !alreadyProven && statusErr == nil && exactPartitionVersionAlreadyProven(status, partition, round) {
		alreadyProven = true
		alreadyProvenRound = status.LastProofRound
	}
	if alreadyProven {
		releaseLifecycle()
		if replayedSubmitTx != "" {
			log.Printf("[partition] dl=%d pt=%d saved proof replay confirmed round=%d tx=%s",
				partition.DeadlineIndex, partition.PartitionIndex, alreadyProvenRound, replayedSubmitTx)
		} else {
			log.Printf("[partition] dl=%d pt=%d skipped duplicate proof; exact content already proven on-chain round=%d",
				partition.DeadlineIndex, partition.PartitionIndex, alreadyProvenRound)
		}
		if err := clearPartitionProofHealth(storage, partition); err != nil {
			log.Printf("[proof-health] clear warning dl=%d pt=%d: %v", partition.DeadlineIndex, partition.PartitionIndex, err)
		}
		return replayedSubmitTx, markPartitionProofed(storage, partition, alreadyProvenRound)
	}

	if !deterministicChallenge {
		challengeStatus, challengeStatusErr := legacyPartitionChallengeStatus(chainCmd, partition, round)
		if challengeStatusErr != nil {
			releaseLifecycle()
			return "", fmt.Errorf("legacy partition challenge status: %w", challengeStatusErr)
		}
		if deferErr := legacyChallengeDeferral(challengeStatus, round); deferErr != nil {
			releaseLifecycle()
			return "", deferErr
		}
	}

	var publicInputs []string
	var challengeErr error
	if deterministicChallenge {
		log.Printf("[partition] dl=%d pt=%d deterministic challenge mode round=%d sectors=%d",
			partition.DeadlineIndex, partition.PartitionIndex, round, len(partition.Sectors))
		challenge, publicInputs, challengeErr = getPartitionChallengeDeterministic(chainCmd, partition, round)
		if challengeErr != nil {
			releaseLifecycle()
			return "", fmt.Errorf("get_partition_challenge_deterministic: %w", challengeErr)
		}
	} else {
		log.Printf("[partition] dl=%d pt=%d opening challenge round=%d sectors=%d",
			partition.DeadlineIndex, partition.PartitionIndex, round, len(partition.Sectors))
		challenge, publicInputs, challengeErr = openPartitionChallenge(chainCmd, partition, round, challengeCount)
		if challengeErr != nil {
			releaseLifecycle()
			return "", fmt.Errorf("open_partition_challenge: %w", challengeErr)
		}
	}
	challengedContent := partitionContentHash(partition)
	releaseLifecycle()

	// Queue only the indivisible prover work globally. Once selected, reacquire
	// the exact partition and reject the challenge if content changed while the
	// job waited; a later scan will obtain a challenge for the new version.
	hostWorkDeadline := chainDeadlineHostDue(workDeadline.Unix(), chainTimestamp, time.Now())
	generation := livePartitionProofGeneration(work, round, challengedContent, intent)
	// G.3 shape key stays `class`; the proof JOB carries the C.1 duration class when the
	// campaign layer supplied one, so single/batch/audit histories never mix.
	jobClass := class
	if strings.TrimSpace(c1DurationClass) != "" {
		jobClass = c1DurationClass
	}
	err := withHostPersistedProofJobDeadline(generation, work, work, jobClass, hostWorkDeadline, func() error {
		if lockErr := acquireAndRefresh(); lockErr != nil {
			return lockErr
		}
		if !sameRoot(partitionContentHash(partition), challengedContent) {
			return fmt.Errorf("partition content changed while proof waited for host resources")
		}
		if saved, found, savedErr := readPartitionState(storage, partition.DeadlineIndex, partition.PartitionIndex); savedErr != nil {
			return savedErr
		} else if found && sameRoot(saved.ContentHash, challengedContent) && saved.LastProofRound >= round {
			alreadyProven = true
			alreadyProvenRound = saved.LastProofRound
			return nil
		}
		req := ZKPartitionProofRequest{
			Partition:    partition,
			Challenge:    challenge,
			StorageDir:   storage,
			PublicInputs: publicInputs,
		}
		var proverErr error
		proof, proverErr = runExternalZKPartitionProverUnlocked(partitionProverCmd, req)
		if proverErr != nil {
			return fmt.Errorf("partition prover: %w", proverErr)
		}
		return nil
	})
	if err != nil {
		releaseLifecycle()
		return "", err
	}
	defer releaseLifecycle()
	if alreadyProven {
		log.Printf("[partition] dl=%d pt=%d skipped queued proof; exact content was completed locally in round=%d",
			partition.DeadlineIndex, partition.PartitionIndex, alreadyProvenRound)
		if err := clearPartitionProofHealth(storage, partition); err != nil {
			log.Printf("[proof-health] clear warning dl=%d pt=%d: %v", partition.DeadlineIndex, partition.PartitionIndex, err)
		}
		return replayedSubmitTx, markPartitionProofed(storage, partition, alreadyProvenRound)
	}

	log.Printf("[partition] dl=%d pt=%d proof generated round=%d content=%s",
		partition.DeadlineIndex, partition.PartitionIndex, round, truncate(partitionContentHash(partition), 18))

	var submitTx string
	authoritativeGeneration := generation
	if lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv)); lockPath != "" {
		authoritative, authorityErr := proofJobGenerationAuthoritative(lockPath, work, generation)
		if authorityErr != nil {
			return "", authorityErr
		}
		if !authoritative {
			authoritativeGeneration = ""
		}
	}
	status, statusErr = partitionVersionStatusOnChain(chainCmd, partition)
	if statusErr != nil {
		return "", fmt.Errorf("pre-submit partition status: %w", statusErr)
	}
	alreadyOnChain, authorityErr := validateLiveProofSubmissionAuthority(
		partition, round, challengedContent, generation, authoritativeGeneration, status,
	)
	if authorityErr != nil {
		return "", authorityErr
	}
	if alreadyOnChain {
		return "", markPartitionProofed(storage, partition, status.LastProofRound)
	}
	if deterministicChallenge {
		submitTx, err = submitPartitionProofDeterministic(chainCmd, partition, challenge, proof)
		if err != nil {
			status, confirmed, statusErr := confirmPartitionProofSubmission(
				chainCmd, partition, round, isContentAlreadyProvenError(err),
			)
			if statusErr == nil && confirmed {
				log.Printf("[partition] dl=%d pt=%d exact content already proven on-chain round=%d",
					partition.DeadlineIndex, partition.PartitionIndex, status.LastProofRound)
				_ = clearPartitionProofHealth(storage, partition)
				return "", markPartitionProofed(storage, partition, status.LastProofRound)
			}
			if persistErr := persistPartitionProofSubmissionFailure(storage, partition, challenge, proof, true, err); persistErr != nil {
				log.Printf("[partition] persist failed proof replay warning: %v", persistErr)
			}
			return "", fmt.Errorf("submit_partition_proof_deterministic: %w", err)
		}
	} else {
		submitTx, err = submitPartitionProofToChain(chainCmd, partition, challenge, proof)
		if err != nil {
			status, confirmed, statusErr := confirmPartitionProofSubmission(
				chainCmd, partition, round, isContentAlreadyProvenError(err),
			)
			if statusErr == nil && confirmed {
				log.Printf("[partition] dl=%d pt=%d exact content already proven on-chain round=%d",
					partition.DeadlineIndex, partition.PartitionIndex, status.LastProofRound)
				_ = clearPartitionProofHealth(storage, partition)
				return "", markPartitionProofed(storage, partition, status.LastProofRound)
			}
			if persistErr := persistPartitionProofSubmissionFailure(storage, partition, challenge, proof, false, err); persistErr != nil {
				log.Printf("[partition] persist failed proof replay warning: %v", persistErr)
			}
			return "", fmt.Errorf("submit_partition_proof: %w", err)
		}
	}

	// The submit returned no error, but a chain mutation that returns NO transaction must never be
	// trusted as a landed proof — recording it (markPartitionProofed) would advance durable proof
	// state while the chain holds nothing, the empty-tx drift class. An empty submit tx means the
	// adapter sent no transaction (the proof for this content/round was already on chain, a
	// no-op). Classify from CHAIN TRUTH before recording: confirmed -> record at the round the
	// chain actually proves; not confirmed -> hold and retry; unavailable -> fail closed and retry.
	if strings.TrimSpace(submitTx) == "" {
		status, confirmed, confErr := confirmPartitionProofSubmission(chainCmd, partition, round, true)
		switch {
		case confErr != nil:
			return "", fmt.Errorf("submit proof dl%d-pt%d returned no transaction and chain read-back unavailable: %w",
				partition.DeadlineIndex, partition.PartitionIndex, confErr)
		case !confirmed:
			return "", fmt.Errorf("submit proof dl%d-pt%d returned no transaction and chain does not show the proof landed (round=%d); not applied, will retry",
				partition.DeadlineIndex, partition.PartitionIndex, round)
		default:
			log.Printf("[partition] dl=%d pt=%d proof already on chain (no tx needed) round=%d",
				partition.DeadlineIndex, partition.PartitionIndex, status.LastProofRound)
			_ = clearPartitionProofHealth(storage, partition)
			return "", markPartitionProofed(storage, partition, status.LastProofRound)
		}
	}

	log.Printf("[partition] dl=%d pt=%d proof submitted round=%d det=%v",
		partition.DeadlineIndex, partition.PartitionIndex, round, deterministicChallenge)
	if err := clearPartitionProofHealth(storage, partition); err != nil {
		log.Printf("[proof-health] clear warning dl=%d pt=%d: %v", partition.DeadlineIndex, partition.PartitionIndex, err)
	}
	return submitTx, markPartitionProofed(storage, partition, round)
}

const (
	capacityBuildRetryFloor = 5 * time.Second
	capacityBuildRetryCeil  = 5 * time.Minute
)

// capacityBuildRetryDelay prevents a persistent disk/configuration fault from
// turning the proof daemon into a tight rebuild loop. Successful and merely
// superseded builds are not delayed: they immediately continue toward the
// newest durable snapshot.
func capacityBuildRetryDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	delay := capacityBuildRetryFloor
	for i := 1; i < failures && delay < capacityBuildRetryCeil; i++ {
		delay *= 2
		if delay >= capacityBuildRetryCeil {
			return capacityBuildRetryCeil
		}
	}
	return delay
}

func partitionsByKind(partitions []PartitionMeta, kind string) []PartitionMeta {
	out := make([]PartitionMeta, 0, len(partitions))
	for _, partition := range partitions {
		if partition.PartitionKind == kind {
			out = append(out, partition)
		}
	}
	return out
}

type partitionProofCandidate struct {
	Partition PartitionMeta
	Priority  string
	Urgent    bool
	Deadline  time.Time
}

func frozenPartitionProofCandidates(storage string, proofEpochID uint64) ([]partitionProofCandidate, error) {
	return frozenPartitionProofCandidatesUrgent(storage, proofEpochID, false)
}

// frozenPartitionProofCandidatesUrgent lists frozen cutoff members.
func frozenPartitionProofCandidatesUrgent(
	storage string,
	proofEpochID uint64,
	_ bool,
) ([]partitionProofCandidate, error) {
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return nil, err
	}
	out := make([]partitionProofCandidate, 0, len(queues))
	for _, queue := range queues {
		if queue.Frozen == nil || queue.Frozen.ProofEpochID != proofEpochID {
			continue
		}
		deadline := time.Time{}
		if queue.Frozen.DeadlineUnix > 0 {
			deadline = time.Unix(queue.Frozen.DeadlineUnix, 0)
		}
		out = append(out, partitionProofCandidate{
			Partition: queue.Frozen.Partition,
			Priority:  queue.Frozen.Partition.PartitionKind + "-frozen-snapshot",
			Urgent:    true,
			Deadline:  deadline,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Deadline.Equal(b.Deadline) {
			if a.Deadline.IsZero() {
				return false
			}
			if b.Deadline.IsZero() {
				return true
			}
			return a.Deadline.Before(b.Deadline)
		}
		if a.Partition.DeadlineIndex != b.Partition.DeadlineIndex {
			return a.Partition.DeadlineIndex < b.Partition.DeadlineIndex
		}
		return a.Partition.PartitionIndex < b.Partition.PartitionIndex
	})
	return out, nil
}

func capacityProofEpochDue(
	status CapacityProofEpochStatus,
	chainTimestamp, proofPeriodSeconds int64,
	_ bool,
) (bool, string) {
	if status.Active {
		return false, "epoch active"
	}
	if status.RegisteredFreeBytes > ^uint64(0)-status.RegisteredDataBytes {
		return false, "registered manifest byte total overflowed"
	}
	registered := status.RegisteredFreeBytes + status.RegisteredDataBytes
	if !capacityManifestWithinProofBounds(status, registered) {
		return false, "registered manifest is outside safe proof bounds"
	}
	if status.LastCapacityProofAt == 0 {
		return true, "initial capacity proof required"
	}
	if status.RegisteredFreeBytes != status.ProvedFreeBytes ||
		status.RegisteredDataBytes != status.ProvedDataBytes {
		return true, "registered partition manifest changed"
	}
	refreshSeconds := int64(status.MaxProofAgeSeconds / 2)
	if refreshSeconds <= 0 {
		refreshSeconds = proofPeriodSeconds
	}
	if proofPeriodSeconds > 0 && (refreshSeconds <= 0 || proofPeriodSeconds < refreshSeconds) {
		refreshSeconds = proofPeriodSeconds
	}
	if refreshSeconds <= 0 {
		return false, "capacity proof refresh interval unavailable"
	}
	if chainTimestamp >= int64(status.LastCapacityProofAt)+refreshSeconds {
		return true, "proof freshness refresh due"
	}
	return false, "proved manifest current"
}

func capacityManifestWithinProofBounds(status CapacityProofEpochStatus, registered uint64) bool {
	declared := status.DeclaredCapacityBytes
	if declared == 0 || registered < declared || status.MaxManifestOverheadBytes == 0 {
		return false
	}
	permitted := status.MaxManifestOverheadBytes
	if permitted > declared {
		permitted = declared
	}
	representable := ^uint64(0) - declared
	if permitted > representable {
		permitted = representable
	}
	return registered-declared <= permitted
}

func capacityProofFreshUntilChain(status CapacityProofEpochStatus) int64 {
	if status.LastCapacityProofAt == 0 || status.MaxProofAgeSeconds == 0 ||
		status.LastCapacityProofAt > ^uint64(0)-status.MaxProofAgeSeconds {
		return 0
	}
	until := status.LastCapacityProofAt + status.MaxProofAgeSeconds
	if until > uint64(^uint64(0)>>1) {
		return 0
	}
	return int64(until)
}

func chainPartitionKind(kind string) int {
	if kind == PartitionKindCapacity {
		return 2
	}
	if kind == PartitionKindData {
		return 1
	}
	return 0
}

func epochPartitionKey(kind string, deadlineIndex, partitionIndex int) string {
	return fmt.Sprintf("%s:%d:%d", kind, deadlineIndex, partitionIndex)
}

func preparedCapacityEpochMemberMatchesChain(
	storage string,
	epochID uint64,
	member capacityEpochMemberRef,
	partition CapacityPartitionInfo,
) (bool, error) {
	if partition.CommittedBytes != member.CommittedBytes {
		return false, nil
	}
	queue, found, err := readPartitionProofSnapshotQueue(
		storage, member.PartitionKind, member.DeadlineIndex, member.PartitionIndex,
	)
	if err != nil {
		return false, err
	}
	if !found || queue.Frozen == nil || queue.Frozen.ProofEpochID != epochID ||
		queue.Frozen.ID != member.SnapshotID ||
		!sameRoot(queue.Frozen.ContentHash, member.ContentHash) {
		return false, nil
	}
	expectedChainHash, err := partitionChainContentHash(
		queue.Frozen.Partition, partition.ChallengeCount,
	)
	if err != nil {
		return false, err
	}
	return sameRoot(partition.ContentHash, expectedChainHash), nil
}

func validatePreparedCapacityEpochManifestOnChain(
	storage string,
	chainCmd string,
	journal capacityEpochJournal,
) error {
	capacityPartitions, err := listActiveCapacityPartitionsOnChain(chainCmd)
	if err != nil {
		return fmt.Errorf("list prepared epoch capacity partitions: %w", err)
	}
	dataPartitions, err := listActiveDataPartitionsOnChain(chainCmd)
	if err != nil {
		return fmt.Errorf("list prepared epoch data partitions: %w", err)
	}
	registered := append(capacityPartitions, dataPartitions...)
	if len(registered) != len(journal.Members) {
		return fmt.Errorf(
			"prepared epoch manifest changed before broadcast: chain=%d journal=%d",
			len(registered), len(journal.Members),
		)
	}
	byKey := make(map[string]CapacityPartitionInfo, len(registered))
	for _, partition := range registered {
		kind := PartitionKindData
		if partition.PartitionKind == 2 {
			kind = PartitionKindCapacity
		}
		byKey[epochPartitionKey(kind, partition.DeadlineIndex, partition.PartitionIndex)] = partition
	}
	for _, member := range journal.Members {
		key := epochPartitionKey(member.PartitionKind, member.DeadlineIndex, member.PartitionIndex)
		partition, found := byKey[key]
		if !found {
			return fmt.Errorf("prepared epoch immutable member changed before broadcast: %s", key)
		}
		matches, hashErr := preparedCapacityEpochMemberMatchesChain(
			storage, journal.EpochID, member, partition,
		)
		if hashErr != nil {
			return fmt.Errorf("prepared epoch chain content hash %s: %w", key, hashErr)
		}
		if !matches {
			return fmt.Errorf("prepared epoch immutable member changed before broadcast: %s", key)
		}
	}
	return nil
}

// resumePreparedCapacityProofEpoch is the only recovery path allowed to submit
// a retained opening intent. It rechecks chain state under the publication
// barrier immediately before changing prepared -> opening. An opening record is
// never resubmitted because it may already represent a broadcast whose response
// was lost.
func resumePreparedCapacityProofEpoch(
	storage string,
	storageCfg ServerConfig,
	clock ProofClockStatus,
	previous CapacityProofEpochStatus,
	journal capacityEpochJournal,
) (CapacityProofEpochStatus, error) {
	if journal.State != capacityEpochStatePrepared {
		return previous, fmt.Errorf("capacity epoch %d is not safe to submit from state %s", journal.EpochID, journal.State)
	}
	if journal.EpochID != previous.ProofEpochID+1 || journal.TargetRound != clock.CurrentRound {
		return previous, fmt.Errorf(
			"prepared capacity epoch intent does not match chain/clock: local=%d/%d chain=%d currentRound=%d",
			journal.EpochID, journal.TargetRound, previous.ProofEpochID, clock.CurrentRound,
		)
	}
	// ── B.3.1 phase 0: chain reads with NO coordination lock held ────────────────────────────
	latest, err := capacityProofStatusOnChain(storageCfg.ChainProofCmd)
	if err != nil {
		return previous, fmt.Errorf("recheck capacity epoch before recovery broadcast: %w", err)
	}
	if latest.ProofEpochID != previous.ProofEpochID || latest.Active {
		// Superseded on chain: nothing to submit.
		return latest, nil
	}
	if err := validatePreparedCapacityEpochManifestOnChain(storage, storageCfg.ChainProofCmd, journal); err != nil {
		return previous, err
	}

	// ── phase 1: under the coordination lock, revalidate the intent and CLAIM the attempt ────
	// The claim is durable before the lock is released, so no other process may open or submit
	// a conflicting epoch operation while the RPC is in flight.
	attemptID := newChainAttemptID()
	if err := withCapacityCoordinationLock(storage, func() error {
		if err := capacityPublicationGuardLocked(storage); err != nil {
			return err
		}
		current, found, readErr := readCapacityEpochJournal(storage)
		if readErr != nil {
			return readErr
		}
		if !found || current.EpochID != journal.EpochID || current.TargetRound != journal.TargetRound {
			return fmt.Errorf("prepared capacity epoch intent changed before recovery broadcast")
		}
		switch current.State {
		case capacityEpochStatePrepared:
		case capacityEpochStateOpening:
			// Only the owning process may resume its own unresolved attempt.
			if current.OpenAttemptID != "" && current.OpenAttemptOwner != vkProcessInstanceID {
				return fmt.Errorf("capacity epoch %d already has an open attempt in flight", journal.EpochID)
			}
			if current.OpenAttemptID != "" {
				attemptID = current.OpenAttemptID
			}
		default:
			return fmt.Errorf("prepared capacity epoch intent changed before recovery broadcast")
		}
		return updateCapacityEpochJournal(storage, journal.EpochID, func(cur *capacityEpochJournal) error {
			cur.State = capacityEpochStateOpening
			cur.LastError = ""
			cur.OpenAttemptID = attemptID
			cur.OpenAttemptOwner = vkProcessInstanceID
			cur.OpenAttemptAt = nowRFC3339()
			return nil
		})
	}); err != nil {
		return previous, err
	}

	// ── phase 2: submit with NO lock held ────────────────────────────────────────────────────
	fullMode := journal.FullSweepMode
	if fullMode == 0 {
		fullMode = 2 // legacy prepared journals were initial/full mode
	}
	tx, submitErr := beginCapacityProofEpochOnChain(
		storageCfg.ChainProofCmd, journal.EpochID, journal.TargetRound, fullMode,
	)
	observed, statusErr := capacityProofStatusOnChain(storageCfg.ChainProofCmd)

	// ── phase 3: reconcile the attempt from CHAIN TRUTH under the lock ───────────────────────
	var outcomeErr error
	if err := withCapacityCoordinationLock(storage, func() error {
		current, found, readErr := readCapacityEpochJournal(storage)
		if readErr != nil {
			return readErr
		}
		if !found || current.EpochID != journal.EpochID || current.OpenAttemptID != attemptID {
			// Another attempt owns the epoch now; ours must complete nothing.
			outcomeErr = fmt.Errorf("capacity epoch %d open attempt was superseded", journal.EpochID)
			return nil
		}
		if statusErr != nil {
			// Chain truth unknown: the submission may or may not have landed. Leave the epoch
			// UNRESOLVED (still opening, attempt intact) rather than calling it success or
			// failure — a later pass reconciles it from chain truth.
			outcomeErr = fmt.Errorf("capacity epoch %d submission unresolved: %w", journal.EpochID, statusErr)
			return updateCapacityEpochJournal(storage, journal.EpochID, func(cur *capacityEpochJournal) error {
				cur.LastError = "chain outcome unconfirmed: " + statusErr.Error()
				return nil
			})
		}
		if observed.Active && observed.ProofEpochID == journal.EpochID && observed.TargetRound == journal.TargetRound {
			return updateCapacityEpochJournal(storage, journal.EpochID, func(cur *capacityEpochJournal) error {
				cur.State = capacityEpochStateActive
				cur.LastError = ""
				if tx != "" {
					cur.BeginTx = tx
				}
				cur.OpenAttemptID, cur.OpenAttemptOwner, cur.OpenAttemptAt = "", "", ""
				applyCapacityEpochChainStatus(cur, observed)
				return nil
			})
		}
		// Chain truth is conclusive that our epoch did not open: release the attempt so the
		// prepared intent can be retried exactly once more, without a duplicate submission.
		outcomeErr = fmt.Errorf(
			"recovered capacity epoch confirmation mismatch: epoch=%d round=%d active=%v",
			observed.ProofEpochID, observed.TargetRound, observed.Active,
		)
		if submitErr != nil {
			outcomeErr = submitErr
		}
		return updateCapacityEpochJournal(storage, journal.EpochID, func(cur *capacityEpochJournal) error {
			cur.State = capacityEpochStatePrepared
			cur.OpenAttemptID, cur.OpenAttemptOwner, cur.OpenAttemptAt = "", "", ""
			cur.LastError = outcomeErr.Error()
			return nil
		})
	}); err != nil {
		return previous, err
	}
	if outcomeErr != nil {
		return previous, outcomeErr
	}
	return observed, nil
}

// queueAndBeginCapacityProofEpoch establishes one exact immutable cutoff. The
// global publication barrier is held only while hard-linking current inputs,
// validating the chain manifest, and opening the epoch. Foreground mutations
// publish a waiter record before this lock; the second guard below yields to a
// waiter instead of starting another chain transaction ahead of it.
func queueAndBeginCapacityProofEpoch(
	storage string,
	storageCfg ServerConfig,
	clock ProofClockStatus,
	previous CapacityProofEpochStatus,
	fullReason FullSweepReason,
) (CapacityProofEpochStatus, error) {
	// A.2 gate: opening a capacity proof epoch is a proof-affecting write.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return previous, gateErr
	}
	// The next FULL epoch id must be read from the FULL-epoch ledger, never from
	// `previous`.
	//
	// CapacityProofEpochStatus carries one id field for two identities owned by two
	// contracts: CapacityProofSC's full epoch id, and CapacityIncrementalBatchSC's batch
	// id. Three call sites overwrite the first with the second
	// (chain_storageproof.go:1136, :1179, capacity_campaign_routing.go:332), and nothing
	// downstream can tell which it holds. So `previous.ProofEpochID + 1` silently derives
	// a FULL id from a BATCH id whenever the last campaign was incremental.
	//
	// The contract keeps the domains apart and rejects the result outright:
	// ProofAuthorityDomains requires 0 < id < 1<<62 for a full epoch, and bit 62 marks the
	// incremental domain. Live 2026-09-22: vk_6's last campaign was batch
	// 4611686018427388054, so this produced 4611686018427388055 and every scan got
	// FullEpochIdOutOfDomain(4611686018427388055) -- forever, because the same input
	// produced the same bad id each time.
	//
	// Reading the ledger removes the guess rather than masking it. This function already
	// calls capacityProofStatusOnChain in phase 2; doing it first costs one extra read and
	// makes the id authoritative.
	ledger, ledgerErr := capacityProofStatusOnChain(storageCfg.ChainProofCmd)
	if ledgerErr != nil {
		return previous, fmt.Errorf("read full capacity epoch ledger: %w", ledgerErr)
	}
	if ledger.ProofEpochID&capacityAuthorityDomainMask != 0 {
		return previous, fmt.Errorf(
			"full capacity epoch ledger returned an out-of-domain id %d", ledger.ProofEpochID)
	}
	epochID := ledger.ProofEpochID + 1
	if epochID == 0 || epochID&capacityAuthorityDomainMask != 0 {
		return previous, fmt.Errorf("capacity proof epoch id overflow")
	}
	fullMode, modeErr := fullSweepReasonOnChainMode(fullReason)
	if modeErr != nil {
		return previous, modeErr
	}
	// ── B.3.1 phase 0: chain reads with NO coordination lock held ────────────────────────────
	hoistedCapacityChain, err := listActiveCapacityPartitionsOnChain(storageCfg.ChainProofCmd)
	if err != nil {
		return previous, fmt.Errorf("list epoch capacity partitions: %w", err)
	}
	hoistedDataChain, err := listActiveDataPartitionsOnChain(storageCfg.ChainProofCmd)
	if err != nil {
		return previous, fmt.Errorf("list epoch data partitions: %w", err)
	}
	attemptID := newChainAttemptID()
	err = withCapacityCoordinationLock(storage, func() error {
		if err := capacityPublicationGuardLocked(storage); err != nil {
			return err
		}
		sectors, err := listSectors(storage)
		if err != nil {
			return err
		}
		local := buildDeadlinePartitionsAt(
			sectors, storageCfg.DeadlineCount, storageCfg.PartitionMaxSectors,
			clock.ChainTimestamp,
		)
		localByKey := make(map[string]PartitionMeta, len(local))
		for _, partition := range local {
			if partition.PartitionKind != PartitionKindCapacity && partition.PartitionKind != PartitionKindData {
				continue
			}
			localByKey[epochPartitionKey(
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
			)] = partition
		}

		// B.3.1: read outside the lock (see the hoisted reads above); validated here against
		// local truth while the coordination lock is held.
		capacityChain, dataChain := hoistedCapacityChain, hoistedDataChain
		chainPartitions := append(capacityChain, dataChain...)
		if len(chainPartitions) == 0 || len(chainPartitions) != len(localByKey) {
			return fmt.Errorf(
				"epoch manifest count mismatch: chain=%d local=%d",
				len(chainPartitions), len(localByKey),
			)
		}
		var chainBytes uint64
		for _, registered := range chainPartitions {
			kind := PartitionKindData
			if registered.PartitionKind == 2 {
				kind = PartitionKindCapacity
			}
			key := epochPartitionKey(kind, registered.DeadlineIndex, registered.PartitionIndex)
			partition, ok := localByKey[key]
			if !ok {
				return fmt.Errorf("epoch chain partition %s is absent locally", key)
			}
			if chainPartitionKind(partition.PartitionKind) != registered.PartitionKind ||
				partition.CommittedBytes != registered.CommittedBytes {
				return fmt.Errorf("epoch partition accounting mismatch for %s", key)
			}
			expectedHash, hashErr := partitionChainContentHash(partition, registered.ChallengeCount)
			if hashErr != nil {
				return fmt.Errorf("epoch partition hash %s: %w", key, hashErr)
			}
			if !sameRoot(expectedHash, registered.ContentHash) {
				return fmt.Errorf("epoch partition content mismatch for %s", key)
			}
			if registered.CommittedBytes < 0 {
				return fmt.Errorf("epoch partition %s has negative committed bytes", key)
			}
			amount := uint64(registered.CommittedBytes)
			if chainBytes > ^uint64(0)-amount {
				return fmt.Errorf("epoch manifest byte total overflow")
			}
			chainBytes += amount
		}
		if !capacityManifestWithinProofBounds(previous, chainBytes) {
			return fmt.Errorf(
				"epoch bytes outside proof bounds: chain=%d declared=%d maxOverhead=%d",
				chainBytes, previous.DeclaredCapacityBytes, previous.MaxManifestOverheadBytes,
			)
		}

		for _, partition := range localByKey {
			if _, destructive, err := queuePartitionProofSnapshot(
				storage, partition, epochID, clock.CurrentRound, time.Time{},
			); err != nil {
				return fmt.Errorf(
					"queue epoch partition %s: %w",
					epochPartitionKey(partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex), err,
				)
			} else if destructive {
				return fmt.Errorf("epoch cutoff encountered an unretained local generation")
			}
		}
		cutoffPartitions := make([]PartitionMeta, 0, len(localByKey))
		for _, partition := range localByKey {
			cutoffPartitions = append(cutoffPartitions, partition)
		}
		journal, err := newCapacityEpochJournal(
			storage, epochID, clock.CurrentRound, previous, cutoffPartitions,
		)
		if err != nil {
			return fmt.Errorf("build durable capacity epoch journal: %w", err)
		}
		journal.FullSweepMode = fullMode
		journal.FullSweepReason = string(fullReason)
		journal.FullBaselineCandidate, err = newFullCapacityBaselineCandidate(
			storage, storageCfg, previous, epochID,
		)
		if err != nil {
			return fmt.Errorf("build full capacity baseline candidate: %w", err)
		}
		if err := createCapacityEpochJournal(storage, journal); err != nil {
			return fmt.Errorf("persist durable capacity epoch journal: %w", err)
		}
		if err := reconcileCapacityMutationEpochUnlocked(
			storage, journal, journal.State,
		); err != nil {
			return fmt.Errorf("seal capacity mutations for epoch %d: %w", epochID, err)
		}

		// A foreground waiter may have appeared while chain reads and hard links
		// were in progress. Yield before broadcasting the epoch transaction.
		if err := capacityPublicationGuardLocked(storage); err != nil {
			_ = updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
				journal.State = capacityEpochStateAbandoned
				journal.LastError = err.Error()
				return nil
			})
			return err
		}
		// B.3.1: durably CLAIM the open attempt before releasing the lock. No other process may
		// then open or submit a conflicting epoch operation while the RPC is in flight.
		if err := updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
			journal.State = capacityEpochStateOpening
			journal.LastError = ""
			journal.OpenAttemptID = attemptID
			journal.OpenAttemptOwner = vkProcessInstanceID
			journal.OpenAttemptAt = nowRFC3339()
			return nil
		}); err != nil {
			return fmt.Errorf("mark capacity epoch opening: %w", err)
		}
		log.Printf(
			"[capacity-epoch] opening epoch=%d round=%d partitions=%d bytes=%d attempt=%s",
			epochID, clock.CurrentRound, len(localByKey), chainBytes, attemptID,
		)
		return nil
	})
	if err != nil {
		return previous, err
	}

	// ── phase 2: submit with NO lock held ────────────────────────────────────────────────────
	tx, submitErr := beginCapacityProofEpochOnChain(
		storageCfg.ChainProofCmd, epochID, clock.CurrentRound, fullMode)
	observed, statusErr := capacityProofStatusOnChain(storageCfg.ChainProofCmd)

	// ── phase 3: reconcile the attempt from CHAIN TRUTH under the lock ───────────────────────
	var outcomeErr error
	if err := withCapacityCoordinationLock(storage, func() error {
		current, found, readErr := readCapacityEpochJournal(storage)
		if readErr != nil {
			return readErr
		}
		if !found || current.EpochID != epochID || current.OpenAttemptID != attemptID {
			outcomeErr = fmt.Errorf("capacity epoch %d open attempt was superseded", epochID)
			return nil
		}
		if statusErr != nil {
			// Chain truth unknown: leave the epoch UNRESOLVED (still opening, attempt intact).
			outcomeErr = fmt.Errorf("capacity epoch %d submission unresolved: %w", epochID, statusErr)
			return updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
				journal.LastError = "chain outcome unconfirmed: " + statusErr.Error()
				return nil
			})
		}
		if observed.Active && observed.ProofEpochID == epochID && observed.TargetRound == clock.CurrentRound {
			return updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
				if tx != "" {
					journal.BeginTx = tx
				}
				journal.LastError = ""
				journal.OpenAttemptID, journal.OpenAttemptOwner, journal.OpenAttemptAt = "", "", ""
				return nil
			})
		}
		outcomeErr = fmt.Errorf(
			"capacity proof epoch confirmation mismatch: epoch=%d round=%d active=%v",
			observed.ProofEpochID, observed.TargetRound, observed.Active,
		)
		if submitErr != nil {
			outcomeErr = submitErr
		}
		return updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
			journal.State = capacityEpochStatePrepared
			journal.OpenAttemptID, journal.OpenAttemptOwner, journal.OpenAttemptAt = "", "", ""
			journal.LastError = outcomeErr.Error()
			return nil
		})
	}); err != nil {
		return previous, err
	}
	if outcomeErr != nil {
		return previous, outcomeErr
	}
	log.Printf("[capacity-epoch] started epoch=%d round=%d tx=%s", epochID, clock.CurrentRound, tx)
	if err := updateCapacityEpochJournal(storage, epochID, func(journal *capacityEpochJournal) error {
		journal.State = capacityEpochStateActive
		journal.LastError = ""
		applyCapacityEpochChainStatus(journal, observed)
		return nil
	}); err != nil {
		return previous, fmt.Errorf("confirm durable capacity epoch journal: %w", err)
	}
	return observed, nil
}

// proofErrorDefersWithoutRetryState reports whether a scan outcome is a DEFERRAL rather than a
// proof failure: the prover was never asked to prove anything, so the recovery budget must not
// move and no retry state may be written.
//
// This exists as a named rule because the retry recorder escalates every error it does not
// recognise, and the cost of a miss is severe and silent: the budget runs out, the partition is
// marked terminal, and a terminal record is never auto-eligible again
// (proof_retry.go:134-139). The keeper then refuses forever to prove a partition that never
// failed to prove, which closes admission on oldest_dirty_hard_lag.
//
// Live on 2026-10-03, keeper 0xFABB0ac9: a plain `fmt.Errorf("deletion in progress")` was not
// recognised here, so 50 ordinary deletion skips drove data dl=42 pt=0 to terminal and held the
// keeper closed for 22 hours with no real proof failure anywhere.
//
// Anything that genuinely attempted and failed a proof must NOT be listed here.
func proofErrorDefersWithoutRetryState(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrPartitionProofSnapshotBatching):
		// Batching is intentional and must not create exponential retry state.
		return true
	case errors.Is(err, ErrPartitionFreezeCrossAuthority):
		// A.3: the other authority owns the frozen slot. Defer to the A.2.5 arbiter (no
		// rebind) and retry on a later scan without escalating retry state.
		return true
	case errors.Is(err, ErrPartitionDeletionInProgress):
		// A deletion owns this content right now. Nothing was proved and nothing failed.
		return true
	}
	return false
}

// abandonExcludedCapacityFreeze releases the on-chain capacity freeze for exactly ONE
// partition, using the generation the CHAIN holds.
//
// reconcileInactiveEpochSnapshotQueues cannot do this. It is record-driven: it walks the local
// snapshot queues and skips any whose `Frozen.ProofEpochID` is 0 or belongs to the active
// epoch. So an on-chain freeze that NO local record claims is invisible to it, and it returns
// success having changed nothing.
//
// Live on 2026-10-03, keeper 0xFABB0ac9, partition data dl=42 pt=0: the chain held a capacity
// freeze (the arbiter read holder=capacity from frozenSnapshots), while the local queue record
// for that same partition carried no epoch id at all -- `proofEpochID` absent, state "queued".
// An orphaned slot: occupied on chain, owned by nobody locally. Making the release reachable
// from the deletion authority was necessary but not sufficient; the release then ran and freed
// nothing, because the reconciler skipped the record on its very first filter.
//
// Returns true when a freeze was actually abandoned on chain.
func abandonExcludedCapacityFreeze(
	chainCmd string, partition PartitionMeta,
) (bool, error) {
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return false, gateErr
	}
	status, err := frozenPartitionSnapshotStatusOnChain(chainCmd, partition)
	if err != nil {
		return false, err
	}
	if !status.Exists || status.ProofEpochID == 0 {
		return false, nil
	}
	if status.ProofEpochID&standaloneDeletionProofFlag != 0 {
		// The standalone deletion slot is owned by the deletion lifecycle and has its own
		// non-preemptible path. Never released from here.
		return false, nil
	}
	if status.ContentVersion == 0 || status.SnapshotNonce == 0 {
		// Without the chain's own generation identity an abandon is refused outright, and
		// guessing one would be worse than waiting.
		return false, nil
	}
	retire := partitionProofSnapshot{
		Partition:        partition,
		ProofEpochID:     status.ProofEpochID,
		ContentVersion:   status.ContentVersion,
		ChainContentHash: status.ContentHash,
		SnapshotNonce:    status.SnapshotNonce,
	}
	if _, err := abandonFrozenPartitionSnapshotOnChain(chainCmd, retire); err != nil {
		return false, err
	}
	log.Printf("[freeze-arbiter] released excluded capacity freeze kind=%s dl=%d pt=%d "+
		"epoch=%d chain=v%d/g%d",
		partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
		status.ProofEpochID, status.ContentVersion, status.SnapshotNonce)
	return true, nil
}

func reconcileInactiveEpochSnapshotQueues(
	storage, chainCmd string,
	active CapacityProofEpochStatus,
) error {
	// A.2 gate: retiring inactive snapshots abandons on-chain and advances records — a
	// proof-affecting write path.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return gateErr
	}
	pendingJournal, pendingJournalFound, err := readCapacityEpochJournal(storage)
	if err != nil {
		return fmt.Errorf("read capacity epoch journal before snapshot recovery: %w", err)
	}
	queues, err := listPartitionProofSnapshotQueues(storage)
	if err != nil {
		return err
	}
	for _, queue := range queues {
		if queue.Frozen == nil || queue.Frozen.ProofEpochID == 0 ||
			(active.Active && queue.Frozen.ProofEpochID == active.ProofEpochID) {
			continue
		}
		if pendingJournalFound && queue.Frozen.ProofEpochID == pendingJournal.EpochID &&
			(pendingJournal.State == capacityEpochStatePrepared ||
				pendingJournal.State == capacityEpochStateOpening) {
			// The chain transaction may not have been broadcast yet, or may be
			// pending with a lost response. Preserve its immutable cutoff until
			// journal reconciliation proves the target round has expired.
			continue
		}
		// Standalone deletion-successor snapshots are owned by the durable
		// deletion lifecycle, not by the capacity-epoch reconciler. Retiring one
		// here could strand a declared deletion between proof and confirmation.
		if queue.Frozen.ProofEpochID&standaloneDeletionProofFlag != 0 {
			continue
		}
		snapshot := *queue.Frozen
		// A.1 fence: the queue set was listed earlier; re-confirm this generation is still
		// the live slot before abandoning it on-chain and advancing the record.
		if err := verifyPartitionGenerationLive(storage, snapshot); err != nil {
			if errors.Is(err, ErrPartitionProofSnapshotSuperseded) {
				continue
			}
			return err
		}
		status, statusErr := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition)
		if statusErr != nil {
			return statusErr
		}
		if status.Exists && status.ProofEpochID == snapshot.ProofEpochID {
			// Abandon the generation the CHAIN actually holds, not the one this record
			// remembers. The chain is the authority on what occupies the slot, and the
			// two can legitimately differ: a re-anchor or re-freeze advances the on-chain
			// generation without rewriting this local record.
			//
			// Sending the stale generation is refused outright — "refuse to abandon
			// snapshot generation 3 as requested generation 2" — and that error aborts the
			// whole reconciler, so the record below is never advanced and every later
			// recovery finds the same stale snapshot again. Live 2026-09-22: vk_6 held
			// capacity dl47-pt128 at local generation 2 against chain generation 3 and
			// repeated those four deferrals every 90 s for three hours.
			//
			// The epoch is still required to match, so this only ever retires a snapshot
			// belonging to the epoch this record names. Identity comes from the chain read
			// taken moments ago in this same scan.
			retire := snapshot
			retire.ContentVersion = status.ContentVersion
			retire.ChainContentHash = status.ContentHash
			retire.SnapshotNonce = status.SnapshotNonce
			if retire.SnapshotNonce != snapshot.SnapshotNonce ||
				retire.ContentVersion != snapshot.ContentVersion {
				log.Printf("[capacity-epoch] retiring chain generation kind=%s dl=%d pt=%d "+
					"chain=v%d/g%d local=v%d/g%d",
					snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex,
					snapshot.Partition.PartitionIndex, retire.ContentVersion, retire.SnapshotNonce,
					snapshot.ContentVersion, snapshot.SnapshotNonce)
			}
			if _, err := abandonFrozenPartitionSnapshotOnChain(chainCmd, retire); err != nil {
				return err
			}
		}
		if err := advancePartitionProofSnapshot(storage, snapshot); err != nil {
			return err
		}
		log.Printf(
			"[capacity-epoch] retired inactive snapshot epoch=%d kind=%s dl=%d pt=%d",
			snapshot.ProofEpochID, snapshot.Partition.PartitionKind,
			snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
		)
	}
	return nil
}

func prependUniqueFrozenCandidates(
	frozen, scheduled []partitionProofCandidate,
) []partitionProofCandidate {
	seen := map[partitionBucketKey]bool{}
	out := make([]partitionProofCandidate, 0, len(frozen)+len(scheduled))
	appendUnique := func(candidate partitionProofCandidate) {
		key := partitionBucketKey{
			deadlineIndex:  candidate.Partition.DeadlineIndex,
			partitionIndex: candidate.Partition.PartitionIndex,
			kind:           candidate.Partition.PartitionKind,
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, candidate)
	}
	for _, candidate := range frozen {
		appendUnique(candidate)
	}
	for _, candidate := range scheduled {
		appendUnique(candidate)
	}
	return out
}

func partitionProofTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// orderedPartitionProofCandidates produces a fair local queue. Each VK submits
// only the first unit to the shared host EDF queue, then rescans durable state.
// Oldest last-proof time wins; capacity wins only an exact age tie, preventing
// continuously arriving data changes from starving capacity forever.
func orderedPartitionProofCandidates(
	urgentData, scheduledData, urgentCapacity, scheduledCapacity []PartitionMeta,
	capacityPending bool,
	deadline time.Time,
) []partitionProofCandidate {
	candidates := make([]partitionProofCandidate, 0,
		len(urgentData)+len(scheduledData)+len(urgentCapacity)+len(scheduledCapacity))
	appendGroup := func(partitions []PartitionMeta, priority string, urgent bool) {
		for _, partition := range partitions {
			candidates = append(candidates, partitionProofCandidate{
				Partition: partition, Priority: priority, Urgent: urgent, Deadline: deadline,
			})
		}
	}
	appendGroup(urgentData, "data-urgent", true)
	appendGroup(scheduledData, "data-deadline", false)
	if !capacityPending {
		appendGroup(urgentCapacity, "capacity-urgent", true)
		appendGroup(scheduledCapacity, "capacity-deadline", false)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		aTime, bTime := partitionProofTime(a.Partition.LastProofAt), partitionProofTime(b.Partition.LastProofAt)
		if !aTime.Equal(bTime) {
			return aTime.Before(bTime)
		}
		if a.Partition.LastProofRound != b.Partition.LastProofRound {
			return a.Partition.LastProofRound < b.Partition.LastProofRound
		}
		if a.Urgent != b.Urgent {
			return a.Urgent
		}
		if a.Partition.PartitionKind != b.Partition.PartitionKind {
			return a.Partition.PartitionKind == PartitionKindCapacity
		}
		if a.Partition.DeadlineIndex != b.Partition.DeadlineIndex {
			return a.Partition.DeadlineIndex < b.Partition.DeadlineIndex
		}
		return a.Partition.PartitionIndex < b.Partition.PartitionIndex
	})
	return candidates
}

// recurringPartitionProofCandidates builds the candidate list for a recurring
// StorageProof round: urgent work of both kinds, plus scheduled work of both kinds
// narrowed to the deadline window that is open now.
//
// Both planners call this. They were open-coded separately before, and the copies
// drifted — snapshot mode passed no capacity partitions at all, so a keeper whose
// capacity content never changed had no path to a recurring capacity proof and went
// four rounds stale while every other signal said it was healthy.
func recurringPartitionProofCandidates(
	storage string,
	urgentDue, scheduledDue []PartitionMeta,
	activeDeadlineIndex int,
	capacityPending bool,
	deadline time.Time,
) []partitionProofCandidate {
	return orderedPartitionProofCandidates(
		partitionsByKind(urgentDue, PartitionKindData),
		deadlinePartitions(partitionsByKind(scheduledDue, PartitionKindData), activeDeadlineIndex),
		withoutCampaignOwnedPartitions(storage, partitionsByKind(urgentDue, PartitionKindCapacity)),
		withoutCampaignOwnedPartitions(storage,
			deadlinePartitions(partitionsByKind(scheduledDue, PartitionKindCapacity), activeDeadlineIndex)),
		capacityPending, deadline,
	)
}

// withoutCampaignOwnedPartitions drops capacity partitions a campaign has frozen.
//
// A campaign anchors its members on chain at the campaign's own round. Proving one
// of those again at the CURRENT round leaves the campaign unable to finish its own
// copy — "refuse to reanchor a different snapshot", seen on vk_6 two minutes after
// the recurring planner first offered capacity work.
//
// Only the frozen partition is withheld, not every capacity partition on a keeper
// that happens to be running a campaign: vk_6 proved its other capacity partition
// in the same minute without trouble, and withholding that one would restore the
// very starvation this planner exists to prevent. Unreadable snapshot state counts
// as frozen — never race a campaign on a guess.
func withoutCampaignOwnedPartitions(storage string, partitions []PartitionMeta) []PartitionMeta {
	if len(partitions) == 0 {
		return partitions
	}
	out := make([]PartitionMeta, 0, len(partitions))
	for _, partition := range partitions {
		frozen, err := partitionHasFrozenProofSnapshot(
			storage, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
		)
		if err != nil {
			log.Printf("[proof-daemon] capacity dl%d-pt%d withheld; snapshot state unreadable: %v",
				partition.DeadlineIndex, partition.PartitionIndex, err)
			continue
		}
		if frozen {
			continue
		}
		out = append(out, partition)
	}
	return out
}

// capacityCampaignDurationClass decides the C.1 class from AUTHORITATIVE campaign facts only:
// the proof-authority domain (incremental batch vs full epoch) and the campaign's FROZEN member
// count. It never inspects timing, partition kind, filenames or the proof-shape key. A standalone
// deletion proof is not capacity work and gets no capacity class.
//
// The member count MUST come from the durable campaign journal, not from the candidates remaining
// in this scan. The remaining set shrinks as members complete (3 -> 2 -> 1), so using it would make
// the FINAL member of every batch train capacity_single and slowly re-mix the very histories C.1
// separates. Observed live 2026-08-13: a 3-member refresh produced 2x capacity_batch + 1x
// capacity_single. A campaign is single or batch work for its whole life, decided once at freeze.
func capacityCampaignDurationClass(storage string, proofEpochID uint64, _ int) string {
	if proofEpochID == 0 || proofEpochID&standaloneDeletionProofFlag != 0 {
		return ""
	}
	// FAIL CLOSED. The ONLY trusted member count is the campaign's frozen journal membership.
	// An active campaign with a missing or mismatched journal is a recovery state (observed live
	// 2026-08-13: "cannot adopt active capacity epoch ...: immutable unresolved members=0
	// chain=7"), and the draining candidate count must NEVER stand in for frozen membership —
	// that is exactly the 3->2->1 bug. Returning "" trains none of capacity_single/batch/audit;
	// the job keeps its G.3 shape-key label, whose legacy `capacity` bucket is retained only for
	// compatibility and is never read for the three class estimates.
	journal, found, err := readCapacityEpochJournal(storage)
	if err != nil || !found || journal.EpochID != proofEpochID || len(journal.Members) == 0 {
		return ""
	}
	// Frozen membership at campaign open — stable for the campaign's whole life.
	return capacityProofDurationClass(
		proofEpochID&incrementalCapacityAuthorityFlag == 0, len(journal.Members))
}

func provePartitionCandidates(
	storage string,
	candidates []partitionProofCandidate,
	proofEpochID, round uint64,
	challengeCount, deadlineCount, partitionMaxSectors int,
	partitionProverCmd, chainCmd string,
	snapshotProtocol, deterministicChallenge, all bool,
	chainTimestamp int64,
) (attempted bool, allSucceeded bool) {
	now := time.Now().UTC()
	eligible := make([]partitionProofCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		ready, retryErr := partitionProofRetryEligible(storage, candidate.Partition, now)
		if retryErr != nil {
			// Retry metadata is only a liveness optimization. Never let it suppress a
			// required proof when its own storage is unavailable.
			log.Printf("[proof-daemon] retry-state warning dl=%d pt=%d: %v",
				candidate.Partition.DeadlineIndex, candidate.Partition.PartitionIndex, retryErr)
			ready = true
		}
		if ready || all {
			eligible = append(eligible, candidate)
		}
	}
	return runPartitionCandidateSequence(eligible, all, func(candidate partitionProofCandidate) bool {
		var proofErr error
		if snapshotProtocol {
			proofErr = provePartitionSnapshotCandidate(
				storage, candidate.Partition, proofEpochID, round,
				deadlineCount, partitionMaxSectors,
				partitionProverCmd, chainCmd,
				candidate.Priority, candidate.Deadline, chainTimestamp, false, false,
				capacityCampaignDurationClass(storage, proofEpochID, len(eligible)),
			)
		} else {
			// Periodic proofs target StorageProofSC directly. They prove exact current
			// content and are independent of capacity/deletion snapshot authority.
			proofErr = provePartitionCandidate(
				storage, candidate.Partition, round,
				challengeCount, deadlineCount, partitionMaxSectors,
				partitionProverCmd, chainCmd, deterministicChallenge,
				candidate.Priority, candidate.Deadline, chainTimestamp,
			)
		}
		if proofErr != nil {
			if proofErrorDefersWithoutRetryState(proofErr) {
				return false
			}
			if errors.Is(proofErr, ErrPartitionProofSnapshotReanchored) {
				// The immutable bytes are still valid. Wait for a block after the new
				// anchor instead of treating normal shared-host queue delay as failure.
				_ = clearPartitionProofRetry(storage, candidate.Partition)
				return false
			}
			if errors.Is(proofErr, ErrPartitionProofSnapshotInvalidated) {
				// The obsolete generation was safely advanced. It is not a failure and
				// the successor is immediately eligible on the next scheduler scan.
				_ = clearPartitionProofRetry(storage, candidate.Partition)
				return true
			}
			// Observability only. Before this, a persistently failing member wrote its error to
			// retry state and returned silently, so a campaign could sit at progress=0/N forever
			// with NOTHING in the log — which is exactly how the 2026-08-12 "partition deletion in
			// progress" stall stayed invisible for a whole run. Log on the FIRST failure and then
			// only on escalating powers of two, so a long-running failure never floods the log.
			failures := 1
			_ = withPartitionProofRetryState(storage, func(state *partitionProofRetryState) error {
				if state != nil && state.Entries != nil {
					if entry, ok := state.Entries[partitionProofRetryKey(candidate.Partition)]; ok {
						failures = entry.Failures + 1
					}
				}
				return nil
			})
			if failures == 1 || failures&(failures-1) == 0 {
				log.Printf("[proof-daemon] partition proof failing kind=%s dl=%d pt=%d epoch=%d "+
					"failures=%d: %v",
					candidate.Partition.PartitionKind, candidate.Partition.DeadlineIndex,
					candidate.Partition.PartitionIndex, proofEpochID, failures, proofErr)
			}
			if retryErr := recordPartitionProofRetry(storage, candidate.Partition, proofErr, time.Now().UTC()); retryErr != nil {
				log.Printf("[proof-daemon] retry-state persist warning dl=%d pt=%d: %v",
					candidate.Partition.DeadlineIndex, candidate.Partition.PartitionIndex, retryErr)
			}
			return false
		}
		if retryErr := clearPartitionProofRetry(storage, candidate.Partition); retryErr != nil {
			log.Printf("[proof-daemon] retry-state clear warning dl=%d pt=%d: %v",
				candidate.Partition.DeadlineIndex, candidate.Partition.PartitionIndex, retryErr)
		}
		return true
	})
}

// runPartitionCandidateSequence caps normal operation at one successful proof
// per scheduler scan, but never lets a broken oldest partition block every
// later partition. `all` is used by the explicit one-shot maintenance mode.
func runPartitionCandidateSequence(
	candidates []partitionProofCandidate,
	all bool,
	prove func(partitionProofCandidate) bool,
) (attempted bool, allSucceeded bool) {
	allSucceeded = true
	for _, candidate := range candidates {
		attempted = true
		if prove(candidate) {
			if !all {
				return true, true
			}
			continue
		}
		allSucceeded = false
		// In normal daemon mode, continue past failures until one durable unit
		// succeeds. This bounds successful work while preserving liveness for all
		// other partitions. If the entire chain/RPC is unavailable, every quick
		// attempt fails and the outer poll delay provides backoff.
	}
	return attempted, allSucceeded
}

func provePartitionCandidate(
	storage string,
	partition PartitionMeta,
	round uint64,
	challengeCount, deadlineCount, partitionMaxSectors int,
	partitionProverCmd, chainCmd string,
	deterministicChallenge bool,
	priority string,
	workDeadline time.Time,
	chainTimestamp int64,
) error {
	pending, pendingErr := partitionHasPendingDeletion(storage, partition.DeadlineIndex, partition.PartitionIndex)
	if pendingErr != nil {
		log.Printf("[proof-daemon] priority=%s partition dl=%d pt=%d deletion check failed: %v",
			priority, partition.DeadlineIndex, partition.PartitionIndex, pendingErr)
		return pendingErr
	}
	if pending {
		err := ErrPartitionDeletionInProgress
		log.Printf("[proof-daemon] priority=%s partition dl=%d pt=%d skipped: %v",
			priority, partition.DeadlineIndex, partition.PartitionIndex, err)
		return err
	}
	log.Printf("[proof-daemon] priority=%s dl=%d pt=%d kind=%s sectors=%d proving ...",
		priority, partition.DeadlineIndex, partition.PartitionIndex, partition.PartitionKind, len(partition.Sectors))
	if _, err := provePartitionWithChain(
		storage, partition, round, challengeCount, deadlineCount, partitionMaxSectors,
		partitionProverCmd, chainCmd, deterministicChallenge, false, workDeadline, chainTimestamp,
	); err != nil {
		log.Printf("[proof-daemon] priority=%s partition dl=%d pt=%d proof failed: %v",
			priority, partition.DeadlineIndex, partition.PartitionIndex, err)
		return err
	}
	log.Printf("[proof-daemon] priority=%s partition dl=%d pt=%d proof submitted round=%d",
		priority, partition.DeadlineIndex, partition.PartitionIndex, round)
	return nil
}

func zeroBytes32(value string) bool {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(value), "0x"), "0X")
	return trimmed == "" || strings.Trim(trimmed, "0") == ""
}

func partitionLatestMutationAt(partition PartitionMeta) time.Time {
	latest := time.Time{}
	for _, sector := range partition.Sectors {
		updated := partitionProofTime(sector.UpdatedAt)
		if updated.After(latest) {
			latest = updated
		}
	}
	return latest
}

// partitionSnapshotFreezeEligible lets a new partition fill before sealing it,
// while deriving the quiescence cutoff from measured proof cost and the chain's
// hard first-proof deadline. This avoids one partition coordinate per piece and
// still makes missing a proof deadline impossible merely because traffic never
// becomes globally idle.
func partitionSnapshotFreezeEligible(
	storage, chainCmd string,
	partition PartitionMeta,
	partitionMaxSectors int,
	chainTimestamp int64,
) (bool, string, error) {
	if frozen, err := partitionHasFrozenProofSnapshot(
		storage, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
	); err != nil {
		return false, "", err
	} else if frozen {
		return true, "resume frozen generation", nil
	}
	if partitionMaxSectors > 0 && len(partition.Sectors) >= partitionMaxSectors {
		return true, "partition reached circuit capacity", nil
	}
	status, err := partitionVersionStatusOnChain(chainCmd, partition)
	if err != nil {
		return false, "", err
	}
	if !partitionMatchesChainContent(status, partition) {
		return false, "waiting for exact chain registration", nil
	}
	// Recurring work for content that is already current/proven is only offered by
	// the scheduler in its assigned deadline window; do not delay it again.
	if currentPartitionVersionIsProven(status, partition) {
		return true, "recurring proof window", nil
	}
	period := time.Duration(status.ProofPeriodSeconds) * time.Second
	if period <= 0 {
		return false, "", fmt.Errorf("partition proof status is missing proof period")
	}
	class := fmt.Sprintf("%s-final-n%d", partition.PartitionKind, len(partition.Sectors))
	estimate := time.Duration(0)
	if lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv)); lockPath != "" {
		estimate = time.Duration(readProofWorkEstimate(lockPath, class))
	}
	if estimate <= 0 {
		// Before hardware-specific measurements exist, reserve one third of the
		// proof period. Subsequent runs converge to the rolling measured duration.
		estimate = period / 3
	}
	if estimate < 30*time.Second {
		estimate = 30 * time.Second
	}
	safety := estimate / 5
	if safety < 30*time.Second {
		safety = 30 * time.Second
	}
	if status.RegisteredAt > 0 {
		hardDeadline := int64(status.RegisteredAt + status.ProofPeriodSeconds)
		if chainTimestamp+int64((estimate+safety)/time.Second) >= hardDeadline {
			return true, "first-proof deadline requires freeze", nil
		}
	}
	quiescence := estimate / 4
	if maximum := period / 10; quiescence > maximum {
		quiescence = maximum
	}
	if quiescence < 5*time.Second {
		quiescence = 5 * time.Second
	}
	latest := partitionLatestMutationAt(partition)
	if latest.IsZero() || time.Since(latest) >= quiescence {
		return true, "adaptive quiescence reached", nil
	}
	return false, fmt.Sprintf("coalescing for %s", quiescence.Round(time.Second)), nil
}

// prepareFrozenPartitionSnapshot captures one immutable generation while the
// partition mutation lock is held. The only chain transactions under this lock
// are the short freeze/status operations; cache preparation and Groth16 proving
// happen after it is released, so uploads to successor coordinates continue.
func prepareFrozenPartitionSnapshot(
	storage string,
	requested PartitionMeta,
	proofEpochID, round uint64,
	deadline time.Time,
	deadlineCount, partitionMaxSectors int,
	chainCmd string,
	chainTimestamp int64,
	allowPendingDeletion bool,
	freezeCoord *freezeBroadcastCoord,
) (partitionProofSnapshot, bool, error) {
	lock, err := acquirePartitionLifecycleLock(storage, requested.DeadlineIndex, requested.PartitionIndex)
	if err != nil {
		return partitionProofSnapshot{}, false, err
	}
	lockHeld := true
	releasePartitionLock := func() {
		if lockHeld {
			lock.Release()
			lockHeld = false
		}
	}
	defer releasePartitionLock()
	existingQueue, queueFound, queueErr := readPartitionProofSnapshotQueue(
		storage, requested.PartitionKind, requested.DeadlineIndex, requested.PartitionIndex,
	)
	if queueErr != nil {
		return partitionProofSnapshot{}, false, queueErr
	}
	if queueFound && existingQueue.Frozen != nil && existingQueue.Frozen.ContentVersion != 0 {
		if existingQueue.Frozen.ProofEpochID != proofEpochID ||
			existingQueue.Frozen.Round != round {
			// Deletion may request the standalone proof domain while the exact
			// same bytes are already frozen as a capacity-cutoff member. Reuse
			// that freeze; do not force a capacity→standalone rebind.
			if allowPendingDeletion && samePartitionSnapshotContent(existingQueue.Frozen, requested) {
				return *existingQueue.Frozen, false, nil
			}
			return partitionProofSnapshot{}, false, fmt.Errorf(
				"durable snapshot belongs to epoch=%d round=%d, requested epoch=%d round=%d",
				existingQueue.Frozen.ProofEpochID, existingQueue.Frozen.Round,
				proofEpochID, round,
			)
		}
		// A chain-frozen generation is independently provable from its pinned
		// artifact even when current live content has moved or disappeared.
		return *existingQueue.Frozen, false, nil
	}

	prepare := func() (partitionProofSnapshot, bool, error) {
		var snapshot partitionProofSnapshot
		var destructive bool
		localPrepare := func() error {
			if requested.PartitionKind == PartitionKindCapacity {
				if err := capacityPublicationGuardLocked(storage); err != nil {
					return err
				}
			}
			live, err := refreshPartitionForProof(
				storage, requested, deadlineCount, partitionMaxSectors, chainTimestamp,
			)
			if err != nil {
				if errors.Is(err, ErrPartitionNoLongerActive) && queueFound && existingQueue.Frozen != nil {
					snapshot, destructive = *existingQueue.Frozen, true
					return nil
				}
				return err
			}
			if live.PartitionKind == PartitionKindData {
				pending, pendingErr := partitionHasPendingDeletion(storage, live.DeadlineIndex, live.PartitionIndex)
				if pendingErr != nil {
					return pendingErr
				}
				if pending && !allowPendingDeletion {
					// G.4B: the ONE exception. A pending deletion normally blocks proving, because
					// the deletion is about to change the content. But G.4's own design records
					// `SealedContentVersion`/`SealedContentHash` as "the immutable post-delete
					// successor that must be proved before confirm" — so the exact declared
					// successor is precisely what has to be proved, and blocking it made the whole
					// qualified-urgency path unreachable (live 2026-08-12:
					// "partition deletion in progress", campaign stuck at progress=0/1 forever).
					//
					// Everything except that exact successor stays blocked, and any ambiguity
					// fails closed.
					permitted, why, permitErr := exactDeletionSuccessorProofPermitted(
						storage, chainCmd, live, proofEpochID)
					if permitErr != nil {
						return permitErr
					}
					if !permitted {
						return ErrPartitionDeletionInProgress
					}
					log.Printf(
						"[delete] proving exact declared successor under pending deletion "+
							"kind=%s dl=%d pt=%d epoch=%d: %s",
						live.PartitionKind, live.DeadlineIndex, live.PartitionIndex, proofEpochID, why)
				}
			}
			snapshot, destructive, err = queuePartitionProofSnapshot(
				storage, live, proofEpochID, round, deadline,
			)
			return err
		}
		if requested.PartitionKind == PartitionKindCapacity {
			err = withCapacityCoordinationLock(storage, localPrepare)
		} else {
			err = localPrepare()
		}
		if err != nil {
			return partitionProofSnapshot{}, false, err
		}
		if destructive {
			return snapshot, true, nil
		}

		// The durable queue record now owns this exact local generation. Chain status/freeze
		// operations run without either upload-path lock; the bind phase reacquires the
		// partition lock and verifies that the same queue generation is still authoritative.
		releasePartitionLock()

		frozenStatus, statusErr := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition)
		if statusErr != nil {
			return partitionProofSnapshot{}, false, fmt.Errorf("read frozen partition snapshot: %w", statusErr)
		}
		if !frozenStatus.Exists {
			// A crash can leave a local queued generation that was never frozen. It
			// can only be frozen if it is still the chain's exact current content.
			current, currentErr := partitionVersionStatusOnChain(chainCmd, snapshot.Partition)
			if currentErr != nil {
				return partitionProofSnapshot{}, false, currentErr
			}
			if !partitionMatchesChainContent(current, snapshot.Partition) {
				return snapshot, true, nil
			}
			// Drain-before-cutover quiesce: existing frozen snapshots keep resolving
			// (submit/abandon/reanchor run normally), but no NEW on-chain freeze may
			// be created — this covers capacity freezes and deletion successor
			// freezes alike, since both prepare through this branch.
			if freezeQuiesceActive(storage) {
				return partitionProofSnapshot{}, false, errFreezeQuiesced
			}
			if freezeCoord != nil {
				// A.2.5: reserve+journal the exact sender nonce under the sender-wide account
				// lock and force the subprocess to use it (see coordinatedFreezeBroadcast).
				frozenStatus, _, err = coordinatedFreezeBroadcast(
					*freezeCoord, chainCmd, snapshot.Partition, proofEpochID, round,
				)
			} else {
				frozenStatus, _, err = freezePartitionSnapshotOnChain(
					chainCmd, snapshot.Partition, proofEpochID, round,
				)
			}
			if err != nil {
				// Resolve an ambiguous transaction before retrying. Never send a
				// second freeze blindly after a transport EOF.
				if observed, observeErr := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition); observeErr == nil && observed.Exists {
					frozenStatus = observed
				} else {
					return partitionProofSnapshot{}, false, err
				}
			}
		}
		if !frozenStatus.Exists || frozenStatus.ProofEpochID != proofEpochID ||
			frozenStatus.ContentVersion == 0 || frozenStatus.ContentHash == "" {
			return partitionProofSnapshot{}, false, fmt.Errorf("chain returned an incomplete frozen partition snapshot")
		}
		if snapshot.ContentVersion != 0 && snapshot.ContentVersion != frozenStatus.ContentVersion {
			return snapshot, true, nil
		}
		if snapshot.ChainContentHash != "" && !sameRoot(snapshot.ChainContentHash, frozenStatus.ContentHash) {
			return snapshot, true, nil
		}
		// On first bind, validate the frozen hash using the current partition's
		// challenge count. The register/freeze lock makes this a single generation.
		if snapshot.ChainContentHash == "" {
			current, currentErr := partitionVersionStatusOnChain(chainCmd, snapshot.Partition)
			if currentErr == nil && current.ChallengeCount > 0 {
				expected, hashErr := partitionChainContentHash(snapshot.Partition, current.ChallengeCount)
				if hashErr != nil || !sameRoot(expected, frozenStatus.ContentHash) {
					return snapshot, true, nil
				}
			}
		}
		if requireSnapshotNonceIdentity && frozenStatus.SnapshotNonce == 0 {
			return partitionProofSnapshot{}, false, fmt.Errorf(
				"active frozen snapshot has no chain snapshot nonce (legacy contract or incomplete command response); refusing under the nonce-enforced snapshot protocol")
		}
		snapshot.ContentVersion = frozenStatus.ContentVersion
		snapshot.ProofEpochID = frozenStatus.ProofEpochID
		snapshot.ChainContentHash = frozenStatus.ContentHash
		snapshot.AnchorBlock = frozenStatus.AnchorBlock
		snapshot.Round = frozenStatus.Round
		snapshot.SnapshotNonce = frozenStatus.SnapshotNonce
		if frozenStatus.Deadline > 0 && frozenStatus.Deadline <= uint64(^uint64(0)>>1) {
			snapshot.DeadlineUnix = int64(frozenStatus.Deadline)
		}
		snapshot.State = proofSnapshotStateFrozen
		snapshot.LastError = ""
		lock, err = acquirePartitionLifecycleLock(
			storage, requested.DeadlineIndex, requested.PartitionIndex,
		)
		if err != nil {
			return partitionProofSnapshot{}, false, err
		}
		lockHeld = true
		latestQueue, found, queueErr := readPartitionProofSnapshotQueue(
			storage, requested.PartitionKind, requested.DeadlineIndex, requested.PartitionIndex,
		)
		if queueErr != nil {
			return partitionProofSnapshot{}, false, queueErr
		}
		if !found || latestQueue.Frozen == nil || latestQueue.Frozen.ID != snapshot.ID ||
			latestQueue.Frozen.Generation != snapshot.Generation {
			return partitionProofSnapshot{}, false, ErrPartitionProofSnapshotInvalidated
		}
		if err := updatePartitionProofSnapshot(storage, snapshot); err != nil {
			return partitionProofSnapshot{}, false, err
		}
		return snapshot, false, nil
	}

	return prepare()
}

func frozenSnapshotDeletionPermit(
	storage, chainCmd string, snapshot partitionProofSnapshot, allowPendingDeletion bool,
) (checked bool, permitted bool, err error) {
	if snapshot.Partition.PartitionKind != PartitionKindData || allowPendingDeletion {
		return false, false, nil
	}
	pending, err := partitionHasPendingDeletion(
		storage, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex)
	if err != nil || !pending {
		return false, false, err
	}
	permitted, _, err = exactDeletionSuccessorProofPermitted(
		storage, chainCmd, snapshot.Partition, snapshot.ProofEpochID)
	return true, permitted, err
}

func frozenSnapshotStillSafeToSubmit(
	storage string,
	snapshot partitionProofSnapshot,
	deadlineCount, partitionMaxSectors int,
	chainTimestamp int64,
	allowPendingDeletion bool,
	requireCurrentContent bool,
	deletionPermitChecked bool,
	deletionPermitted bool,
) error {
	if snapshot.Partition.PartitionKind != PartitionKindData {
		return nil
	}
	pending, err := partitionHasPendingDeletion(
		storage, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
	)
	if err != nil {
		return err
	}
	if pending && !allowPendingDeletion {
		// G.4B: the same ONE exception applied at freeze time must also hold at submit time.
		// Without it a campaign that legitimately froze the exact declared successor would have
		// its snapshot invalidated here and abandoned, reintroducing the deadlock one step later.
		// B.3.1: chain authority is pinned BEFORE the partition lock. If deletion appeared
		// after that pin, fail closed and let the next scan evaluate the new identity. Never
		// perform exactDeletionSuccessorProofPermitted (a chain command) under this lock.
		if !deletionPermitChecked || !deletionPermitted {
			return ErrPartitionProofSnapshotInvalidated
		}
	}
	live, err := refreshPartitionForProof(
		storage, snapshot.Partition, deadlineCount, partitionMaxSectors, chainTimestamp,
	)
	if err != nil {
		return ErrPartitionProofSnapshotInvalidated
	}
	// A routine capacity-epoch cutoff may remain valid across append-only
	// successors. A deletion-successor proof is different: confirmation releases
	// allocation, so the submitted snapshot must still be the exact live version.
	if requireCurrentContent {
		if !samePartitionSnapshotContent(&snapshot, live) {
			return ErrPartitionProofSnapshotInvalidated
		}
		return nil
	}
	if !partitionTransitionRetainsFrozenData(snapshot.Partition, live) {
		return ErrPartitionProofSnapshotInvalidated
	}
	return nil
}

func abandonAndAdvancePartitionSnapshot(storage, chainCmd string, snapshot partitionProofSnapshot, reason string) error {
	// A.2 gate: an abandon is a proof-affecting chain transition.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return gateErr
	}
	// A.1 fence: never send an abandon transaction for a slot this worker no longer owns.
	// A stale abandon would retire the live newer generation on-chain.
	if err := verifyPartitionGenerationLive(storage, snapshot); err != nil {
		return err
	}
	if snapshot.ContentVersion != 0 {
		if _, err := abandonFrozenPartitionSnapshotOnChain(chainCmd, snapshot); err != nil {
			return fmt.Errorf("abandon frozen partition snapshot: %w", err)
		}
	}
	snapshot.LastError = reason
	if err := advancePartitionProofSnapshot(storage, snapshot); err != nil {
		return err
	}
	log.Printf("[proof-snapshot] advanced obsolete generation kind=%s dl=%d pt=%d version=%d reason=%s",
		snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex,
		snapshot.Partition.PartitionIndex, snapshot.ContentVersion, reason)
	return nil
}

func reanchorPartitionProofSnapshot(
	storage, chainCmd string,
	snapshot partitionProofSnapshot,
) error {
	// A.2 gate: a reanchor is a proof-affecting chain transition.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return gateErr
	}
	// A.1 fence: never send a reanchor transaction for a slot this worker no longer owns.
	if err := verifyPartitionGenerationLive(storage, snapshot); err != nil {
		return err
	}
	status, tx, err := reanchorFrozenPartitionSnapshotOnChain(chainCmd, snapshot)
	if err != nil {
		return fmt.Errorf("reanchor frozen partition snapshot: %w", err)
	}
	if !status.Exists || status.ProofEpochID != snapshot.ProofEpochID ||
		status.ContentVersion != snapshot.ContentVersion || status.Round != snapshot.Round ||
		!sameRoot(status.ContentHash, snapshot.ChainContentHash) || status.AnchorBlock == 0 ||
		status.Deadline == 0 || !zeroBytes32(status.ChallengeSeed) ||
		status.SnapshotNonce == 0 {
		return fmt.Errorf("reanchored partition snapshot identity is incomplete or changed")
	}
	// The reanchor force-assigned a fresh on-chain nonce; adopt it, and (A.1) advance the
	// local generation so any worker still holding the pre-reanchor generation is fenced.
	snapshot.SnapshotNonce = status.SnapshotNonce
	snapshot.AnchorBlock = status.AnchorBlock
	snapshot.DeadlineUnix = int64(status.Deadline)
	snapshot.State = proofSnapshotStateFrozen
	snapshot.Challenge = PartitionChallenge{}
	snapshot.PublicInputs = nil
	snapshot.Proof = ZKProofResult{}
	snapshot.LastError = ""
	if _, err := reanchorUpdatePartitionProofSnapshot(storage, snapshot); err != nil {
		return err
	}
	log.Printf(
		"[proof-snapshot] refreshed challenge anchor epoch=%d kind=%s dl=%d pt=%d version=%d tx=%s",
		snapshot.ProofEpochID, snapshot.Partition.PartitionKind,
		snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
		snapshot.ContentVersion, tx,
	)
	return nil
}

// provePartitionSnapshotCandidate is the production proof path. The immutable
// artifact is built and persisted before challenge generation. A completed
// proof is persisted before submission, so an RPC failure/restart retries only
// the exact transaction and never spends prover resources twice.
func provePartitionSnapshotCandidate(
	storage string,
	partition PartitionMeta,
	proofEpochID, round uint64,
	deadlineCount, partitionMaxSectors int,
	partitionProverCmd, chainCmd string,
	priority string,
	workDeadline time.Time,
	chainTimestamp int64,
	allowPendingDeletion bool,
	requireCurrentContent bool,
	c1DurationClass string,
) error {
	// A.2 gate: the entire snapshot proof driver (freeze, seal, submit, abandon, reanchor)
	// is a proof-affecting write path — refuse it until the startup barrier has opened.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return gateErr
	}
	// A.2.5 cross-authority freeze ownership (cross-process atomic): establish a durable,
	// generation-bound authority claim under the per-partition flock (gather chain-reconciled
	// inputs → arbitrate → claim) before touching the single frozen slot, so two processes can
	// never both broadcast a freeze. Deferral is benign (batching) — retried next scan.
	freezeMe := freezeHolderCapacity
	if proofEpochID&standaloneDeletionProofFlag != 0 {
		freezeMe = freezeHolderDeletion
	}
	var freezeClaimSeq uint64
	freezeArbitrated := chainCmd != ""
	if freezeArbitrated {
		oracle := realFreezeOracle(chainCmd)
		granted, seq, decision, reason, claimErr := acquirePartitionFreezeClaim(storage, oracle, partition, freezeMe, time.Now())
		if claimErr != nil {
			return claimErr
		}
		if decision == freezeDecisionCapacityMustAbandon {
			// Point 4: directly and boundedly abandon the excluded capacity member (full-identity
			// A.0 abandon via the reconciler) and BLOCK further proving this scan.
			//
			// Deliberately NOT gated on `freezeMe == freezeHolderCapacity` any more. That gate
			// made the release executable only by the capacity authority, and for a data
			// partition with a pending deletion the capacity pass never gets here: it is
			// refused ~300 lines earlier by the pending-deletion check, which returns
			// ErrPartitionDeletionInProgress long before any freeze claim is attempted. Only
			// the deletion sweep reached the arbiter, and a deletion may not release capacity's
			// slot (partition_freeze_claim.go sets granted=false and leaves the abandon "to the
			// caller" -- a caller that never arrived). Both doors were shut, each by the other's
			// state.
			//
			// Live on 2026-10-03, keeper 0xFABB0ac9, partition data dl=42 pt=0: the arbiter
			// answered "capacity member excluded on-chain; release the slot promptly" 804 times
			// over 22 hours and the abandon ran ZERO times. The keeper stayed closed on
			// oldest_dirty_hard_lag and every data owner read the cluster as inconclusive, so
			// the whole run stopped.
			//
			// Safe from either authority: the decision itself comes from on-chain truth
			// (frozenSnapshots holder + chain-confirmed declaration), and the abandon path
			// re-verifies on chain before acting. Whoever observes an excluded holder may
			// therefore release it; waiting for the excluded side to release itself is what
			// deadlocked.
			epoch, epErr := capacityCampaignStatusForStorage(storage, chainCmd)
			if epErr != nil {
				return epErr
			}
			if abErr := reconcileInactiveEpochSnapshotQueues(storage, chainCmd, epoch); abErr != nil {
				return abErr
			}
			// The reconciler above only retires freezes that a LOCAL record claims. An
			// on-chain freeze no local record owns survives it untouched, so release this
			// partition's slot directly from the chain's own generation as well.
			released, relErr := abandonExcludedCapacityFreeze(chainCmd, partition)
			if relErr != nil {
				return relErr
			}
			log.Printf("[freeze-arbiter] capacity member excluded; abandoned by %s (chain slot released=%t) "+
				"and deferring proof kind=%s dl=%d pt=%d: %s",
				freezeMe, released, partition.PartitionKind,
				partition.DeadlineIndex, partition.PartitionIndex, reason)
			return ErrPartitionProofSnapshotBatching
		}
		if !granted {
			log.Printf("[freeze-arbiter] deferring %s freeze kind=%s dl=%d pt=%d: %s",
				freezeMe, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex, reason)
			return ErrPartitionProofSnapshotBatching
		}
		freezeClaimSeq = seq
	}
	queue, queueFound, queueErr := readPartitionProofSnapshotQueue(
		storage, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
	)
	if queueErr != nil {
		return queueErr
	}
	epochCutoffReady := queueFound && queue.Frozen != nil &&
		queue.Frozen.ProofEpochID == proofEpochID
	if !epochCutoffReady && !allowPendingDeletion {
		eligible, batchingReason, err := partitionSnapshotFreezeEligible(
			storage, chainCmd, partition, partitionMaxSectors, chainTimestamp,
		)
		if err != nil {
			return err
		}
		if !eligible {
			log.Printf("[proof-snapshot] batching kind=%s dl=%d pt=%d sectors=%d reason=%s",
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
				len(partition.Sectors), batchingReason)
			return ErrPartitionProofSnapshotBatching
		}
	}
	// A.2.5: revalidate the generation-bound freeze claim IMMEDIATELY before the freeze. If a
	// concurrent process superseded/expired it, defer rather than broadcast a losing freeze.
	if freezeArbitrated {
		if valid, vErr := revalidatePartitionFreezeClaim(storage, partition, freezeMe, freezeClaimSeq, time.Now()); vErr != nil {
			return vErr
		} else if !valid {
			log.Printf("[freeze-arbiter] freeze claim superseded before broadcast kind=%s dl=%d pt=%d",
				partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex)
			return ErrPartitionProofSnapshotBatching
		}
	}
	// A.2.5: the broadcast attempt is journalled with the EXACTLY reserved sender nonce inside
	// the coordinated freeze (under the sender-wide account lock), so the journal describes the
	// real freeze transaction rather than a re-read confirmed count.
	var freezeCoord *freezeBroadcastCoord
	if freezeArbitrated {
		freezeCoord = &freezeBroadcastCoord{storage: storage, me: freezeMe, seq: freezeClaimSeq}
	}
	snapshot, destructive, err := prepareFrozenPartitionSnapshot(
		storage, partition, proofEpochID, round, workDeadline, deadlineCount, partitionMaxSectors,
		chainCmd, chainTimestamp, allowPendingDeletion, freezeCoord,
	)
	if err != nil {
		return err
	}
	if destructive {
		if err := abandonAndAdvancePartitionSnapshot(storage, chainCmd, snapshot, "live deletion/replacement invalidated frozen bytes"); err != nil {
			return err
		}
		return ErrPartitionProofSnapshotInvalidated
	}

	status, err := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition)
	if err != nil {
		return err
	}
	if status.Proven && status.ProofEpochID == snapshot.ProofEpochID &&
		status.ContentVersion == snapshot.ContentVersion && status.Round == snapshot.Round {
		if status.Current {
			if err := markPartitionProofed(storage, snapshot.Partition, snapshot.Round); err != nil {
				return err
			}
		}
		return advancePartitionProofSnapshot(storage, snapshot)
	}
	if !status.Exists || status.ProofEpochID != snapshot.ProofEpochID ||
		status.ContentVersion != snapshot.ContentVersion || status.Round != snapshot.Round ||
		!sameRoot(status.ContentHash, snapshot.ChainContentHash) {
		return fmt.Errorf("frozen partition snapshot identity changed on-chain")
	}
	// A.2.5: the slot is now confirmed frozen under this authority's identity — the broadcast
	// attempt won. Retire the broadcast_pending marker so normal arbitration can resume.
	if freezeArbitrated {
		if aErr := resolveFreezeBroadcastAttempt(storage, partition, freezeMe, freezeClaimSeq, freezeAttemptConfirmed, ""); aErr != nil {
			return aErr
		}
	}
	clock, clockErr := proofClockStatusOnChain(chainCmd)
	if clockErr != nil {
		return clockErr
	}
	// Avoid spending prover time on a generation that is already known to be
	// unusable. This is only an early optimization; the same check is repeated
	// under the lifecycle lock immediately before submission.
	deletionPermitChecked, deletionPermitted, permitErr := frozenSnapshotDeletionPermit(
		storage, chainCmd, snapshot, allowPendingDeletion)
	if permitErr != nil {
		return permitErr
	}
	if err := frozenSnapshotStillSafeToSubmit(
		storage, snapshot, deadlineCount, partitionMaxSectors, clock.ChainTimestamp,
		allowPendingDeletion, requireCurrentContent, deletionPermitChecked, deletionPermitted,
	); err != nil {
		if errors.Is(err, ErrPartitionProofSnapshotInvalidated) {
			if advanceErr := abandonAndAdvancePartitionSnapshot(
				storage, chainCmd, snapshot, "live content invalidated frozen proof before proving",
			); advanceErr != nil {
				return advanceErr
			}
		}
		return err
	}
	if status.Deadline > 0 && uint64(clock.ChainTimestamp) > status.Deadline {
		if err := reanchorPartitionProofSnapshot(storage, chainCmd, snapshot); err != nil {
			return err
		}
		return ErrPartitionProofSnapshotReanchored
	}

	if zeroBytes32(status.ChallengeSeed) {
		if status.AnchorBlock > 0 && clock.BlockNumber > status.AnchorBlock+256 {
			if err := reanchorPartitionProofSnapshot(storage, chainCmd, snapshot); err != nil {
				return err
			}
			return ErrPartitionProofSnapshotReanchored
		}
		status, _, err = sealPartitionSnapshotOnChain(chainCmd, snapshot.Partition, snapshot.ContentVersion)
		if err != nil {
			return fmt.Errorf("seal frozen partition snapshot: %w", err)
		}
	}
	if zeroBytes32(status.ChallengeSeed) {
		return fmt.Errorf("sealed partition snapshot has no challenge seed")
	}
	challenge, publicInputs, err := frozenPartitionChallengeOnChain(chainCmd, snapshot)
	if err != nil {
		return err
	}
	if snapshot.Proof.OK && snapshot.Proof.Proof != "" {
		if snapshot.Challenge.Round != challenge.Round || !sameRoot(snapshot.Challenge.ChallengeSeed, challenge.ChallengeSeed) ||
			!equalPublicInputs(snapshot.PublicInputs, publicInputs) {
			return fmt.Errorf("persisted frozen proof does not match current immutable challenge")
		}
	} else {
		snapshot.State = proofSnapshotStateProving
		snapshot.Challenge = challenge
		snapshot.PublicInputs = append([]string(nil), publicInputs...)
		if err := updatePartitionProofSnapshot(storage, snapshot); err != nil {
			return err
		}
		class := fmt.Sprintf("%s-final-n%d", snapshot.Partition.PartitionKind, len(snapshot.Partition.Sectors))
		work := fmt.Sprintf("snapshot-%s-dl%d-pt%d-v%d", snapshot.Partition.PartitionKind,
			snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex, snapshot.ContentVersion)
		latestClock, clockErr := proofClockStatusOnChain(chainCmd)
		if clockErr != nil {
			return clockErr
		}
		chainDeadline := workDeadline.Unix()
		if snapshot.DeadlineUnix > 0 {
			chainDeadline = snapshot.DeadlineUnix
		}
		deadline := chainDeadlineHostDue(chainDeadline, latestClock.ChainTimestamp, time.Now())
		generation := frozenPartitionProofGeneration(work, snapshot, challenge)
		scope := snapshotProofJobScope(snapshot)
		// A.1 fence: do not dispatch the (expensive, long-running) prover for a generation
		// that has already been overtaken. The submit boundary re-checks after proving.
		if err := verifyPartitionGenerationLive(storage, snapshot); err != nil {
			return err
		}
		// A.2 fence: the persisted ArtifactDir must equal the directory recomputed from the
		// record's complete identity, be a real (non-symlink) direct child of the artifact
		// root, and carry a manifest matching the full identity — so a forged/copied/stale
		// ArtifactDir can never direct the external prover at another snapshot's directory.
		if err := verifyArtifactReadyForUse(storage, snapshot); err != nil {
			return err
		}
		// G.3 shape key stays `class`; the JOB carries the C.1 campaign duration class so
		// capacity_single / capacity_batch / capacity_audit histories never mix.
		jobClass := class
		if strings.TrimSpace(c1DurationClass) != "" {
			jobClass = c1DurationClass
		}
		err = withHostPersistedProofJobDeadline(generation, scope, work, jobClass, deadline, func() error {
			var proveErr error
			snapshot.Proof, proveErr = runExternalZKPartitionProverUnlocked(
				partitionProverCmd,
				ZKPartitionProofRequest{
					Partition: snapshot.Partition, Challenge: challenge,
					StorageDir: snapshot.ArtifactDir, PublicInputs: publicInputs,
				},
			)
			return proveErr
		})
		if err != nil {
			snapshot.LastError = err.Error()
			_ = updatePartitionProofSnapshot(storage, snapshot)
			return err
		}
		snapshot.State = proofSnapshotStateSubmitting
		snapshot.LastError = ""
		if err := updatePartitionProofSnapshot(storage, snapshot); err != nil {
			return err
		}
	}

	// Pin chain truth before entering the final local validation section. No chain RPC may run
	// while the partition lifecycle lock is held.
	latestClock, err := proofClockStatusOnChain(chainCmd)
	if err != nil {
		return err
	}
	preSubmitStatus, statusErr := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition)
	if statusErr != nil {
		return statusErr
	}
	requireEpoch := snapshot.ProofEpochID&standaloneDeletionProofFlag == 0
	preSubmitEpoch := CapacityProofEpochStatus{}
	if requireEpoch {
		preSubmitEpoch, statusErr = capacityCampaignStatusForStorage(storage, chainCmd)
		if statusErr != nil {
			return statusErr
		}
	}
	// Pin the G.4B deletion-successor authority outside the partition lifecycle lock. A
	// deletion that appears after this read is rejected by the checked=false branch inside
	// frozenSnapshotStillSafeToSubmit; a content change is independently rejected by its live
	// identity comparison. This preserves fail-closed submission without wrapping chain RPC in
	// an upload-path lock (live G.7 regression, 2026-08-13).
	deletionPermitChecked, deletionPermitted, permitErr = frozenSnapshotDeletionPermit(
		storage, chainCmd, snapshot, allowPendingDeletion)
	if permitErr != nil {
		return permitErr
	}

	// Only this final, short local validation section excludes mutations.
	lock, err := acquirePartitionLifecycleLock(storage, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex)
	if err != nil {
		return err
	}
	lockHeld := true
	releasePartitionLock := func() {
		if lockHeld {
			lock.Release()
			lockHeld = false
		}
	}
	defer releasePartitionLock()
	if err := frozenSnapshotStillSafeToSubmit(
		storage, snapshot, deadlineCount, partitionMaxSectors, latestClock.ChainTimestamp,
		allowPendingDeletion, requireCurrentContent, deletionPermitChecked, deletionPermitted,
	); err != nil {
		releasePartitionLock()
		if errors.Is(err, ErrPartitionProofSnapshotInvalidated) {
			if advanceErr := abandonAndAdvancePartitionSnapshot(storage, chainCmd, snapshot, "deletion changed frozen data before submission"); advanceErr != nil {
				return advanceErr
			}
		}
		return err
	}
	if snapshot.DeadlineUnix > 0 && latestClock.ChainTimestamp > snapshot.DeadlineUnix {
		releasePartitionLock()
		// The immutable cutoff remains a valid member of the capacity epoch. A
		// busy shared prover may legitimately finish after its short challenge
		// window, so refresh only the unpredictable anchor and prove the same
		// bytes again. Abandoning here would make the entire epoch impossible to
		// complete even though no storage content was lost or changed.
		if err := reanchorPartitionProofSnapshot(storage, chainCmd, snapshot); err != nil {
			return err
		}
		return ErrPartitionProofSnapshotReanchored
	}

	work := fmt.Sprintf("snapshot-%s-dl%d-pt%d-v%d", snapshot.Partition.PartitionKind,
		snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex, snapshot.ContentVersion)
	generation := frozenPartitionProofGeneration(work, snapshot, challenge)
	scope := snapshotProofJobScope(snapshot)
	authoritativeGeneration := generation
	if lockPath := strings.TrimSpace(os.Getenv(proofHostLockPathEnv)); lockPath != "" {
		authoritative, authorityErr := proofJobGenerationAuthoritative(lockPath, scope, generation)
		if authorityErr != nil {
			return authorityErr
		}
		if !authoritative {
			authoritativeGeneration = ""
		}
	}
	queue, found, queueErr := readPartitionProofSnapshotQueue(
		storage, snapshot.Partition.PartitionKind,
		snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
	)
	if queueErr != nil {
		return queueErr
	}
	if !found {
		return fmt.Errorf("authoritative snapshot queue disappeared before submission")
	}
	alreadySubmitted, authorityErr := validateFrozenProofSubmissionAuthority(
		snapshot, queue, preSubmitStatus, preSubmitEpoch, requireEpoch,
		generation, authoritativeGeneration,
	)
	if authorityErr != nil {
		return authorityErr
	}
	if alreadySubmitted {
		return advancePartitionProofSnapshot(storage, snapshot)
	}

	releasePartitionLock()
	submitTx, submitErr := submitFrozenPartitionProofOnChain(chainCmd, snapshot, challenge, snapshot.Proof)
	if submitErr != nil {
		observed, observeErr := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition)
		if observeErr != nil || !observed.Proven || observed.ProofEpochID != snapshot.ProofEpochID ||
			observed.ContentVersion != snapshot.ContentVersion || observed.Round != snapshot.Round {
			snapshot.LastError = submitErr.Error()
			_ = updatePartitionProofSnapshot(storage, snapshot)
			return fmt.Errorf("submit frozen partition proof: %w", submitErr)
		}
	}
	log.Printf("[proof-snapshot] submitted kind=%s dl=%d pt=%d version=%d round=%d tx=%s",
		snapshot.Partition.PartitionKind, snapshot.Partition.DeadlineIndex,
		snapshot.Partition.PartitionIndex, snapshot.ContentVersion, snapshot.Round, submitTx)
	confirmed, confirmErr := frozenPartitionSnapshotStatusOnChain(chainCmd, snapshot.Partition)
	if confirmErr != nil {
		return fmt.Errorf("confirm submitted frozen partition proof: %w", confirmErr)
	}
	if !confirmed.Proven || confirmed.ProofEpochID != snapshot.ProofEpochID ||
		confirmed.ContentVersion != snapshot.ContentVersion || confirmed.Round != snapshot.Round {
		return fmt.Errorf("submitted frozen partition proof is not confirmed on-chain")
	}
	lock, err = acquirePartitionLifecycleLock(
		storage, snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
	)
	if err != nil {
		return err
	}
	lockHeld = true
	latestQueue, found, queueErr := readPartitionProofSnapshotQueue(
		storage, snapshot.Partition.PartitionKind,
		snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex,
	)
	if queueErr != nil {
		return queueErr
	}
	if !found || latestQueue.Frozen == nil || latestQueue.Frozen.ID != snapshot.ID ||
		latestQueue.Frozen.Generation != snapshot.Generation {
		return ErrPartitionProofSnapshotInvalidated
	}
	if confirmed.Current {
		if err := markPartitionProofed(storage, snapshot.Partition, snapshot.Round); err != nil {
			return err
		}
	}
	if err := advancePartitionProofSnapshot(storage, snapshot); err != nil {
		return err
	}
	// The obligation this partition owed is now discharged on-chain, so any retry record for it
	// is terminal and must not survive. provePartitionCandidates clears on its own success path,
	// but this snapshot prover is a SECOND route to the same outcome and cleared nothing — so a
	// failure recorded by one route could be settled by the other and leave the record behind,
	// pinning the vault keeper to degraded forever. Run 11 (data:dl39:pt0) is that exact case.
	if retryErr := clearPartitionProofRetry(storage, snapshot.Partition); retryErr != nil {
		log.Printf("[proof-snapshot] retry-state clear warning dl=%d pt=%d: %v",
			snapshot.Partition.DeadlineIndex, snapshot.Partition.PartitionIndex, retryErr)
	}
	return nil
}

// runProofDaemon is the background proof loop. When deadlineCount > 0 and
// partitionProverCmd is set it uses the partition path; otherwise falls back
// to the existing per-sector path.
func runProofDaemon(
	storage string,
	periodSeconds, pollSeconds int64,
	challengeCount int,
	proverCmd, chainCmd string,
	once bool,
	deadlineCount, partitionMaxSectors int,
	partitionProverCmd string,
	deterministicChallenge bool,
	capacityBytes int64,
	storageCfg ServerConfig,
) {
	ensureStorageForCLI(storage)
	// A.2.5: publish the chain config the freeze oracle needs for on-chain reconciliation.
	activeFreezeChainConfig = storageCfg
	// A.2 startup barrier: migrate pre-A.2 artifact directories and sweep orphans BEFORE any
	// proving begins. Fail closed (the proving process refuses to start) on failure so a
	// malformed/unsafe legacy artifact keeps proving disabled rather than running workers.
	if err := runArtifactStartupBarrier(storage); err != nil {
		log.Fatalf("[proof-snapshot] snapshot artifact startup barrier failed; proving disabled: %v", err)
	}
	if pollSeconds <= 0 {
		pollSeconds = 60
	}
	if storageCfg.Storage == "" {
		storageCfg.Storage = storage
	}
	if storageCfg.CapacityBytes <= 0 {
		storageCfg.CapacityBytes = capacityBytes
	}
	if storageCfg.CapacityBytes > 0 {
		// Capacity materialization is started by the scheduler below. It must not
		// block this process before it can service urgent data/deletion proofs. Each
		// cache batch takes its own shared-host lock and persists a restart point.
		capacityBytes = storageCfg.CapacityBytes
		if slotSize, err := resolvedCapacitySlotSize(storageCfg); err == nil {
			log.Printf("[capacity] proof-daemon config declared=%.1f MB slotSize=%.1f MB continuousCheckpointedBuild=true",
				float64(storageCfg.CapacityBytes)/1e6, float64(slotSize)/1e6)
		}
	}
	// G.4B-LV0: the deployed proof profile must agree with the local one BEFORE any partition
	// can be assigned or registered. A disagreement makes the contract compute different
	// committed bytes for the same sectors, which the VK correctly refuses to accept — it would
	// then retry the first partition forever without ever reaching certification. This gate is
	// terminal: no registration, no retry scheduling, no capacity campaign.
	if err := enforceDeployedProofProfile(storageCfg); err != nil {
		log.Fatalf("[capacity] deployed proof-profile preflight failed; capacity bootstrap "+
			"aborted before the first partition registration: %v", err)
	}

	if err := ensureAllPartitionAssignments(storage, storageCfg); err != nil {
		log.Fatalf("[partition] proof-daemon assignment initialization failed: %v", err)
	}

	usePartitions := deadlineCount > 0 && partitionProverCmd != ""

	if usePartitions {
		mode := "legacy (2-tx)"
		if deterministicChallenge {
			mode = "deterministic (1-tx)"
		}
		log.Printf("[proof-daemon] mode=partition  challenge=%s  deadline_count=%d  partition_max_sectors=%d",
			mode, deadlineCount, partitionMaxSectors)
	} else {
		log.Printf("[proof-daemon] mode=per-sector (partition disabled or no partitionProverCmd)")
	}

	gcInterval := 24 * time.Hour
	lastGC := time.Time{} // zero = run immediately on first tick
	cacheGCInterval := 10 * time.Minute
	retryReconcileInterval := 5 * time.Minute
	lastRetryReconcile := time.Time{} // zero = run immediately on first tick
	cacheRetention := 30 * time.Minute
	lastCacheGC := time.Time{} // zero = run immediately on first tick
	capacityCleanupInterval := 10 * time.Minute
	lastCapacityCleanup := time.Time{} // zero = run immediately on first tick

	capacityDeclared := false
	lastRegisteredCapacityContent := map[string]string{}
	lastCapacityDirtyDetail := ""
	lastEligibilityWaitLog := time.Time{}
	// Temporal-liveness reporting state. The verdict is recomputed every scan; the LOG is
	// rate-limited so an ordinary healthy wait cannot flood, while any class change — and in
	// particular the transition into an unowned pending-deadline wait — is reported at once.
	lastWaitLiveness := capacityWaitLivenessClass("")
	lastWaitLivenessLog := time.Time{}
	capacityBuildRunning := false
	capacityBuildResult := make(chan error, 1)
	capacityBuildFailures := 0
	capacityBuildRetryAt := time.Time{}
	capacityForceBuildRequired := storageCfg.ForceCapacityRebuild

	for {
		if vkStopping() {
			if capacityBuildRunning {
				<-capacityBuildResult
			}
			return
		}
		select {
		case buildErr := <-capacityBuildResult:
			capacityBuildRunning = false
			if buildErr != nil {
				capacityBuildFailures++
				retryDelay := capacityBuildRetryDelay(capacityBuildFailures)
				capacityBuildRetryAt = time.Now().Add(retryDelay)
				log.Printf("[capacity] background reconcile failed; retrying in %s: %v", retryDelay, buildErr)
				_ = setCapacityProofCatchupPhase(storage, "rebuild_failed", buildErr.Error())
			} else {
				capacityBuildFailures = 0
				capacityBuildRetryAt = time.Time{}
				capacityForceBuildRequired = false
				log.Printf("[capacity] exact background snapshot build completed; validating freshness")
				_ = setCapacityProofCatchupPhase(storage, "awaiting_registration", "")
				// The rebuilt local manifest may have retired an entire capacity
				// partition coordinate. Run stale-chain cleanup in this same scan;
				// otherwise the normal maintenance interval can leave chain/local
				// manifests different and delay the next proof epoch unnecessarily.
				lastCapacityCleanup = time.Time{}
			}
		default:
		}
		// Daily expired-sector GC — runs at daemon startup then every 24 h.
		if time.Since(lastGC) >= gcInterval {
			gcClock, gcClockErr := proofClockStatusOnChain(chainCmd)
			if gcClockErr != nil {
				log.Printf("[gc] daily expired-sector cleanup deferred; chain clock unavailable: %v", gcClockErr)
			} else {
				log.Printf("[gc] starting daily expired-sector cleanup at chain timestamp=%d", gcClock.ChainTimestamp)
				gcResult := runExpiredGCDetailedAt(storage, nil, gcClock.ChainTimestamp)
				for _, affected := range gcResult.Affected {
					if affected.PartitionKind == PartitionKindCapacity {
						_ = markCapacityProofCatchup(storage, "expired capacity sector removed; exact snapshot rebuild required")
						break
					}
				}
				log.Printf("[gc] daily cleanup done sectorsRemoved=%d piecesRemoved=%d pendingPartitions=%d failures=%d",
					gcResult.SectorsRemoved, gcResult.PiecesRemoved, len(gcResult.Affected), gcResult.Failures)
				lastGC = time.Now()
			}
		}
		if time.Since(lastCacheGC) >= cacheGCInterval {
			removed, err := cleanupObsoleteZKSectorCaches(storage, cacheRetention)
			if err != nil {
				log.Printf("[zk] cache gc skipped: %v", err)
			} else if removed > 0 {
				log.Printf("[zk] cache gc removed %d stale cache dir(s) older than %s", removed, cacheRetention)
			}
			lastCacheGC = time.Now()
		}
		// Retire retry records whose obligation is already terminal. This runs on the daemon's
		// own timer rather than on traffic, because the failure mode it closes appears precisely
		// when traffic has stopped and no other sweep will run again.
		if time.Since(lastRetryReconcile) >= retryReconcileInterval {
			if retired, err := retirePartitionProofRetryForDeadObligations(storage); err != nil {
				log.Printf("[proof-daemon] retry-state reconcile skipped: %v", err)
			} else if retired > 0 {
				log.Printf("[proof-daemon] retired %d proof-retry record(s) whose partition no longer holds any live sector", retired)
			}
			if retired, err := retireProofJobsForDeadDataPartitions(storage); err != nil {
				log.Printf("[proof-daemon] scheduler-state reconcile skipped: %v", err)
			} else if retired > 0 {
				log.Printf("[proof-daemon] retired %d scheduler job(s) whose data partition is terminal", retired)
			}
			// A queued job is only dispatchable while a live waiter holds it; the journal is durable
			// and the waiter is not. Sweep records that outlived their waiter, or they hold the drain
			// contract open forever (fresh9: 3 orphans, >2h, run could not certify).
			if retired, err := retireWaiterlessProofJobs(storage, time.Now()); err != nil {
				log.Printf("[proof-daemon] waiterless scheduler-state reconcile skipped: %v", err)
			} else if retired > 0 {
				log.Printf("[proof-daemon] retired %d queued scheduler job(s) with no live waiter (owner re-enqueues if still owed)", retired)
			}
			lastRetryReconcile = time.Now()
		}

		capacityPending := false
		capacityRebalanceDue := false
		capacityRebalanceDetail := ""
		if capacityBytes > 0 {
			needsRebalance, detail, err := capacityNeedsRebalance(storage, storageCfg)
			if err != nil {
				log.Printf("[capacity] background reconcile skipped: %v", err)
				capacityPending = true
			} else if needsRebalance || capacityForceBuildRequired {
				capacityPending = true
				if capacityForceBuildRequired && !needsRebalance {
					detail = "forced capacity rebuild requested"
				}
				if detail != lastCapacityDirtyDetail {
					if lastCapacityDirtyDetail == "" {
						log.Printf("[capacity] continuous background reconcile pending (%s)", detail)
					} else {
						log.Printf("[capacity] continuous background reconcile updated (%s)", detail)
					}
					lastCapacityDirtyDetail = detail
				}
				if once || capacityBuildRetryAt.IsZero() || !time.Now().Before(capacityBuildRetryAt) {
					capacityRebalanceDue = true
					capacityRebalanceDetail = detail
				}
			} else {
				lastCapacityDirtyDetail = ""
			}
		}
		if capacityBuildRunning {
			capacityPending = true
		}
		if capacityRebalanceDue && !capacityBuildRunning {
			log.Printf("[capacity] exact snapshot background build due (%s)", capacityRebalanceDetail)
			if err := markCapacityProofCatchup(storage, capacityRebalanceDetail); err != nil {
				log.Printf("[capacity] cannot persist catch-up state; refusing unsafe rebuild: %v", err)
			} else if once {
				err := rebalanceCapacitySectors(storage, storageCfg)
				if err != nil {
					log.Printf("[capacity] background reconcile failed: %v", err)
					_ = setCapacityProofCatchupPhase(storage, "rebuild_failed", err.Error())
				} else {
					capacityBuildFailures = 0
					capacityBuildRetryAt = time.Time{}
					capacityForceBuildRequired = false
					_ = setCapacityProofCatchupPhase(storage, "awaiting_registration", "")
					lastCapacityCleanup = time.Time{}
					if stillDirty, detail, checkErr := capacityNeedsRebalance(storage, storageCfg); checkErr != nil {
						log.Printf("[capacity] rebuilt snapshot validation failed: %v", checkErr)
					} else if stillDirty {
						log.Printf("[capacity] snapshot superseded while building; next generation remains pending (%s)", detail)
					} else {
						capacityPending = false
						lastCapacityDirtyDetail = ""
					}
				}
			} else {
				capacityBuildRunning = true
				go func() {
					capacityBuildResult <- rebalanceCapacitySectors(storage, storageCfg)
				}()
			}
		}

		// Declare capacity once, then register changed capacity partition content
		// and report initial/changed usage from the reconciled local state.
		if !capacityDeclared {
			eligible, eligibilityErr := vaultKeeperEligibleOnChain(storageCfg)
			if eligibilityErr != nil {
				if lastEligibilityWaitLog.IsZero() || time.Since(lastEligibilityWaitLog) >= 30*time.Second {
					log.Printf("[capacity] eligibility unavailable; declaration deferred: %v", eligibilityErr)
					lastEligibilityWaitLog = time.Now()
				}
			} else if !eligible {
				if lastEligibilityWaitLog.IsZero() || time.Since(lastEligibilityWaitLog) >= 30*time.Second {
					log.Printf("[capacity] VK not yet eligible; declaration deferred until registry/stake activation")
					lastEligibilityWaitLog = time.Now()
				}
			} else {
				capacityDeclared = declareCapacityOnChain(chainCmd, capacityBytes)
			}
		}
		if capacityDeclared && !capacityPending && !capacityBuildRunning {
			if registered, err := registerChangedCapacityPartitionsOnChain(storageCfg, lastRegisteredCapacityContent); err != nil {
				log.Printf("[capacity] partition registration warning: %v", err)
			} else if registered > 0 {
				log.Printf("[capacity] registered %d changed capacity partition(s)", registered)
				_ = setCapacityProofCatchupPhase(storage, "awaiting_proof", "")
			}
		}
		// Finish sealed deletion successors on our own initiative. Without this
		// they only advanced while delete traffic drove their lifecycle, so a
		// quiet keeper could hold a proved-but-unsubmitted successor forever and
		// stay closed on a deadline that can never return. See
		// deletion_successor_sweep.go.
		if chainCmd != "" {
			if sweepClock, clockErr := proofClockStatusOnChain(chainCmd); clockErr == nil {
				sweepPendingDeletionSuccessors(
					storage, deadlineCount, partitionMaxSectors,
					partitionProverCmd, chainCmd, sweepClock.ChainTimestamp,
				)
			}
		}
		maybeSyncAdmissionStatus(storageCfg)
		if capacityBytes > 0 && chainCmd != "" && time.Since(lastCapacityCleanup) >= capacityCleanupInterval {
			if err := cleanupStaleCapacityPartitionsOnChain(storage, storageCfg); err != nil {
				log.Printf("[capacity] stale partition cleanup warning: %v", err)
			}
			lastCapacityCleanup = time.Now()
		}

		capacityAdmissionRequired := deterministicChallenge && capacityBytes > 0
		capacityProofFreshUntil := int64(0)
		clock, clockErr := proofClockStatusOnChain(chainCmd)
		proofSchedulingReady := clockErr == nil
		effectivePeriodSeconds := periodSeconds
		if clockErr != nil {
			log.Printf("[proof-daemon] chain clock unavailable; proof scheduling deferred: %v", clockErr)
		} else {
			effectivePeriodSeconds = clock.ProofPeriodSeconds
			// Expired-sector removal is journaled before local bytes disappear. Retry
			// chain reconciliation every healthy tick until each journal is settled.
			reconcileExpiredGCDataPartitions(storageCfg, clock.ChainTimestamp, nil)
			settleExpiredGCCapacityRecords(storageCfg, clock.ChainTimestamp, nil)
			if periodSeconds > 0 && periodSeconds != effectivePeriodSeconds {
				log.Printf("[proof-daemon] configured proof period %ds differs from chain %ds; using chain value",
					periodSeconds, effectivePeriodSeconds)
			}
		}
		round := clock.CurrentRound
		dataProofDeadline := nextProofWindowDeadlineAt(clock.ChainTimestamp, effectivePeriodSeconds, deadlineCount)
		proofUnitSucceeded := false

		if !proofSchedulingReady {
			// Capacity preparation may continue independently, but no round-bound
			// proof is generated from the host clock.
		} else if usePartitions {
			assignmentErr := ensureAllPartitionAssignmentsAt(storage, storageCfg, clock.ChainTimestamp)
			if assignmentErr != nil {
				log.Printf("[proof-daemon] chain-time partition assignment refresh failed; proof scheduling deferred: %v", assignmentErr)
			} else if sectors, err := listSectors(storage); err != nil {
				log.Printf("[proof-daemon] sector list error: %v", err)
			} else {
				currentPartitions := buildDeadlinePartitionsAt(
					sectors, deadlineCount, partitionMaxSectors, clock.ChainTimestamp,
				)
				if healthErr := reconcilePartitionProofHealthSnapshot(
					storage, chainCmd, currentPartitions, clock.BlockNumber,
				); healthErr != nil {
					log.Printf("[proof-health] pinned snapshot refresh deferred: %v", healthErr)
				}

				if deterministicChallenge && capacityBytes > 0 {
					epoch, epochErr := capacityCampaignStatusForStorage(storage, chainCmd)
					capacityMutationDeadline := int64(0)
					// Retained for the temporal-liveness verdict below: the same scan's
					// authoritative pending-mutation age and hard-lag limit.
					lagSnapshot := capacityProofLagSnapshot{}
					if epochErr != nil {
						log.Printf("[capacity-epoch] status unavailable; proof scheduling deferred: %v", epochErr)
					} else {
						// One progress line per keeper while it proves its declared capacity,
						// and READY when admission actually opens. Rate-limited internally, so
						// calling it every scan is what keeps the bar moving during the long
						// silence a single partition proof produces.
						reportCapacityStartupProgress(
							epoch.ProvenPartitions, epoch.ExpectedPartitions,
							!computeAdmissionState(storage, storageCfg).Closed,
							time.Now(),
						)
						lag, lagErr := refreshCapacityProofLagSnapshot(
							storage, epoch, currentPartitions, clock.ChainTimestamp,
							effectivePeriodSeconds, storageCfg,
						)
						if lagErr != nil {
							log.Printf("[capacity-lag] refresh failed: %v", lagErr)
						} else {
							capacityMutationDeadline = lag.MutationDeadlineUnix
							lagSnapshot = lag
						}
						capacityProofFreshUntil = capacityProofFreshUntilChain(epoch)
						if err := reconcileInactiveEpochSnapshotQueues(storage, chainCmd, epoch); err != nil {
							log.Printf("[capacity-epoch] inactive snapshot recovery deferred: %v", err)
						}
						if recovered, recoverErr := recoverOpenedIncrementalBatchJournal(
							storage, chainCmd, epoch, currentPartitions,
						); recoverErr != nil {
							log.Printf("[capacity-epoch] opened incremental journal recovery deferred: %v", recoverErr)
						} else if recovered {
							log.Printf("[capacity-epoch] reconstructed opened incremental batch=%d from exact durable chunk", epoch.ProofEpochID)
						}
						journal, journalReady, journalErr := reconcileCapacityEpochJournalWithExclusions(
							storage, epoch, clock.CurrentRound,
							func(member capacityEpochMemberRef) (capacityEpochExclusionStatus, error) {
								return capacityEpochExclusionStatusOnChain(chainCmd, epoch.ProofEpochID, member)
							},
						)
						if journalErr != nil {
							log.Printf("[capacity-epoch] durable journal recovery deferred: %v", journalErr)
							journalReady = false
						}
						// An unopenable journal can never become READY: reconciliation fails on
						// its own baseline candidate, which names the same out-of-domain id. So
						// this check must sit OUTSIDE readiness, or the discard below is
						// unreachable for exactly the journals that need it. Read it straight
						// from disk rather than trusting the reconciled copy.
						if stale, staleFound, staleErr := readCapacityEpochJournal(storage); staleErr != nil {
							log.Printf("[capacity-epoch] unopenable-journal check deferred: %v", staleErr)
						} else if staleFound && stale.State == capacityEpochStatePrepared &&
							stale.EpochID&capacityAuthorityDomainMask != 0 {
							log.Printf("[capacity-epoch] discarding prepared epoch %d: "+
								"its id is outside the full-epoch domain and can never be opened",
								stale.EpochID)
							if discardErr := discardUnopenableCapacityEpochJournal(
								storage, stale.EpochID,
							); discardErr != nil {
								log.Printf("[capacity-epoch] discard deferred: %v", discardErr)
							} else {
								journalReady = false
							}
						}
						if epoch.Active {
							if err := clearCapacityEpochBatchState(storage); err != nil {
								log.Printf("[capacity-epoch] batching state cleanup deferred: %v", err)
							}
						} else if journalReady && journal.State == capacityEpochStatePrepared {
							started, startErr := resumePreparedCapacityProofEpoch(
								storage, storageCfg, clock, epoch, journal,
							)
							if startErr != nil {
								log.Printf("[capacity-epoch] prepared opening recovery deferred: %v", startErr)
							} else {
								epoch = started
								journalReady = true
							}
						} else if journalReady && journal.State == capacityEpochStateOpening {
							// Opening is ambiguous by construction: the transaction may be pending
							// even when its response and hash were lost. Never resubmit it.
							log.Printf(
								"[capacity-epoch] recovery waiting epoch=%d round=%d state=%s tx=%s",
								journal.EpochID, journal.TargetRound, journal.State, journal.BeginTx,
							)
						} else if freezeQuiesceActive(storage) {
							log.Printf("[capacity-epoch] new epoch start quiesced for drain-before-cutover")
						} else {
							ready, reason, readinessErr := capacityProofEpochStartReadyWithConfig(
								storage, epoch, currentPartitions,
								clock.ChainTimestamp, effectivePeriodSeconds,
								capacityProofCatchupPending(storage),
								false,
								storageCfg,
							)
							if readinessErr != nil {
								log.Printf("[capacity-epoch] adaptive batching unavailable; starting safely (%s): %v", reason, readinessErr)
							}
							if ready {
								decision, decisionOK := latestCapacityStartDecision()
								if !decisionOK || !decision.MayOpenCampaign() {
									log.Printf("[capacity-epoch] launch gate lost typed decision; start refused")
									continue
								}
								started, startErr := queueAndBeginCapacityCampaign(
									storage, storageCfg, clock, epoch, currentPartitions, decision,
								)
								if startErr != nil {
									log.Printf("[capacity-epoch] start deferred (%s): %v", reason, startErr)
								} else {
									epoch = started
									journalReady = true
									if err := clearCapacityEpochBatchState(storage); err != nil {
										log.Printf("[capacity-epoch] batching state cleanup deferred: %v", err)
									}
								}
							} else if strings.Contains(reason, "adaptively batching") ||
								strings.Contains(reason, "deletion mutations still active") {
								log.Printf("[capacity-epoch] %s", reason)
							}
							// TEMPORAL LIVENESS (smoke 10). A decision that WAITS while
							// deadline-bearing mutations are pending must never be silent. The
							// two predicates above match only two of the reasons this decision
							// can produce; VK2 spent 18 minutes returning
							// `no_exact_selected_work` — matched by neither — while two
							// mutations aged from 0 to 1798 s against the 1800 s hard lag and
							// then breached, without emitting a single line. The wedge was
							// invisible, which is why it read as "the scheduler stopped
							// running". This states, every scan, who owns the pending work and
							// whether the next reevaluation still precedes the binding deadline.
							if decision, ok := latestCapacityStartDecision(); ok {
								// Read after readiness reconciliation: it may just have resolved
								// the last aggregate record counted by the earlier lag snapshot.
								observedLag, observationErr := observeCapacityWaitLag(storage, lagSnapshot)
								if observationErr != nil {
									log.Printf("[capacity-liveness] journal observation failed; retaining earlier pending snapshot: %v", observationErr)
								}
								liveness := evaluateCapacityStartWaitLiveness(
									decision, observedLag, time.Duration(pollSeconds)*time.Second)
								if logCapacityWaitLiveness(liveness, lastWaitLiveness, lastWaitLivenessLog) {
									log.Printf("[capacity-liveness] %s", liveness)
									lastWaitLiveness = liveness.Class
									lastWaitLivenessLog = time.Now()
								}
							}
						}

						if epoch.Active && !journalReady {
							// An active contract epoch must never fall back to a live-sector
							// reconstruction. Recovery resumes only after its durable cutoff
							// journal can be validated or safely adopted from legacy queues.
							log.Printf(
								"[capacity-epoch] epoch=%d proof deferred until durable cutoff journal is available",
								epoch.ProofEpochID,
							)
							// BOUNDED PROGRESS OWNER. Before this, the branch only logged, and an
							// epoch whose journal could not be reconciled deferred forever — Run 12
							// left two vault keepers repeating this line 64 times over 93 minutes
							// with no terminal path. The sibling branch below already had this
							// protection ("an unresolvable cutoff must not wedge the epoch
							// forever"); the guard simply was not attached to this one.
							//
							// This is SECONDARY protection only. The ordinary case that wedged
							// Run 12 — a local member snapshot ahead of chain registration — now
							// reconciles directly and never reaches here. The grace window still
							// lets a merely slow chain read win before anything is terminated.
							if aborted, detail, recoverErr := recoverUnresolvableCapacityEpoch(
								storage, chainCmd, epoch, time.Unix(clock.ChainTimestamp, 0),
							); recoverErr != nil {
								log.Printf("[capacity-epoch] unreconciled journal recovery deferred: %v", recoverErr)
							} else if aborted {
								log.Printf("[capacity-epoch] %s", detail)
							} else if detail != "" {
								log.Printf("[capacity-epoch] %s", detail)
							}
						} else if epoch.Active {
							candidates, queueErr := capacityEpochJournalCandidatesWithLagDeadline(
								storage, epoch, false, capacityMutationDeadline,
							)
							if queueErr != nil {
								log.Printf("[capacity-epoch] durable cutoff validation failed: %v", queueErr)
								// G.4B: an unresolvable cutoff must not wedge the epoch forever.
								// A locally abandoned member that the chain will never exclude
								// leaves no provable path, and the epoch-start processing behind
								// it (including blocked-demand reconciliation) would starve.
								// Terminate deterministically after a grace window; the journal
								// reaches `aborted` via the ordinary chain-derived reconcile.
								if aborted, detail, recoverErr := recoverUnresolvableCapacityEpoch(
									storage, chainCmd, epoch, time.Unix(clock.ChainTimestamp, 0),
								); recoverErr != nil {
									log.Printf("[capacity-epoch] cutoff recovery deferred: %v", recoverErr)
								} else if aborted {
									log.Printf("[capacity-epoch] %s", detail)
								} else if detail != "" {
									log.Printf("[capacity-epoch] %s", detail)
								}
							} else if len(candidates) == 0 {
								// expected-proven is zero. The contract may complete between this
								// status read and the next poll; never abort an intact journal.
								log.Printf("[capacity-epoch] epoch=%d has no unresolved cutoff members", epoch.ProofEpochID)
							} else {
								log.Printf(
									"[capacity-epoch] epoch=%d round=%d progress=%d/%d queued=%d",
									epoch.ProofEpochID, epoch.TargetRound,
									epoch.ProvenPartitions, epoch.ExpectedPartitions, len(candidates),
								)
								// Empty-delete release needs the whole epoch to finish. Prove
								// every frozen cutoff member in this scan instead of one unit.
								attempted, succeeded := provePartitionCandidates(
									storage, candidates, epoch.ProofEpochID, epoch.TargetRound,
									challengeCount, deadlineCount, partitionMaxSectors,
									partitionProverCmd, chainCmd, true, true,
									once,
									clock.ChainTimestamp,
								)
								proofUnitSucceeded = attempted && succeeded
								switch {
								case proofUnitSucceeded:
									// Only a member that actually PROVED resolves the cutoff. Retire the
									// marker so a later unrelated divergence starts its own grace window.
									if clearErr := clearCapacityEpochCutoffUnresolvable(
										storage, epoch.ProofEpochID,
									); clearErr != nil {
										log.Printf("[capacity-epoch] cutoff marker clear failed: %v", clearErr)
									}
								case attempted:
									// Enumerable members are not provable members. A frozen snapshot anchored
									// at an older round can never be reanchored ("refuse to reanchor a
									// different snapshot"), so such a member fails identically on every scan
									// while the epoch stays active and admission stays shut.
									//
									// The marker used to be cleared BEFORE this call, merely because candidates
									// could be listed — so every failing scan reset the grace window and the
									// recovery below could never mature. Live 2026-09-22: vk_6 dl47-pt128
									// reached 32 identical failures over three hours without the recovery
									// being reached once.
									//
									// Recovery stays conservative: this call only notes the marker and aborts
									// after capacityEpochCutoffRecoveryGrace, so a merely slow member still wins.
									if _, detail, recoverErr := recoverUnresolvableCapacityEpoch(
										storage, chainCmd, epoch, time.Unix(clock.ChainTimestamp, 0),
									); recoverErr != nil {
										log.Printf("[capacity-epoch] unprovable-member recovery deferred: %v", recoverErr)
									} else if detail != "" {
										log.Printf("[capacity-epoch] %s", detail)
									}
								}
							}
						}

						latest, latestErr := capacityCampaignStatusForStorage(storage, chainCmd)
						if latestErr == nil {
							capacityProofFreshUntil = capacityProofFreshUntilChain(latest)
						}
						if latestErr == nil && !latest.Active && latest.LastCapacityProofAt > 0 &&
							latest.RegisteredFreeBytes == latest.ProvedFreeBytes &&
							latest.RegisteredDataBytes == latest.ProvedDataBytes &&
							capacityProofCatchupPending(storage) {
							if clearErr := clearCapacityProofCatchup(storage); clearErr != nil {
								log.Printf("[capacity] catch-up marker clear failed: %v", clearErr)
							} else {
								log.Printf("[capacity] exact rolling epoch completed; catch-up state cleared")
								// The counterpart to the "proving …" milestone:
								// this is the moment the work that was holding
								// admission closed is finished.
								logCapacityMilestone(
									"proving complete -- %s registered and proved, admission can reopen",
									humanBytes(int64(latest.RegisteredDataBytes)))
								forceAdmissionRegistrySync(storageCfg)
							}
						}
					}
				} else {
					// Compatibility for deployments that have not enabled the
					// epoch-bound snapshot protocol.
					activeDL := currentDeadlineIndexAt(clock.ChainTimestamp, deadlineCount, effectivePeriodSeconds)
					urgentDue, scheduledDue, planErr := partitionProofPlanAt(
						storage, sectors, round, deadlineCount, partitionMaxSectors, clock.ChainTimestamp,
					)
					if planErr != nil {
						log.Printf("[proof-daemon] due-partitions error: %v", planErr)
					} else {
						candidates := recurringPartitionProofCandidates(
							storage, urgentDue, scheduledDue, activeDL, capacityPending, dataProofDeadline,
						)
						attempted, succeeded := provePartitionCandidates(
							storage, candidates, 0, round, challengeCount, deadlineCount,
							partitionMaxSectors, partitionProverCmd, chainCmd,
							false, false, once, clock.ChainTimestamp,
						)
						proofUnitSucceeded = attempted && succeeded
					}
				}
				if deterministicChallenge && capacityBytes > 0 && !proofUnitSucceeded {
					// Capacity/deletion snapshots and recurring StorageProof rounds are
					// independent obligations. Snapshot mode used to remove this planner
					// entirely, so unchanged data partitions were never proved in later
					// rounds. Run one exact-current deterministic StorageProof unit when
					// no lifecycle unit completed in this scan.
					//
					// Capacity partitions belong here for the same reason. An epoch only
					// proves the members it froze, so a keeper whose capacity never
					// changes has no other path to a recurring proof and goes stale
					// while looking perfectly healthy. capacityPending still hands the
					// epoch sole authority whenever a snapshot rebuild is in flight.
					activeDL := currentDeadlineIndexAt(
						clock.ChainTimestamp, deadlineCount, effectivePeriodSeconds)
					urgentDue, scheduledDue, planErr := partitionProofPlanAt(
						storage, sectors, round, deadlineCount, partitionMaxSectors,
						clock.ChainTimestamp,
					)
					if planErr != nil {
						log.Printf("[proof-daemon] periodic proof plan error: %v", planErr)
					} else {
						candidates := recurringPartitionProofCandidates(
							storage, urgentDue, scheduledDue, activeDL, capacityPending, dataProofDeadline,
						)
						attempted, succeeded := provePartitionCandidates(
							storage, candidates, 0, round, challengeCount, deadlineCount,
							partitionMaxSectors, partitionProverCmd, chainCmd,
							false, true, once, clock.ChainTimestamp,
						)
						proofUnitSucceeded = attempted && succeeded
					}
				}
			}
		} else {
			// Original per-sector path — unchanged.
			sectors, err := dueSectorsAt(storage, round, clock.ChainTimestamp)
			if err != nil {
				log.Printf("[proof-daemon] due sector scan error: %v", err)
			} else if len(sectors) == 0 {
				log.Printf("[proof-daemon] no due sectors for round=%d", round)
			} else {
				log.Printf("[proof-daemon] %d due sector(s), round=%d", len(sectors), round)
				for _, sector := range sectors {
					if err := proveSectorWithChain(storage, sector, round, challengeCount, proverCmd, chainCmd); err != nil {
						log.Printf("[proof-daemon] sector %s proof failed: %v", sector.SectorID, err)
						continue
					}
					log.Printf("[proof-daemon] sector %s proof submitted for round=%d", sector.SectorID, round)
				}
			}
		}

		if usePartitions {
			// Admission consumes a small durable health snapshot instead of doing
			// chain calls on the request path. Refresh it after proof work so queue
			// completion, deadlines, and successor pressure are immediately visible.
			if sectors, err := listSectors(storage); err != nil {
				log.Printf("[proof-backlog] health refresh deferred: %v", err)
			} else {
				obligations := len(buildDeadlinePartitionsAt(
					sectors, deadlineCount, partitionMaxSectors, clock.ChainTimestamp,
				)) > 0
				if err := refreshProofBacklogMetrics(
					storage, obligations, pollSeconds,
					clock.ChainTimestamp, proofSchedulingReady,
					capacityAdmissionRequired, capacityProofFreshUntil,
				); err != nil {
					log.Printf("[proof-backlog] health refresh failed: %v", err)
				}
			}
		}

		if once {
			return
		}
		if proofUnitSucceeded {
			// Rescan immediately after one durable unit. Sleeping here would impose
			// an artificial poll delay on every partition and capacity catch-up.
			continue
		}
		vkWait(time.Duration(pollSeconds) * time.Second)
	}
}
