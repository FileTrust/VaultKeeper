package main

// G.4B-LV0 — deployed proof-profile preflight.
//
// StorageProofSC computes a partition's committed bytes as
// `sum(sectorBlockCounts) * zkBlockSizeBytes` (StorageProofSC.sol:707). If the deployed
// zkBlockSizeBytes disagrees with the VK's local proof profile, the same sectors produce
// different byte totals on each side. The VK then correctly refuses to accept the registration
// it just made, and retries the SAME partition forever — never advancing to partition 2, never
// reaching certification, never opening a campaign.
//
// That is exactly what blocked the first G.4B live run: deployed 128 versus local 512, which
// made 262144 blocks read back as 33,554,432 bytes instead of 134,217,728. The VK's refusal was
// correct; what was missing was a fail-fast check so the operator learns the real reason before
// the first registration instead of watching an opaque retry loop.
//
// This check is authoritative: it compares the VK's local profile against the DEPLOYED contract
// state pinned in the verified deployment manifest, not against environment variables.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

// ProofProfileMismatchError reports a deployment/profile disagreement. It is deliberately not
// retryable: no amount of retrying changes a deployed constant.
type ProofProfileMismatchError struct {
	Field    string
	Deployed string
	Local    string
}

func (e *ProofProfileMismatchError) Error() string {
	return fmt.Sprintf(
		"deployed proof profile does not match the local VK profile: %s deployed=%s local=%s; "+
			"capacity bootstrap aborted before the first partition registration",
		e.Field, e.Deployed, e.Local)
}

// ErrProofProfileUnpinned marks a manifest that does not pin the proof profile at all.
var ErrProofProfileUnpinned = errors.New(
	"deployment manifest does not pin the deployed proof profile")

// deployedProofProfile is the pinned on-chain proof shape.
type deployedProofProfile struct {
	ZkBlockSizeBytes           string `json:"zkBlockSizeBytes"`
	ZkTreeDepth                string `json:"zkTreeDepth"`
	PartitionCircuitSectors    string `json:"partitionCircuitSectors"`
	PartitionCircuitChallenges string `json:"partitionCircuitChallenges"`
}

// localProofProfile is what this VK will actually prove with.
type localProofProfile struct {
	ZKBlockSize         int64
	ZKTreeDepth         int64
	PartitionMaxSectors int64
	ChallengeCount      int64
}

func localProofProfileFromConfig(cfg ServerConfig) localProofProfile {
	return localProofProfile{
		ZKBlockSize:         cfg.ZKBlockSize,
		ZKTreeDepth:         int64(cfg.ZKTreeDepth),
		PartitionMaxSectors: int64(cfg.PartitionMaxSectors),
		ChallengeCount:      int64(cfg.ChallengeCount),
	}
}

// verifyDeployedProofProfile compares the pinned deployed profile against the local one.
//
// It returns a typed mismatch error on the FIRST disagreeing field, so the operator sees both
// values. A profile the manifest does not pin is itself a failure: an unverifiable profile must
// not be assumed compatible.
func verifyDeployedProofProfile(deployed deployedProofProfile, local localProofProfile) error {
	parse := func(field, raw string) (int64, error) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			return 0, fmt.Errorf("%w: %s is absent", ErrProofProfileUnpinned, field)
		}
		value, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %s is not an integer (%q)", ErrProofProfileUnpinned, field, raw)
		}
		return value, nil
	}

	blockSize, err := parse("zkBlockSizeBytes", deployed.ZkBlockSizeBytes)
	if err != nil {
		return err
	}
	depth, err := parse("zkTreeDepth", deployed.ZkTreeDepth)
	if err != nil {
		return err
	}
	sectors, err := parse("partitionCircuitSectors", deployed.PartitionCircuitSectors)
	if err != nil {
		return err
	}
	challenges, err := parse("partitionCircuitChallenges", deployed.PartitionCircuitChallenges)
	if err != nil {
		return err
	}
	if local.ZKBlockSize > 0 && blockSize != local.ZKBlockSize {
		return &ProofProfileMismatchError{
			Field:    "zkBlockSizeBytes",
			Deployed: strconv.FormatInt(blockSize, 10),
			Local:    strconv.FormatInt(local.ZKBlockSize, 10),
		}
	}

	// Tree depth changes the Merkle shape the verifier expects; a disagreement makes every
	// submitted proof invalid even though registration itself would succeed.
	if local.ZKTreeDepth > 0 {
		if depth != local.ZKTreeDepth {
			return &ProofProfileMismatchError{
				Field:    "zkTreeDepth",
				Deployed: strconv.FormatInt(depth, 10),
				Local:    strconv.FormatInt(local.ZKTreeDepth, 10),
			}
		}
	}

	// The partition sector limit bounds every registration; a local profile above the deployed
	// circuit limit would have every registration reverted.
	if local.PartitionMaxSectors > 0 {
		if local.PartitionMaxSectors > sectors {
			return &ProofProfileMismatchError{
				Field:    "partitionCircuitSectors",
				Deployed: strconv.FormatInt(sectors, 10),
				Local:    strconv.FormatInt(local.PartitionMaxSectors, 10),
			}
		}
	}

	if local.ChallengeCount > 0 {
		if local.ChallengeCount > challenges {
			return &ProofProfileMismatchError{
				Field:    "partitionCircuitChallenges",
				Deployed: strconv.FormatInt(challenges, 10),
				Local:    strconv.FormatInt(local.ChallengeCount, 10),
			}
		}
	}
	return nil
}

// proofProfileMismatch reports whether an error is a non-retryable profile disagreement.
func proofProfileMismatch(err error) bool {
	var mismatch *ProofProfileMismatchError
	return errors.As(err, &mismatch) || errors.Is(err, ErrProofProfileUnpinned)
}

// committedBytesFor mirrors StorageProofSC.sol:707 so a caller can show the operator the exact
// arithmetic that will disagree.
func committedBytesFor(totalSectorBlocks, zkBlockSize int64) int64 {
	if totalSectorBlocks <= 0 || zkBlockSize <= 0 {
		return 0
	}
	return totalSectorBlocks * zkBlockSize
}

// ─── production bootstrap gate ─────────────────────────────────────────────────────────

// proofProfilePreflightRuns counts executions so a test can prove the check runs once per
// startup rather than once per partition.
var proofProfilePreflightRuns atomic.Int64

// enforceDeployedProofProfile is the production gate. It MUST run after the deployment manifest
// is loaded and validated, and BEFORE the first partition can be registered.
//
// The order it enforces is:
//
//	load and validate deployment manifest
//	  -> read/select the local proof profile
//	  -> verifyDeployedProofProfile
//	  -> only on success may capacity bootstrap/registration begin
//
// A mismatch or an unpinned profile is terminal for this process: the caller must abort, not
// log and continue, and not enter retry scheduling. Only a restart against a corrected
// deployment or profile can clear it.
func enforceDeployedProofProfile(cfg ServerConfig) error {
	proofProfilePreflightRuns.Add(1)
	path := strings.TrimSpace(cfg.DeploymentManifestPath)
	if path == "" {
		// No manifest is pinned for this deployment, so there is nothing authoritative to
		// verify against. This is the pre-existing opt-in behaviour of manifest enforcement
		// and is left unchanged here.
		return nil
	}
	manifest, err := loadDeploymentManifest(path)
	if err != nil {
		return fmt.Errorf("proof-profile preflight: %w", err)
	}
	local := localProofProfileFromConfig(cfg)
	if err := verifyDeployedProofProfile(manifest.ProofProfile, local); err != nil {
		var mismatch *ProofProfileMismatchError
		if errors.As(err, &mismatch) && mismatch.Field == "zkBlockSizeBytes" {
			// Show the operator the arithmetic that would silently disagree, using one
			// full 16-sector partition at the local profile as the worked example.
			const exampleBlocks = int64(16 * 8192)
			deployedSize, _ := strconv.ParseInt(mismatch.Deployed, 10, 64)
			return fmt.Errorf("%w (worked example: %d sector blocks store %d bytes on chain "+
				"but %d bytes locally)", err, exampleBlocks,
				committedBytesFor(exampleBlocks, deployedSize),
				committedBytesFor(exampleBlocks, local.ZKBlockSize))
		}
		return err
	}
	return nil
}
