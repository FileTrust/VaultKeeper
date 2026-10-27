package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var partitionContentABI = struct {
	sync.Once
	arguments abi.Arguments
	err       error
}{}

func partitionContentABIArguments() (abi.Arguments, error) {
	partitionContentABI.Do(func() {
		typeNames := []string{
			"uint8", "uint8", "uint8", "bytes32[]", "bytes32[]", "uint32[]",
			"bytes32[]", "uint64", "uint64", "uint16",
		}
		arguments := make(abi.Arguments, 0, len(typeNames))
		for _, name := range typeNames {
			typ, err := abi.NewType(name, "", nil)
			if err != nil {
				partitionContentABI.err = err
				return
			}
			arguments = append(arguments, abi.Argument{Type: typ})
		}
		partitionContentABI.arguments = arguments
	})
	return partitionContentABI.arguments, partitionContentABI.err
}

func strictPartitionBytes32(value, label string) ([32]byte, error) {
	var out [32]byte
	raw := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(value), "0x"), "0X")
	if len(raw) != 64 {
		return out, fmt.Errorf("%s must contain exactly 32 bytes", label)
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return out, fmt.Errorf("decode %s: %w", label, err)
	}
	copy(out[:], decoded)
	return out, nil
}

// partitionChainContentHash exactly mirrors StorageProofSC's
// keccak256(abi.encode(...)) in registerOrUpdatePartition. partitionContentHash
// remains the private local scheduling fingerprint; the two hashes are
// intentionally different and must never be compared with each other.
func partitionChainContentHash(partition PartitionMeta, challengeCount uint16) (string, error) {
	if partition.DeadlineIndex < 0 || partition.DeadlineIndex > 255 ||
		partition.PartitionIndex < 0 || partition.PartitionIndex > 255 {
		return "", fmt.Errorf("partition coordinates exceed uint8")
	}
	if challengeCount == 0 {
		return "", fmt.Errorf("partition challenge count must be positive")
	}
	kind := uint8(1)
	wantKind := PartitionKindData
	if partition.PartitionIndex >= CapacityPartitionIndexOffset {
		kind = 2
		wantKind = PartitionKindCapacity
	}
	if partition.PartitionKind != "" && partition.PartitionKind != wantKind {
		return "", fmt.Errorf("partition kind %q conflicts with index %d", partition.PartitionKind, partition.PartitionIndex)
	}
	if len(partition.Sectors) == 0 {
		return "", fmt.Errorf("partition has no sectors")
	}
	sectorIDs := make([][32]byte, len(partition.Sectors))
	sectorRoots := make([][32]byte, len(partition.Sectors))
	blockCounts := make([]uint32, len(partition.Sectors))
	pieceCommitments := make([][32]byte, len(partition.Sectors))
	for i, sector := range partition.Sectors {
		sectorIDs[i] = ethcrypto.Keccak256Hash([]byte(sector.SectorID))
		root, err := strictPartitionBytes32(sector.SectorRoot, fmt.Sprintf("sector root %d", i))
		if err != nil {
			return "", err
		}
		sectorRoots[i] = root
		if sector.SectorBlockCount <= 0 || uint64(sector.SectorBlockCount) > uint64(^uint32(0)) {
			return "", fmt.Errorf("sector %d block count is outside uint32", i)
		}
		blockCounts[i] = uint32(sector.SectorBlockCount)
		commitment, err := strictPartitionBytes32(sector.ZKPieceCommitment, fmt.Sprintf("piece commitment %d", i))
		if err != nil {
			return "", err
		}
		pieceCommitments[i] = commitment
	}
	if partition.CommittedBytes < 0 {
		return "", fmt.Errorf("partition committed bytes are outside uint64")
	}
	if partition.Expiration <= 0 {
		return "", fmt.Errorf("partition expiration must be positive")
	}
	arguments, err := partitionContentABIArguments()
	if err != nil {
		return "", fmt.Errorf("initialize partition content ABI: %w", err)
	}
	encoded, err := arguments.Pack(
		uint8(partition.DeadlineIndex), uint8(partition.PartitionIndex), kind,
		sectorIDs, sectorRoots, blockCounts, pieceCommitments,
		uint64(partition.CommittedBytes), uint64(partition.Expiration), challengeCount,
	)
	if err != nil {
		return "", fmt.Errorf("encode partition chain content: %w", err)
	}
	return ethcrypto.Keccak256Hash(encoded).Hex(), nil
}

func partitionMatchesChainContent(status PartitionVersionStatus, partition PartitionMeta) bool {
	if status.ChallengeCount == 0 {
		return false
	}
	expected, err := partitionChainContentHash(partition, status.ChallengeCount)
	return err == nil && sameRoot(status.ContentHash, expected)
}
