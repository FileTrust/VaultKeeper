package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func normalizeRoot(root string) string {
	clean := strings.ToLower(strings.TrimSpace(root))
	clean = strings.TrimPrefix(clean, "0x")
	return "0x" + clean
}

func validateRoot(root string) error {
	clean := strings.TrimPrefix(strings.TrimSpace(root), "0x")
	if len(clean) != 64 {
		return fmt.Errorf("root must be 32 bytes hex")
	}
	_, err := hex.DecodeString(clean)
	return err
}

func rootBytes(root string) ([]byte, error) {
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(normalizeRoot(root), "0x"))
}

func bytesToRoot(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

func hashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func merkleRootFromLeaves(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return hashLeaf(nil)
	}
	level := make([][]byte, len(leaves))
	for i := range leaves {
		level[i] = append([]byte(nil), leaves[i]...)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, hashNode(left, right))
		}
		level = next
	}
	return level[0]
}

func merkleProofFromLeaves(leaves [][]byte, index int) ([]string, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("empty tree")
	}
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("proof index out of range")
	}
	level := make([][]byte, len(leaves))
	for i := range leaves {
		level[i] = append([]byte(nil), leaves[i]...)
	}
	proof := []string{}
	idx := index
	for len(level) > 1 {
		siblingIdx := idx ^ 1
		if siblingIdx >= len(level) {
			siblingIdx = idx
		}
		proof = append(proof, bytesToRoot(level[siblingIdx]))

		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, hashNode(left, right))
		}
		idx = idx / 2
		level = next
	}
	return proof, nil
}

func computePieceCommitment(path string, blockSize int64) (pieceRoot string, wholeHash string, blockCount int64, size int64, err error) {
	if blockSize <= 0 {
		return "", "", 0, 0, fmt.Errorf("invalid block size")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0, 0, err
	}
	defer f.Close()

	whole := sha256.New()
	if blockSize > int64(int(^uint(0)>>1)) {
		return "", "", 0, 0, fmt.Errorf("block size too large")
	}
	buf := make([]byte, int(blockSize))
	leaves := [][]byte{}
	for {
		n, rerr := io.ReadFull(f, buf)
		if rerr == io.EOF {
			break
		}
		if rerr == io.ErrUnexpectedEOF {
			// Final short block.
		} else if rerr != nil {
			return "", "", 0, 0, rerr
		}
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			whole.Write(chunk)
			leaves = append(leaves, hashLeaf(chunk))
			size += int64(n)
			blockCount++
		}
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	root := merkleRootFromLeaves(leaves)
	return bytesToRoot(root), hex.EncodeToString(whole.Sum(nil)), blockCount, size, nil
}

func computeSectorRoot(pieceRoots []string) (string, error) {
	leaves := make([][]byte, 0, len(pieceRoots))
	for _, r := range pieceRoots {
		b, err := rootBytes(r)
		if err != nil {
			return "", err
		}
		leaves = append(leaves, b)
	}
	return bytesToRoot(merkleRootFromLeaves(leaves)), nil
}

func computeSectorProof(pieceRoots []string, piecePosition int) ([]string, error) {
	leaves := make([][]byte, 0, len(pieceRoots))
	for _, r := range pieceRoots {
		b, err := rootBytes(r)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, b)
	}
	return merkleProofFromLeaves(leaves, piecePosition)
}

func cidV0FromSHA256Hex(hashHex string) string {
	b, err := hex.DecodeString(hashHex)
	if err != nil || len(b) != 32 {
		return ""
	}
	return cidV0FromSHA256(b)
}
