package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func initStorage(storage string) error {
	for _, d := range []string{pieceDir(storage), metaDir(storage), sectorDir(storage), tmpDir(storage)} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	return nil
}

func pieceDir(storage string) string  { return filepath.Join(storage, "pieces") }
func metaDir(storage string) string   { return filepath.Join(storage, "meta") }
func sectorDir(storage string) string { return filepath.Join(storage, "sectors") }
func tmpDir(storage string) string    { return filepath.Join(storage, "tmp") }

func safeID(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "0x")
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, ":", "_")
	return id
}

func piecePath(storage, pieceRoot string) string {
	return filepath.Join(pieceDir(storage), safeID(pieceRoot)+".piece")
}

func metaPath(storage, pieceRoot string) string {
	return filepath.Join(metaDir(storage), safeID(pieceRoot)+".json")
}

func writeMeta(storage string, meta PieceMeta) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(metaPath(storage, meta.PieceRoot), b, 0600)
}

func readMeta(storage, pieceRoot string) (PieceMeta, error) {
	var meta PieceMeta
	if err := validateRoot(pieceRoot); err != nil {
		return meta, err
	}
	b, err := os.ReadFile(metaPath(storage, pieceRoot))
	if err != nil {
		return meta, err
	}
	err = json.Unmarshal(b, &meta)
	return meta, err
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func storePieceFromTemp(storage, tempPath string, req StoreReq, pieceBlockSize int64) (PieceMeta, error) {
	pieceRoot, pieceHash, blockCount, size, err := computePieceCommitment(tempPath, pieceBlockSize)
	if err != nil {
		return PieceMeta{}, err
	}
	if size != req.Size {
		return PieceMeta{}, fmt.Errorf("received size %d does not match request size %d", size, req.Size)
	}
	finalPath := piecePath(storage, pieceRoot)
	if _, err := os.Stat(finalPath); err == nil {
		_ = os.Remove(tempPath)
	} else if err := os.Rename(tempPath, finalPath); err != nil {
		return PieceMeta{}, err
	}
	legacyCID := cidV0FromSHA256Hex(pieceHash)
	meta := PieceMeta{
		FileID:          req.FileID,
		TransferID:      req.TransferID,
		Uploader:        req.Uploader,
		Name:            req.Name,
		PieceIndex:      req.PieceIndex,
		PieceRoot:       pieceRoot,
		PieceID:         pieceRoot,
		CID:             legacyCID,
		PieceHash:       pieceHash,
		HashAlg:         HashAlgSha256,
		RootAlg:         RootAlgMerkleSHA256,
		PieceBlockSize:  pieceBlockSize,
		PieceBlockCount: blockCount,
		Size:            size,
		ServiceEnd:      req.ServiceEnd,
		StoredAt:        nowRFC3339(),
		FileFormat:      req.FileFormat,
	}
	return meta, writeMeta(storage, meta)
}

func verifyStoredPiece(storage, pieceRoot string) (bool, string, error) {
	root := normalizeRoot(pieceRoot)
	meta, err := readMeta(storage, root)
	if err != nil {
		return false, "", err
	}
	got, _, _, _, err := computePieceCommitment(piecePath(storage, root), meta.PieceBlockSize)
	if err != nil {
		return false, "", err
	}
	return strings.EqualFold(got, root), got, nil
}

func runGC(storage string, olderThan time.Duration) {
	mutation, mutationErr := beginCapacityMutation(storage, "manual-gc")
	if mutationErr != nil {
		fatalJSON(fmt.Errorf("coordinate manual gc: %w", mutationErr))
	}
	defer mutation.Release()
	cutoff := time.Now().UTC().Add(-olderThan)
	entries, err := os.ReadDir(metaDir(storage))
	if err != nil {
		fatalJSON(err)
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		metaFile := filepath.Join(metaDir(storage), e.Name())
		b, err := os.ReadFile(metaFile)
		if err != nil {
			continue
		}
		var meta PieceMeta
		if err := json.Unmarshal(b, &meta); err != nil {
			continue
		}
		// Age-based GC is only for orphaned files. A live sector is a storage
		// obligation and must be removed through expiration/deletion lifecycle,
		// never merely because its local piece metadata is old.
		if meta.SectorID != "" {
			if sector, sectorErr := readSector(storage, meta.SectorID); sectorErr == nil && sector.Status != "deleted" {
				continue
			}
		}
		storedAt, err := time.Parse(time.RFC3339, meta.StoredAt)
		if err != nil || storedAt.After(cutoff) {
			continue
		}
		_ = os.Remove(piecePath(storage, meta.PieceRoot))
		_ = os.Remove(metaFile)
		removed++
	}
	fmt.Printf("garbage collection done; removed %d piece(s)\n", removed)
}

func runExpiredGCAt(storage string, logger *log.Logger, chainTimestamp int64) (sectorsRemoved, piecesRemoved int) {
	result := runExpiredGCDetailedAt(storage, logger, chainTimestamp)
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("[gc] expired-gc local pass complete sectorsRemoved=%d piecesRemoved=%d pendingPartitions=%d failures=%d",
		result.SectorsRemoved, result.PiecesRemoved, len(result.Affected), result.Failures)
	return result.SectorsRemoved, result.PiecesRemoved
}
