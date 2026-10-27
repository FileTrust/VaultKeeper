package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

const ridaHeaderSize = 16

type ridaHeader struct {
	Version    byte
	N          int
	Threshold  int
	ShareIndex int
	OrigSize   uint64
}

func normalizeStorePieceFormat(format string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(format))
	switch value {
	case "", PieceFormatRIDAV1, "rida", "ida":
		return PieceFormatRIDAV1, nil
	default:
		return "", fmt.Errorf("unsupported piece format %q", format)
	}
}

func readRIDAHeader(path string) (ridaHeader, error) {
	var header ridaHeader
	f, err := os.Open(path)
	if err != nil {
		return header, err
	}
	defer f.Close()

	raw := make([]byte, ridaHeaderSize)
	n, err := f.Read(raw)
	if err != nil {
		return header, err
	}
	if n != ridaHeaderSize {
		return header, fmt.Errorf("RIDA header must be %d bytes", ridaHeaderSize)
	}
	if string(raw[:4]) != "RIDA" {
		return header, fmt.Errorf("invalid RIDA magic")
	}
	header.Version = raw[4]
	header.N = int(raw[5])
	header.Threshold = int(raw[6])
	header.ShareIndex = int(raw[7])
	header.OrigSize = binary.BigEndian.Uint64(raw[8:16])
	return header, nil
}

func validateRIDAPieceFile(path string, req StoreReq) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("piece path is a directory")
	}
	if st.Size() != req.Size {
		return fmt.Errorf("piece size %d does not match request size %d", st.Size(), req.Size)
	}
	if st.Size() < ridaHeaderSize {
		return fmt.Errorf("piece is smaller than RIDA header")
	}

	header, err := readRIDAHeader(path)
	if err != nil {
		return err
	}
	if header.Version != 1 {
		return fmt.Errorf("unsupported RIDA version %d", header.Version)
	}
	if header.N <= 0 || header.Threshold <= 0 || header.Threshold > header.N {
		return fmt.Errorf("invalid RIDA n/t values n=%d t=%d", header.N, header.Threshold)
	}
	if req.PieceIndex <= 0 {
		return fmt.Errorf("pieceIndex is required for RIDA pieces")
	}
	expectedIndex := req.PieceIndex - 1
	if header.ShareIndex != expectedIndex {
		return fmt.Errorf("RIDA share index %d does not match request pieceIndex %d", header.ShareIndex, req.PieceIndex)
	}

	expectedPayload := (header.OrigSize + uint64(header.Threshold) - 1) / uint64(header.Threshold)
	if expectedPayload > uint64(^uint64(0)>>1) {
		return fmt.Errorf("RIDA original size is too large")
	}
	payloadSize := uint64(st.Size() - ridaHeaderSize)
	if payloadSize != expectedPayload {
		return fmt.Errorf("RIDA payload size %d does not match expected %d", payloadSize, expectedPayload)
	}
	return nil
}
