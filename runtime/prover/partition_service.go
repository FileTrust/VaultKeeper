package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

const maxPartitionServiceRequestBytes = 16 << 20

type partitionProvingArtifacts struct {
	params PartitionProverParams
	cs     constraint.ConstraintSystem
	pk     groth16.ProvingKey
	vk     groth16.VerifyingKey
}

type artifactReader interface {
	ReadFrom(io.Reader) (int64, error)
}

func readProvingArtifact(path string, target artifactReader, stage *partitionStageLogger, label string) error {
	started := time.Now()
	stage.Log("%s load start path=%s", label, path)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", label, err)
	}
	defer f.Close()
	h := sha256.New()
	bytesRead, err := target.ReadFrom(io.TeeReader(f, h))
	if err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}
	stage.Log("%s load done bytes=%d sha256=%s took=%.3fs", label, bytesRead, hex.EncodeToString(h.Sum(nil)), time.Since(started).Seconds())
	return nil
}

func loadPartitionProvingArtifacts(keysDir string, params PartitionProverParams, stage *partitionStageLogger) (*partitionProvingArtifacts, error) {
	if err := params.validatePartition(); err != nil {
		return nil, err
	}
	artifacts := &partitionProvingArtifacts{
		params: params,
		cs:     groth16.NewCS(ecc.BN254),
		pk:     groth16.NewProvingKey(ecc.BN254),
		vk:     groth16.NewVerifyingKey(ecc.BN254),
	}
	if err := readProvingArtifact(filepath.Join(keysDir, "storageproof_partition.r1cs"), artifacts.cs, stage, "partition r1cs"); err != nil {
		return nil, err
	}
	if err := readProvingArtifact(filepath.Join(keysDir, "storageproof_partition.pk"), artifacts.pk, stage, "partition proving key"); err != nil {
		return nil, err
	}
	if err := readProvingArtifact(filepath.Join(keysDir, "storageproof_partition.vk"), artifacts.vk, stage, "partition verifying key"); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func writePartitionServiceError(w io.Writer, err error) {
	_ = json.NewEncoder(w).Encode(ProverResponse{OK: false, Err: err.Error()})
}

func handlePartitionServiceConnection(conn net.Conn, keysDir string, params PartitionProverParams, artifacts *partitionProvingArtifacts) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Hour))
	payload, err := io.ReadAll(io.LimitReader(conn, maxPartitionServiceRequestBytes+1))
	if err != nil {
		writePartitionServiceError(conn, fmt.Errorf("read partition service request: %w", err))
		return
	}
	if len(payload) == 0 {
		writePartitionServiceError(conn, fmt.Errorf("empty partition service request"))
		return
	}
	if len(payload) > maxPartitionServiceRequestBytes {
		writePartitionServiceError(conn, fmt.Errorf("partition service request exceeds %d bytes", maxPartitionServiceRequestBytes))
		return
	}

	var response bytes.Buffer
	if err := cmdPartitionProveWithIO(keysDir, params, bytes.NewReader(payload), &response, artifacts); err != nil {
		writePartitionServiceError(conn, err)
		return
	}
	if _, err := conn.Write(response.Bytes()); err != nil {
		fmt.Fprintf(os.Stderr, "%s [partition-service] response write failed: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	}
}

func preparePartitionServiceSocket(socketPath string) error {
	if socketPath == "" {
		return fmt.Errorf("partition-serve requires --socket")
	}
	if len(socketPath) >= 100 {
		return fmt.Errorf("partition service socket path is too long (%d bytes): %s", len(socketPath), socketPath)
	}
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create partition service socket directory: %w", err)
	}
	info, err := os.Lstat(socketPath)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refuse to replace non-socket path: %s", socketPath)
		}
		if conn, dialErr := net.DialTimeout("unix", socketPath, 500*time.Millisecond); dialErr == nil {
			conn.Close()
			return fmt.Errorf("partition prover service is already listening on %s", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return fmt.Errorf("remove stale partition service socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect partition service socket: %w", err)
	}
	return nil
}

func cmdPartitionServe(socketPath, keysDir string, params PartitionProverParams) error {
	if err := preparePartitionServiceSocket(socketPath); err != nil {
		return err
	}
	stage := newPartitionStageLogger()
	stage.Log("persistent service artifact load start socket=%s", socketPath)
	artifacts, err := loadPartitionProvingArtifacts(keysDir, params, stage)
	if err != nil {
		return err
	}
	stage.Log("persistent service artifact load complete")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on partition service socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		return fmt.Errorf("secure partition service socket: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s [partition-service] ready socket=%s pid=%d profile={block=%d depth=%d sectors=%d challenges=%d}\n",
		time.Now().UTC().Format(time.RFC3339), socketPath, os.Getpid(), params.ZKBlockSize, params.ZKTreeDepth, params.PartitionSectors, params.MaxChallenges)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		<-signals
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil
		}
		// Deliberately sequential: loaded gnark artifacts remain immutable and
		// host memory is bounded to one active partition witness/proof.
		handlePartitionServiceConnection(conn, keysDir, params, artifacts)
	}
}
