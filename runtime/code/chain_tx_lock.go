package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const chainTxLockDirEnv = "FILETRUST_CHAIN_TX_LOCK_DIR"

// accountTxLock serializes nonce allocation and transaction submission for one
// signing account across all VK processes on the host. The Python proof client
// uses the same path and lock convention.
type accountTxLock struct {
	file *os.File
	path string
}

func acquireAccountTxLock(address string) (*accountTxLock, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	address = strings.TrimPrefix(address, "0x")
	if address == "" {
		return nil, fmt.Errorf("acquire account transaction lock: empty address")
	}
	for _, r := range address {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return nil, fmt.Errorf("acquire account transaction lock: invalid address %q", address)
		}
	}

	dir := strings.TrimSpace(os.Getenv(chainTxLockDirEnv))
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "filetrust-chain-tx-locks")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create account transaction lock directory: %w", err)
	}
	path := filepath.Join(dir, address+".lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open account transaction lock: %w", err)
	}

	waitStarted := time.Now()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire account transaction lock: %w", err)
	}
	if waited := time.Since(waitStarted); waited >= 250*time.Millisecond {
		log.Printf("[chain-tx] account=%s waited=%s for signer lock", address, waited.Round(time.Millisecond))
	}
	return &accountTxLock{file: file, path: path}, nil
}

func (lock *accountTxLock) Release() {
	if lock == nil || lock.file == nil {
		return
	}
	if err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN); err != nil {
		log.Printf("[chain-tx] release warning path=%s: %v", lock.path, err)
	}
	if err := lock.file.Close(); err != nil {
		log.Printf("[chain-tx] close warning path=%s: %v", lock.path, err)
	}
	lock.file = nil
}
