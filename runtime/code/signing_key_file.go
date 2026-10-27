package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Keep the key out of /proc/*/cmdline. Do not follow links or read devices/FIFOs.
func loadSigningKeyFile(path, inline string) (string, error) {
	if path == "" {
		return inline, nil // compatibility for existing manual invocations
	}
	if inline != "" {
		return "", errors.New("choose either a key file or the legacy key argument")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errors.New("cannot open VK signing key file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	var st unix.Stat_t
	if err != nil || unix.Fstat(fd, &st) != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || int(st.Uid) != os.Geteuid() || info.Size() > 128 {
		return "", errors.New("VK signing key must be an owner-only regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 128))
	if err != nil {
		return "", errors.New("cannot read VK signing key file")
	}
	key := strings.TrimSpace(string(b))
	if _, err := ParseVKPrivKey(key); err != nil {
		return "", errors.New("invalid VK signing key file")
	}
	return key, nil
}

// Do not silently rotate existing peer identities.
func readOwnerPrivateFile(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	var st unix.Stat_t
	if err != nil || unix.Fstat(fd, &st) != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || int(st.Uid) != os.Geteuid() || info.Size() > limit {
		return nil, errors.New("invalid owner-only credential file")
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}
