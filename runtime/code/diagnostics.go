package main

// Local-only diagnostic drafts. No HTTP client, exception value, wallet, peer,
// storage path or payload is included. Python's preview/send tool handles consent.
import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed diagnostics-policy.json
var diagnosticPolicyJSON []byte

var diagnosticState = struct {
	sync.Mutex
	home, operation string
	last            map[string]time.Time
}{last: make(map[string]time.Time)}

func diagnosticInit(mode, storage string) {
	operation := ""
	switch mode {
	case "server":
		operation = "storage.write"
	case "proof-daemon":
		operation = "proof.generate"
	}
	home := os.Getenv("FILETRUST_DIAGNOSTICS_HOME")
	if home == "" {
		home = filepath.Dir(storage)
	}
	home, _ = filepath.Abs(home)
	diagnosticState.Lock()
	diagnosticState.home, diagnosticState.operation = home, operation
	diagnosticState.Unlock()
}

func diagnosticPrivateDir(path string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe diagnostic directory")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("diagnostic directory is not private")
	}
	return nil
}

func diagnosticCapture(code, kind string) {
	diagnosticState.Lock()
	defer diagnosticState.Unlock()
	if diagnosticState.operation == "" {
		return
	}
	var policy struct {
		Release    string         `json:"release"`
		Files      map[string]int `json:"files"`
		ErrorCodes []string       `json:"error_codes"`
	}
	if json.Unmarshal(diagnosticPolicyJSON, &policy) != nil {
		return
	}
	validCode := false
	for _, allowed := range policy.ErrorCodes {
		if code == allowed {
			validCode = true
		}
	}
	if !validCode || (kind != "error" && kind != "panic") {
		return
	}
	now := time.Now()
	fingerprint := code + kind + diagnosticState.operation
	if now.Sub(diagnosticState.last[fingerprint]) < time.Minute {
		return
	}
	directory := filepath.Join(diagnosticState.home, ".filetrust-diagnostics")
	if diagnosticPrivateDir(directory) != nil {
		base := filepath.Join(os.TempDir(), "filetrust-diagnostics-"+strconv.Itoa(os.Getuid()))
		if diagnosticPrivateDir(base) != nil {
			return
		}
		identity := sha256.Sum256([]byte("VK" + diagnosticState.home))
		directory = filepath.Join(base, hex.EncodeToString(identity[:])[:24])
		if diagnosticPrivateDir(directory) != nil {
			return
		}
	}
	environment := os.Getenv("FILETRUST_DIAGNOSTICS_ENVIRONMENT")
	if environment == "" {
		environment = "testnet"
	}
	if environment != "development" && environment != "testnet" && environment != "mainnet" {
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(id[:])
	identifier := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	frames := make([]map[string]any, 0)
	_, ownFile, _, _ := runtime.Caller(0)
	pcs := make([]uintptr, 64)
	count := runtime.Callers(2, pcs)
	iterator := runtime.CallersFrames(pcs[:count])
	for {
		frame, more := iterator.Next()
		name := "code/" + filepath.Base(frame.File)
		if filepath.Dir(frame.File) == filepath.Dir(ownFile) && filepath.Base(frame.File) != "diagnostics.go" && frame.Line > 0 && frame.Line <= policy.Files[name] {
			frames = append(frames, map[string]any{"file": name, "line": frame.Line})
		}
		if !more {
			break
		}
	}
	// runtime.Callers lists newest first; Sentry expects oldest first.
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	if len(frames) > 20 {
		frames = frames[len(frames)-20:]
	}
	report := map[string]any{"schema_version": 1, "report_id": identifier, "app": "VK", "release": policy.Release,
		"environment": environment, "component": "go", "operation": diagnosticState.operation, "error_code": code,
		"exception_type": kind, "frames": frames, "steps": []any{}}
	payload, err := json.Marshal(report)
	if err != nil || len(payload) > 32768 {
		return
	}
	file, err := os.CreateTemp(directory, ".draft-")
	if err != nil {
		return
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	_, err = file.Write(payload)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return
	}
	if os.Rename(temporary, filepath.Join(directory, identifier+".json")) != nil {
		return
	}
	diagnosticState.last[fingerprint] = now
	entries, _ := os.ReadDir(directory)
	type saved struct {
		name string
		when time.Time
	}
	var drafts []saved
	for _, entry := range entries {
		name := entry.Name()
		// Only manage UUID-shaped draft filenames, never other application data.
		if len(name) != 41 || !strings.HasSuffix(name, ".json") || name[8] != '-' || name[13] != '-' || name[18] != '-' || name[23] != '-' || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if now.Sub(info.ModTime()) > 7*24*time.Hour {
			_ = os.Remove(filepath.Join(directory, name))
			continue
		}
		drafts = append(drafts, saved{name, info.ModTime()})
	}
	sort.Slice(drafts, func(i, j int) bool { return drafts[i].when.Before(drafts[j].when) })
	for len(drafts) > 20 {
		_ = os.Remove(filepath.Join(directory, drafts[0].name))
		drafts = drafts[1:]
	}
}

func diagnosticPanic() {
	if value := recover(); value != nil {
		diagnosticCapture("FT_UNEXPECTED_ERROR", "panic")
		panic(value) // Preserve the application's existing failure behavior.
	}
}

func diagnosticFatal(values ...any) {
	diagnosticCapture("FT_OPERATION_FAILED", "error")
	log.Fatal(values...)
}

func diagnosticFatalf(format string, values ...any) {
	diagnosticCapture("FT_OPERATION_FAILED", "error")
	log.Fatalf(format, values...)
}
