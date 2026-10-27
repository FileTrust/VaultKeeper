package main

// Keeps a Vault Keeper's log folder from growing forever.
//
// This mirrors the Python log_archive.py that the other entities carry. Each
// entity owns its own copy on purpose: a VK has to be deployable by itself, on
// a machine with no FileTrust checkout around it, so there is nothing shared to
// import.
//
// One pass, in order:
//
//  1. Rotate. A log over maxMB, or belonging to a day other than today, is
//     gzipped.
//  2. Age out. Archives older than keepDays are deleted.
//  3. Cap. While the folder is still over maxTotalMB, the oldest archive goes.
//
// Two naming styles are handled, matching what the entities actually write:
//
//	vk_2026-08-24.log  already dated; any day but today is finished, so it is
//	                   gzipped and the original removed.
//	vk.log             one growing file; it is copied out and then truncated
//	                   rather than renamed, so anything holding it open keeps
//	                   writing to the same inode (logrotate's copytruncate).
//
// Nothing here returns a fatal error. Failing to tidy logs must never take a
// Vault Keeper down.

import (
	"compress/gzip"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultLogMaxMB      = 50
	defaultLogKeepDays   = 14
	defaultLogMaxTotalMB = 1000
	bytesPerMB           = 1024 * 1024
)

var dateInName = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})`)

// LogArchiveOptions carries the three knobs from config.json.
type LogArchiveOptions struct {
	MaxMB      int64
	KeepDays   int
	MaxTotalMB int64
	// KeepDaysByName lets one file outlive the rest, e.g. {"transactions": 90}.
	KeepDaysByName map[string]int
}

func (o *LogArchiveOptions) applyDefaults() {
	if o.MaxMB <= 0 {
		o.MaxMB = defaultLogMaxMB
	}
	if o.KeepDays <= 0 {
		o.KeepDays = defaultLogKeepDays
	}
	if o.MaxTotalMB <= 0 {
		o.MaxTotalMB = defaultLogMaxTotalMB
	}
}

// ArchiveSummary reports what a pass did, for logging or tests.
type ArchiveSummary struct {
	Rotated         int
	DeletedOld      int
	DeletedForSize  int
}

// datedIn pulls the calendar day out of a filename, if there is one.
func datedIn(name string) (time.Time, bool) {
	match := dateInName.FindStringSubmatch(name)
	if match == nil {
		return time.Time{}, false
	}
	day, err := time.ParseInLocation("2006-01-02", match[1], time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return day, true
}

// ageDays reports how old a log's *contents* are.
//
// The date in the filename wins over mtime: an archive named 2026-01-01 holds
// January's log no matter when it was gzipped, and mtime is easily disturbed by
// copying or restoring files, which would spare or destroy the wrong archive.
func ageDays(path string, info os.FileInfo) float64 {
	if day, ok := datedIn(filepath.Base(path)); ok {
		return time.Since(day).Hours() / 24
	}
	if info == nil {
		return 0
	}
	return time.Since(info.ModTime()).Hours() / 24
}

func gzipTo(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dest + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	writer, _ := gzip.NewWriterLevel(out, gzip.DefaultCompression)
	if _, err := io.Copy(writer, in); err != nil {
		writer.Close()
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := writer.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// archiveName turns vk.log + 2026-08-24 into vk-2026-08-24.log.gz, avoiding
// collisions with anything already archived.
func archiveName(dir, name, stamp string) string {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)

	var candidate string
	if _, dated := datedIn(name); dated {
		candidate = filepath.Join(dir, name+".gz")
	} else {
		candidate = filepath.Join(dir, base+"-"+stamp+ext+".gz")
	}
	for n := 1; ; n++ {
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
		trimmed := strings.TrimSuffix(candidate, ".gz")
		trimmed = regexp.MustCompile(`\.\d+$`).ReplaceAllString(trimmed, "")
		candidate = trimmed + "." + itoa(n) + ".gz"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// rotateOne gzips path if it is finished or oversized. Reports whether it did.
func rotateOne(dir, name string, maxBytes int64, today time.Time) bool {
	full := filepath.Join(dir, name)
	info, err := os.Stat(full)
	if err != nil || info.Size() == 0 {
		return false
	}

	day, dated := datedIn(name)
	finished := dated && !sameDay(day, today)
	oversized := info.Size() >= maxBytes
	if !finished && !oversized {
		return false
	}

	stamp := today.Format("2006-01-02")
	if dated {
		stamp = day.Format("2006-01-02")
	}
	if err := gzipTo(full, archiveName(dir, name, stamp)); err != nil {
		return false
	}

	if finished {
		// Nothing writes to a past day's file, so it can go outright.
		os.Remove(full)
	} else {
		// Live file: truncate in place so an open handle keeps working.
		os.Truncate(full, 0)
	}
	return true
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func isLogName(name string) bool {
	return strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".jsonl")
}

// ArchiveLogs runs one tidy-up pass over dir. It never returns a fatal error.
func ArchiveLogs(dir string, opts LogArchiveOptions) ArchiveSummary {
	var summary ArchiveSummary
	opts.applyDefaults()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return summary
	}

	today := time.Now()
	maxBytes := opts.MaxMB * bytesPerMB

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if !isLogName(name) {
			continue
		}
		if rotateOne(dir, name, maxBytes, today) {
			summary.Rotated++
		}
	}

	// Collect archives after rotation so newly made ones are considered.
	archives := []string{}
	if entries, err = os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".gz") {
				archives = append(archives, filepath.Join(dir, entry.Name()))
			}
		}
	}

	survivors := make([]string, 0, len(archives))
	for _, arc := range archives {
		info, statErr := os.Stat(arc)
		if statErr != nil {
			continue
		}
		limit := opts.KeepDays
		for fragment, override := range opts.KeepDaysByName {
			if strings.Contains(filepath.Base(arc), fragment) {
				limit = override
				break
			}
		}
		if ageDays(arc, info) > float64(limit) {
			if os.Remove(arc) == nil {
				summary.DeletedOld++
				continue
			}
		}
		survivors = append(survivors, arc)
	}

	summary.DeletedForSize = pruneBySize(dir, survivors, opts.MaxTotalMB*bytesPerMB)
	return summary
}

func folderSize(dir string) int64 {
	var total int64
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

func pruneBySize(dir string, archives []string, maxTotal int64) int {
	current := folderSize(dir)
	if current <= maxTotal {
		return 0
	}

	sort.Slice(archives, func(i, j int) bool {
		infoI, _ := os.Stat(archives[i])
		infoJ, _ := os.Stat(archives[j])
		return ageDays(archives[i], infoI) > ageDays(archives[j], infoJ) // oldest first
	})

	removed := 0
	for _, arc := range archives {
		if current <= maxTotal {
			break
		}
		info, err := os.Stat(arc)
		if err != nil {
			continue
		}
		if os.Remove(arc) == nil {
			current -= info.Size()
			removed++
		}
	}
	return removed
}

// vkLogDir picks the folder this VK keeps its logs in.
//
// The transaction log path from config wins, so an operator who points it
// somewhere specific gets their logs tidied there. Otherwise it falls back to
// a log/ folder beside the storage directory, which keeps everything a VK
// writes inside the VK -- the point of the whole exercise.
func vkLogDir(cfg ServerConfig) string {
	if cfg.TransactionLogPath != "" {
		if dir := filepath.Dir(cfg.TransactionLogPath); dir != "" && dir != "." {
			return dir
		}
	}
	if cfg.Storage != "" {
		return filepath.Join(filepath.Dir(cfg.Storage), "log")
	}
	return "log"
}

// StartLogArchiver tidies dir now, then once a day. Runs in its own goroutine
// and never blocks or panics the caller.
func StartLogArchiver(dir string, opts LogArchiveOptions) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		for {
			summary := ArchiveLogs(dir, opts)
			if summary.Rotated > 0 || summary.DeletedOld > 0 || summary.DeletedForSize > 0 {
				log.Printf("[log-archive] zipped %d, removed %d old archive(s) in %s",
					summary.Rotated, summary.DeletedOld+summary.DeletedForSize, dir)
			}
			time.Sleep(24 * time.Hour)
		}
	}()
}
