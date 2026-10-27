package main

// Console presentation for the keeper's log.
//
// This is a WRITER, not a rewrite. It sits under the standard `log` package and
// reformats whole lines on their way out, so not one of the several hundred
// existing log.Printf call sites changes. That matters twice over: touching
// them all would be a large diff through code that is otherwise correct, and it
// would risk changing what gets recorded while trying only to change how it
// looks.
//
// What it produces:
//
//	[OK]   11:11:33  admission   REOPENED — 97.6 MB free
//	[WARN] 10:25:57  admission   CLOSED — proof subsystem not initialized
//	[FAIL] 13:32:04  store       registration never landed
//	[··]   11:11:42  store       piece 0x95f81d… → sector-1789549902
//
// Nothing is dropped and no text is invented: the tag and message are the ones
// the call site already wrote. Only the severity, the column layout and the
// colour are added, all derived from the line itself.
//
// Level is inferred, which is a deliberate trade: a wrong guess mis-colours one
// line, where rewriting every call site to carry an explicit level risks
// changing behaviour. Explicit markers (✓ ✗) and an exact-match table cover the
// lines that matter; everything else defaults to routine.

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type consoleLevel int

const (
	levelRoutine consoleLevel = iota
	levelOK
	levelWarn
	levelFail
)

const (
	ansiReset = "\033[0m"
	ansiGreen = "\033[32;1m"
	ansiAmber = "\033[33;1m"
	ansiRed   = "\033[31;1m"
	ansiDim   = "\033[2m"
	ansiGrey  = "\033[90m"
)

// Width of the subsystem column. Sized to the common tags (store, capacity,
// vk_adm, proof-lane, partition_link) rather than the longest one in the tree:
// a handful of tags reach 20 characters, and padding every line to those would
// push each message far to the right for no gain. The rare long tag overflows
// and nudges its own message; it is never truncated, because losing which
// subsystem spoke would be worse than one ragged line.
const consoleTagWidth = 14

// A Merkle cache level is only worth its own line when it was slow enough to
// explain a delay. Below this it is noise: the summary line carries the totals.
const zkCacheLevelReportThreshold = 2 * time.Second

// Go's default log prefix: "2026/09/16 11:11:33 ".
var consoleStampRe = regexp.MustCompile(`^(\d{4})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? ?`)

// A leading "[tag] " written by the call site.
var consoleTagRe = regexp.MustCompile(`^\[([^\]]{1,24})\]\s*`)

// Lines whose meaning is known exactly. Checked as substrings, first match
// wins, so order is significance order.
var consoleLevelRules = []struct {
	needle string
	level  consoleLevel
}{
	// Specific phrases first: a generic needle further down would otherwise
	// claim them. "overload cleared" is the end of an overload, not another one.
	{"overload cleared", levelOK},
	{"overload resolved", levelOK},

	// Hard failures.
	{"panic", levelFail},
	{"fatal", levelFail},
	{"WILL NOT START", levelFail},
	{" ✗", levelFail},
	{"✗]", levelFail},

	// Things an operator must notice, but which are not faults.
	{"ADMISSION CLOSED", levelWarn},
	{"overload", levelWarn},
	{"deferred", levelWarn},
	{"pending", levelWarn},
	{"waiting", levelWarn},
	{"retry", levelWarn},
	{"skipped", levelWarn},
	{"unavailable", levelWarn},
	{"not yet accepting", levelWarn},

	// Completions worth seeing.
	{"ADMISSION REOPENED", levelOK},
	{"READY", levelOK},
	{" ✓", levelOK},
	{"✓]", levelOK},
	{"registered", levelOK},
	{"confirmed", levelOK},
	{"submitted", levelOK},
	{"mined", levelOK},
	{"complete", levelOK},
	{"sealed", levelOK},
	{"linked", levelOK},
	{"cleared", levelOK},
	{"issued", levelOK},
	{"recovered", levelOK},
	{"ready", levelOK},
}

// "error" and "failed" appear inside ordinary prose often enough ("failed on
// attempt 1/4, retrying") that a bare substring match over-reports. They count
// only when the line is not already explaining a retry or a wait.
var consoleFailureNeedles = []string{"error", "failed", "refused", "denied", "corrupt"}

func classifyConsoleLine(tag, message string) consoleLevel {
	if tag == "capacity-urgency" && strings.TrimSpace(message) == "qualifiedLifecycleUrgency=false reason=no pending blocked demand" {
		return levelRoutine
	}
	haystack := tag + " " + message
	lower := strings.ToLower(haystack)
	// Short background waits are diagnostic detail rather than warnings.
	if tag == "proof-background" && (strings.HasPrefix(message, "waiting work=") || strings.HasPrefix(message, "acquired work=")) {
		return levelRoutine
	}
	if tag == "gc" && strings.Contains(message, "daily cleanup done") && strings.HasSuffix(strings.TrimSpace(message), "failures=0") {
		return levelOK
	}

	for _, rule := range consoleLevelRules {
		needle := rule.needle
		var hit bool
		if strings.ToUpper(needle) == needle && strings.ContainsAny(needle, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			hit = strings.Contains(haystack, needle) // case-sensitive shout
		} else {
			hit = strings.Contains(lower, strings.ToLower(needle))
		}
		if hit {
			return rule.level
		}
	}
	for _, needle := range consoleFailureNeedles {
		if strings.Contains(lower, needle) {
			return levelFail
		}
	}
	return levelRoutine
}

func (l consoleLevel) label() string {
	switch l {
	case levelOK:
		return "[OK]  "
	case levelWarn:
		return "[WARN]"
	case levelFail:
		return "[FAIL]"
	default:
		return "[··]  "
	}
}

func (l consoleLevel) colour() string {
	switch l {
	case levelOK:
		return ansiGreen
	case levelWarn:
		return ansiAmber
	case levelFail:
		return ansiRed
	default:
		return ansiDim
	}
}

type consoleWriter struct {
	mu    sync.Mutex
	out   io.Writer
	color bool
	buf   bytes.Buffer
}

// formatConsoleLine turns one raw log line into the presented form. Exported
// shape kept simple so tests can pin it without a writer.
func formatConsoleLine(raw string, color bool) string {
	line := strings.TrimRight(raw, "\r\n")
	if strings.TrimSpace(line) == "" {
		return line
	}

	stamp := ""
	if m := consoleStampRe.FindStringSubmatch(line); m != nil {
		stamp = m[4]
		line = line[len(m[0]):]
	}

	tag := ""
	if m := consoleTagRe.FindStringSubmatch(line); m != nil {
		tag = strings.TrimSpace(m[1])
		line = line[len(m[0]):]
	}

	// A line with neither stamp nor tag is banner/config text (the keeper prints
	// its settings block unprefixed). Leave it exactly as written -- reformatting
	// configuration as an event would be a lie about what it is.
	if stamp == "" && tag == "" {
		return raw2(raw)
	}

	level := classifyConsoleLine(tag, line)

	var b strings.Builder
	if color {
		b.WriteString(level.colour())
	}
	b.WriteString(level.label())
	if color {
		b.WriteString(ansiReset)
	}
	b.WriteString(" ")

	if stamp != "" {
		if color {
			b.WriteString(ansiGrey)
		}
		b.WriteString(stamp)
		if color {
			b.WriteString(ansiReset)
		}
		b.WriteString("  ")
	}

	if tag != "" {
		b.WriteString(tag)
		for i := len(tag); i < consoleTagWidth; i++ {
			b.WriteString(" ")
		}
		b.WriteString(" ")
	}
	b.WriteString(line)
	return b.String()
}

// raw2 strips the trailing newline the writer re-adds, so untouched lines pass
// through byte-identical apart from that newline.
func raw2(raw string) string {
	return strings.TrimRight(raw, "\r\n")
}

func (w *consoleWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := len(p)
	w.buf.Write(p)
	for {
		idx := bytes.IndexByte(w.buf.Bytes(), '\n')
		if idx < 0 {
			break
		}
		line := string(w.buf.Next(idx + 1))
		formatted := formatConsoleLine(line, w.color)
		if _, err := io.WriteString(w.out, formatted+"\n"); err != nil {
			// Never fail the caller's log write: a presentation problem must not
			// become a keeper problem.
			return n, nil
		}
	}
	return n, nil
}

// consoleColorEnabled follows the usual convention plus one project-specific
// need: the keeper's stdout is captured to a file that the operator tails, so
// colour cannot be decided by "is this a terminal".
func consoleColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	switch strings.ToLower(os.Getenv("VK_LOG_COLOR")) {
	case "never", "off", "0", "false":
		return false
	}
	return true
}

// consoleFormattingEnabled allows a full opt-out back to the raw format, so a
// deployment that parses these lines with existing tooling can keep them.
func consoleFormattingEnabled() bool {
	switch strings.ToLower(os.Getenv("VK_LOG_FORMAT")) {
	case "raw", "plain", "off":
		return false
	}
	return true
}
