package output

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"

	"goupload/internal/oracle"
	"goupload/internal/types"
)

var (
	// Color definitions
	headerColor  = color.New(color.FgCyan, color.Bold)
	moduleColor  = color.New(color.FgYellow, color.Bold)
	vulnColor    = color.New(color.FgRed, color.Bold)
	suspectColor = color.New(color.FgYellow, color.Bold)
	safeColor    = color.New(color.FgGreen)
	errorColor   = color.New(color.FgMagenta)
	infoColor    = color.New(color.FgWhite, color.Faint)
	dimColor     = color.New(color.FgWhite, color.Faint)

	// Verdict color functions
	vulnFn    = color.New(color.FgRed, color.Bold).SprintFunc()
	suspectFn = color.New(color.FgYellow, color.Bold).SprintFunc()
	safeFn    = color.New(color.FgGreen).SprintFunc()
	errorFn   = color.New(color.FgMagenta).SprintFunc()
)

// Printer handles all terminal output with thread-safe locking.
type Printer struct {
	mu           sync.Mutex
	lastModule   string
	total        int
	done         int
	startTime    time.Time
	showProgress bool
}

// NewPrinter creates a new output printer.
func NewPrinter(total int) *Printer {
	return &Printer{
		total:        total,
		done:         0,
		startTime:    time.Now(),
		showProgress: true,
	}
}

// PrintBanner displays the RAINBOW GoUpload banner with target information.
func (p *Printer) PrintBanner(url, param string, concurrency int, payloadCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Rainbow colors for the ASCII art
	rainbowColors := []*color.Color{
		color.New(color.FgRed, color.Bold),
		color.New(color.FgYellow, color.Bold),
		color.New(color.FgGreen, color.Bold),
		color.New(color.FgCyan, color.Bold),
		color.New(color.FgBlue, color.Bold),
		color.New(color.FgMagenta, color.Bold),
	}

	// ASCII Art Logo
	logo := []string{
		"   ██████╗  ██████╗ ██╗   ██╗██████╗ ██╗      ██████╗  █████╗ ██████╗ ",
		"  ██╔════╝ ██╔═══██╗██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗",
		"  ██║  ███╗██║   ██║██║   ██║██████╔╝██║     ██║   ██║███████║██║  ██║",
		"  ██║   ██║██║   ██║██║   ██║██╔═══╝ ██║     ██║   ██║██╔══██║██║  ██║",
		"  ╚██████╔╝╚██████╔╝╚██████╔╝██║     ███████╗╚██████╔╝██║  ██║██████╔╝",
		"   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ",
	}

	fmt.Println()
	fmt.Println()
	
	// Print rainbow logo
	for i, line := range logo {
		rainbowColors[i%len(rainbowColors)].Println(line)
	}
	
	fmt.Println()
	
	// Subtitle with flames
	subtitleColor := color.New(color.FgWhite, color.Bold)
	flameColor := color.New(color.FgYellow, color.Bold)
	
	flameColor.Print("   ⚡ ")
	subtitleColor.Print("Web Application File Upload Security Tester")
	flameColor.Println(" ⚡")
	
	fmt.Println()
	
	// Version info
	versionColor := color.New(color.FgHiWhite, color.Faint)
	versionColor.Println("   v1.0.0  │  Built for Security Professionals  │  @haakimsec")
	
	fmt.Println()
	
	// Separator
	dimColor.Println("  ╔══════════════════════════════════════════════════════════════════╗")
	
	// Target information
	infoBox := color.New(color.FgWhite)
	labelColor := color.New(color.FgCyan, color.Bold)
	
	fmt.Fprintf(color.Output, "  ║  ")
	labelColor.Print("🎯 Target URL    ")
	infoBox.Printf(": %-52s", truncate(url, 50))
	fmt.Fprintf(color.Output, "║\n")
	
	fmt.Fprintf(color.Output, "  ║  ")
	labelColor.Print("📦 Upload Param  ")
	infoBox.Printf(": %-52s", truncate(param, 50))
	fmt.Fprintf(color.Output, "║\n")
	
	fmt.Fprintf(color.Output, "  ║  ")
	labelColor.Print("🚀 Concurrency   ")
	infoBox.Printf(": %-52d", concurrency)
	fmt.Fprintf(color.Output, "║\n")
	
	fmt.Fprintf(color.Output, "  ║  ")
	labelColor.Print("🧪 Test Payloads ")
	infoBox.Printf(": %-52d", payloadCount)
	fmt.Fprintf(color.Output, "║\n")
	
	dimColor.Println("  ╚══════════════════════════════════════════════════════════════════╝")
	
	fmt.Println()
	p.printSeparator()
}

// PrintBaseline displays baseline upload results.
func (p *Printer) PrintBaseline(baseline *oracle.Baseline) {
	p.mu.Lock()
	defer p.mu.Unlock()

	moduleColor.Fprintln(color.Output, "  [BASELINE] Establishing upload baseline...")
	fmt.Println()
	fmt.Fprintf(color.Output, "    %-18s %s\n", "Filename:", baseline.Filename)
	fmt.Fprintf(color.Output, "    %-18s %s\n", "Status Code:",
		statusColor(baseline.StatusCode)(fmt.Sprintf("%d %s", baseline.StatusCode, statusText(baseline.StatusCode))))
	fmt.Fprintf(color.Output, "    %-18s %d bytes\n", "Response Length:", baseline.ResponseLength)
	fmt.Fprintf(color.Output, "    %-18s %s\n", "Content-Type:", baseline.ContentType)
	fmt.Println()
	p.printSeparator()
}

// PrintModuleHeader prints a section header for a test module.
func (p *Printer) PrintModuleHeader(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lastModule != name {
		p.lastModule = name
		fmt.Println()
		moduleColor.Fprintf(color.Output, "  ┌─ %s\n", name)
		moduleColor.Fprintln(color.Output, "  │")
	}
}

// PrintResult prints a single test result with a live progress bar.
func (p *Printer) PrintResult(r *types.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.done++

	if p.showProgress && p.total > 0 {
		pct := float64(p.done) / float64(p.total) * 100
		pctStr := fmt.Sprintf("%.0f%%", pct)
		elapsed := time.Since(p.startTime).Truncate(time.Millisecond)

		barWidth := 20
		filled := int(float64(barWidth) * float64(p.done) / float64(p.total))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		doneColor := color.New(color.FgGreen).SprintFunc()
		fmt.Fprintf(color.Output, "\r  %s [%s] %d/%d (%s) %s   ",
			doneColor(bar), pctStr, p.done, p.total, elapsed,
			"                              ")
	}
}

// PrintFinalResult prints the complete details of a flagged result.
func (p *Printer) PrintFinalResult(r *types.Result, idx int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	verdictStr := formatVerdict(r.Vulnerable)
	statusStr := fmt.Sprintf("%d", r.StatusCode)
	if r.Err == nil {
		statusStr = fmt.Sprintf("%d %s", r.StatusCode, statusText(r.StatusCode))
	}

	fmt.Fprintf(color.Output, "  │  #%02d  %-55s %s\n",
		idx, truncate(r.Technique, 55), verdictStr)
	fmt.Fprintf(color.Output, "  │       %-18s %s\n", "Filename:", r.Filename)
	fmt.Fprintf(color.Output, "  │       %-18s %s\n", "Status:", statusStr)
	fmt.Fprintf(color.Output, "  │       %-18s %d bytes\n", "Response Length:", r.RespLen)

	if r.Duration > 0 {
		fmt.Fprintf(color.Output, "  │       %-18s %s\n", "Duration:", r.Duration.Truncate(time.Millisecond).String())
	}

	if len(r.Flags) > 0 {
		fmt.Fprintf(color.Output, "  │       %-18s %s\n", "Flags:", oracle.FormatFlags(r.Flags))
	}

	if r.Err != nil {
		fmt.Fprintf(color.Output, "  │       %-18s %s\n", "Error:", r.Err.Error())
	}

	fmt.Fprintln(color.Output, "  │")
}

// PrintSummary displays the final summary with statistics.
func (p *Printer) PrintSummary(stats oracle.SummaryStats) {
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.startTime).Truncate(time.Millisecond)

	fmt.Println()
	p.printSeparator()

	headerColor.Fprintln(color.Output, "  SUMMARY")
	fmt.Println()

	fmt.Fprintf(color.Output, "    %-22s %s\n", "Total Tests:", fmt.Sprintf("%d", stats.Total))
	fmt.Fprintf(color.Output, "    %-22s %s\n", "Safe:", safeFn(fmt.Sprintf("%d", stats.Safe)))
	fmt.Fprintf(color.Output, "    %-22s %s\n", "Suspect:", suspectFn(fmt.Sprintf("%d", stats.Suspect)))
	fmt.Fprintf(color.Output, "    %-22s %s\n", "Vulnerable:", vulnFn(fmt.Sprintf("%d", stats.Vulnerable)))
	fmt.Fprintf(color.Output, "    %-22s %s\n", "Errors:", errorFn(fmt.Sprintf("%d", stats.Errors)))
	fmt.Fprintf(color.Output, "    %-22s %s\n", "Avg Response Time:", fmt.Sprintf("%.3fs", stats.Duration))
	fmt.Fprintf(color.Output, "    %-22s %s\n", "Total Elapsed:", elapsed.String())

	if stats.Vulnerable > 0 || stats.Suspect > 0 {
		fmt.Println()
		vulnColor.Fprintln(color.Output, "  ⚠  Potential vulnerabilities detected — manual verification recommended!")
	}
	if stats.Vulnerable == 0 && stats.Suspect == 0 {
		fmt.Println()
		safeColor.Fprintln(color.Output, "  ✓  No obvious vulnerabilities detected in automated testing.")
	}

	fmt.Println()
	p.printSeparator()
}

// PrintProgressNewline ensures a clean line after progress bar.
func (p *Printer) PrintProgressNewline() {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Println()
}

// PrintSeparatorFunc is a package-level separator printer.
func PrintSeparatorFunc() {
	dimColor.Fprintln(color.Output, "  ────────────────────────────────────────────────────────────────────────")
}

// printSeparator prints a visual separator line.
func (p *Printer) printSeparator() {
	PrintSeparatorFunc()
}

// ResultPrinter creates a PrintResult callback compatible with the worker pool's ResultHandler.
func ResultPrinter(p *Printer) func(r *types.Result) {
	return func(r *types.Result) {
		p.PrintResult(r)
	}
}

// ── Helper functions ─────────────────────────────────────────────────

func formatVerdict(v string) string {
	switch oracle.Verdict(v) {
	case oracle.VerdictVulnerable:
		return vulnFn("⚠  VULNERABLE")
	case oracle.VerdictSuspect:
		return suspectFn("⚡ SUSPECT")
	case oracle.VerdictSafe:
		return safeFn("✓  SAFE")
	case oracle.VerdictError:
		return errorFn("✗  ERROR")
	default:
		return "  UNKNOWN"
	}
}

func statusColor(code int) func(a ...interface{}) string {
	if code >= 200 && code < 300 {
		return safeFn
	}
	if code >= 300 && code < 400 {
		return suspectFn
	}
	return errorFn
}

func statusText(code int) string {
	codes := map[int]string{
		200: "OK", 201: "Created", 204: "No Content",
		301: "Moved Permanently", 302: "Found", 304: "Not Modified",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
		404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
		413: "Payload Too Large", 415: "Unsupported Media Type", 422: "Unprocessable Entity",
		429: "Too Many Requests",
		500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
	}
	if text, ok := codes[code]; ok {
		return text
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
