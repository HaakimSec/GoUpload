package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/HaakimSec/GoUpload/internal/oracle"
	"github.com/HaakimSec/GoUpload/internal/types"
)

// PrintExecutiveSummary displays module statistics card
func PrintExecutiveSummary(moduleName string, results []*types.Result) {
	bold := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.FgHiBlack)
	critical := color.New(color.FgRed, color.Bold)
	high := color.New(color.FgHiRed)
	medium := color.New(color.FgYellow)
	low := color.New(color.FgGreen)
	info := color.New(color.FgHiBlack)

	// Count by risk
	counts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
	}
	totalFlags := 0
	var totalTime time.Duration

	for _, r := range results {
		risk := getRiskFromFlags(r.Flags, r)
		counts[risk]++
		totalFlags += len(r.Flags)
		totalTime += r.Duration
	}

	avgTime := time.Duration(0)
	if len(results) > 0 {
		avgTime = totalTime / time.Duration(len(results))
	}

	fmt.Println()
	dim.Println("  ┌──────────────────────────────────────────────┐")
	bold.Printf("  │ %-44s │\n", strings.ToUpper(moduleName))
	dim.Println("  ├──────────────────────────────────────────────┤")
	fmt.Printf("  │ Total Payloads      %-22d│\n", len(results))
	critical.Printf("  │ Critical            %-22d│\n", counts["CRITICAL"])
	high.Printf("  │ High                %-22d│\n", counts["HIGH"])
	medium.Printf("  │ Medium              %-22d│\n", counts["MEDIUM"])
	low.Printf("  │ Low                 %-22d│\n", counts["LOW"])
	info.Printf("  │ Info                %-22d│\n", counts["INFO"])
	fmt.Printf("  │ Avg Response Time   %-22s│\n", avgTime.String())
	dim.Println("  └──────────────────────────────────────────────┘")
	fmt.Println()
}

// PrintFindingsTable displays the redesigned findings table
func PrintFindingsTable(moduleName string, results []*types.Result) {
	bold := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.FgHiBlack)

	// Sort by risk first
	oracle.SortResultsByRisk(results)

	fmt.Println()
	bold.Printf("  %s\n", moduleName)
	fmt.Println()

	// Table header
	dim.Println("  ┌────┬──────────┬────────────┬──────────────────────────────┬─────────┬────────┐")
	dim.Println("  │ ID │ Risk     │ Confidence │ Finding                      │ Status  │ Time   │")
	dim.Println("  ├────┼──────────┼────────────┼──────────────────────────────┼─────────┼────────┤")

	// Table rows
	for i, r := range results {
		id := fmt.Sprintf("%02d", i+1)
		risk := formatRiskLevel(getRiskFromFlags(r.Flags, r))
		confidence := calculateConfidencePercent(r.Flags)
		finding := truncateTableName(r.Technique, 28)
		status := formatStatusWithText(r.StatusCode)
		timeStr := formatDurationMs(r.Duration)

		fmt.Printf("  │ %s │ %-8s │ %-10s │ %-28s │ %-7s │ %-6s │\n",
			id, risk, confidence, finding, status, timeStr)
	}

	// Table footer
	dim.Println("  └────┴──────────┴────────────┴──────────────────────────────┴─────────┴────────┘")
	fmt.Println()
}

// formatRiskLevel colors the risk level
func formatRiskLevel(risk string) string {
	switch risk {
	case "CRITICAL":
		return color.New(color.FgRed, color.Bold).Sprint("CRITICAL")
	case "HIGH":
		return color.New(color.FgHiRed).Sprint("HIGH    ")
	case "MEDIUM":
		return color.New(color.FgYellow).Sprint("MEDIUM  ")
	case "LOW":
		return color.New(color.FgGreen).Sprint("LOW     ")
	default:
		return color.New(color.FgHiBlack).Sprint("INFO    ")
	}
}

// calculateConfidencePercent calculates confidence from flags
func calculateConfidencePercent(flags []string) string {
	confidence := 0
	for _, f := range flags {
		switch f {
		case "xxe-file-accepted", "xxe-file-disclosure":
			confidence += 20
		case "filename-reflected-in-response", "path-structure-in-response":
			confidence += 20
		case "json-indicates-success", "html-indicates-success":
			confidence += 20
		case "suspicious-ext-accepted", "traversal-filename-accepted":
			confidence += 15
		}
	}
	if confidence > 100 {
		confidence = 100
	}
	return fmt.Sprintf("%d%%", confidence)
}

// formatStatusWithText formats status code with text
func formatStatusWithText(code int) string {
	switch {
	case code == 200:
		return color.New(color.FgGreen).Sprint("200 OK")
	case code == 201:
		return color.New(color.FgGreen).Sprint("201 OK")
	case code == 204:
		return color.New(color.FgGreen).Sprint("204 OK")
	case code >= 300 && code < 400:
		return color.New(color.FgYellow).Sprintf("%d REDIRECT", code)
	case code >= 400:
		return color.New(color.FgRed).Sprintf("%d ERR", code)
	default:
		return fmt.Sprintf("%d", code)
	}
}

// formatDurationMs formats duration in milliseconds
func formatDurationMs(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 1 {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0)
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000.0)
}

// truncateTableName truncates a technique name
func truncateTableName(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := s[:maxLen]
	if idx := strings.LastIndex(cut, " "); idx > maxLen/2 {
		cut = cut[:idx]
	}
	return cut + "…"
}

// getRiskFromFlags determines risk level from flags
func getRiskFromFlags(flags []string, r *types.Result) string {
	for _, f := range flags {
		if f == "file-overwrite-confirmed" || f == "xxe-file-disclosure" {
			return "CRITICAL"
		}
	}
	for _, f := range flags {
		if f == "graphql-mutation-accepted" || f == "traversal-filename-accepted" {
			return "HIGH"
		}
	}
	for _, f := range flags {
		if f == "spoofed-content-accepted" || f == "xxe-file-accepted" {
			return "MEDIUM"
		}
	}
	return "LOW"
}
