package output

import (
	"encoding/json"
	"fmt"
	"github.com/HaakimSec/GoUpload/internal/oracle"
	"github.com/HaakimSec/GoUpload/internal/types"
	"os"
	"strings"
	"time"
)

// JSONReport represents the complete scan report in JSON format
type JSONReport struct {
	Tool        string        `json:"tool"`
	Version     string        `json:"version"`
	ScanTime    string        `json:"scan_time"`
	TargetURL   string        `json:"target_url"`
	UploadParam string        `json:"upload_param"`
	Concurrency int           `json:"concurrency"`
	Summary     JSONSummary   `json:"summary"`
	Findings    []JSONFinding `json:"findings"`
	Metadata    JSONMetadata  `json:"metadata"`
}

// JSONSummary contains scan statistics
type JSONSummary struct {
	TotalTests      int     `json:"total_tests"`
	Safe            int     `json:"safe"`
	Suspect         int     `json:"suspect"`
	Vulnerable      int     `json:"vulnerable"`
	Errors          int     `json:"errors"`
	DetectionRate   float64 `json:"detection_rate_percent"`
	AvgResponseTime float64 `json:"avg_response_time_seconds"`
	TotalElapsed    string  `json:"total_elapsed"`
}

// JSONFinding represents a single vulnerability finding
type JSONFinding struct {
	ID             int      `json:"id"`
	Module         string   `json:"module"`
	Technique      string   `json:"technique"`
	Filename       string   `json:"filename"`
	Extension      string   `json:"extension"`
	Verdict        string   `json:"verdict"`
	Confidence     int      `json:"confidence_percent"`
	StatusCode     int      `json:"status_code"`
	ResponseLength int      `json:"response_length_bytes"`
	Duration       string   `json:"duration"`
	Flags          []string `json:"flags"`
	Error          string   `json:"error,omitempty"`
}

// JSONMetadata contains scan metadata
type JSONMetadata struct {
	TechStack    string `json:"tech_stack,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	TemplateUsed string `json:"template_used,omitempty"`
	BaselineUsed bool   `json:"baseline_used"`
}

// JSONPrinter handles JSON output formatting
type JSONPrinter struct {
	report  JSONReport
	printer *Printer
}

// NewJSONPrinter creates a new JSON printer
func NewJSONPrinter(printer *Printer, url, param string, concurrency int) *JSONPrinter {
	return &JSONPrinter{
		printer: printer,
		report: JSONReport{
			Tool:        "GoUpload",
			Version:     "1.2.0",
			ScanTime:    time.Now().Format(time.RFC3339),
			TargetURL:   url,
			UploadParam: param,
			Concurrency: concurrency,
			Findings:    []JSONFinding{},
		},
	}
}

// SetTechStack sets the detected tech stack
func (jp *JSONPrinter) SetTechStack(techStack string) {
	jp.report.Metadata.TechStack = techStack
}

// SetFingerprint sets fingerprint info
func (jp *JSONPrinter) SetFingerprint(info string) {
	jp.report.Metadata.Fingerprint = info
}

// SetTemplate sets the template used
func (jp *JSONPrinter) SetTemplate(name string) {
	jp.report.Metadata.TemplateUsed = name
}

// SetBaselineUsed sets whether baseline was used
func (jp *JSONPrinter) SetBaselineUsed(used bool) {
	jp.report.Metadata.BaselineUsed = used
}

// AddFinding adds a single finding to the report
func (jp *JSONPrinter) AddFinding(r *types.Result, moduleName string, id int) {
	confidence := calculateConfidence(r.Flags, r.Vulnerable)

	finding := JSONFinding{
		ID:             id,
		Module:         moduleName,
		Technique:      r.Technique,
		Filename:       r.Filename,
		Extension:      extractExtensionFromFilename(r.Filename),
		Verdict:        r.Vulnerable,
		Confidence:     confidence,
		StatusCode:     r.StatusCode,
		ResponseLength: r.RespLen,
		Duration:       r.Duration.String(),
		Flags:          r.Flags,
	}

	if r.Err != nil {
		finding.Error = r.Err.Error()
	}

	jp.report.Findings = append(jp.report.Findings, finding)
}

// SetSummary sets the scan summary
func (jp *JSONPrinter) SetSummary(stats oracle.SummaryStats) {
	detectionRate := 0.0
	if stats.Total > 0 {
		detectionRate = float64(stats.Vulnerable+stats.Suspect) / float64(stats.Total) * 100
	}

	jp.report.Summary = JSONSummary{
		TotalTests:      stats.Total,
		Safe:            stats.Safe,
		Suspect:         stats.Suspect,
		Vulnerable:      stats.Vulnerable,
		Errors:          stats.Errors,
		DetectionRate:   roundFloat(detectionRate, 1),
		AvgResponseTime: roundFloat(stats.Duration, 3),
		TotalElapsed:    fmt.Sprintf("%.3fs", stats.Duration),
	}
}

// WriteToFile writes the JSON report to a file
func (jp *JSONPrinter) WriteToFile(filepath string) error {
	data, err := json.MarshalIndent(jp.report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	fmt.Printf("\n  📄 JSON report saved to: %s\n", filepath)
	return nil
}

// PrintToStdout prints the JSON report to stdout
func (jp *JSONPrinter) PrintToStdout() error {
	data, err := json.MarshalIndent(jp.report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// calculateConfidence estimates confidence based on flags
func calculateConfidence(flags []string, verdict string) int {
	if verdict == "SAFE" || verdict == "" {
		return 0
	}

	confidence := 50 // Base confidence

	highConfidenceFlags := map[string]int{
		"suspicious-ext-accepted":     15,
		"spoofed-content-accepted":    15,
		"traversal-filename-accepted": 20,
		"graphql-mutation-accepted":   20,
		"html-indicates-success":      10,
		"filepath-disclosed":          15,
		"json-indicates-success":      10,
		"image-upload-accepted":       10,
		"exif-data-processed":         15,
	}

	for _, flag := range flags {
		if boost, ok := highConfidenceFlags[flag]; ok {
			confidence += boost
		}
	}

	if verdict == "VULNERABLE" {
		confidence += 20
	}

	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

// extractExtensionFromFilename gets extension from filename
func extractExtensionFromFilename(filename string) string {
	if idx := strings.LastIndex(filename, "."); idx != -1 {
		return filename[idx:]
	}
	return ""
}

// roundFloat rounds a float to specified decimal places
func roundFloat(f float64, decimals int) float64 {
	format := fmt.Sprintf("%%.%df", decimals)
	s := fmt.Sprintf(format, f)
	var result float64
	fmt.Sscanf(s, "%f", &result)
	return result
}
