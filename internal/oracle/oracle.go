package oracle

import (
	"fmt"
	"math"
	"strings"

	"github.com/HaakimSec/GoUpload/internal/payload"
	"github.com/HaakimSec/GoUpload/internal/types"
)

// Verdict indicates the assessed risk level of a test result.
type Verdict string

const (
	VerdictVulnerable Verdict = "VULNERABLE"
	VerdictSuspect    Verdict = "SUSPECT"
	VerdictSafe       Verdict = "SAFE"
	VerdictError      Verdict = "ERROR"
	VerdictUnknown    Verdict = "UNKNOWN"
)

// Baseline holds the expected "good" response metrics from a legitimate upload.
type Baseline struct {
	StatusCode     int
	ResponseLength int
	ContentType    string
	BodySnippet    string
	Filename       string
}

// AnalysisResult contains the verdict and any flags raised.
type AnalysisResult struct {
	Verdict Verdict
	Flags   []string
}

// Analyze compares a test result against the baseline to detect anomalies.
func Analyze(baseline *Baseline, result *types.Result, pl *payload.Payload) AnalysisResult {
	if result.Err != nil {
		return AnalysisResult{Verdict: VerdictError, Flags: []string{"request-error"}}
	}

	var flags []string

	// Check 1: Successful status code for an executable/suspicious payload
	isSuspiciousExt := isExecutableExtension(pl.Extension)
	statusOK := isSuccessStatus(result.StatusCode)

	if statusOK && isSuspiciousExt {
		flags = append(flags, "suspicious-ext-accepted")
	}

	// Check 2: Response length similarity to baseline
	if baseline.ResponseLength > 0 && result.RespLen > 0 {
		ratio := float64(result.RespLen) / float64(baseline.ResponseLength)
		if ratio > 0.9 && ratio < 1.1 {
			if isSuspiciousExt {
				flags = append(flags, "response-length-matches-baseline")
			}
		}
	}

	// Check 3: Exact status code match with baseline
	if result.StatusCode == baseline.StatusCode && isSuspiciousExt {
		flags = append(flags, "status-matches-baseline")
	}

	// Check 4: JSON response indicating success
	if strings.Contains(result.RespCT, "application/json") {
		lower := strings.ToLower(result.BodySnippet)
		jsonSuccessIndicators := []string{
			`"success":true`, `"success": true`,
			`"status":"ok"`, `"status":"success"`,
			`"status": "ok"`, `"status": "success"`,
			`"uploaded":true`, `"uploaded": true`,
			`"error":null`, `"error": null`,
			`"code":200`, `"code": 200`,
			`"code":201`, `"code": 201`,
			`"message":"success"`, `"message": "success"`,
		}
		for _, indicator := range jsonSuccessIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "json-indicates-success")
				break
			}
		}
	}

	// Check 5a: Filename or path reflected in response
	if result.BodySnippet != "" {
		cleanFilename := strings.Split(pl.Filename, "%")[0]
		cleanFilename = strings.Split(cleanFilename, "\x00")[0]

		if strings.Contains(result.BodySnippet, cleanFilename) {
			flags = append(flags, "filename-reflected-in-response")
		}

		pathIndicators := []string{
			"/uploads/", "/upload/", "/files/", "/images/",
			"uploads/", "upload/", "files/",
			`src="`, `href="`, "url(", `path":`,
		}
		for _, indicator := range pathIndicators {
			if strings.Contains(strings.ToLower(result.BodySnippet), indicator) {
				flags = append(flags, "path-structure-in-response")
				break
			}
		}
	}

	// Check 5b: HTML success patterns
	if result.BodySnippet != "" {
		lower := strings.ToLower(result.BodySnippet)
		htmlSuccessPatterns := []string{
			"file uploaded successfully",
			"file has been uploaded",
			"upload successful",
			"successfully uploaded",
			"profile updated",
			"avatar uploaded",
			"document uploaded",
			"file uploaded",
			"uploaded:",
			"location:",
			"file uploaded to",
			"has been saved",
			"upload complete",
			"file saved",
		}
		for _, pattern := range htmlSuccessPatterns {
			if strings.Contains(lower, pattern) {
				flags = append(flags, "html-indicates-success")
				break
			}
		}

		// Check 5c: Direct file path disclosure
		pathDisclosurePatterns := []string{
			"href=\"uploads/",
			"href='uploads/",
			"href=\"profile_uploads/",
			"href=\"document_uploads/",
			"href=\"avatar_uploads/",
			"src=\"uploads/",
			"location: uploads/",
			"location: profile_uploads/",
			"path:",
			"filepath:",
			"file_path:",
		}
		for _, pattern := range pathDisclosurePatterns {
			if strings.Contains(lower, pattern) {
				flags = append(flags, "filepath-disclosed")
				break
			}
		}

		// Check 5d: Generic success keywords
		genericSuccessWords := []string{"success", "succeeded", "completed"}
		for _, word := range genericSuccessWords {
			if strings.Contains(lower, word) && isSuspiciousExt {
				flags = append(flags, "success-keyword-with-suspicious-ext")
				break
			}
		}
	}

	// Check 6: Content-Type spoofing
	if pl.TestType == payload.TestTypeContentTypeSpoof || pl.TestType == payload.TestTypeMagicByteSpoof {
		if statusOK && isSuspiciousExt {
			flags = append(flags, "spoofed-content-accepted")
		}
	}

	if pl.TestType == payload.TestTypeContentTypeSpoof {
		if pl.ContentType != "" && !strings.HasPrefix(pl.ContentType, "text/") {
			lower := strings.ToLower(result.BodySnippet)
			if strings.Contains(lower, "upload") &&
				(strings.Contains(lower, "success") || strings.Contains(lower, "uploaded")) {
				flags = append(flags, "content-type-spoof-accepted")
			}
		}

		if result.RespCT != "" && pl.ContentType != "" {
			if strings.Contains(result.RespCT, pl.ContentType) {
				flags = append(flags, "content-type-reflected")
			}
		}
	}

	// Check 7: Path traversal specific
	if pl.TestType == payload.TestTypePathTraversal {
		lower := strings.ToLower(result.BodySnippet)
		traversalErrorIndicators := []string{
			"no such file", "permission denied", "is a directory",
			"not a directory", "file exists", "cannot open",
			"no such file or directory",
		}
		for _, indicator := range traversalErrorIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "filesystem-error-disclosed")
				break
			}
		}
		if statusOK {
			flags = append(flags, "traversal-filename-accepted")
		}
	}

	// Check 8: Image upload specific checks
	if pl.TestType == payload.TestTypeMagicByteSpoof {
		lower := strings.ToLower(result.BodySnippet)
		imageSuccessIndicators := []string{
			"avatar uploaded",
			"image uploaded",
			"profile picture",
			"thumbnail created",
			"image resized",
			"image saved",
			"picture uploaded",
		}
		for _, indicator := range imageSuccessIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "image-upload-accepted")
				break
			}
		}

		exifIndicators := []string{
			"exif", "metadata", "image description",
			"comment", "makernote",
		}
		for _, indicator := range exifIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "exif-data-processed")
				break
			}
		}
	}

	// Check 9: GraphQL response detection
	if pl.GraphQL != nil {
		lower := strings.ToLower(result.BodySnippet)

		if strings.Contains(lower, `"data":{`) || strings.Contains(lower, `"data": {`) {
			flags = append(flags, "graphql-mutation-accepted")

			if strings.Contains(lower, `"__typename"`) || strings.Contains(lower, `"resumeid"`) {
				flags = append(flags, "graphql-expected-response")
			}
		}

		if strings.Contains(lower, `"errors":[{`) || strings.Contains(lower, `"errors": [{"`) {
			flags = append(flags, "graphql-errors-returned")
		}

		if strings.Contains(lower, "/home/") || strings.Contains(lower, "/var/www/") {
			flags = append(flags, "graphql-stack-trace-disclosed")
		}

		if strings.Contains(lower, "cannot find module") ||
			strings.Contains(lower, "require(") ||
			strings.Contains(lower, "node_modules") {
			flags = append(flags, "nodejs-module-error-disclosed")
		}
	}

	// Check 10: Race condition specific detection (SET FLAGS HERE)
	if pl.TestType == payload.TestTypeRaceCondition {
		lower := strings.ToLower(result.BodySnippet)

		raceSuccessIndicators := []string{
			"file uploaded",
			"file saved",
			"uploaded successfully",
			"overwritten",
			"already exists",
			"replaced",
			"file exists",
		}
		for _, indicator := range raceSuccessIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "race-condition-file-accepted")
				break
			}
		}

		concurrentIndicators := []string{
			"concurrent",
			"already in use",
			"locked",
			"being used by another process",
			"resource temporarily unavailable",
		}
		for _, indicator := range concurrentIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "concurrent-access-detected")
				break
			}
		}

		if strings.Contains(lower, "overwrite") ||
			strings.Contains(lower, "replace") ||
			strings.Contains(lower, "already exists") {
			flags = append(flags, "file-overwrite-confirmed")
		}

		if result.StatusCode == 200 || result.StatusCode == 201 {
			if strings.Contains(pl.Filename, ".php") ||
				strings.Contains(pl.Filename, ".jsp") ||
				strings.Contains(pl.Filename, ".asp") {
				flags = append(flags, "executable-accepted-in-race")
			}
		}
	}

	// Check 11: XXE detection (SET FLAGS HERE)
	if pl.TestType == payload.TestTypeXXE {
		lower := strings.ToLower(result.BodySnippet)

		if result.StatusCode == 200 &&
			(strings.Contains(lower, "success") || strings.Contains(lower, "uploaded")) {
			flags = append(flags, "xxe-file-accepted")
		}

		xxeSuccessIndicators := []string{
			"root:", "daemon:", "bin:",
			"for 16-bit app support",
			"[extensions]",
			"aws_access_key_id",
			"<?xml",
		}
		for _, indicator := range xxeSuccessIndicators {
			if strings.Contains(lower, indicator) {
				flags = append(flags, "xxe-file-disclosure")
				break
			}
		}

		if strings.Contains(lower, "lol") || strings.Contains(lower, "entity") {
			flags = append(flags, "xxe-entity-expansion")
		}
	}

	verdict := determineVerdict(flags, result, pl)

	return AnalysisResult{
		Verdict: verdict,
		Flags:   flags,
	}
}

// determineVerdict maps the collected flags to a final risk verdict.
func determineVerdict(flags []string, result *types.Result, pl *payload.Payload) Verdict {
	if result.Err != nil {
		return VerdictError
	}

	flagSet := make(map[string]bool)
	for _, f := range flags {
		flagSet[f] = true
	}

	// SAFE: Confirmed blocked or sanitized
	if result.StatusCode == 403 || result.StatusCode == 400 {
		return VerdictSafe
	}
	if flagSet["sanitized"] || result.Sanitized {
		return VerdictSafe
	}
	if !isSuccessStatus(result.StatusCode) {
		return VerdictSafe
	}

	hasSuspiciousExt := isExecutableExtension(pl.Extension) ||
		strings.Contains(pl.Filename, ".php") ||
		strings.Contains(pl.Filename, ".jsp") ||
		strings.Contains(pl.Filename, ".asp")

	hasSuccessIndicator := flagSet["json-indicates-success"] ||
		flagSet["html-indicates-success"] ||
		flagSet["elfinder-upload-success"] ||
		flagSet["filepath-disclosed"] ||
		flagSet["filename-reflected-in-response"]

	hasExecutionEvidence := flagSet["executable-accepted-in-race"] ||
		flagSet["xxe-file-disclosure"] ||
		flagSet["file-overwrite-confirmed"] ||
		flagSet["graphql-mutation-accepted"]

	if result.StatusCode == 200 && hasSuspiciousExt && hasSuccessIndicator && hasExecutionEvidence {
		return VerdictVulnerable
	}

	if flagSet["graphql-mutation-accepted"] && hasSuspiciousExt {
		return VerdictVulnerable
	}

	if flagSet["xxe-file-accepted"] {
		return VerdictVulnerable
	}

	if flagSet["file-overwrite-confirmed"] {
		return VerdictVulnerable
	}

	if result.StatusCode == 200 && hasSuspiciousExt && hasSuccessIndicator {
		return VerdictSuspect
	}

	if result.StatusCode == 200 && hasSuccessIndicator && !hasSuspiciousExt {
		return VerdictSuspect
	}

	if flagSet["concurrent-access-detected"] {
		return VerdictSuspect
	}

	if len(flags) > 0 {
		return VerdictSuspect
	}

	return VerdictSafe
}

// hasSuspiciousExt is a helper to check if payload has executable extension
func hasSuspiciousExt(pl *payload.Payload) bool {
	return isExecutableExtension(pl.Extension)
}

// isSuccessStatus returns true for HTTP status codes that typically indicate success.
func isSuccessStatus(code int) bool {
	return (code >= 200 && code < 300) || code == 302 || code == 303
}

// isExecutableExtension checks if an extension is commonly associated with
// server-side executable content.
func isExecutableExtension(ext string) bool {
	if ext == "" {
		return false
	}

	lower := strings.ToLower(strings.TrimSpace(ext))

	executableExts := map[string]bool{
		".php": true, ".php3": true, ".php4": true, ".php5": true,
		".php7": true, ".phps": true, ".phtml": true, ".phar": true,
		".asp": true, ".aspx": true, ".ashx": true, ".asmx": true,
		".ascx": true, ".asax": true, ".config": true,
		".jsp": true, ".jspx": true, ".jspa": true, ".jsw": true,
		".jsv": true, ".jss": true,
		".cgi": true, ".pl": true, ".py": true, ".rb": true,
		".sh": true, ".bash": true, ".zsh": true,
		".exe": true, ".bat": true, ".cmd": true, ".ps1": true,
		".msi": true, ".dll": true, ".so": true,
		".shtml": true, ".shtm": true, ".js": true,
	}

	return executableExts[lower]
}

// FormatFlags joins flags into a readable string.
func FormatFlags(flags []string) string {
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ", ")
}

// SummaryStats provides aggregate statistics for the test run.
type SummaryStats struct {
	Total      int
	Safe       int
	Suspect    int
	Vulnerable int
	Errors     int
	Duration   float64
}

// ComputeSummary calculates aggregate statistics from a slice of results.
func ComputeSummary(results []*types.Result) SummaryStats {
	stats := SummaryStats{Total: len(results)}
	for _, r := range results {
		switch r.Vulnerable {
		case string(VerdictVulnerable):
			stats.Vulnerable++
		case string(VerdictSuspect):
			stats.Suspect++
		case string(VerdictSafe):
			stats.Safe++
		case string(VerdictError):
			stats.Errors++
		default:
			stats.Errors++
		}
	}
	if len(results) > 0 {
		var total float64
		for _, r := range results {
			total += r.Duration.Seconds()
		}
		stats.Duration = math.Round(total/float64(len(results))*1000) / 1000
	}
	return stats
}

// String returns a human-readable summary line.
func (s SummaryStats) String() string {
	return fmt.Sprintf("Total: %d | Safe: %d | Suspect: %d | Vulnerable: %d | Errors: %d | Avg: %.3fs",
		s.Total, s.Safe, s.Suspect, s.Vulnerable, s.Errors, s.Duration)
}

// hasSuspiciousFilename checks if filename has executable extension
func hasSuspiciousFilename(filename string) bool {
	lower := strings.ToLower(filename)
	suspiciousExts := []string{
		".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
		".jsp", ".jspx", ".asp", ".aspx", ".ashx",
		".js", ".py", ".cgi", ".sh",
	}
	for _, ext := range suspiciousExts {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return false
}
