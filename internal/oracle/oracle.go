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

	// IMPORTANT: Use full response body for analysis
	bodyToCheck := result.ResponseBody
	if bodyToCheck == "" {
		bodyToCheck = result.BodySnippet
	}
	lowerBody := strings.ToLower(bodyToCheck)

	// Check 1: Successful status code for an executable/suspicious payload
	isSuspiciousExt := isExecutableExtension(pl.Extension)
	statusOK := isSuccessStatus(result.StatusCode)

	if statusOK && isSuspiciousExt {
		flags = append(flags, "suspicious-ext-accepted")
	}

	// Check 2: Response length similarity to baseline
	if baseline != nil && baseline.ResponseLength > 0 && result.RespLen > 0 {
		ratio := float64(result.RespLen) / float64(baseline.ResponseLength)
		if ratio > 0.9 && ratio < 1.1 {
			if isSuspiciousExt {
				flags = append(flags, "response-length-matches-baseline")
			}
		}
	}

	// Check 3: Exact status code match with baseline
	if baseline != nil && result.StatusCode == baseline.StatusCode && isSuspiciousExt {
		flags = append(flags, "status-matches-baseline")
	}

	// Check 4: JSON response indicating success
	if strings.Contains(result.RespCT, "application/json") {
		jsonSuccessIndicators := []string{
			`"success":true`, `"success": true`,
			`"status":"ok"`, `"status":"success"`,
			`"status": "ok"`, `"status": "success"`,
			`"uploaded":true`, `"uploaded": true`,
			`"error":null`, `"error": null`,
			`"code":200`, `"code": 200`,
			`"code":201`, `"code": 201`,
			`"message":"success"`, `"message": "success"`,
			`"added"`, `"added":`,
		}
		for _, indicator := range jsonSuccessIndicators {
			if strings.Contains(lowerBody, indicator) {
				flags = append(flags, "json-indicates-success")
				break
			}
		}
	}

	// Check 5a: Filename or path reflected in response
	cleanFilename := strings.Split(pl.Filename, "%")[0]
	cleanFilename = strings.Split(cleanFilename, "\x00")[0]

	if strings.Contains(bodyToCheck, cleanFilename) {
		flags = append(flags, "filename-reflected-in-response")
	}

	pathIndicators := []string{
		"/uploads/", "/upload/", "/files/", "/images/",
		"uploads/", "upload/", "files/",
		`src="`, `href="`, "url(", `path":`,
		"target file:", "target dir:", "file exists:", "dir writable:",
	}
	for _, indicator := range pathIndicators {
		if strings.Contains(lowerBody, indicator) {
			flags = append(flags, "path-structure-in-response")
			break
		}
	}

	// Check 5b: HTML success patterns - Use FULL response body
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
		"uploaded successfully",
		"file uploaded successfully",
		"target file:",      // HTML comment debug info
		"dir writable: yes", // Debug info
		"file exists: yes",  // Debug info
	}
	for _, pattern := range htmlSuccessPatterns {
		if strings.Contains(lowerBody, pattern) {
			flags = append(flags, "html-indicates-success")
			break
		}
	}

	// Check 5c: Direct file path disclosure - Use FULL response body
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
		"uploads/",
		"upload/",
		"target file:",
		"target dir:",
	}
	for _, pattern := range pathDisclosurePatterns {
		if strings.Contains(lowerBody, pattern) {
			flags = append(flags, "filepath-disclosed")
			break
		}
	}

	// Check 5d: Generic success keywords
	genericSuccessWords := []string{"success", "succeeded", "completed", "uploaded"}
	for _, word := range genericSuccessWords {
		if strings.Contains(lowerBody, word) && isSuspiciousExt {
			flags = append(flags, "success-keyword-with-suspicious-ext")
			break
		}
	}

	// Check 5e: Simple upload lab detection - Check BOTH body and snippet
	if isSuspiciousExt && strings.Contains(lowerBody, ".php") {
		if strings.Contains(lowerBody, "uploads/") || strings.Contains(lowerBody, "upload/") ||
			strings.Contains(lowerBody, "target file:") || strings.Contains(lowerBody, "target dir:") {
			flags = append(flags, "filepath-disclosed")
			flags = append(flags, "filename-reflected-in-response")
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
			if strings.Contains(lowerBody, "upload") &&
				(strings.Contains(lowerBody, "success") || strings.Contains(lowerBody, "uploaded")) {
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
		traversalErrorIndicators := []string{
			"no such file", "permission denied", "is a directory",
			"not a directory", "file exists", "cannot open",
			"no such file or directory",
		}
		for _, indicator := range traversalErrorIndicators {
			if strings.Contains(lowerBody, indicator) {
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
			if strings.Contains(lowerBody, indicator) {
				flags = append(flags, "image-upload-accepted")
				break
			}
		}

		exifIndicators := []string{
			"exif", "metadata", "image description",
			"comment", "makernote",
		}
		for _, indicator := range exifIndicators {
			if strings.Contains(lowerBody, indicator) {
				flags = append(flags, "exif-data-processed")
				break
			}
		}
	}

	// Check 9: GraphQL response detection
	if pl.GraphQL != nil {
		if strings.Contains(lowerBody, `"data":{`) || strings.Contains(lowerBody, `"data": {`) {
			flags = append(flags, "graphql-mutation-accepted")

			if strings.Contains(lowerBody, `"__typename"`) || strings.Contains(lowerBody, `"resumeid"`) {
				flags = append(flags, "graphql-expected-response")
			}
		}

		if strings.Contains(lowerBody, `"errors":[{`) || strings.Contains(lowerBody, `"errors": [{"`) {
			flags = append(flags, "graphql-errors-returned")
		}

		if strings.Contains(lowerBody, "/home/") || strings.Contains(lowerBody, "/var/www/") {
			flags = append(flags, "graphql-stack-trace-disclosed")
		}

		if strings.Contains(lowerBody, "cannot find module") ||
			strings.Contains(lowerBody, "require(") ||
			strings.Contains(lowerBody, "node_modules") {
			flags = append(flags, "nodejs-module-error-disclosed")
		}
	}

	// Check 10: Race condition specific detection
	if pl.TestType == payload.TestTypeRaceCondition {
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
			if strings.Contains(lowerBody, indicator) {
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
			if strings.Contains(lowerBody, indicator) {
				flags = append(flags, "concurrent-access-detected")
				break
			}
		}

		if strings.Contains(lowerBody, "overwrite") ||
			strings.Contains(lowerBody, "replace") ||
			strings.Contains(lowerBody, "already exists") {
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

	// Check 11: XXE detection
	if pl.TestType == payload.TestTypeXXE {
		if result.StatusCode == 200 &&
			(strings.Contains(lowerBody, "success") || strings.Contains(lowerBody, "uploaded")) {
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
			if strings.Contains(lowerBody, indicator) {
				flags = append(flags, "xxe-file-disclosure")
				break
			}
		}

		if strings.Contains(lowerBody, "lol") || strings.Contains(lowerBody, "entity") {
			flags = append(flags, "xxe-entity-expansion")
		}
	}

	// Check 12: elFinder/WordPress File Manager specific detection
	if strings.Contains(bodyToCheck, `"added"`) {
		flags = append(flags, "elfinder-upload-success")
		flags = append(flags, "json-indicates-success")

		if strings.Contains(bodyToCheck, `"url"`) {
			flags = append(flags, "filepath-disclosed")
		}
		if strings.Contains(bodyToCheck, pl.Filename) {
			flags = append(flags, "filename-reflected-in-response")
		}
	}

	// Check 13: Simple upload detection (for labs and basic apps)
	// Use FULL response body
	if statusOK && isSuspiciousExt {
		// Check for successful upload indicators in full body
		if strings.Contains(lowerBody, "upload") || strings.Contains(lowerBody, "success") {
			// Check for file path disclosure
			if strings.Contains(lowerBody, "uploads/") ||
				strings.Contains(lowerBody, "upload/") ||
				strings.Contains(lowerBody, "target file:") ||
				strings.Contains(lowerBody, "target dir:") ||
				strings.Contains(lowerBody, ".php") ||
				strings.Contains(lowerBody, "href=") {
				flags = append(flags, "filepath-disclosed")
				flags = append(flags, "html-indicates-success")
			}
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

	// Check for executable extensions
	hasSuspiciousExt := isExecutableExtension(pl.Extension) ||
		strings.Contains(pl.Filename, ".php") ||
		strings.Contains(pl.Filename, ".phtml") ||
		strings.Contains(pl.Filename, ".phar") ||
		strings.Contains(pl.Filename, ".jsp") ||
		strings.Contains(pl.Filename, ".jspx") ||
		strings.Contains(pl.Filename, ".asp") ||
		strings.Contains(pl.Filename, ".aspx") ||
		strings.Contains(pl.Filename, ".py") ||
		strings.Contains(pl.Filename, ".cgi") ||
		strings.Contains(pl.Filename, ".sh")

	// Success indicators
	hasSuccessIndicator := flagSet["json-indicates-success"] ||
		flagSet["html-indicates-success"] ||
		flagSet["filepath-disclosed"] ||
		flagSet["filename-reflected-in-response"] ||
		flagSet["success-keyword-with-suspicious-ext"]

	// CRITICAL FIX: WordPress File Manager / elFinder detection
	if flagSet["elfinder-upload-success"] {
		if hasSuspiciousExt {
			return VerdictVulnerable
		}
		if hasSuccessIndicator {
			return VerdictSuspect
		}
		return VerdictSafe
	}

	// Direct WordPress File Manager RCE check
	if isWordPressFileManagerRCE(result, pl) {
		return VerdictVulnerable
	}

	// GraphQL mutation with executable extension
	if flagSet["graphql-mutation-accepted"] && hasSuspiciousExt {
		return VerdictVulnerable
	}

	// XXE file accepted
	if flagSet["xxe-file-accepted"] {
		return VerdictVulnerable
	}

	// File overwrite confirmed
	if flagSet["file-overwrite-confirmed"] {
		return VerdictVulnerable
	}

	// SIMPLE UPLOAD LAB DETECTION
	// 200 + suspicious ext + HTML success + filepath disclosed = VULNERABLE
	if result.StatusCode == 200 && hasSuspiciousExt &&
		flagSet["html-indicates-success"] && flagSet["filepath-disclosed"] {
		return VerdictVulnerable
	}

	// Strong evidence: 200 + suspicious ext + success
	if result.StatusCode == 200 && hasSuspiciousExt && hasSuccessIndicator {
		return VerdictVulnerable
	}

	// Medium evidence: 200 + suspicious ext (no explicit success indicator)
	if result.StatusCode == 200 && hasSuspiciousExt {
		// Check if response contains upload indicators
		bodyToCheck := strings.ToLower(result.ResponseBody)
		if bodyToCheck == "" {
			bodyToCheck = strings.ToLower(result.BodySnippet)
		}
		if strings.Contains(bodyToCheck, "upload") || strings.Contains(bodyToCheck, "success") {
			return VerdictVulnerable
		}
		return VerdictSuspect
	}

	// Success without suspicious extension
	if result.StatusCode == 200 && hasSuccessIndicator && !hasSuspiciousExt {
		return VerdictSuspect
	}

	// Race condition detection
	if flagSet["concurrent-access-detected"] {
		return VerdictSuspect
	}

	// Any other flags
	if len(flags) > 0 {
		return VerdictSuspect
	}

	return VerdictSafe
}

// Helper function to detect WordPress File Manager RCE
func isWordPressFileManagerRCE(result *types.Result, pl *payload.Payload) bool {
	if !strings.Contains(result.ResponseBody, "added") &&
		!strings.Contains(result.ResponseBody, "success") {
		return false
	}

	executableExts := []string{
		".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".phar",
		".jsp", ".jspx", ".asp", ".aspx", ".ashx",
	}

	for _, ext := range executableExts {
		if strings.Contains(pl.Filename, ext) {
			if strings.Contains(result.ResponseBody, pl.Filename) ||
				strings.Contains(result.ResponseBody, "url") ||
				strings.Contains(result.ResponseBody, "file") {
				return true
			}
		}
	}

	return false
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

// hasSuspiciousExt is a helper to check if payload has executable extension
func hasSuspiciousExt(pl *payload.Payload) bool {
	return isExecutableExtension(pl.Extension)
}

// isSuccessStatus returns true for HTTP status codes that typically indicate success.
func isSuccessStatus(code int) bool {
	return (code >= 200 && code < 300) || code == 302 || code == 303
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
