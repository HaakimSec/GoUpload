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

	// Check 5b: HTML success patterns (for labs and legacy apps)
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

		// Check 5d: Generic success keywords combined with file reflection
		genericSuccessWords := []string{"success", "succeeded", "completed"}
		for _, word := range genericSuccessWords {
			if strings.Contains(lower, word) && isSuspiciousExt {
				flags = append(flags, "success-keyword-with-suspicious-ext")
				break
			}
		}
	}

	// Check 6: Content-Type spoofing specific checks
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

		// Check for GraphQL success
		if strings.Contains(lower, `"data":{`) || strings.Contains(lower, `"data": {`) {
			flags = append(flags, "graphql-mutation-accepted")

			// Check if it returned expected fields
			if strings.Contains(lower, `"__typename"`) || strings.Contains(lower, `"resumeid"`) {
				flags = append(flags, "graphql-expected-response")
			}
		}

		// Check for GraphQL errors
		if strings.Contains(lower, `"errors":[{`) || strings.Contains(lower, `"errors": [{"`) {
			flags = append(flags, "graphql-errors-returned")
		}

		// Check for stack traces (info disclosure!)
		if strings.Contains(lower, "/home/") || strings.Contains(lower, "/var/www/") {
			flags = append(flags, "graphql-stack-trace-disclosed")
		}

		// Check for Node.js specific errors
		if strings.Contains(lower, "cannot find module") ||
			strings.Contains(lower, "require(") ||
			strings.Contains(lower, "node_modules") {
			flags = append(flags, "nodejs-module-error-disclosed")
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

	// GraphQL Validation Safeguard: If validation failed, the file was rejected
	if flagSet["graphql-validation-error"] {
		return VerdictSafe
	}

	// GraphQL mutation accepted with executable extension = VULNERABLE
	if flagSet["graphql-mutation-accepted"] && hasSuspiciousExt(pl) {
		return VerdictVulnerable
	}

	// GraphQL stack trace disclosed = VULNERABLE (info disclosure)
	if flagSet["graphql-stack-trace-disclosed"] {
		return VerdictVulnerable
	}

	// Node.js module error disclosed = SUSPECT (potential path traversal success)
	if flagSet["nodejs-module-error-disclosed"] {
		return VerdictSuspect
	}

	// Fall back to HTTP status check for standard modules
	if !isSuccessStatus(result.StatusCode) {
		return VerdictSafe
	}

	// HIGH CONFIDENCE: HTML success + filepath disclosure = VULNERABLE
	if flagSet["html-indicates-success"] && flagSet["filepath-disclosed"] {
		return VerdictVulnerable
	}

	// HIGH CONFIDENCE: HTML success + suspicious extension = VULNERABLE
	if flagSet["html-indicates-success"] && hasSuspiciousExt(pl) {
		return VerdictVulnerable
	}

	// HIGH CONFIDENCE: Content-type spoof accepted with success indicators
	if flagSet["content-type-spoof-accepted"] &&
		(flagSet["html-indicates-success"] || flagSet["filename-reflected-in-response"]) {
		return VerdictVulnerable
	}

	// HIGH CONFIDENCE: Traversal accepted with file error disclosure
	if flagSet["traversal-filename-accepted"] && flagSet["filesystem-error-disclosed"] {
		return VerdictVulnerable
	}

	// HIGH CONFIDENCE: Image upload with executable content accepted
	if flagSet["image-upload-accepted"] && hasSuspiciousExt(pl) {
		return VerdictVulnerable
	}

	// EXIF data processed with image upload = VULNERABLE
	if flagSet["exif-data-processed"] && flagSet["image-upload-accepted"] {
		return VerdictVulnerable
	}

	// Original high confidence flags
	highConfidenceFlags := []string{
		"suspicious-ext-accepted",
		"spoofed-content-accepted",
		"traversal-filename-accepted",
	}
	highCount := 0
	for _, hf := range highConfidenceFlags {
		if flagSet[hf] {
			highCount++
		}
	}

	supportingFlags := []string{
		"response-length-matches-baseline",
		"status-matches-baseline",
		"json-indicates-success",
		"filename-reflected-in-response",
		"html-indicates-success",
		"filepath-disclosed",
		"image-upload-accepted",
		"graphql-mutation-accepted",
		"graphql-expected-response",
	}
	supportCount := 0
	for _, sf := range supportingFlags {
		if flagSet[sf] {
			supportCount++
		}
	}

	if highCount >= 1 && supportCount >= 1 {
		return VerdictVulnerable
	}
	if highCount >= 2 {
		return VerdictVulnerable
	}
	if highCount >= 1 {
		return VerdictSuspect
	}
	if flagSet["traversal-filename-accepted"] {
		return VerdictSuspect
	}
	if flagSet["filename-reflected-in-response"] && flagSet["path-structure-in-response"] {
		return VerdictSuspect
	}
	if flagSet["html-indicates-success"] || flagSet["filepath-disclosed"] {
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

