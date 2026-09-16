package verifier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/HaakimSec/GoUpload/internal/types"
)

// VerificationStatus distinguishes a confirmed-safe result from a check that
// simply couldn't be completed (network error, ambiguous response, etc).
// Collapsing both into "not vulnerable" was the root cause of Bug 6 — a
// flaky request during dataset construction would otherwise become a hard
// SAFE label with claimed 100% confidence.
type VerificationStatus int

const (
	StatusUnverified   VerificationStatus = iota // verification could not be completed
	StatusNotExecuting                           // checks completed, no execution proof found
	StatusExecuting                              // confirmed RCE
)

func (s VerificationStatus) String() string {
	switch s {
	case StatusExecuting:
		return "EXECUTING"
	case StatusNotExecuting:
		return "NOT_EXECUTING"
	default:
		return "UNVERIFIED"
	}
}

type RCEVerifier struct {
	client   *http.Client
	timeout  time.Duration
	commands []string // ordered list of probe commands; first to produce proof wins
	patterns []PathPattern
}

type PathPattern struct {
	Regex *regexp.Regexp
	Type  string
}

func NewRCEVerifier(client *http.Client, timeout time.Duration) *RCEVerifier {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}
	}

	return &RCEVerifier{
		client:  client,
		timeout: timeout,
		// "whoami" resolves on both *nix and Windows; "id" is *nix-only but
		// kept first since most real-world targets in our dataset are PHP/Linux.
		commands: []string{"id", "whoami"},
		patterns: []PathPattern{
			// Simple HTML upload patterns (for labs and simple apps)
			{
				Regex: regexp.MustCompile(`(?i)href=['"]uploads/([^'"]+\.php)['"]`),
				Type:  "html-upload",
			},
			{
				Regex: regexp.MustCompile(`(?i)((?:/)?uploads/[a-zA-Z0-9_\-]+\.php)`),
				Type:  "uploads-path",
			},
			{
				Regex: regexp.MustCompile(`(?i)Location:\s*(?:<[^>]+>)?\s*['"]?([^'"<>\s]+\.php)['"]?`),
				Type:  "html-location",
			},
			// WordPress File Manager specific pattern
			{
				Regex: regexp.MustCompile(`"name":"([^"]+\.php)"`),
				Type:  "wordpress",
			},
			// JSON patterns
			{
				Regex: regexp.MustCompile(`(?i)"url":"([^"]+\.php)"`),
				Type:  "json-url",
			},
			{
				Regex: regexp.MustCompile(`(?i)"(?:url|path|file|filename|location|href|src)"\s*:\s*"([^"]+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js))"`),
				Type:  "json",
			},
			// HTML patterns
			{
				Regex: regexp.MustCompile(`(?i)(?:href|src|action|url|path|file|location)=["']([^"']+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js))["']`),
				Type:  "html",
			},
			// Text patterns
			{
				Regex: regexp.MustCompile(`(?i)(?:uploads|upload|files|images|media|tmp|temp|data|storage|static|assets)/[^"'\s<>]+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js)`),
				Type:  "text",
			},
			// Header patterns
			{
				Regex: regexp.MustCompile(`(?i)Location:\s*([^\s]+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js))`),
				Type:  "header",
			},
		},
	}
}

func (v *RCEVerifier) VerifyRCE(result *types.Result, baseURL string) error {
	if result == nil || result.Vulnerable != "VULNERABLE" {
		return fmt.Errorf("result is not vulnerable")
	}

	startTime := time.Now()

	// Try simple upload verification first (for labs and simple apps)
	if strings.Contains(result.ResponseBody, "uploads/") ||
		strings.Contains(result.ResponseBody, "File uploaded") ||
		strings.Contains(result.ResponseBody, "uploaded successfully") {
		fileURL, status, proof, cmd := v.verifySimpleUpload(result, baseURL)
		if status == StatusExecuting {
			result.RCEVerified = true
			result.RCEProof = proof
			result.FileURL = fileURL
			result.RCECommand = cmd
			// NOTE: add `RCEStatus string` to types.Result if not present.
			result.RCEStatus = status.String()
			result.VerificationTime = time.Since(startTime)
			return nil
		}
		if status == StatusUnverified {
			// Don't fall through and let the generic path silently overwrite
			// this with a confident-looking SAFE — surface it as unverified.
			result.RCEVerified = false
			result.RCEStatus = status.String()
			result.FileURL = fileURL
			result.VerificationTime = time.Since(startTime)
			return fmt.Errorf("verification inconclusive: network/response error during simple-upload check")
		}
		// status == StatusNotExecuting here: fall through and let the
		// generic extraction path have a try too, in case the simple-upload
		// heuristic picked the wrong path pattern.
	}

	// Extract file path from response
	filePath := v.extractFilePath(result.ResponseBody, result.ResponseHeaders, baseURL)
	if filePath == "" {
		result.RCEStatus = StatusUnverified.String()
		return fmt.Errorf("could not extract file path from response")
	}

	// Resolve URL (same-origin enforced inside resolveURL)
	fileURL := v.resolveURL(baseURL, filePath)
	if fileURL == "" {
		result.RCEStatus = StatusUnverified.String()
		return fmt.Errorf("could not resolve file URL (missing, unparsable, or cross-origin)")
	}

	// Verify execution
	status, proof, cmd := v.verifyExecution(fileURL)

	// Update result
	result.RCEVerified = status == StatusExecuting
	result.RCEProof = proof
	result.FileURL = fileURL
	result.RCECommand = cmd
	result.RCEStatus = status.String()
	result.VerificationTime = time.Since(startTime)

	if status == StatusUnverified {
		return fmt.Errorf("verification inconclusive: could not confirm execution or absence of it")
	}

	return nil
}

// verifySimpleUpload handles simple HTML responses with uploads/ paths
func (v *RCEVerifier) verifySimpleUpload(result *types.Result, baseURL string) (string, VerificationStatus, string, string) {
	patterns := []string{
		`href=['"]uploads/([^'"]+\.(?:php|phtml|pht|phar|php5|php7))['"]`,
		`uploads/([a-zA-Z0-9_\-\.%]+\.(?:php|phtml|pht|phar|php5|php7))`,
		`Location:\s*['"]?([^'"<>\s]+\.(?:php|phtml|pht|phar|php5|php7))['"]?`,
		`Target file:\s*([^\s<]+\.(?:php|phtml|pht|phar|php5|php7))`,
	}

	var uploadPath string
	for _, pattern := range patterns {
		if matches := regexp.MustCompile(pattern).FindStringSubmatch(result.ResponseBody); len(matches) > 1 {
			uploadPath = matches[1]
			break
		}
	}

	if uploadPath == "" {
		return "", StatusUnverified, "", ""
	}

	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return "", StatusUnverified, "", ""
	}

	var fileURL string
	if strings.HasPrefix(uploadPath, "http://") || strings.HasPrefix(uploadPath, "https://") {
		if !v.sameOrigin(baseURL, uploadPath) {
			// Bug 5 fix: refuse to fetch an absolute URL pulled from the
			// target's own response body if it points off-host.
			return "", StatusUnverified, "", ""
		}
		fileURL = uploadPath
	} else if strings.HasPrefix(uploadPath, "/") {
		fileURL = fmt.Sprintf("%s://%s%s", baseURLParsed.Scheme, baseURLParsed.Host, uploadPath)
	} else if strings.HasPrefix(uploadPath, "uploads/") {
		fileURL = fmt.Sprintf("%s://%s/%s", baseURLParsed.Scheme, baseURLParsed.Host, uploadPath)
	} else {
		fileURL = fmt.Sprintf("%s://%s/uploads/%s", baseURLParsed.Scheme, baseURLParsed.Host, uploadPath)
	}

	status, proof, cmd := v.verifyExecution(fileURL)
	return fileURL, status, proof, cmd
}

func (v *RCEVerifier) extractFilePath(body string, headers map[string]string, baseURL string) string {
	// Special handling for WordPress File Manager
	if strings.Contains(baseURL, "wp-file-manager") {
		return v.extractWordPressFilePath(body, baseURL)
	}

	// Check all patterns against body
	for _, pattern := range v.patterns {
		if matches := pattern.Regex.FindStringSubmatch(body); len(matches) > 1 {
			p := matches[1]

			if pattern.Type == "html-upload" {
				if !strings.HasPrefix(p, "/") {
					p = "/uploads/" + p
				}
			}

			return p
		}
	}

	// Check headers for location
	if location, ok := headers["Location"]; ok {
		if parsed, err := url.Parse(location); err == nil && parsed.IsAbs() {
			return location
		}
		for _, pattern := range v.patterns {
			if matches := pattern.Regex.FindStringSubmatch(location); len(matches) > 1 {
				return matches[1]
			}
		}
	}

	return ""
}

// extractWordPressFilePath handles WordPress File Manager responses.
// Bug 4 fix: derive the install root from baseURL instead of assuming a
// fixed "/wordpress/" path, which only held true in the lab environment.
func (v *RCEVerifier) extractWordPressFilePath(body, baseURL string) string {
	if matches := regexp.MustCompile(`"url":"([^"]+\.php)"`).FindStringSubmatch(body); len(matches) > 1 {
		u := strings.ReplaceAll(matches[1], `\/`, `/`)
		return u
	}

	if matches := regexp.MustCompile(`"name":"([^"]+\.php)"`).FindStringSubmatch(body); len(matches) > 1 {
		filename := matches[1]

		root := ""
		if base, err := url.Parse(baseURL); err == nil {
			if idx := strings.Index(base.Path, "/wp-"); idx >= 0 {
				root = base.Path[:idx]
			}
		}
		return fmt.Sprintf("%s/wp-content/plugins/wp-file-manager/lib/files/%s", root, filename)
	}

	return ""
}

// sameOrigin reports whether candidate points at the same host as baseURL.
// Bug 5 fix: used to gate any absolute URL extracted from a scanned
// target's own response before GoUpload fetches it, closing an SSRF gap
// where a malicious/compromised target could steer requests off-host.
func (v *RCEVerifier) sameOrigin(baseURL, candidate string) bool {
	b, err1 := url.Parse(baseURL)
	c, err2 := url.Parse(candidate)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(b.Hostname(), c.Hostname())
}

func (v *RCEVerifier) resolveURL(baseURL, filePath string) string {
	if strings.HasPrefix(filePath, "http://") || strings.HasPrefix(filePath, "https://") {
		if !v.sameOrigin(baseURL, filePath) {
			return ""
		}
		return filePath
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(filePath, "/") {
		return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, filePath)
	}
	if strings.HasPrefix(filePath, "uploads/") {
		return fmt.Sprintf("%s://%s/%s", base.Scheme, base.Host, filePath)
	}

	if strings.HasSuffix(base.Path, "/") {
		base.Path = strings.TrimSuffix(base.Path, "/") + "/"
		resolved := base.ResolveReference(&url.URL{Path: filePath})
		return resolved.String()
	}

	return fmt.Sprintf("%s://%s/uploads/%s", base.Scheme, base.Host, filePath)
}

// fetchBody performs a GET and returns the body, or "" on any failure.
// Centralized so verifyExecution's retry loop (Bug 2) stays simple.
func (v *RCEVerifier) fetchBody(ctx context.Context, rawURL string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// verifyExecution attempts command-injection proof first (Bug 3 fix: the
// source-visibility check is no longer a gate that can short-circuit before
// the proof attempt — it's only used to annotate the result when no proof
// is found). It also tries multiple commands for cross-platform coverage
// (Bug 2), and distinguishes "confirmed not executing" from "could not
// verify" (Bug 6) instead of collapsing both into false.
func (v *RCEVerifier) verifyExecution(fileURL string) (VerificationStatus, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	fileURL = cleanURL(fileURL)

	// Baseline fetch — used only as a secondary signal, never a gate.
	baselineBody, baselineStatus, baselineErr := v.fetchBody(ctx, fileURL)
	if baselineErr != nil {
		return StatusUnverified, "", ""
	}
	if baselineStatus == 404 {
		// Ambiguous, not confirmed-safe: the extracted path may simply be wrong.
		return StatusUnverified, "", ""
	}
	looksLikeSource := v.isSourceVisible(baselineBody)

	// Always attempt command injection, regardless of the baseline signal.
	sawAnySuccessfulProbe := false
	for _, cmd := range v.commands {
		commandURL := v.addCommandParam(fileURL, cmd)

		// Fresh timeout per probe so one slow request doesn't starve the rest.
		probeCtx, probeCancel := context.WithTimeout(context.Background(), v.timeout)
		body, status, err := v.fetchBody(probeCtx, commandURL)
		probeCancel()

		if err != nil {
			continue // try next command
		}
		if status >= 200 && status < 300 || status == 500 {
			// treat 5xx as worth checking too — some payloads trigger a
			// server error page that still leaks command output
			sawAnySuccessfulProbe = true
		}
		if proof := v.extractProof(body); proof != "" {
			return StatusExecuting, proof, cmd
		}
	}

	if !sawAnySuccessfulProbe {
		// Every probe failed at the transport/HTTP level — we genuinely
		// don't know whether this executes or not.
		return StatusUnverified, "", ""
	}

	// All probes completed but produced no proof. If the baseline looked
	// like raw source, that's consistent with (but not proof of) non-execution;
	// either way we have a completed check with no execution evidence.
	_ = looksLikeSource
	return StatusNotExecuting, "", ""
}

// cleanURL resolves ../ in URLs
func cleanURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Path = path.Clean(u.Path)
	return u.String()
}

func (v *RCEVerifier) isSourceVisible(body string) bool {
	rceMarkers := []string{
		"PHTML_RCE_MARKER",
		"PHP_RCE_MARKER",
		"RCE_SUCCESS",
		"UNAUTH_RCE_SUCCESS",
		"RCE_TEST_MARKER",
	}
	for _, marker := range rceMarkers {
		if strings.Contains(body, marker) {
			return false
		}
	}

	if strings.Contains(body, "<?php") || strings.Contains(body, "<?=") {
		return true
	}

	if strings.Contains(body, "<%@") || strings.Contains(body, "<%=") {
		return true
	}

	sourcePatterns := []string{
		"function ",
		"namespace ",
		"import java",
		"Response.Write",
		"Server.MapPath",
		"eval(",
		"system(",
		"exec(",
	}

	for _, pattern := range sourcePatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

func (v *RCEVerifier) addCommandParam(fileURL, command string) string {
	parsedURL, err := url.Parse(fileURL)
	if err != nil {
		return fileURL
	}

	q := parsedURL.Query()
	q.Set("cmd", command)
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String()
}

func (v *RCEVerifier) extractProof(output string) string {
	indicators := []string{
		"uid=",
		"gid=",
		"groups=",
		"www-data",
		"apache",
		"nginx",
		"nobody",
		"httpd",
		"root:",
		"NT AUTHORITY",
		"nt authority\\",
		// ── Windows environment markers ──
		"USERNAME=",
		"COMPUTERNAME=",
		"USERPROFILE=",
		// ── Custom markers injected by GoUpload payloads ──
		"PHTML_RCE_MARKER",
		"PHP_RCE_MARKER",
		"JSP_RCE_MARKER",
		"ASP_RCE_MARKER",
		"NODE_RCE_MARKER",
		"RCE_TEST_MARKER",
		"RCE_SUCCESS",
		"UNAUTH_RCE_SUCCESS",
	}
	indicators = append(indicators, debugIndicators...)

	for _, indicator := range indicators {
		if strings.Contains(output, indicator) {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(line, indicator) {
					return strings.TrimSpace(line)
				}
			}
			if len(output) > 100 {
				return output[:100]
			}
			return output
		}
	}

	return ""
}
