package validator

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ValidateTarget checks if the target URL is reachable and not a placeholder
func ValidateTarget(targetURL string, timeout time.Duration) error {
	// Parse URL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Check scheme
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported protocol: %s (use http:// or https://)", parsed.Scheme)
	}

	// Check if host is valid
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("no host specified in URL")
	}

	// Check for common placeholder domains
	placeholderDomains := []string{
		"target.com",
		"example.com",
		"domain.com",
		"website.com",
		"mysite.com",
		"test.com",
		"yoursite.com",
		"myapp.com",
		"app.com",
		"server.com",
	}

	hostLower := strings.ToLower(host)
	for _, placeholder := range placeholderDomains {
		if hostLower == placeholder {
			return fmt.Errorf("placeholder domain detected: '%s' - please provide a real target URL", host)
		}
	}

	// Check for common misspellings
	if strings.Contains(hostLower, "target.") || strings.Contains(hostLower, "example.") {
		return fmt.Errorf("test/example domain detected: '%s' - did you mean to test a real target?", host)
	}

	// Try DNS resolution (skip for localhost)
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && !isIPAddress(host) {
		_, err := net.LookupHost(host)
		if err != nil {
			return fmt.Errorf("cannot resolve host '%s': %w - check the URL or your network connection", host, err)
		}
	}

	// Try TCP connection
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return fmt.Errorf("cannot connect to %s:%s - %w (is the server running?)", host, port, err)
	}
	conn.Close()

	// Try HTTP request
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}
	req.Header.Set("User-Agent", "GoUpload-Validator/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s - %w", targetURL, err)
	}
	resp.Body.Close()

	// Check for error status codes
	if resp.StatusCode >= 500 {
		return fmt.Errorf("target returned server error (HTTP %d) - the endpoint may not be functional", resp.StatusCode)
	}

	if resp.StatusCode == 404 {
		return fmt.Errorf("target returned 404 Not Found - the upload endpoint may not exist")
	}

	return nil
}

// ValidateUploadEndpoint performs a quick test upload to verify the endpoint
func ValidateUploadEndpoint(targetURL, param string, timeout time.Duration) error {
	// Create a benign test file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile(param, "GoUpload_validation_test.txt")
	if err != nil {
		return fmt.Errorf("failed to create test upload: %w", err)
	}
	part.Write([]byte("GoUpload connectivity test - safe to delete"))
	writer.Close()

	req, err := http.NewRequest("POST", targetURL, body)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "GoUpload-Validator/1.0")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload endpoint test failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body (limited)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	// Check for server errors
	if resp.StatusCode >= 500 {
		return fmt.Errorf("upload endpoint returned server error (HTTP %d): %s",
			resp.StatusCode, string(respBody[:min(len(respBody), 100)]))
	}

	return nil
}

// GetWarnings checks for potential issues with the target
func GetWarnings(targetURL string) []string {
	var warnings []string

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return warnings
	}

	host := parsed.Hostname()

	// Check for localhost
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		warnings = append(warnings, "Testing against localhost - make sure your local server is running")
	}

	// Check for HTTP (not HTTPS)
	if parsed.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && !isIPAddress(host) {
		warnings = append(warnings, "Using HTTP - consider using HTTPS for production targets")
	}

	// Check for raw IP addresses
	if isIPAddress(host) && host != "127.0.0.1" && host != "::1" {
		warnings = append(warnings, "Using IP address instead of domain name")
	}

	return warnings
}

// isIPAddress checks if a string is a valid IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
