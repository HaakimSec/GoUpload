package verifier

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/goupload/internal/types"
)

func TestExtractFilePath(t *testing.T) {
	verifier := NewRCEVerifier(nil, 5*time.Second)

	tests := []struct {
		name     string
		body     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "JSON path",
			body:     `{"status":"success","url":"/uploads/shell.php"}`,
			expected: "/uploads/shell.php",
		},
		{
			name:     "HTML path",
			body:     `<a href="/uploads/shell.php">Download</a>`,
			expected: "/uploads/shell.php",
		},
		{
			name:     "Text path",
			body:     "File uploaded to uploads/shell.php successfully",
			expected: "uploads/shell.php",
		},
		{
			name:     "Header location",
			body:     "",
			headers:  map[string]string{"Location": "http://example.com/uploads/shell.php"},
			expected: "http://example.com/uploads/shell.php",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.extractFilePath(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestResolveURL(t *testing.T) {
	verifier := NewRCEVerifier(nil, 5*time.Second)

	tests := []struct {
		baseURL  string
		filePath string
		expected string
	}{
		{
			baseURL:  "http://example.com/upload.php",
			filePath: "/uploads/shell.php",
			expected: "http://example.com/uploads/shell.php",
		},
		{
			baseURL:  "http://example.com/upload/",
			filePath: "shell.php",
			expected: "http://example.com/upload/shell.php",
		},
		{
			baseURL:  "http://example.com/upload.php",
			filePath: "http://example.com/uploads/shell.php",
			expected: "http://example.com/uploads/shell.php",
		},
	}

	for _, tt := range tests {
		t.Run(tt.baseURL, func(t *testing.T) {
			result := verifier.resolveURL(tt.baseURL, tt.filePath)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestVerifyExecution(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cmd") != "" {
			// Simulate command execution
			w.Write([]byte("uid=33(www-data) gid=33(www-data) groups=33(www-data)"))
		} else {
			// Simulate PHP execution (no source shown)
			w.Write([]byte(""))
		}
	}))
	defer server.Close()

	verifier := NewRCEVerifier(server.Client(), 5*time.Second)

	result := verifier.verifyExecution(server.URL + "/shell.php")

	if !result.Verified {
		t.Error("expected verification to succeed")
	}

	if result.Proof == "" {
		t.Error("expected proof to be non-empty")
	}

	if result.FileURL != server.URL+"/shell.php" {
		t.Errorf("expected file URL %s, got %s", server.URL+"/shell.php", result.FileURL)
	}
}

func TestIsSourceVisible(t *testing.T) {
	verifier := NewRCEVerifier(nil, 5*time.Second)

	tests := []struct {
		body     string
		expected bool
	}{
		{
			body:     "<?php system($_GET['cmd']); ?>",
			expected: true,
		},
		{
			body:     "",
			expected: false,
		},
		{
			body:     "<%@ page import=\"java.io.*\" %>",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := verifier.isSourceVisible(tt.body)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestVerifyRCE(t *testing.T) {
	// Create test server for upload
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","url":"/uploads/shell.php"}`))
	}))
	defer uploadServer.Close()

	// Create test server for file access
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cmd") != "" {
			w.Write([]byte("uid=33(www-data) gid=33(www-data)"))
		} else {
			w.Write([]byte(""))
		}
	}))
	defer fileServer.Close()

	verifier := NewRCEVerifier(nil, 5*time.Second)

	result := &types.Result{
		Vulnerable:   "VULNERABLE",
		ResponseBody: `{"status":"success","url":"` + fileServer.URL + `/shell.php"}`,
		ResponseHeaders: map[string]string{
			"Content-Type": "application/json",
		},
	}

	err := verifier.VerifyRCE(result, uploadServer.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.RCEVerified {
		t.Error("expected RCE to be verified")
	}

	if result.RCEProof == "" {
		t.Error("expected RCE proof to be non-empty")
	}
}

