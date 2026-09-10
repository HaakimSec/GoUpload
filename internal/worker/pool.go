package worker

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HaakimSec/GoUpload/internal/ml"
	"github.com/HaakimSec/GoUpload/internal/oracle"
	"github.com/HaakimSec/GoUpload/internal/payload"
	"github.com/HaakimSec/GoUpload/internal/types"
)

// ResultHandler is a callback invoked for each completed test result.
type ResultHandler func(r *types.Result)

// Pool manages a fixed set of goroutine workers processing upload tests.
type Pool struct {
	client   *http.Client
	config   *PoolConfig
	mu       sync.Mutex // protects result printing
	progress atomic.Int64
	total    int
	printer  ResultHandler
}

// PoolConfig configures the worker pool.
type PoolConfig struct {
	URL         string
	Param       string
	Headers     map[string]string
	Data        map[string]string
	Concurrency int
	Baseline    *oracle.Baseline
	MLClient    *ml.MLClient
}

// NewPool creates a new worker pool with the given configuration.
func NewPool(cfg *PoolConfig) *Pool {
	return &Pool{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		config:  cfg,
		total:   0,
		printer: nil,
	}
}

// SetResultHandler sets the callback for real-time result processing.
func (p *Pool) SetResultHandler(h ResultHandler) {
	p.printer = h
}

// Execute runs all payloads through the worker pool and returns collected results.
func (p *Pool) Execute(payloads []*payload.Payload) []*types.Result {
	jobs := make(chan *payload.Payload, len(payloads))
	results := make(chan *types.Result, len(payloads))

	p.total = len(payloads)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < p.config.Concurrency; i++ {
		wg.Add(1)
		go p.worker(i, jobs, results, &wg)
	}

	// Send jobs
	for _, pl := range payloads {
		jobs <- pl
	}
	close(jobs)

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	var allResults []*types.Result
	for r := range results {
		p.progress.Add(1)
		if p.printer != nil {
			p.printer(r)
		}
		allResults = append(allResults, r)
	}

	return allResults
}

// ExecuteRaceBurst executes race condition payloads in synchronized bursts
// All payloads with the same TargetFilename are sent simultaneously
func (p *Pool) ExecuteRaceBurst(payloads []*payload.Payload) []*types.Result {
	// Group payloads by target filename
	groups := make(map[string][]*payload.Payload)
	var sequential []*payload.Payload

	for _, pl := range payloads {
		if pl.RaceSync && pl.TargetFilename != "" {
			groups[pl.TargetFilename] = append(groups[pl.TargetFilename], pl)
		} else {
			sequential = append(sequential, pl)
		}
	}

	var allResults []*types.Result
	results := make(chan *types.Result, len(payloads))

	// Execute non-race payloads normally
	for _, pl := range sequential {
		results <- p.executeTest(pl)
	}

	// Execute race groups in synchronized bursts
	for targetFile, group := range groups {
		fmt.Printf("  🏃 Executing race burst for: %s (%d workers)\n", targetFile, len(group))

		var wg sync.WaitGroup
		var barrier sync.WaitGroup
		barrier.Add(len(group))

		for _, pl := range group {
			wg.Add(1)
			go func(pl *payload.Payload) {
				defer wg.Done()

				// All goroutines wait at the barrier
				barrier.Done()
				barrier.Wait() // Release simultaneously

				// All execute at the same time
				results <- p.executeTest(pl)
			}(pl)
		}

		wg.Wait()
	}

	close(results)

	for r := range results {
		allResults = append(allResults, r)
	}

	return allResults
}

// Progress returns the current number of completed tests.
func (p *Pool) Progress() int {
	return int(p.progress.Load())
}

// Total returns the total number of tests to execute.
func (p *Pool) Total() int {
	return p.total
}

// worker processes upload test jobs from the jobs channel.
func (p *Pool) worker(id int, jobs <-chan *payload.Payload, results chan<- *types.Result, wg *sync.WaitGroup) {
	defer wg.Done()

	for pl := range jobs {
		r := p.executeTest(pl)
		results <- r
	}
}

// executeTest performs a single upload test and evaluates the result.
func (p *Pool) executeTest(pl *payload.Payload) *types.Result {
	start := time.Now()
	r := &types.Result{
		TestType:  pl.TestType,
		Technique: pl.Technique,
		Filename:  pl.Filename,
	}

	// Build multipart form body
	reqBody := &bytes.Buffer{}
	writer := multipart.NewWriter(reqBody)

	// Add additional form fields
	for key, val := range p.config.Data {
		if err := writer.WriteField(key, val); err != nil {
			r.Err = fmt.Errorf("failed to write form field %s: %w", key, err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}
	}

	// ── BRANCH 1: GRAPHQL MULTIPART UPLOADS ──
	if pl.GraphQL != nil {
		// 1. Write GraphQL operations field
		if err := writer.WriteField("operations", pl.GraphQL.Operations); err != nil {
			r.Err = fmt.Errorf("failed to write GraphQL operations: %w", err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}

		// 2. Write GraphQL map field
		if err := writer.WriteField("map", pl.GraphQL.Map); err != nil {
			r.Err = fmt.Errorf("failed to write GraphQL map: %w", err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}

		// 3. Prepare the part with or without Content-Type override
		var part io.Writer
		var err error

		if pl.ContentType != "" {
			h := make(map[string][]string)
			h["Content-Disposition"] = []string{
				fmt.Sprintf(`form-data; name="%s"; filename="%s"`, pl.GraphQL.FileIndex, pl.Filename),
			}
			h["Content-Type"] = []string{pl.ContentType}

			part, err = writer.CreatePart(h)
		} else {
			part, err = writer.CreateFormFile(pl.GraphQL.FileIndex, pl.Filename)
		}

		if err != nil {
			r.Err = fmt.Errorf("failed to create GraphQL file part: %w", err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}

		// 4. Copy the file binary data into the part
		if _, err := io.Copy(part, bytes.NewReader(pl.Body)); err != nil {
			r.Err = fmt.Errorf("failed to write file content: %w", err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}

		// ── BRANCH 2: STANDARD REST MULTIPART UPLOADS ──
	} else {
		var part io.Writer
		var err error

		if pl.ContentType != "" {
			h := make(map[string][]string)
			h["Content-Disposition"] = []string{
				fmt.Sprintf(`form-data; name="%s"; filename="%s"`, p.config.Param, pl.Filename),
			}
			h["Content-Type"] = []string{pl.ContentType}

			part, err = writer.CreatePart(h)
		} else {
			part, err = writer.CreateFormFile(p.config.Param, pl.Filename)
		}

		if err != nil {
			r.Err = fmt.Errorf("failed to create form file: %w", err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}

		if _, err := io.Copy(part, bytes.NewReader(pl.Body)); err != nil {
			r.Err = fmt.Errorf("failed to write payload body: %w", err)
			r.ErrType = types.ErrValidation
			r.Duration = time.Since(start)
			return r
		}
	}

	// Close the writer to finalize the multipart boundary
	if err := writer.Close(); err != nil {
		r.Err = fmt.Errorf("failed to close multipart writer: %w", err)
		r.ErrType = types.ErrValidation
		r.Duration = time.Since(start)
		return r
	}

	// Build the HTTP request
	req, err := http.NewRequest("POST", p.config.URL, reqBody)
	if err != nil {
		r.Err = fmt.Errorf("failed to create request: %w", err)
		r.ErrType = types.ErrValidation
		r.Duration = time.Since(start)
		return r
	}

	// Set Content-Type with boundary
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Set custom headers
	for k, v := range p.config.Headers {
		req.Header.Set(k, v)
	}

	// Execute the request
	resp, err := p.client.Do(req)
	r.Duration = time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			r.Err = fmt.Errorf("request timeout: %w", err)
			r.ErrType = types.ErrTimeout
		} else if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe") {
			r.Err = fmt.Errorf("connection error: %w", err)
			r.ErrType = types.ErrConnection
		} else {
			r.Err = fmt.Errorf("request failed: %w", err)
			r.ErrType = types.ErrOther
		}
		return r
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		r.Err = fmt.Errorf("failed to read response: %w", err)
		r.ErrType = types.ErrConnection
		return r
	}

	r.StatusCode = resp.StatusCode
	r.RespLen = len(bodyBytes)
	r.RespCT = resp.Header.Get("Content-Type")

	// FIX: Store the FULL response body
	r.ResponseBody = string(bodyBytes)

	// BodySnippet: Store first 250 and last 250 chars to capture both beginning and end
	if len(bodyBytes) > 500 {
		firstPart := string(bodyBytes[:250])
		lastPart := string(bodyBytes[len(bodyBytes)-250:])
		r.BodySnippet = firstPart + "..." + lastPart
	} else {
		r.BodySnippet = string(bodyBytes)
	}

	r.ResponseHeaders = make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			r.ResponseHeaders[key] = values[0]
		}
	}

	r.Sanitized = detectSanitization(r.Filename, r.ResponseBody, r.ResponseHeaders)

	r.FinalFilename = extractFinalFilename(r.ResponseBody)

	// Run oracle analysis - ALWAYS, even without baseline
	verdict := oracle.Analyze(p.config.Baseline, r, pl)
	r.Vulnerable = string(verdict.Verdict)
	r.Flags = verdict.Flags

	// Apply ML prediction if available (Python ML server)
	if p.config.MLClient != nil && p.config.MLClient.Enabled {
		features := ml.ExtractFeatures(r, pl)
		normalizedFeatures := ml.NormalizeFeatures(features)

		prediction, err := p.config.MLClient.Predict(normalizedFeatures)
		if err == nil && prediction != nil {
			r.MLProbability = prediction.Confidence
			r.MLConfidence = prediction.Confidence
			r.MLLabel = prediction.Verdict

			if prediction.Verdict == "VULNERABLE" && prediction.Confidence >= p.config.MLClient.MinConfidence {
				r.Vulnerable = "VULNERABLE"
				r.Flags = append(r.Flags, "ml-confirmed-vulnerable")
			} else if prediction.Verdict == "SAFE" && prediction.Confidence >= 0.8 {
				r.Vulnerable = "SAFE"
				r.Flags = append(r.Flags, "ml-confirmed-safe")
			} else if prediction.Verdict == "REVIEW_NEEDED" {
				r.Flags = append(r.Flags, "ml-review-needed")
			}
		}
	}

	return r
}

func BaselineUpload(url, param string, headers, data map[string]string, allowList []string) (*oracle.Baseline, error) {
	if len(allowList) == 0 {
		return nil, fmt.Errorf("no allow-list provided; cannot establish baseline")
	}

	ext := allowList[0]
	filename := "baseline_test" + ext
	body := []byte("GoUpload baseline verification file")

	client := &http.Client{Timeout: 30 * time.Second}

	reqBody := &bytes.Buffer{}
	writer := multipart.NewWriter(reqBody)

	for key, val := range data {
		_ = writer.WriteField(key, val)
	}

	part, err := writer.CreateFormFile(param, filename)
	if err != nil {
		return nil, fmt.Errorf("baseline: failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, bytes.NewReader(body)); err != nil {
		return nil, fmt.Errorf("baseline: failed to write body: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("baseline: failed to close writer: %w", err)
	}

	req, err := http.NewRequest("POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("baseline: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("baseline: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("baseline: failed to read response: %w", err)
	}

	return &oracle.Baseline{
		StatusCode:     resp.StatusCode,
		ResponseLength: len(respBody),
		ContentType:    resp.Header.Get("Content-Type"),
		BodySnippet:    string(respBody),
		Filename:       filename,
	}, nil
}

// detectSanitization checks if server sanitized the uploaded file
func detectSanitization(originalFilename, body string, headers map[string]string) bool {
	// Check if original filename appears in response
	if strings.Contains(body, originalFilename) {
		return false // Not sanitized (filename preserved)
	}

	// Check for sanitization keywords
	sanitizationKeywords := []string{
		"sanitized", "renamed", "stripped", "cleaned",
		"neutralized", "filtered", "modified", "quarantined",
	}
	for _, keyword := range sanitizationKeywords {
		if strings.Contains(strings.ToLower(body), keyword) {
			return true
		}
	}

	// Check if Content-Disposition has different filename
	if cd, ok := headers["Content-Disposition"]; ok {
		if strings.Contains(cd, "filename=") {
			parts := strings.Split(cd, "filename=")
			if len(parts) > 1 {
				extractedName := strings.Trim(parts[1], `"'`)
				if extractedName != "" && extractedName != originalFilename {
					return true
				}
			}
		}
	}

	return false
}

// extractFinalFilename finds the final filename from response
func extractFinalFilename(body string) string {
	// Look for patterns like "Stored as: filename" or "saved as filename"
	patterns := []string{
		`"filename":"`,
		`"filename": "`,
		`"name":"`,
		`"name": "`,
		`filename=`,
		`Stored as: `,
		`saved as: `,
		`File: `,
		`Target file: `,
		`uploads/`,
	}

	for _, pattern := range patterns {
		if idx := strings.Index(body, pattern); idx != -1 {
			remaining := body[idx+len(pattern):]
			// Extract until quote, space, comma, newline, or HTML tag
			end := len(remaining)
			for i, ch := range remaining {
				if ch == '"' || ch == ',' || ch == ' ' || ch == '\n' || ch == '}' || ch == '<' || ch == '\'' {
					end = i
					break
				}
			}
			if end > 0 {
				filename := remaining[:end]
				// Clean up the filename
				filename = strings.Trim(filename, `"'<>`)
				return filename
			}
		}
	}
	return ""
}
