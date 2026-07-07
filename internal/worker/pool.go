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

	"goupload/internal/oracle"
	"goupload/internal/payload"
	"goupload/internal/types"
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
			r.Duration = time.Since(start)
			return r
		}
	}

	// If the payload specifies a Content-Type override, use CreatePart
	// to manually set Content-Type for the file part
	if pl.ContentType != "" {
		h := make(map[string][]string)
		h["Content-Disposition"] = []string{
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`, p.config.Param, pl.Filename),
		}
		h["Content-Type"] = []string{pl.ContentType}

		part, err := writer.CreatePart(h)
		if err != nil {
			r.Err = fmt.Errorf("failed to create part with override Content-Type: %w", err)
			r.Duration = time.Since(start)
			return r
		}
		if _, err := io.Copy(part, bytes.NewReader(pl.Body)); err != nil {
			r.Err = fmt.Errorf("failed to write payload body: %w", err)
			r.Duration = time.Since(start)
			return r
		}
	} else {
		// Standard file part (no Content-Type override)
		part, err := writer.CreateFormFile(p.config.Param, pl.Filename)
		if err != nil {
			r.Err = fmt.Errorf("failed to create form file: %w", err)
			r.Duration = time.Since(start)
			return r
		}
		if _, err := io.Copy(part, bytes.NewReader(pl.Body)); err != nil {
			r.Err = fmt.Errorf("failed to write payload body: %w", err)
			r.Duration = time.Since(start)
			return r
		}
	}

	// Close the writer to finalize the multipart boundary
	if err := writer.Close(); err != nil {
		r.Err = fmt.Errorf("failed to close multipart writer: %w", err)
		r.Duration = time.Since(start)
		return r
	}

	// Build the HTTP request
	req, err := http.NewRequest("POST", p.config.URL, reqBody)
	if err != nil {
		r.Err = fmt.Errorf("failed to create request: %w", err)
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
		} else if strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe") {
			r.Err = fmt.Errorf("connection error: %w", err)
		} else {
			r.Err = fmt.Errorf("request failed: %w", err)
		}
		return r
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		r.Err = fmt.Errorf("failed to read response: %w", err)
		return r
	}

	r.StatusCode = resp.StatusCode
	r.RespLen = len(bodyBytes)
	r.RespCT = resp.Header.Get("Content-Type")

	// Capture a snippet of the body for analysis (first 500 chars)
	if len(bodyBytes) > 500 {
		r.BodySnippet = string(bodyBytes[:500])
	} else {
		r.BodySnippet = string(bodyBytes)
	}

	// Run oracle analysis
	if p.config.Baseline != nil {
		verdict := oracle.Analyze(p.config.Baseline, r, pl)
		r.Vulnerable = string(verdict.Verdict)
		r.Flags = verdict.Flags
	}

	return r
}

// BaselineUpload performs a baseline upload using an allowed extension.
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
