package ml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MLClient connects to Python ML server
type MLClient struct {
	BaseURL       string
	HTTPClient    *http.Client
	Enabled       bool
	MinConfidence float64
}

// PredictionRequest matches Python API
type PredictionRequest struct {
	Features []float64 `json:"features"`
}

// PredictionResponse matches Python API response
type PredictionResponse struct {
	Prediction  int       `json:"prediction"`
	Probability []float64 `json:"probability"`
	Verdict     string    `json:"verdict"`
	Confidence  float64   `json:"confidence"`
}

// NewMLClient creates a new ML client
func NewMLClient(baseURL string, enabled bool) *MLClient {
	return &MLClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		Enabled:       enabled,
		MinConfidence: 0.65,
	}
}

// Predict sends features to Python ML server
func (c *MLClient) Predict(features []float64) (*PredictionResponse, error) {
	if !c.Enabled || c.BaseURL == "" {
		return nil, fmt.Errorf("ML client disabled")
	}

	reqBody := PredictionRequest{Features: features}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal features: %w", err)
	}

	url := fmt.Sprintf("%s/predict", c.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ML server request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ML server returned status %d", resp.StatusCode)
	}

	var prediction PredictionResponse
	if err := json.NewDecoder(resp.Body).Decode(&prediction); err != nil {
		return nil, fmt.Errorf("failed to decode prediction: %w", err)
	}

	return &prediction, nil
}

// HealthCheck verifies ML server is running
func (c *MLClient) HealthCheck() bool {
	if !c.Enabled || c.BaseURL == "" {
		return false
	}

	url := fmt.Sprintf("%s/health", c.BaseURL)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
