package types

import (
	"time"

	"github.com/HaakimSec/GoUpload/internal/payload"
)

type Result struct {
	TestType         payload.TestType
	Technique        string
	Filename         string
	StatusCode       int
	RespLen          int
	RespCT           string
	BodySnippet      string
	ResponseBody     string
	ResponseHeaders  map[string]string
	FinalFilename    string
	Sanitized        bool
	Duration         time.Duration
	Err              error
	Vulnerable       string
	Flags            []string
	RCEVerified      bool          `json:"rce_verified,omitempty"`
	RCEProof         string        `json:"rce_proof,omitempty"`
	FileURL          string        `json:"file_url,omitempty"`
	RCECommand       string        `json:"rce_command,omitempty"`
	VerificationTime time.Duration `json:"verification_time,omitempty"`
	MLProbability    float64       `json:"ml_probability,omitempty"`
	MLConfidence     float64       `json:"ml_confidence,omitempty"`
	MLLabel          string        `json:"ml_label,omitempty"`
}
