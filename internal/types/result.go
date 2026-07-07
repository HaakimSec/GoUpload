package types

import (
	"time"

	"goupload/internal/payload"
)

// Result holds the outcome of a single upload test.
// Defined in a shared package to avoid import cycles between worker and oracle.
type Result struct {
	TestType    payload.TestType
	Technique   string
	Filename    string
	StatusCode  int
	RespLen     int
	RespCT      string
	BodySnippet string
	Duration    time.Duration
	Err         error
	Vulnerable  string // Will be set to oracle.Verdict value
	Flags       []string
}
