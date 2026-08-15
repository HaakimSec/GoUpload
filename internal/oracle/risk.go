package oracle

import (
	"sort"
	"strings"

	"github.com/HaakimSec/GoUpload/internal/payload"
	"github.com/HaakimSec/GoUpload/internal/types"
)

// RiskLevel represents the severity of a finding
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
	RiskInfo     RiskLevel = "INFO"
)

// RiskScore calculates risk level and confidence for a result
type RiskScore struct {
	Level      RiskLevel
	Confidence int
	Evidence   []string
}

// CalculateRiskScore determines risk and confidence from flags
func CalculateRiskScore(pl *payload.Payload, result *types.Result, flags []string) RiskScore {
	score := RiskScore{
		Level:      RiskInfo,
		Confidence: 0,
		Evidence:   []string{},
	}

	flagSet := make(map[string]bool)
	for _, f := range flags {
		flagSet[f] = true
	}

	// Confidence scoring
	if flagSet["xxe-file-accepted"] {
		score.Confidence += 20
		score.Evidence = append(score.Evidence, "Upload accepted")
	}
	if flagSet["filename-reflected-in-response"] {
		score.Confidence += 20
		score.Evidence = append(score.Evidence, "Filename reflected")
	}
	if flagSet["path-structure-in-response"] {
		score.Confidence += 20
		score.Evidence = append(score.Evidence, "Path reflected")
	}
	if flagSet["json-indicates-success"] || flagSet["html-indicates-success"] {
		score.Confidence += 20
		score.Evidence = append(score.Evidence, "Success indicators")
	}
	if flagSet["xxe-file-disclosure"] {
		score.Confidence += 20
		score.Evidence = append(score.Evidence, "XXE file disclosure")
	}
	if flagSet["suspicious-ext-accepted"] {
		score.Confidence += 10
		score.Evidence = append(score.Evidence, "Suspicious extension")
	}
	if flagSet["traversal-filename-accepted"] {
		score.Confidence += 15
		score.Evidence = append(score.Evidence, "Traversal accepted")
	}

	if score.Confidence > 100 {
		score.Confidence = 100
	}

	// Risk level determination for XXE
	if pl.TestType == payload.TestTypeXXE {
		lowerFilename := strings.ToLower(pl.Filename)

		switch {
		case strings.Contains(lowerFilename, "/etc/passwd"),
			strings.Contains(lowerFilename, "win.ini"),
			strings.Contains(lowerFilename, "aws"),
			strings.Contains(lowerFilename, "169.254"):
			score.Level = RiskCritical
		case strings.Contains(lowerFilename, "localhost"),
			strings.Contains(lowerFilename, "parameter"),
			strings.Contains(lowerFilename, "out-of-band"):
			score.Level = RiskHigh
		case strings.Contains(lowerFilename, "docx"),
			strings.Contains(lowerFilename, "xlsx"),
			strings.Contains(lowerFilename, "jpeg"),
			strings.Contains(lowerFilename, "xmp"):
			score.Level = RiskMedium
		default:
			score.Level = RiskLow
		}
	}

	// Risk level for other module types
	switch {
	case flagSet["file-overwrite-confirmed"]:
		score.Level = RiskCritical
	case flagSet["graphql-mutation-accepted"] && hasSuspiciousExt(pl):
		score.Level = RiskHigh
	case flagSet["traversal-filename-accepted"] && hasSuspiciousExt(pl):
		score.Level = RiskHigh
	case flagSet["spoofed-content-accepted"]:
		score.Level = RiskMedium
	case flagSet["xxe-file-accepted"]:
		if score.Level == RiskInfo {
			score.Level = RiskLow
		}
	}

	return score
}

// SortResultsByRisk sorts results by risk level
func SortResultsByRisk(results []*types.Result) {
	riskOrder := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
		"INFO":     4,
	}

	sort.Slice(results, func(i, j int) bool {
		// Get risk for both
		ri := getRiskFromFlags(results[i].Flags, results[i])
		rj := getRiskFromFlags(results[j].Flags, results[j])
		return riskOrder[ri] < riskOrder[rj]
	})
}

// getRiskFromFlags extracts risk level from flags
func getRiskFromFlags(flags []string, r *types.Result) string {
	// Check critical indicators
	for _, f := range flags {
		if f == "file-overwrite-confirmed" || f == "xxe-file-disclosure" {
			return "CRITICAL"
		}
	}
	// Check high indicators
	for _, f := range flags {
		if f == "graphql-mutation-accepted" || f == "traversal-filename-accepted" {
			return "HIGH"
		}
	}
	// Check medium
	for _, f := range flags {
		if f == "spoofed-content-accepted" || f == "xxe-file-accepted" {
			return "MEDIUM"
		}
	}
	return "LOW"
}
