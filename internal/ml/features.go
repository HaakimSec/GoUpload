package ml

import (
	"math"
	"strings"

	"github.com/HaakimSec/GoUpload/internal/payload"
	"github.com/HaakimSec/GoUpload/internal/types"
)

// ExtractFeatures converts Result into 36 float features for Python model
func ExtractFeatures(result *types.Result, pl *payload.Payload) []float64 {
	body := strings.ToLower(result.ResponseBody)

	features := make([]float64, 36)

	// Features 0-5: File extension features
	features[0] = float64(len(pl.Extension))                          // Extension length
	features[1] = boolToFloat(strings.Contains(pl.Extension, ".php")) // Has PHP
	features[2] = boolToFloat(strings.Contains(pl.Extension, ".jsp")) // Has JSP
	features[3] = boolToFloat(strings.Contains(pl.Extension, ".asp")) // Has ASP
	features[4] = boolToFloat(strings.Count(pl.Filename, ".") > 1)    // Double extension
	features[5] = boolToFloat(strings.Contains(pl.Filename, ".."))    // Path traversal

	// Features 6-15: Response features
	features[6] = float64(result.StatusCode)                           // Status code
	features[7] = float64(result.RespLen)                              // Response length
	features[8] = boolToFloat(strings.Contains(result.RespCT, "json")) // JSON response
	features[9] = boolToFloat(strings.Contains(result.RespCT, "html")) // HTML response
	features[10] = boolToFloat(strings.Contains(body, "success"))      // Has success
	features[11] = boolToFloat(strings.Contains(body, "uploaded"))     // Has uploaded
	features[12] = boolToFloat(strings.Contains(body, "error"))        // Has error
	features[13] = boolToFloat(strings.Contains(body, "not allowed"))  // Not allowed
	features[14] = boolToFloat(strings.Contains(body, "uploads/"))     // Has uploads path
	features[15] = boolToFloat(strings.Contains(body, "files/"))       // Has files path

	// Features 16-25: Oracle flags
	features[16] = float64(len(result.Flags)) // Flag count
	features[17] = boolToFloat(containsFlag(result.Flags, "suspicious-ext-accepted"))
	features[18] = boolToFloat(containsFlag(result.Flags, "html-indicates-success"))
	features[19] = boolToFloat(containsFlag(result.Flags, "json-indicates-success"))
	features[20] = boolToFloat(containsFlag(result.Flags, "filepath-disclosed"))
	features[21] = boolToFloat(containsFlag(result.Flags, "filename-reflected-in-response"))
	features[22] = boolToFloat(containsFlag(result.Flags, "elfinder-upload-success"))
	features[23] = boolToFloat(containsFlag(result.Flags, "graphql-mutation-accepted"))
	features[24] = boolToFloat(containsFlag(result.Flags, "file-overwrite-confirmed"))
	features[25] = boolToFloat(containsFlag(result.Flags, "executable-accepted-in-race"))

	// Features 26-30: File content features
	features[26] = float64(len(pl.Body))                                         // Body length
	features[27] = boolToFloat(strings.Contains(string(pl.Body), "system("))     // Has system()
	features[28] = boolToFloat(strings.Contains(string(pl.Body), "exec("))       // Has exec()
	features[29] = boolToFloat(strings.Contains(string(pl.Body), "shell_exec(")) // Has shell_exec()
	features[30] = boolToFloat(strings.Contains(string(pl.Body), "eval("))       // Has eval()

	// Features 31-35: Metadata features
	features[31] = boolToFloat(result.Sanitized)           // Sanitized
	features[32] = boolToFloat(result.FinalFilename != "") // Has final filename
	features[33] = boolToFloat(result.RCEVerified)         // RCE verified
	features[34] = result.VerificationTime.Seconds()       // Verification time
	features[35] = boolToFloat(result.StatusCode == 200)   // Status is 200

	return features
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func containsFlag(flags []string, target string) bool {
	for _, f := range flags {
		if f == target {
			return true
		}
	}
	return false
}

// NormalizeFeatures scales numerical features for better model performance
func NormalizeFeatures(features []float64) []float64 {
	normalized := make([]float64, len(features))
	copy(normalized, features)

	// Normalize status code (0-600)
	if normalized[6] > 0 {
		normalized[6] = normalized[6] / 600.0
	}

	// Normalize response length (log scale)
	if normalized[7] > 0 {
		normalized[7] = math.Log1p(normalized[7]) / 10.0
	}

	// Normalize body length (log scale)
	if normalized[26] > 0 {
		normalized[26] = math.Log1p(normalized[26]) / 10.0
	}

	return normalized
}
