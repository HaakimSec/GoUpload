package payload

import (
	"strings"
)

// extractExtension extracts the file extension from a filename.
func extractExtension(filename string) string {
	// Handle URL-encoded null bytes
	cleaned := strings.ReplaceAll(filename, "%00", "")
	
	// Handle raw null bytes
	if idx := strings.IndexByte(cleaned, 0); idx != -1 {
		cleaned = cleaned[:idx]
	}
	
	cleaned = strings.TrimRight(cleaned, " ")
	cleaned = strings.TrimRight(cleaned, ".")
	
	dotIdx := strings.LastIndex(cleaned, ".")
	if dotIdx == -1 {
		return ""
	}
	
	return strings.TrimRight(cleaned[dotIdx:], " .")
}
