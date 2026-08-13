package output

import (
	"fmt"
	"strings"

	"github.com/HaakimSec/GoUpload/internal/discovery"
	"github.com/fatih/color"
)

// PrintDiscoveryResults prints discovered upload forms
func PrintDiscoveryResults(result *discovery.DiscoveryResult) {
	bold := color.New(color.FgCyan, color.Bold)
	accent := color.New(color.FgYellow)
	info := color.New(color.FgWhite)
	dim := color.New(color.FgHiBlack)

	if result.Error != "" {
		color.New(color.FgRed).Fprintf(color.Output, "\n  ❌ Discovery error: %s\n", result.Error)
		return
	}

	if len(result.Targets) == 0 {
		color.New(color.FgYellow).Fprintln(color.Output, "\n  ⚠️  No upload forms discovered on this page.")
		return
	}

	bold.Fprintf(color.Output, "\n  🔍 Discovered %d upload surface(s) on %s\n\n", len(result.Targets), result.PageURL)
	dim.Println("  " + strings.Repeat("─", 68))

	for i, target := range result.Targets {
		accent.Fprintf(color.Output, "  [%d] Upload Form\n", i+1)
		info.Fprintf(color.Output, "      Method:       %s\n", target.Method)
		info.Fprintf(color.Output, "      Action:       %s\n", target.ActionURL)
		info.Fprintf(color.Output, "      Encoding:     %s\n", target.Enctype)

		for _, ff := range target.FileFields {
			info.Fprintf(color.Output, "      File field:   %s\n", ff.Name)
			if len(ff.Accept) > 0 {
				info.Fprintf(color.Output, "      Accept:       %s\n", strings.Join(ff.Accept, ", "))
			}
			if ff.Multiple {
				info.Fprintf(color.Output, "      Multiple:     true\n")
			}
		}

		if len(target.FormFields) > 0 {
			info.Fprintln(color.Output, "      Form fields:")
			for _, ff := range target.FormFields {
				if ff.Type == "hidden" {
					info.Fprintf(color.Output, "        [hidden] %s = %s\n", ff.Name, maskValue(ff.Name, ff.Value))
				} else {
					info.Fprintf(color.Output, "        [%s] %s = %s\n", ff.Type, ff.Name, ff.Value)
				}
			}
		}

		dim.Println("  " + strings.Repeat("─", 68))
	}

	fmt.Println()
	bold.Fprintln(color.Output, "  💡 Run GoUpload with --discover-auto to automatically test discovered forms.")
	fmt.Fprintf(color.Output, "     Example: ./GoUpload -u %s --discover-auto\n\n", result.PageURL)
}

// maskValue masks potentially sensitive values
func maskValue(name, value string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "token") ||
		strings.Contains(lower, "auth") || strings.Contains(lower, "key") {
		if len(value) > 8 {
			return value[:4] + "..." + value[len(value)-4:]
		}
		return "***"
	}
	return value
}
