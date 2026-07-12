package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/HaakimSec/GoUpload/internal/config"
	"github.com/HaakimSec/GoUpload/internal/fingerprint"
	"github.com/HaakimSec/GoUpload/internal/oracle"
	"github.com/HaakimSec/GoUpload/internal/output"
	"github.com/HaakimSec/GoUpload/internal/payload"
	"github.com/HaakimSec/GoUpload/internal/types"
	"github.com/HaakimSec/GoUpload/internal/validator"
	"github.com/HaakimSec/GoUpload/internal/worker"
)

func main() {
	// ── Parse CLI configuration ──────────────────────────────────────────
	cfg, err := config.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  Error: %s\n\n", err)
		os.Exit(1)
	}

	// ── VALIDATE TARGET BEFORE RUNNING ───────────────────────────────────
	if !cfg.NoValidate {
		fmt.Fprintf(os.Stderr, "  🔍 Validating target...\n")

		if err := validator.ValidateTarget(cfg.URL, 10*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "\n  ❌ Target validation failed:\n")
			fmt.Fprintf(os.Stderr, "  %s\n\n", err)
			fmt.Fprintf(os.Stderr, "  💡 Tips:\n")
			fmt.Fprintf(os.Stderr, "    - Make sure the URL is correct and the server is running\n")
			fmt.Fprintf(os.Stderr, "    - Try: GoUpload --check -u %s\n", cfg.URL)
			fmt.Fprintf(os.Stderr, "    - Use --no-validate to skip this check\n\n")
			os.Exit(1)
		}

		color.New(color.FgGreen).Fprintf(os.Stderr, "  ✅ Target is reachable\n")

		// Show warnings
		warnings := validator.GetWarnings(cfg.URL)
		for _, w := range warnings {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  ⚠️  %s\n", w)
		}

		// Test upload endpoint if allow-list provided
		if len(cfg.AllowList) > 0 {
			fmt.Fprintf(os.Stderr, "  📤 Testing upload endpoint...\n")
			if err := validator.ValidateUploadEndpoint(cfg.URL, cfg.Param, 10*time.Second); err != nil {
				color.New(color.FgYellow).Fprintf(os.Stderr, "  ⚠️  Warning: %s\n", err)
				color.New(color.FgYellow).Fprintf(os.Stderr, "  Continuing anyway, but results may be inaccurate.\n")
			} else {
				color.New(color.FgGreen).Fprintf(os.Stderr, "  ✅ Upload endpoint is functional\n")
			}
		}

		fmt.Fprintln(os.Stderr)
	}

	// ── CHECK ONLY MODE ──────────────────────────────────────────────────
	if cfg.CheckOnly {
		fmt.Fprintln(os.Stderr)
		color.New(color.FgGreen, color.Bold).Fprintln(os.Stderr, "  ✅ Target validation passed - endpoint is reachable and ready for testing!")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  Run without --check to start the full scan:\n")
		fmt.Fprintf(os.Stderr, "    GoUpload -u %s -p %s --allow-list .txt,.jpg\n\n", cfg.URL, cfg.Param)
		os.Exit(0)
	}

	// ── FINGERPRINT TARGET (AUTO-DETECT TECH STACK) ─────────────────────
	techStack := cfg.TechStack

	if cfg.AutoDetect || techStack == "auto" {
		fmt.Fprintf(os.Stderr, "  🔍 Fingerprinting target...\n")
		ts, err := fingerprint.Fingerprint(cfg.URL, cfg.Headers)
		if err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  Warning: Fingerprint failed: %s\n", err)
			color.New(color.FgYellow).Fprintf(os.Stderr, "  Falling back to testing all payloads.\n\n")
			techStack = "all"
		} else {
			techStack = mapLanguageToTechStack(ts.Language)
			color.New(color.FgGreen).Fprintf(os.Stderr, "  ✅ Detected %s with %d%% confidence\n\n", techStack, ts.Confidence)
		}
	}

	// ── Generate filtered payloads based on tech stack ───────────────────
	allPayloads := payload.AllPayloads(techStack)
	printer := output.NewPrinter(len(allPayloads))
	printer.PrintBanner(cfg.URL, cfg.Param, cfg.Concurrency, len(allPayloads))

	// Show tech stack targeting info
	if techStack != "all" {
		color.New(color.FgCyan).Fprintf(os.Stderr, "  🎯 Targeting: %s\n", strings.ToUpper(techStack))
		color.New(color.FgCyan).Fprintf(os.Stderr, "  🧪 Payloads: %d (filtered for %s stack)\n", len(allPayloads), techStack)
		output.PrintSeparatorFunc()
	}

	// ── Establish baseline (if allow-list provided) ──────────────────────
	var baseline *oracle.Baseline
	if len(cfg.AllowList) > 0 {
		fmt.Fprintf(os.Stderr, "  Establishing baseline with extension %s...\n", cfg.AllowList[0])
		baseline, err = worker.BaselineUpload(cfg.URL, cfg.Param, cfg.Headers, cfg.Data, cfg.AllowList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: baseline upload failed: %s\n", err)
			fmt.Fprintf(os.Stderr, "  Continuing without baseline — results will lack comparative analysis.\n\n")
			baseline = nil
		} else {
			printer.PrintBaseline(baseline)
		}
	} else {
		color.New(color.FgYellow).Fprintf(os.Stderr, "  Warning: No --allow-list provided. Running without baseline comparison.\n")
		color.New(color.FgYellow).Fprintln(os.Stderr, "  Status-based heuristics only — use --allow-list for better accuracy.")
		output.PrintSeparatorFunc()
	}

	// ── Group payloads by test module for organized output ───────────────
	modules := groupByModule(allPayloads)

	// ── Execute tests module by module ───────────────────────────────────
	allResults := make([]*types.Result, 0, len(allPayloads))

	moduleOrder := []payload.TestType{
		payload.TestTypeExtensionEvasion,
		payload.TestTypeContentTypeSpoof,
		payload.TestTypeMagicByteSpoof,
		payload.TestTypeFilenameObfuscation,
		payload.TestTypePathTraversal,
	}

	moduleNames := map[payload.TestType]string{
		payload.TestTypeExtensionEvasion:    "MODULE A: Extension Evasion Matrix",
		payload.TestTypeContentTypeSpoof:    "MODULE B: Content-Type Spoofing",
		payload.TestTypeMagicByteSpoof:      "MODULE B: Magic Byte Injection",
		payload.TestTypeFilenameObfuscation: "MODULE C: Filename Obfuscation & Sanitization Faults",
		payload.TestTypePathTraversal:       "MODULE D: Path Traversal Sequences",
	}

	for _, modType := range moduleOrder {
		modPayloads, ok := modules[modType]
		if !ok || len(modPayloads) == 0 {
			continue
		}

		printer.PrintModuleHeader(moduleNames[modType])

		pool := worker.NewPool(&worker.PoolConfig{
			URL:         cfg.URL,
			Param:       cfg.Param,
			Headers:     cfg.Headers,
			Data:        cfg.Data,
			Concurrency: cfg.Concurrency,
			Baseline:    baseline,
		})
		pool.SetResultHandler(output.ResultPrinter(printer))

		results := pool.Execute(modPayloads)
		allResults = append(allResults, results...)
	}

	printer.PrintProgressNewline()

	// ── Print detailed results for flagged items ─────────────────────────
	flagged := collectFlagged(allResults)
	if len(flagged) > 0 {
		color.New(color.FgRed, color.Bold).Fprintf(os.Stderr, "\n  ⚠  FLAGGED RESULTS (%d items)\n", len(flagged))
		output.PrintSeparatorFunc()
		fmt.Println()

		for i, r := range flagged {
			printer.PrintFinalResult(r, i+1)
		}

		fmt.Fprintln(color.Output, "  └─────────────────────────────────────────────────────────────────")
	}

	// ── Compute and display summary ──────────────────────────────────────
	stats := oracle.ComputeSummary(allResults)
	printer.PrintSummary(stats)

	// ── Show tech stack recommendation if using all payloads ─────────────
	if techStack == "all" && (stats.Vulnerable > 0 || stats.Suspect > 0) {
		fmt.Fprintln(color.Output)
		color.New(color.FgCyan).Fprintln(os.Stderr, "  💡 Tip: Use --auto-detect to fingerprint the target and reduce payloads.")
		color.New(color.FgCyan).Fprintf(os.Stderr, "     Example: GoUpload -u %s -p %s --auto-detect\n", cfg.URL, cfg.Param)
	}

	// ── Exit code based on findings ──────────────────────────────────────
	if stats.Vulnerable > 0 {
		os.Exit(2)
	} else if stats.Suspect > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// groupByModule organizes payloads by their test type
func groupByModule(payloads []*payload.Payload) map[payload.TestType][]*payload.Payload {
	groups := make(map[payload.TestType][]*payload.Payload)
	for _, p := range payloads {
		groups[p.TestType] = append(groups[p.TestType], p)
	}
	return groups
}

// collectFlagged returns results that are not marked as safe
func collectFlagged(results []*types.Result) []*types.Result {
	var flagged []*types.Result
	for _, r := range results {
		if r.Vulnerable != string(oracle.VerdictSafe) && r.Vulnerable != "" {
			flagged = append(flagged, r)
		}
	}
	sort.Slice(flagged, func(i, j int) bool {
		priority := map[string]int{
			string(oracle.VerdictVulnerable): 0,
			string(oracle.VerdictSuspect):    1,
			string(oracle.VerdictError):      2,
			string(oracle.VerdictUnknown):    3,
		}
		pi, pj := priority[flagged[i].Vulnerable], priority[flagged[j].Vulnerable]
		if pi != pj {
			return pi < pj
		}
		return strings.Compare(flagged[i].Technique, flagged[j].Technique) < 0
	})
	return flagged
}

// mapLanguageToTechStack converts fingerprint language to tech stack identifier
func mapLanguageToTechStack(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "php":
		return "php"
	case "asp.net", "asp":
		return "asp.net"
	case "java", "jsp", "tomcat":
		return "java"
	case "node.js", "nodejs", "express":
		return "nodejs"
	case "python", "django", "flask":
		return "python"
	case "ruby", "rails":
		return "ruby"
	default:
		return "all"
	}
}
