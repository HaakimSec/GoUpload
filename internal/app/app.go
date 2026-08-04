package app

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
	"github.com/HaakimSec/GoUpload/internal/template"
	"github.com/HaakimSec/GoUpload/internal/types"
	"github.com/HaakimSec/GoUpload/internal/validator"
	"github.com/HaakimSec/GoUpload/internal/worker"
)

// App represents the main GoUpload application
type App struct {
	Config    *config.Config
	Printer   *output.Printer
	TechStack string
	Baseline  *oracle.Baseline
}

// New creates a new App instance
func New(cfg *config.Config) *App {
	return &App{
		Config:    cfg,
		TechStack: cfg.TechStack,
	}
}

// Run executes the main application logic
func (a *App) Run() error {
	// Validate target
	if err := a.validateTarget(); err != nil {
		return err
	}

	// Check only mode
	if a.Config.CheckOnly {
		a.printCheckSuccess()
		return nil
	}

	// Fingerprint target
	a.fingerprint()

	// List templates or modules
	if a.Config.ListTemplates {
		template.ListAvailableTemplates("templates/")
		return nil
	}
	if a.Config.ListModules {
		fmt.Println(payload.ListModules())
		return nil
	}

	// Load templates
	templatePayloads := a.loadTemplates()

	// Module selection
	a.selectModules()

	// Generate payloads
	allPayloads := a.generatePayloads(templatePayloads)

	// Initialize printer
	a.Printer = output.NewPrinter(len(allPayloads))
	a.Printer.PrintBanner(a.Config.URL, a.Config.Param, a.Config.Concurrency, len(allPayloads))

	a.printTechStackInfo(len(allPayloads))

	// Establish baseline
	a.establishBaseline()

	// Execute tests
	allResults := a.executeTests(allPayloads)

	a.Printer.PrintProgressNewline()

	// Print results
	a.printResults(allResults)

	// Compute summary
	stats := oracle.ComputeSummary(allResults)
	a.Printer.PrintSummary(stats)

	// JSON output
	a.handleJSONOutput(allResults, stats)

	// Show tips
	a.printTips(stats)

	// Exit code
	return a.getExitError(stats)
}

// validateTarget checks if the target is reachable
func (a *App) validateTarget() error {
	if a.Config.NoValidate {
		return nil
	}

	fmt.Fprintf(os.Stderr, "  🔍 Validating target...\n")

	if err := validator.ValidateTarget(a.Config.URL, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "\n  ❌ Target validation failed:\n")
		fmt.Fprintf(os.Stderr, "  %s\n\n", err)
		fmt.Fprintf(os.Stderr, "  💡 Tips:\n")
		fmt.Fprintf(os.Stderr, "    - Make sure the URL is correct and the server is running\n")
		fmt.Fprintf(os.Stderr, "    - Try: GoUpload --check -u %s\n", a.Config.URL)
		fmt.Fprintf(os.Stderr, "    - Use --no-validate to skip this check\n\n")
		return fmt.Errorf("target validation failed")
	}

	color.New(color.FgGreen).Fprintf(os.Stderr, "  ✅ Target is reachable\n")

	warnings := validator.GetWarnings(a.Config.URL)
	for _, w := range warnings {
		color.New(color.FgYellow).Fprintf(os.Stderr, "  ⚠️  %s\n", w)
	}

	if len(a.Config.AllowList) > 0 {
		fmt.Fprintf(os.Stderr, "  📤 Testing upload endpoint...\n")
		if err := validator.ValidateUploadEndpoint(a.Config.URL, a.Config.Param, 10*time.Second); err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  ⚠️  Warning: %s\n", err)
			color.New(color.FgYellow).Fprintf(os.Stderr, "  Continuing anyway, but results may be inaccurate.\n")
		} else {
			color.New(color.FgGreen).Fprintf(os.Stderr, "  ✅ Upload endpoint is functional\n")
		}
	}

	fmt.Fprintln(os.Stderr)
	return nil
}

// printCheckSuccess shows success message for --check mode
func (a *App) printCheckSuccess() {
	fmt.Fprintln(os.Stderr)
	color.New(color.FgGreen, color.Bold).Fprintln(os.Stderr, "  ✅ Target validation passed!")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  Run without --check to start the full scan:\n")
	fmt.Fprintf(os.Stderr, "    GoUpload -u %s -p %s --allow-list .txt,.jpg\n\n", a.Config.URL, a.Config.Param)
}

// fingerprint detects the target tech stack
func (a *App) fingerprint() {
	if a.Config.AutoDetect || a.TechStack == "auto" {
		fmt.Fprintf(os.Stderr, "  🔍 Fingerprinting target...\n")
		ts, err := fingerprint.Fingerprint(a.Config.URL, a.Config.Headers)
		if err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  Warning: Fingerprint failed: %s\n", err)
			color.New(color.FgYellow).Fprintf(os.Stderr, "  Falling back to testing all payloads.\n\n")
			a.TechStack = "all"
		} else {
			a.TechStack = mapLanguageToTechStack(ts.Language)
			color.New(color.FgGreen).Fprintf(os.Stderr, "  ✅ Detected %s with %d%% confidence\n\n", a.TechStack, ts.Confidence)
		}
	}
}

// loadTemplates loads template payloads if specified
func (a *App) loadTemplates() []*payload.Payload {
	var templatePayloads []*payload.Payload

	if a.Config.Template != "" {
		tmpl, err := template.LoadTemplate(a.Config.Template)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading template: %s\n", err)
			os.Exit(1)
		}
		templatePayloads = tmpl.ToPayloads()
		fmt.Printf("  📄 Loaded template: %s (%d payloads)\n", tmpl.Name, len(templatePayloads))
	}

	if a.Config.TemplateDir != "" {
		templates, err := template.LoadTemplates(a.Config.TemplateDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading templates: %s\n", err)
		} else {
			for _, tmpl := range templates {
				templatePayloads = append(templatePayloads, tmpl.ToPayloads()...)
				fmt.Printf("  📄 Loaded template: %s\n", tmpl.Name)
			}
		}
	}

	return templatePayloads
}

// selectModules enables only specified modules
func (a *App) selectModules() {
	if len(a.Config.Modules) > 0 {
		payload.EnableModules(a.Config.Modules)
		fmt.Fprintf(os.Stderr, "  🎯 Running modules: %s\n", strings.Join(a.Config.Modules, ", "))
	}
}

// generatePayloads creates payloads from templates or standard modules
func (a *App) generatePayloads(templatePayloads []*payload.Payload) []*payload.Payload {
	if len(templatePayloads) > 0 {
		return templatePayloads
	}
	return payload.AllPayloads(a.TechStack,
		a.Config.GraphQLMutation,
		a.Config.GraphQLVariable,
		a.Config.ModulePath,
		a.Config.ModuleOverwrite)
}

// printTechStackInfo shows targeting information
func (a *App) printTechStackInfo(payloadCount int) {
	if a.TechStack != "all" {
		color.New(color.FgCyan).Fprintf(os.Stderr, "  🎯 Targeting: %s\n", strings.ToUpper(a.TechStack))
		color.New(color.FgCyan).Fprintf(os.Stderr, "  🧪 Payloads: %d (filtered for %s stack)\n", payloadCount, a.TechStack)
		output.PrintSeparatorFunc()
	}
}

// establishBaseline uploads a benign file for comparison
func (a *App) establishBaseline() {
	if len(a.Config.AllowList) > 0 {
		fmt.Fprintf(os.Stderr, "  Establishing baseline with extension %s...\n", a.Config.AllowList[0])
		baseline, err := worker.BaselineUpload(a.Config.URL, a.Config.Param, a.Config.Headers, a.Config.Data, a.Config.AllowList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: baseline upload failed: %s\n", err)
			fmt.Fprintf(os.Stderr, "  Continuing without baseline.\n\n")
		} else {
			a.Baseline = baseline
			a.Printer.PrintBaseline(baseline)
		}
	} else {
		color.New(color.FgYellow).Fprintf(os.Stderr, "  Warning: No --allow-list provided.\n")
		color.New(color.FgYellow).Fprintln(os.Stderr, "  Status-based heuristics only — use --allow-list for better accuracy.")
		output.PrintSeparatorFunc()
	}
}

// executeTests runs all payloads through the worker pool
func (a *App) executeTests(allPayloads []*payload.Payload) []*types.Result {
	modules := groupByModule(allPayloads)
	allResults := make([]*types.Result, 0, len(allPayloads))

	moduleOrder := []payload.TestType{
		payload.TestTypeTemplate,
		payload.TestTypeExtensionEvasion,
		payload.TestTypeContentTypeSpoof,
		payload.TestTypeMagicByteSpoof,
		payload.TestTypeFilenameObfuscation,
		payload.TestTypePathTraversal,
		payload.TestTypeServerConfig,
		payload.TestTypeUnicodeEncoding,
		payload.TestTypeGraphQL,
	}

	moduleNames := map[payload.TestType]string{
		payload.TestTypeTemplate:            "TEMPLATE PAYLOADS",
		payload.TestTypeExtensionEvasion:    "MODULE A: Extension Evasion Matrix",
		payload.TestTypeContentTypeSpoof:    "MODULE B: Content-Type Spoofing",
		payload.TestTypeMagicByteSpoof:      "MODULE B: Magic Byte Injection",
		payload.TestTypeFilenameObfuscation: "MODULE C: Filename Obfuscation & Sanitization Faults",
		payload.TestTypePathTraversal:       "MODULE D: Path Traversal Sequences",
		payload.TestTypeServerConfig:        "MODULE F: Server Configuration Overrides",
		payload.TestTypeUnicodeEncoding:     "MODULE G: Unicode & Encoding Vulnerabilities",
		payload.TestTypeGraphQL:             "MODULE H: GraphQL File Uploads",
	}

	for _, modType := range moduleOrder {
		modPayloads, ok := modules[modType]
		if !ok || len(modPayloads) == 0 {
			continue
		}

		a.Printer.PrintModuleHeader(moduleNames[modType])

		pool := worker.NewPool(&worker.PoolConfig{
			URL:         a.Config.URL,
			Param:       a.Config.Param,
			Headers:     a.Config.Headers,
			Data:        a.Config.Data,
			Concurrency: a.Config.Concurrency,
			Baseline:    a.Baseline,
		})
		pool.SetResultHandler(output.ResultPrinter(a.Printer))

		results := pool.Execute(modPayloads)
		allResults = append(allResults, results...)
	}

	return allResults
}

// printResults displays flagged findings
func (a *App) printResults(allResults []*types.Result) {
	flagged := collectFlagged(allResults)
	if len(flagged) > 0 {
		color.New(color.FgRed, color.Bold).Fprintf(os.Stderr, "\n  ⚠  FLAGGED RESULTS (%d items)\n", len(flagged))
		output.PrintSeparatorFunc()
		fmt.Println()

		for i, r := range flagged {
			a.Printer.PrintFinalResult(r, i+1)
		}

		fmt.Fprintln(color.Output, "  └─────────────────────────────────────────────────────────────────")
	}
}

// handleJSONOutput writes JSON report if requested
func (a *App) handleJSONOutput(allResults []*types.Result, stats oracle.SummaryStats) {
	if a.Config.OutputFormat != "json" {
		return
	}

	jsonPrinter := output.NewJSONPrinter(a.Printer, a.Config.URL, a.Config.Param, a.Config.Concurrency)

	if a.TechStack != "all" {
		jsonPrinter.SetTechStack(a.TechStack)
	}
	if a.Config.Template != "" {
		jsonPrinter.SetTemplate(a.Config.Template)
	}
	jsonPrinter.SetBaselineUsed(len(a.Config.AllowList) > 0)

	for i, r := range allResults {
		if r.Vulnerable != string(oracle.VerdictSafe) && r.Vulnerable != "" {
			jsonPrinter.AddFinding(r, "GENERAL", i+1)
		}
	}

	jsonPrinter.SetSummary(stats)

	if a.Config.OutputFile != "" {
		if err := jsonPrinter.WriteToFile(a.Config.OutputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %s\n", err)
		}
	} else {
		jsonPrinter.PrintToStdout()
	}
}

// printTips shows helpful tips
func (a *App) printTips(stats oracle.SummaryStats) {
	if a.TechStack == "all" && (stats.Vulnerable > 0 || stats.Suspect > 0) {
		fmt.Fprintln(color.Output)
		color.New(color.FgCyan).Fprintln(os.Stderr, "  💡 Tip: Use --auto-detect to fingerprint the target and reduce payloads.")
		color.New(color.FgCyan).Fprintf(os.Stderr, "     Example: GoUpload -u %s -p %s --auto-detect\n", a.Config.URL, a.Config.Param)
	}
}

// getExitError returns appropriate exit code
func (a *App) getExitError(stats oracle.SummaryStats) error {
	if stats.Vulnerable > 0 {
		return fmt.Errorf("vulnerabilities found")
	}
	if stats.Suspect > 0 {
		return fmt.Errorf("suspect findings")
	}
	return nil
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
