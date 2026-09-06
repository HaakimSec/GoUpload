// internal/app/app.go
package app

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/HaakimSec/GoUpload/internal/config"
	"github.com/HaakimSec/GoUpload/internal/discovery"
	"github.com/HaakimSec/GoUpload/internal/fingerprint"
	"github.com/HaakimSec/GoUpload/internal/ml"
	"github.com/HaakimSec/GoUpload/internal/oracle"
	"github.com/HaakimSec/GoUpload/internal/output"
	"github.com/HaakimSec/GoUpload/internal/payload"
	"github.com/HaakimSec/GoUpload/internal/template"
	"github.com/HaakimSec/GoUpload/internal/types"
	"github.com/HaakimSec/GoUpload/internal/validator"
	"github.com/HaakimSec/GoUpload/internal/verifier"
	"github.com/HaakimSec/GoUpload/internal/worker"
)

// App represents the main GoUpload application
type App struct {
	Config           *config.Config
	Printer          *output.Printer
	TechStack        string
	Baseline         *oracle.Baseline
	Verifier         *verifier.RCEVerifier
	MLClient         *ml.MLClient
	TemplateRegistry *template.TemplateRegistry // NEW: Template registry
	TemplateExecutor *template.TemplateExecutor // NEW: Template executor
}

// New creates a new App instance
func New(cfg *config.Config) *App {
	app := &App{
		Config:    cfg,
		TechStack: cfg.TechStack,
	}

	// Initialize shared HTTP client
	httpClient := app.getHTTPClient()

	// Initialize RCE verifier if enabled
	if cfg.VerifyRCE {
		app.Verifier = verifier.NewRCEVerifier(httpClient, 15*time.Second)
	}

	// Initialize template registry and executor
	app.TemplateRegistry = template.NewTemplateRegistry()
	app.TemplateExecutor = template.NewTemplateExecutor(httpClient, app.TemplateRegistry)

	// Initialize ML client if enabled
	if cfg.MLEnabled {
		app.MLClient = ml.NewMLClient(cfg.MLServerURL, true)
		app.MLClient.MinConfidence = cfg.MLMinConfidence

		// Check ML server health
		if app.MLClient.HealthCheck() {
			color.New(color.FgGreen).Fprintf(os.Stderr, "  🤖 ML server connected: %s\n", cfg.MLServerURL)
		} else {
			color.New(color.FgYellow).Fprintf(os.Stderr, "  ⚠️  ML server not reachable: %s\n", cfg.MLServerURL)
			color.New(color.FgYellow).Fprintf(os.Stderr, "     Continuing without ML predictions.\n")
		}
	}

	return app
}

// getHTTPClient returns a shared HTTP client with sensible defaults
func (a *App) getHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// Run executes the main application logic
func (a *App) Run() error {
	if a.Config.DiscoverMode {
		return a.discoverUploadForms()
	}

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

	// Apply ML predictions if enabled
	if a.Config.MLEnabled && a.MLClient != nil && a.MLClient.Enabled {
		a.applyMLPredictions(allResults)
	}

	// Verify RCE on vulnerable results if enabled
	if a.Config.VerifyRCE && a.Verifier != nil {
		a.verifyRCE(allResults)
	}

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

// loadTemplates loads template payloads if specified
func (a *App) loadTemplates() []*payload.Payload {
	var templatePayloads []*payload.Payload

	// Load single template
	if a.Config.Template != "" {
		payloads := a.loadSingleTemplate(a.Config.Template)
		templatePayloads = append(templatePayloads, payloads...)
	}

	// Load template directory
	if a.Config.TemplateDir != "" {
		payloads := a.loadTemplateDirectory(a.Config.TemplateDir)
		templatePayloads = append(templatePayloads, payloads...)
	}

	return templatePayloads
}

// loadSingleTemplate loads a single template (dynamic or regular)
func (a *App) loadSingleTemplate(templatePath string) []*payload.Payload {
	var templatePayloads []*payload.Payload

	// Try loading as dynamic template first
	dynamicTmpl, err := template.LoadDynamicTemplate(templatePath)
	if err == nil && dynamicTmpl != nil {
		// Register it
		a.TemplateRegistry.Register(dynamicTmpl)

		fmt.Printf("  📄 Loaded dynamic template: %s", dynamicTmpl.Name)

		// Show type and CVE if available
		if dynamicTmpl.Type != "" {
			fmt.Printf(" [%s]", dynamicTmpl.Type)
		}
		if dynamicTmpl.CVE != "" {
			fmt.Printf(" [%s]", dynamicTmpl.CVE)
		}
		fmt.Println()

		// Execute dynamic template if it has multi-step requests
		if len(dynamicTmpl.Requests) > 0 {
			fmt.Printf("  🔄 Executing %d-step attack sequence...\n", len(dynamicTmpl.Requests))

			result, err := a.TemplateExecutor.ExecuteDynamicTemplate(dynamicTmpl, a.Config.URL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  Dynamic template execution failed: %s\n", err)
			} else {
				fmt.Printf("  ✅ Template execution result: %s\n", result.Verdict)

				// Convert execution result to payloads for GoUpload pipeline
				for _, payload := range dynamicTmpl.ToPayloads() {
					templatePayloads = append(templatePayloads, payload)
				}
			}
		} else {
			// Dynamic template without multi-step (backward compatible)
			for _, payload := range dynamicTmpl.ToPayloads() {
				templatePayloads = append(templatePayloads, payload)
			}
		}
	} else {
		// Fall back to regular template
		tmpl, err := template.LoadTemplate(templatePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading template: %s\n", err)
			os.Exit(1)
		}

		templatePayloads = tmpl.ToPayloads()
		fmt.Printf("  📄 Loaded template: %s (%d payloads)\n", tmpl.Name, len(templatePayloads))
	}

	return templatePayloads
}

// loadTemplateDirectory loads all templates from a directory
func (a *App) loadTemplateDirectory(templateDir string) []*payload.Payload {
	var templatePayloads []*payload.Payload

	// Use registry for directory loading
	err := a.TemplateRegistry.LoadDirectory(templateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading templates directory: %s\n", err)
		return templatePayloads
	}

	allTemplates := a.TemplateRegistry.GetAll()
	for _, tmpl := range allTemplates {
		templatePayloads = append(templatePayloads, tmpl.ToPayloads()...)
		fmt.Printf("  📄 Loaded template: %s\n", tmpl.Name)
	}

	return templatePayloads
}

// applyMLPredictions sends features to ML server and updates results
func (a *App) applyMLPredictions(allResults []*types.Result) {
	flaggedCount := 0
	for _, r := range allResults {
		if r.Vulnerable != "" && r.Vulnerable != "SAFE" {
			flaggedCount++
		}
	}

	if flaggedCount == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  🤖 Applying ML predictions to %d findings...\n", flaggedCount)

	mlUpdatedCount := 0
	for _, r := range allResults {
		if r.Vulnerable == "" || r.Vulnerable == "SAFE" {
			continue
		}

		// Find the payload for this result
		pl := findPayloadForResult(allResults, r)
		if pl == nil {
			continue
		}

		// Extract features
		features := ml.ExtractFeatures(r, pl)
		normalizedFeatures := ml.NormalizeFeatures(features)

		// Get prediction from ML server
		prediction, err := a.MLClient.Predict(normalizedFeatures)
		if err != nil {
			continue
		}

		// Store ML results
		r.MLProbability = prediction.Confidence
		r.MLConfidence = prediction.Confidence
		r.MLLabel = prediction.Verdict

		// Adjust verdict based on ML prediction
		if prediction.Verdict == "VULNERABLE" && prediction.Confidence >= a.MLClient.MinConfidence {
			if r.Vulnerable != "VULNERABLE" {
				r.Vulnerable = "VULNERABLE"
				mlUpdatedCount++
			}
		} else if prediction.Verdict == "SAFE" && prediction.Confidence >= 0.8 {
			if r.Vulnerable != "SAFE" {
				r.Vulnerable = "SAFE"
				mlUpdatedCount++
			}
		} else if prediction.Verdict == "REVIEW_NEEDED" {
			r.Flags = append(r.Flags, "ml-review-needed")
		}
	}

	if mlUpdatedCount > 0 {
		color.New(color.FgCyan).Fprintf(os.Stderr, "  🤖 ML updated %d verdicts\n", mlUpdatedCount)
	}
}

// findPayloadForResult finds the payload associated with a result
func findPayloadForResult(allResults []*types.Result, target *types.Result) *payload.Payload {
	return &payload.Payload{
		Filename:  target.Filename,
		Extension: extractExtension(target.Filename),
		Body:      []byte(target.ResponseBody),
	}
}

// extractExtension gets extension from filename
func extractExtension(filename string) string {
	if idx := strings.LastIndex(filename, "."); idx != -1 {
		return filename[idx:]
	}
	return ""
}

// discoverUploadForms discovers upload forms on the target
func (a *App) discoverUploadForms() error {
	fmt.Fprintf(os.Stderr, "  🔍 Discovering upload forms on %s...\n", a.Config.URL)

	client := a.getHTTPClient()
	parser := discovery.NewHTMLFormParser(client)
	result, err := parser.DiscoverFromURL(a.Config.URL, a.Config.Headers)
	if err != nil {
		return err
	}

	output.PrintDiscoveryResults(result)
	return nil
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

// executeTests executes all payloads
func (a *App) executeTests(allPayloads []*payload.Payload) []*types.Result {
	modules := groupByModule(allPayloads)
	allResults := make([]*types.Result, 0, len(allPayloads))

	moduleOrder := []payload.TestType{
		payload.TestTypeTemplate,
		payload.TestTypeRaceCondition,
		payload.TestTypeExtensionEvasion,
		payload.TestTypeContentTypeSpoof,
		payload.TestTypeMagicByteSpoof,
		payload.TestTypeFilenameObfuscation,
		payload.TestTypePathTraversal,
		payload.TestTypeServerConfig,
		payload.TestTypeUnicodeEncoding,
		payload.TestTypeGraphQL,
		payload.TestTypeXXE,
	}

	moduleNames := map[payload.TestType]string{
		payload.TestTypeTemplate:            "TEMPLATE PAYLOADS",
		payload.TestTypeRaceCondition:       "MODULE H: Race Condition & TOCTOU Attacks",
		payload.TestTypeExtensionEvasion:    "MODULE A: Extension Evasion Matrix",
		payload.TestTypeContentTypeSpoof:    "MODULE B: Content-Type Spoofing",
		payload.TestTypeMagicByteSpoof:      "MODULE B: Magic Byte Injection",
		payload.TestTypeFilenameObfuscation: "MODULE C: Filename Obfuscation & Sanitization Faults",
		payload.TestTypePathTraversal:       "MODULE D: Path Traversal Sequences",
		payload.TestTypeServerConfig:        "MODULE F: Server Configuration Overrides",
		payload.TestTypeUnicodeEncoding:     "MODULE G: Unicode & Encoding Vulnerabilities",
		payload.TestTypeGraphQL:             "MODULE I: GraphQL File Uploads",
		payload.TestTypeXXE:                 "MODULE J: XXE Injection via File Upload",
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
			MLClient:    a.MLClient,
		})
		pool.SetResultHandler(output.ResultPrinter(a.Printer))

		var results []*types.Result
		if modType == payload.TestTypeRaceCondition {
			results = pool.ExecuteRaceBurst(modPayloads)
		} else {
			results = pool.Execute(modPayloads)
		}
		allResults = append(allResults, results...)
	}

	return allResults
}

// verifyRCE attempts to verify RCE on vulnerable results
func (a *App) verifyRCE(allResults []*types.Result) {
	vulnerableCount := 0
	for _, r := range allResults {
		if r.Vulnerable == "VULNERABLE" {
			vulnerableCount++
		}
	}

	if vulnerableCount == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "\n  🚀 Verifying RCE on %d vulnerable uploads...\n", vulnerableCount)

	verifiedCount := 0
	for _, r := range allResults {
		if r.Vulnerable != "VULNERABLE" {
			continue
		}

		fmt.Fprintf(os.Stderr, "  🔍 Testing %s...", r.Filename)

		err := a.Verifier.VerifyRCE(r, a.Config.URL)
		if err != nil {
			fmt.Fprintf(os.Stderr, " ❌ %s\n", err)
			continue
		}

		if r.RCEVerified {
			verifiedCount++
			color.New(color.FgGreen).Fprintf(os.Stderr, " ✅ RCE CONFIRMED\n")
			color.New(color.FgGreen).Fprintf(os.Stderr, "    Proof: %s\n", r.RCEProof)
			color.New(color.FgGreen).Fprintf(os.Stderr, "    URL: %s?cmd=%s\n", r.FileURL, r.RCECommand)
		} else {
			color.New(color.FgYellow).Fprintf(os.Stderr, " ⚠️  Not verified\n")
		}
	}

	if verifiedCount > 0 {
		color.New(color.FgGreen, color.Bold).Fprintf(os.Stderr, "\n  ✅ RCE verified on %d/%d vulnerable uploads!\n\n", verifiedCount, vulnerableCount)
	} else {
		color.New(color.FgYellow).Fprintf(os.Stderr, "\n  ⚠️  RCE could not be verified on any vulnerable uploads.\n\n")
	}
}

// printResults displays flagged findings in table format
func (a *App) printResults(allResults []*types.Result) {
	modules := groupResultsByType(allResults)

	moduleOrder := []payload.TestType{
		payload.TestTypeRaceCondition,
		payload.TestTypeXXE,
		payload.TestTypeGraphQL,
		payload.TestTypePathTraversal,
		payload.TestTypeExtensionEvasion,
		payload.TestTypeContentTypeSpoof,
		payload.TestTypeMagicByteSpoof,
		payload.TestTypeFilenameObfuscation,
		payload.TestTypeServerConfig,
		payload.TestTypeUnicodeEncoding,
		payload.TestTypeTemplate,
	}

	moduleNames := map[payload.TestType]string{
		payload.TestTypeRaceCondition:       "RACE CONDITION MODULE",
		payload.TestTypeXXE:                 "XXE MODULE",
		payload.TestTypeGraphQL:             "GRAPHQL MODULE",
		payload.TestTypePathTraversal:       "PATH TRAVERSAL MODULE",
		payload.TestTypeExtensionEvasion:    "EXTENSION EVASION MODULE",
		payload.TestTypeContentTypeSpoof:    "CONTENT-TYPE SPOOFING MODULE",
		payload.TestTypeMagicByteSpoof:      "MAGIC BYTE MODULE",
		payload.TestTypeFilenameObfuscation: "FILENAME OBFUSCATION MODULE",
		payload.TestTypeServerConfig:        "SERVER CONFIG MODULE",
		payload.TestTypeUnicodeEncoding:     "UNICODE MODULE",
		payload.TestTypeTemplate:            "TEMPLATE MODULE",
	}

	for _, modType := range moduleOrder {
		results, ok := modules[modType]
		if !ok || len(results) == 0 {
			continue
		}

		var flagged []*types.Result
		for _, r := range results {
			if r.Vulnerable != string(oracle.VerdictSafe) && r.Vulnerable != "" {
				flagged = append(flagged, r)
			}
		}

		if len(flagged) > 0 {
			output.PrintExecutiveSummary(moduleNames[modType], flagged)
			output.PrintFindingsTable(moduleNames[modType], flagged)
		}
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
		jsonPrinter.AddFinding(r, "GENERAL", i+1)
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

// groupResultsByType organizes results by their test type
func groupResultsByType(results []*types.Result) map[payload.TestType][]*types.Result {
	groups := make(map[payload.TestType][]*types.Result)
	for _, r := range results {
		groups[r.TestType] = append(groups[r.TestType], r)
	}
	return groups
}
