package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

// Config holds all parsed CLI configuration.
type Config struct {
	URL             string
	Param           string
	Headers         map[string]string
	Data            map[string]string
	AllowList       []string
	Concurrency     int
	TechStack       string // Tech stack to target: php, asp.net, java, nodejs, python, all, auto
	AutoDetect      bool   // Auto-detect tech stack before testing
	CheckOnly       bool   // Only validate target, don't run tests
	NoValidate      bool   // Skip target validation
	GraphQLMutation string // Custom GraphQL mutation string
	GraphQLVariable string // GraphQL variable name for file upload
	ModuleOverwrite bool   // Enable Node.js module overwrite payloads
	ModulePath      string // Custom module path for overwrite
}

// HeaderFile is the JSON structure for loading headers from a file.
type HeaderFile struct {
	Headers map[string]string `json:"headers"`
}

// Parse reads and validates CLI flags, returning a populated Config.
func Parse() (*Config, error) {
	var (
		url             string
		param           string
		headersRaw      string
		dataRaw         string
		allowRaw        string
		concurrency     int
		techStack       string
		autoDetect      bool
		checkOnly       bool
		noValidate      bool
		graphqlMutation string
		graphqlVariable string
		moduleOverwrite bool
		modulePath      string
	)

	flag.StringVar(&url, "url", "", "Target upload endpoint URL (required)")
	flag.StringVar(&url, "u", "", "Target upload endpoint URL (shorthand)")
	flag.StringVar(&param, "param", "file", "Name of the multipart file parameter")
	flag.StringVar(&param, "p", "file", "Name of the multipart file parameter (shorthand)")
	flag.StringVar(&headersRaw, "headers", "", "Custom headers as key:value pairs or path to a JSON file")
	flag.StringVar(&headersRaw, "H", "", "Custom headers as key:value pairs or path to a JSON file (shorthand)")
	flag.StringVar(&dataRaw, "data", "", "Additional form fields as key:value pairs")
	flag.StringVar(&dataRaw, "d", "", "Additional form fields as key:value pairs (shorthand)")
	flag.StringVar(&allowRaw, "allow-list", "", "Comma-separated list of allowed extensions for baseline")
	flag.IntVar(&concurrency, "concurrency", 10, "Number of concurrent workers")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers (shorthand)")
	flag.StringVar(&techStack, "tech", "all", "Target tech stack: php, asp.net, java, nodejs, python, all, auto")
	flag.StringVar(&techStack, "t", "all", "Target tech stack (shorthand)")
	flag.BoolVar(&autoDetect, "auto-detect", false, "Auto-detect target tech stack before testing")
	flag.BoolVar(&checkOnly, "check", false, "Only validate target connectivity (no payloads)")
	flag.BoolVar(&checkOnly, "C", false, "Only validate target connectivity (shorthand)")
	flag.BoolVar(&noValidate, "no-validate", false, "Skip target validation before testing")
	flag.StringVar(&graphqlMutation, "graphql-mutation", "", "Custom GraphQL mutation string")
	flag.StringVar(&graphqlVariable, "graphql-variable", "file", "GraphQL variable name for file")
	flag.BoolVar(&moduleOverwrite, "module-overwrite", false, "Enable Node.js module overwrite payloads")
	flag.StringVar(&modulePath, "module-path", "../../", "Base path for module overwrite traversal")

	flag.Usage = func() {
		// Rainbow colors
		rainbowColors := []*color.Color{
			color.New(color.FgRed, color.Bold),
			color.New(color.FgYellow, color.Bold),
			color.New(color.FgGreen, color.Bold),
			color.New(color.FgCyan, color.Bold),
			color.New(color.FgBlue, color.Bold),
			color.New(color.FgMagenta, color.Bold),
		}

		// Rainbow ASCII Art Banner
		logo := []string{
			"   ██████╗  ██████╗ ██╗   ██╗██████╗ ██╗      ██████╗  █████╗ ██████╗ ",
			"  ██╔════╝ ██╔═══██╗██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗",
			"  ██║  ███╗██║   ██║██║   ██║██████╔╝██║     ██║   ██║███████║██║  ██║",
			"  ██║   ██║██║   ██║██║   ██║██╔═══╝ ██║     ██║   ██║██╔══██║██║  ██║",
			"  ╚██████╔╝╚██████╔╝╚██████╔╝██║     ███████╗╚██████╔╝██║  ██║██████╔╝",
			"   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ",
		}

		fmt.Fprintln(os.Stderr)
		for i, line := range logo {
			rainbowColors[i%len(rainbowColors)].Fprintln(os.Stderr, line)
		}
		fmt.Fprintln(os.Stderr)

		// Subtitle
		subtitle := color.New(color.FgWhite, color.Bold)
		flame := color.New(color.FgYellow, color.Bold)
		flame.Fprint(os.Stderr, "   ⚡ ")
		subtitle.Fprint(os.Stderr, "Web Application File Upload Security Tester")
		flame.Fprintln(os.Stderr, " ⚡")
		fmt.Fprintln(os.Stderr)

		// Version
		version := color.New(color.FgHiWhite, color.Faint)
		version.Fprintln(os.Stderr, "   v1.0.0  │  Built for Security Professionals  │  @haakimsec")
		fmt.Fprintln(os.Stderr)

		// Separator
		dim := color.New(color.FgHiBlack)
		dim.Fprintln(os.Stderr, "  ══════════════════════════════════════════════════════════════════")
		fmt.Fprintln(os.Stderr)

		// Usage
		bold := color.New(color.FgCyan, color.Bold)
		bold.Fprintln(os.Stderr, "  USAGE:")
		fmt.Fprintf(os.Stderr, "    GoUpload -u <URL> -p <param> [flags]\n")
		fmt.Fprintln(os.Stderr)

		// Examples
		bold.Fprintln(os.Stderr, "  EXAMPLES:")
		fmt.Fprintf(os.Stderr, "    GoUpload -u http://target.com/upload -p file\n")
		fmt.Fprintf(os.Stderr, "    GoUpload -u http://target.com/upload -H \"Authorization: Bearer TOKEN\"\n")
		fmt.Fprintf(os.Stderr, "    GoUpload -u http://target.com/upload --allow-list \".jpg,.png\" -c 20\n")
		fmt.Fprintf(os.Stderr, "    GoUpload -u http://target.com/upload --auto-detect\n")
		fmt.Fprintf(os.Stderr, "    GoUpload -u http://target.com/upload --tech php\n")
		fmt.Fprintf(os.Stderr, "    GoUpload --check -u http://target.com/upload\n")
		fmt.Fprintf(os.Stderr, "    GoUpload -u https://api.target.com/graphql --graphql-mutation \"mutation(\\$file:Upload!){uploadFile(file:\\$file){id}}\"\n")
		fmt.Fprintln(os.Stderr)

		// Flags
		bold.Fprintln(os.Stderr, "  FLAGS:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)

		// Tech Stack Info
		bold.Fprintln(os.Stderr, "  TECH STACK OPTIONS:")
		fmt.Fprintf(os.Stderr, "    php      - PHP payloads (<?php shells, .php5, .phtml, etc.)\n")
		fmt.Fprintf(os.Stderr, "    asp.net  - ASP.NET payloads (.asp, .aspx, .ashx, etc.)\n")
		fmt.Fprintf(os.Stderr, "    java     - Java/JSP payloads (.jsp, .jspx, etc.)\n")
		fmt.Fprintf(os.Stderr, "    nodejs   - Node.js payloads (.js, etc.)\n")
		fmt.Fprintf(os.Stderr, "    python   - Python payloads (.py, etc.)\n")
		fmt.Fprintf(os.Stderr, "    all      - Test all payloads (default)\n")
		fmt.Fprintf(os.Stderr, "    auto     - Auto-detect via fingerprinting\n")
		fmt.Fprintln(os.Stderr)
	}

	flag.Parse()

	if url == "" {
		return nil, fmt.Errorf("target URL is required (-u, --url)")
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("URL must start with http:// or https://")
	}

	// Validate tech stack
	validTechStacks := []string{"php", "asp.net", "java", "nodejs", "python", "all", "auto"}
	techValid := false
	for _, vts := range validTechStacks {
		if techStack == vts {
			techValid = true
			break
		}
	}
	if !techValid {
		return nil, fmt.Errorf("invalid tech stack: %s (use: php, asp.net, java, nodejs, python, all, auto)", techStack)
	}

	// auto-detect flag overrides tech stack
	if autoDetect {
		techStack = "auto"
	}

	headers, err := parseHeaders(headersRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse headers: %w", err)
	}

	data, err := parseFormData(dataRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse form data: %w", err)
	}

	var allowList []string
	if allowRaw != "" {
		parts := strings.Split(allowRaw, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				if !strings.HasPrefix(trimmed, ".") {
					trimmed = "." + trimmed
				}
				allowList = append(allowList, trimmed)
			}
		}
	}

	if concurrency < 1 {
		concurrency = 1
	}

	return &Config{
		URL:             url,
		Param:           param,
		Headers:         headers,
		Data:            data,
		AllowList:       allowList,
		Concurrency:     concurrency,
		TechStack:       techStack,
		AutoDetect:      autoDetect || techStack == "auto",
		CheckOnly:       checkOnly,
		NoValidate:      noValidate,
		GraphQLMutation: graphqlMutation,
		GraphQLVariable: graphqlVariable,
		ModuleOverwrite: moduleOverwrite,
		ModulePath:      modulePath,
	}, nil
}

// parseHeaders handles both inline key:value pairs and JSON file paths.
func parseHeaders(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}

	// Try as a JSON file path first
	if _, err := os.Stat(raw); err == nil {
		data, err := os.ReadFile(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to read header file: %w", err)
		}

		var hf HeaderFile
		if err := json.Unmarshal(data, &hf); err != nil {
			return nil, fmt.Errorf("invalid JSON in header file: %w", err)
		}
		return hf.Headers, nil
	}

	// Parse as inline key:value pairs separated by newlines
	headers := make(map[string]string)
	entries := strings.Split(raw, "\n")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ": ", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			continue
		}
		parts = strings.SplitN(entry, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers, nil
}

// parseFormData parses key:value form field pairs.
func parseFormData(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}

	data := make(map[string]string)
	entries := strings.Split(raw, "&")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			data[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return data, nil
}

