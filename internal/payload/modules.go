package payload

import "fmt"

// ModuleInfo describes a loadable module
type ModuleInfo struct {
	Name        string
	Description string
	TestType    TestType
	Enabled     bool
}

// ModuleRegistry holds all available modules
var ModuleRegistry = []ModuleInfo{
	{
		Name:        "extension",
		Description: "Extension Evasion Matrix",
		TestType:    TestTypeExtensionEvasion,
		Enabled:     true,
	},
	{
		Name:        "content-type",
		Description: "Content-Type Spoofing",
		TestType:    TestTypeContentTypeSpoof,
		Enabled:     true,
	},
	{
		Name:        "magic-byte",
		Description: "Magic Byte Injection",
		TestType:    TestTypeMagicByteSpoof,
		Enabled:     true,
	},
	{
		Name:        "filename",
		Description: "Filename Obfuscation & Sanitization Faults",
		TestType:    TestTypeFilenameObfuscation,
		Enabled:     true,
	},
	{
		Name:        "path-traversal",
		Description: "Path Traversal Sequences",
		TestType:    TestTypePathTraversal,
		Enabled:     true,
	},
	{
		Name:        "graphql",
		Description: "GraphQL File Uploads",
		TestType:    TestTypeExtensionEvasion, // GraphQL uses multiple types
		Enabled:     true,
	},
	{
		Name:        "unicode",
		Description: "Unicode & Encoding Vulnerabilities",
		TestType:    TestTypeUnicodeEncoding,
		Enabled:     true,
	},
	{
		Name:        "size-boundary",
		Description: "Size Boundary Testing",
		TestType:    TestTypeSizeBoundary,
		Enabled:     true,
	},
	{
		Name:        "polyglot",
		Description: "Polyglot & Archive Attacks",
		TestType:    TestTypePolyglotArchive,
		Enabled:     true,
	},
	{
		Name:        "race-condition",
		Description: "Race Condition & TOCTOU Testing",
		TestType:    TestTypeRaceCondition,
		Enabled:     true,
	},
	{
		Name:        "server-config",
		Description: "Server Configuration Overrides",
		TestType:    TestTypeServerConfig,
		Enabled:     true,
	},
	{
		Name:        "template",
		Description: "Template Payloads",
		TestType:    TestTypeTemplate,
		Enabled:     true,
	},
	{
		Name:        "xxe",
		Description: "XXE Injection via File Upload",
		TestType:    TestTypeXXE,
		Enabled:     true,
	},
}

// GetModuleByName returns a module by its name
func GetModuleByName(name string) *ModuleInfo {
	for i := range ModuleRegistry {
		if ModuleRegistry[i].Name == name {
			return &ModuleRegistry[i]
		}
	}
	return nil
}

// GetEnabledModules returns all enabled modules
func GetEnabledModules() []ModuleInfo {
	var enabled []ModuleInfo
	for _, m := range ModuleRegistry {
		if m.Enabled {
			enabled = append(enabled, m)
		}
	}
	return enabled
}

// EnableModules enables only the specified modules
func EnableModules(names []string) {
	// Disable all first
	for i := range ModuleRegistry {
		ModuleRegistry[i].Enabled = false
	}

	// Enable only specified ones
	for _, name := range names {
		for i := range ModuleRegistry {
			if ModuleRegistry[i].Name == name {
				ModuleRegistry[i].Enabled = true
			}
		}
	}
}

// EnableAllModules enables all modules
func EnableAllModules() {
	for i := range ModuleRegistry {
		ModuleRegistry[i].Enabled = true
	}
}

// IsModuleEnabled checks if a module is enabled by test type
func IsModuleEnabled(testType TestType) bool {
	for _, m := range ModuleRegistry {
		if m.TestType == testType && m.Enabled {
			return true
		}
	}
	return false
}

// ListModules returns a formatted string of available modules
func ListModules() string {
	var result string
	result = "Available modules:\n"
	for _, m := range ModuleRegistry {
		status := "✅"
		if !m.Enabled {
			status = "❌"
		}
		result += fmt.Sprintf("  %s %-20s - %s\n", status, m.Name, m.Description)
	}
	return result
}

