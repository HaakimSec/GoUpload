// dynamic_template.go
package template

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DynamicTemplate extends Template for multi-step attacks
type DynamicTemplate struct {
	Template `yaml:",inline"`

	Requests     []RequestStep   `yaml:"requests,omitempty"`
	Variables    []Variable      `yaml:"variables,omitempty"`
	Type         string          `yaml:"type"`
	CVE          string          `yaml:"cve,omitempty"`
	Severity     string          `yaml:"severity,omitempty"`
	CVSSScore    float64         `yaml:"cvss_score,omitempty"`
	Flow         string          `yaml:"flow,omitempty"`
	TrainingData *TrainingConfig `yaml:"training_data,omitempty"`
}

// RequestStep represents a single step in a multi-step attack
type RequestStep struct {
	ID         string            `yaml:"id"`
	Name       string            `yaml:"name"`
	Method     string            `yaml:"method"`
	Path       string            `yaml:"path"`
	Headers    map[string]string `yaml:"headers"`
	Body       string            `yaml:"body"`
	DependsOn  string            `yaml:"depends_on,omitempty"`
	Matchers   []Matcher         `yaml:"matchers,omitempty"`
	Extractors []Extractor       `yaml:"extractors,omitempty"`
}

// Variable represents a dynamic variable
type Variable struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
	Regex  string `yaml:"regex,omitempty"`
	Length int    `yaml:"length,omitempty"`
}

// TrainingConfig auto-generates ML training data
type TrainingConfig struct {
	Generate    bool    `yaml:"generate"`
	Verdict     string  `yaml:"verdict"`
	Confidence  float64 `yaml:"confidence"`
	RCEVerified bool    `yaml:"rce_verified"`
}

// StepResult represents the result of executing a single step
type StepResult struct {
	StepID       string
	StatusCode   int
	ResponseBody string
	Matched      bool
	Extracted    map[string]string
	Details      []string
}

// ExecutionResult represents the result of executing a template
type ExecutionResult struct {
	TemplateName string
	TargetURL    string
	Steps        []StepResult
	Verdict      string
	Confidence   float64
	RCEVerified  bool
}

// LoadDynamicTemplate loads a dynamic template from a YAML file
func LoadDynamicTemplate(path string) (*DynamicTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var dynamicTmpl DynamicTemplate
	if err := yaml.Unmarshal(data, &dynamicTmpl); err != nil {
		return nil, fmt.Errorf("invalid dynamic template YAML: %w", err)
	}

	// Validate required fields
	if dynamicTmpl.Name == "" {
		return nil, fmt.Errorf("template must have a name")
	}

	// Check if it's actually dynamic (has requests or variables)
	isDynamic := len(dynamicTmpl.Requests) > 0 || len(dynamicTmpl.Variables) > 0 || dynamicTmpl.Type != ""

	if !isDynamic {
		return nil, fmt.Errorf("not a dynamic template (no requests, variables, or type)")
	}

	// Validate requests if present
	for i, req := range dynamicTmpl.Requests {
		if req.Method == "" {
			return nil, fmt.Errorf("request step %d missing method", i+1)
		}
		if req.Path == "" {
			return nil, fmt.Errorf("request step %d missing path", i+1)
		}
	}

	return &dynamicTmpl, nil
}

// LoadDynamicTemplates loads all dynamic templates from a directory
func LoadDynamicTemplates(dir string) ([]*DynamicTemplate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []*DynamicTemplate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := ""
		if idx := strings.LastIndex(entry.Name(), "."); idx != -1 {
			ext = strings.ToLower(entry.Name()[idx:])
		}

		if ext == ".yaml" || ext == ".yml" {
			tmpl, err := LoadDynamicTemplate(filepath.Join(dir, entry.Name()))
			if err != nil {
				// Skip non-dynamic templates silently
				continue
			}
			templates = append(templates, tmpl)
		}
	}

	return templates, nil
}
