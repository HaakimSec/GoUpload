package discovery

import (
	"fmt"
	"net/http"
)

// DiscoveryType indicates how the upload target was discovered
type DiscoveryType string

const (
	DiscoveryHTMLForm DiscoveryType = "HTML_FORM"
	DiscoveryManual   DiscoveryType = "MANUAL"
	DiscoveryAPI      DiscoveryType = "API"
)

// UploadTarget represents a discovered file upload endpoint
type UploadTarget struct {
	PageURL       string            `json:"page_url"`
	ActionURL     string            `json:"action_url"`
	Method        string            `json:"method"`
	Enctype       string            `json:"enctype"`
	FileFields    []FileField       `json:"file_fields"`
	FormFields    []FormField       `json:"form_fields"`
	Headers       map[string]string `json:"headers"`
	Cookies       []*http.Cookie    `json:"-"`
	DiscoveryType DiscoveryType     `json:"discovery_type"`
}

// FileField represents a file input field in an HTML form
type FileField struct {
	Name     string   `json:"name"`
	Accept   []string `json:"accept,omitempty"`
	Multiple bool     `json:"multiple"`
}

// FormField represents a non-file form field
type FormField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

// DiscoveryResult holds all discovered upload targets from a page
type DiscoveryResult struct {
	PageURL string         `json:"page_url"`
	Targets []UploadTarget `json:"targets"`
	Error   string         `json:"error,omitempty"`
}

// FormData builds a map of form fields for multipart submission
func (ut *UploadTarget) FormData() map[string]string {
	data := make(map[string]string)
	for _, field := range ut.FormFields {
		if field.Type != "file" {
			data[field.Name] = field.Value
		}
	}
	return data
}

// HasFileField checks if a specific file field exists
func (ut *UploadTarget) HasFileField(name string) bool {
	for _, ff := range ut.FileFields {
		if ff.Name == name {
			return true
		}
	}
	return false
}

// GetFileField returns a file field by name
func (ut *UploadTarget) GetFileField(name string) *FileField {
	for _, ff := range ut.FileFields {
		if ff.Name == name {
			return &ff
		}
	}
	return nil
}

// Validate checks if the upload target is usable
func (ut *UploadTarget) Validate() error {
	if ut.ActionURL == "" {
		return fmt.Errorf("no action URL")
	}
	if len(ut.FileFields) == 0 {
		return fmt.Errorf("no file fields discovered")
	}
	if ut.Method == "" {
		ut.Method = "POST"
	}
	return nil
}
