package template

import (
	"fmt"
	"sync"
	"time"
)

// TemplateRegistry manages templates dynamically
type TemplateRegistry struct {
	mu        sync.RWMutex
	templates map[string]*DynamicTemplate
	byCVE     map[string]*DynamicTemplate
	byType    map[string][]*DynamicTemplate
	updatedAt time.Time
}

// NewTemplateRegistry creates a template registry
func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{
		templates: make(map[string]*DynamicTemplate),
		byCVE:     make(map[string]*DynamicTemplate),
		byType:    make(map[string][]*DynamicTemplate),
		updatedAt: time.Now(),
	}
}

// Register adds a template to the registry
func (r *TemplateRegistry) Register(tmpl *DynamicTemplate) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.templates[tmpl.Name] = tmpl

	if tmpl.CVE != "" {
		r.byCVE[tmpl.CVE] = tmpl
	}

	if tmpl.Type != "" {
		r.byType[tmpl.Type] = append(r.byType[tmpl.Type], tmpl)
	}

	r.updatedAt = time.Now()
}

// GetByName retrieves template by name
func (r *TemplateRegistry) GetByName(name string) (*DynamicTemplate, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tmpl, exists := r.templates[name]
	return tmpl, exists
}

// GetByCVE retrieves template by CVE ID
func (r *TemplateRegistry) GetByCVE(cve string) (*DynamicTemplate, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tmpl, exists := r.byCVE[cve]
	return tmpl, exists
}

// GetByType retrieves all templates of a specific type
func (r *TemplateRegistry) GetByType(templateType string) []*DynamicTemplate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.byType[templateType]
}

// GetAll returns all templates
func (r *TemplateRegistry) GetAll() []*DynamicTemplate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	templates := make([]*DynamicTemplate, 0, len(r.templates))
	for _, tmpl := range r.templates {
		templates = append(templates, tmpl)
	}
	return templates
}

// LoadDirectory loads all templates from a directory into the registry
func (r *TemplateRegistry) LoadDirectory(dir string) error {
	templates, err := LoadTemplates(dir)
	if err != nil {
		return fmt.Errorf("failed to load templates from %s: %w", dir, err)
	}

	for _, tmpl := range templates {
		dynamicTmpl := &DynamicTemplate{
			Template: *tmpl,
		}
		r.Register(dynamicTmpl)
	}

	return nil
}

// Count returns the number of registered templates
func (r *TemplateRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.templates)
}

// template_registry.go - Add this method if missing

// LoadDynamicDirectory loads dynamic templates from a directory
func (r *TemplateRegistry) LoadDynamicDirectory(dir string) error {
	templates, err := LoadDynamicTemplates(dir)
	if err != nil {
		return fmt.Errorf("failed to load dynamic templates from %s: %w", dir, err)
	}

	for _, tmpl := range templates {
		r.Register(tmpl)
	}

	return nil
}
