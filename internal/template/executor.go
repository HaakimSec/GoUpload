package template

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// TemplateExecutor executes templates
type TemplateExecutor struct {
	client         *http.Client
	variableEngine *VariableEngine
	registry       *TemplateRegistry
}

// NewTemplateExecutor creates a template executor
func NewTemplateExecutor(client *http.Client, registry *TemplateRegistry) *TemplateExecutor {
	return &TemplateExecutor{
		client:         client,
		variableEngine: NewVariableEngine(),
		registry:       registry,
	}
}

// ExecuteDynamicTemplate executes a dynamic template
func (e *TemplateExecutor) ExecuteDynamicTemplate(tmpl *DynamicTemplate, target string) (*ExecutionResult, error) {
	// Process variables
	if err := e.variableEngine.ProcessVariables(tmpl.Variables); err != nil {
		return nil, err
	}

	// Set base variables
	e.variableEngine.SetVariable("base_url", target)
	e.variableEngine.SetVariable("hostname", extractHostname(target))

	result := &ExecutionResult{
		TemplateName: tmpl.Name,
		TargetURL:    target,
		Steps:        make([]StepResult, 0),
	}

	// Execute multi-step requests if present
	if len(tmpl.Requests) > 0 {
		for _, step := range tmpl.Requests {
			stepResult, err := e.executeStep(step, result)
			if err != nil {
				return result, err
			}
			result.Steps = append(result.Steps, stepResult)

			// If step has matchers and didn't match, stop the chain
			if len(step.Matchers) > 0 && !stepResult.Matched {
				break
			}
		}
	} else {
		// Fall back to existing single-step execution
		stepResult, err := e.executeSingleStep(tmpl, target)
		if err != nil {
			return result, err
		}
		result.Steps = append(result.Steps, stepResult)
	}

	// Determine final verdict
	result.Verdict = e.determineVerdict(tmpl, result)

	return result, nil
}

// executeStep executes a single step in a multi-step template
func (e *TemplateExecutor) executeStep(step RequestStep, result *ExecutionResult) (StepResult, error) {
	// Interpolate variables
	path := e.variableEngine.Interpolate(step.Path)
	body := e.variableEngine.Interpolate(step.Body)

	// Build full URL
	fullURL := result.TargetURL + path

	// Build request
	req, err := http.NewRequest(step.Method, fullURL, strings.NewReader(body))
	if err != nil {
		return StepResult{}, err
	}

	// Add headers
	for key, value := range step.Headers {
		req.Header.Set(key, e.variableEngine.Interpolate(value))
	}

	// Execute request
	resp, err := e.client.Do(req)
	if err != nil {
		return StepResult{}, err
	}
	defer resp.Body.Close()

	// Read response
	responseBody := readResponse(resp)

	// Convert headers to map
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// ============================================
	// USE YOUR EXISTING Evaluate FUNCTION HERE!
	// ============================================
	matchResult := Evaluate(&Template{
		Matchers:          step.Matchers,
		MatchersCondition: "", // Or "or"/"and" from step
		Extractors:        step.Extractors,
	}, responseBody, resp.StatusCode, headers)

	// Extract values if needed
	for key, value := range matchResult.Extracted {
		e.variableEngine.SetVariable(key, value)
	}

	return StepResult{
		StepID:       step.ID,
		StatusCode:   resp.StatusCode,
		ResponseBody: responseBody,
		Matched:      matchResult.Matched,
		Extracted:    matchResult.Extracted,
		Details:      matchResult.Details,
	}, nil
}

// executeSingleStep executes a simple template (backward compatibility)
func (e *TemplateExecutor) executeSingleStep(tmpl *DynamicTemplate, target string) (StepResult, error) {
	// Build request from template target config
	endpoint := e.variableEngine.Interpolate(tmpl.Target.Endpoint)
	fullURL := target + endpoint

	// Use first payload
	if len(tmpl.Payloads) == 0 {
		return StepResult{}, fmt.Errorf("no payloads in template")
	}

	payload := tmpl.Payloads[0]

	// Build multipart or simple request
	// (This connects to your existing execution logic)

	// Execute request
	req, err := http.NewRequest(tmpl.Target.Method, fullURL, strings.NewReader(payload.Body))
	if err != nil {
		return StepResult{}, err
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return StepResult{}, err
	}
	defer resp.Body.Close()

	responseBody := readResponse(resp)

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// ============================================
	// USE YOUR EXISTING Evaluate FUNCTION HERE!
	// ============================================
	matchResult := Evaluate(&tmpl.Template, responseBody, resp.StatusCode, headers)

	return StepResult{
		StepID:       "single",
		StatusCode:   resp.StatusCode,
		ResponseBody: responseBody,
		Matched:      matchResult.Matched,
		Extracted:    matchResult.Extracted,
		Details:      matchResult.Details,
	}, nil
}

// determineVerdict determines the final verdict
func (e *TemplateExecutor) determineVerdict(tmpl *DynamicTemplate, result *ExecutionResult) string {
	// Check if any step matched
	for _, step := range result.Steps {
		if step.Matched {
			if tmpl.TrainingData != nil && tmpl.TrainingData.Verdict != "" {
				return tmpl.TrainingData.Verdict
			}
			return "VULNERABLE"
		}
	}
	return "SAFE"
}

// Helper functions
func extractHostname(target string) string {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	return target
}

func readResponse(resp *http.Response) string {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
