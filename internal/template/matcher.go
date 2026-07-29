package template

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type MatchResult struct {
	Matched   bool
	Details   []string
	Extracted map[string]string
}

// Evaluate runs all matchers against a response
func Evaluate(tmpl *Template, body string, statusCode int, headers map[string]string) *MatchResult {
	result := &MatchResult{
		Matched:   false,
		Details:   []string{},
		Extracted: make(map[string]string),
	}

	if len(tmpl.Matchers) == 0 {
		return evaluateOldFormat(tmpl, body)
	}

	condition := tmpl.MatchersCondition
	if condition == "" {
		condition = "or"
	}

	matchResults := make([]bool, len(tmpl.Matchers))

	for i, matcher := range tmpl.Matchers {
		matched, details := evaluateMatcher(&matcher, body, statusCode, headers)
		matchResults[i] = matched
		result.Details = append(result.Details, details...)

		if matched && condition == "or" {
			result.Matched = true
			break
		}
	}

	if condition == "and" {
		result.Matched = allTrue(matchResults)
	}

	if result.Matched {
		for _, extractor := range tmpl.Extractors {
			extracted := runExtractor(&extractor, body)
			for k, v := range extracted {
				result.Extracted[k] = v
			}
		}
	}

	return result
}

// evaluateOldFormat checks old-style success/failure indicators
func evaluateOldFormat(tmpl *Template, body string) *MatchResult {
	result := &MatchResult{
		Matched:   false,
		Details:   []string{},
		Extracted: make(map[string]string),
	}

	bodyLower := strings.ToLower(body)

	for _, indicator := range tmpl.SuccessInd {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			result.Matched = true
			result.Details = append(result.Details, fmt.Sprintf("Success indicator: %s", indicator))
		}
	}

	for _, indicator := range tmpl.FailureInd {
		if strings.Contains(bodyLower, strings.ToLower(indicator)) {
			result.Matched = false
			result.Details = append(result.Details, fmt.Sprintf("Failure indicator: %s", indicator))
			break
		}
	}

	return result
}

// evaluateMatcher evaluates a single matcher
func evaluateMatcher(m *Matcher, body string, statusCode int, headers map[string]string) (bool, []string) {
	compileMatcherRegex(m)

	switch m.Type {
	case "word":
		return matchWords(m, body)
	case "regex":
		return matchRegex(m, body)
	case "status":
		return matchStatus(m, statusCode)
	case "size":
		return matchSize(m, len(body))
	}

	return false, nil
}

func compileMatcherRegex(m *Matcher) {
	if len(m.Regex) > 0 && len(m.compiledRegex) == 0 {
		for _, r := range m.Regex {
			compiled, err := regexp.Compile(r)
			if err == nil {
				m.compiledRegex = append(m.compiledRegex, compiled)
			}
		}
	}
}

// matchWords checks for word presence in body
func matchWords(m *Matcher, body string) (bool, []string) {
	var details []string
	bodyLower := strings.ToLower(body)

	matchCount := 0
	for _, word := range m.Words {
		if strings.Contains(bodyLower, strings.ToLower(word)) {
			matchCount++
			details = append(details, fmt.Sprintf("✓ Word matched: '%s'", word))
		} else {
			details = append(details, fmt.Sprintf("✗ Word not found: '%s'", word))
		}
	}

	matched := false
	if m.Condition == "and" {
		matched = matchCount == len(m.Words)
	} else {
		matched = matchCount > 0
	}

	if m.Negative {
		matched = !matched
	}

	return matched, details
}

// matchRegex checks for regex pattern matches
func matchRegex(m *Matcher, body string) (bool, []string) {
	var details []string

	matchCount := 0
	for _, r := range m.compiledRegex {
		if matches := r.FindStringSubmatch(body); len(matches) > 0 {
			matchCount++
			matched := matches[0]
			if len(matched) > 50 {
				matched = matched[:50] + "..."
			}
			details = append(details, fmt.Sprintf("✓ Regex matched: '%s'", matched))
		} else {
			details = append(details, fmt.Sprintf("✗ Regex no match: '%s'", r.String()))
		}
	}

	matched := false
	if m.Condition == "and" {
		matched = matchCount == len(m.compiledRegex)
	} else {
		matched = matchCount > 0
	}

	if m.Negative {
		matched = !matched
	}

	return matched, details
}

// matchStatus checks HTTP status codes
func matchStatus(m *Matcher, statusCode int) (bool, []string) {
	for _, s := range m.Status {
		if s == statusCode {
			return !m.Negative, []string{fmt.Sprintf("✓ Status matched: %d", statusCode)}
		}
	}
	return m.Negative, []string{fmt.Sprintf("✗ Status not matched: %d", statusCode)}
}

// matchSize checks response body size
func matchSize(m *Matcher, size int) (bool, []string) {
	for _, s := range m.Size {
		operator := s[0]
		value, err := strconv.Atoi(s[1:])
		if err != nil {
			continue
		}

		matched := false
		switch operator {
		case '>':
			matched = size > value
		case '<':
			matched = size < value
		case '=':
			matched = size == value
		}

		if matched {
			return !m.Negative, []string{fmt.Sprintf("✓ Size matched: %s %d (got %d)", string(operator), value, size)}
		}
	}
	return m.Negative, []string{fmt.Sprintf("✗ Size not matched: got %d bytes", size)}
}

// runExtractor extracts data from response body
func runExtractor(e *Extractor, body string) map[string]string {
	results := make(map[string]string)

	if len(e.Regex) > 0 && len(e.compiledRegex) == 0 {
		for _, r := range e.Regex {
			compiled, err := regexp.Compile(r)
			if err == nil {
				e.compiledRegex = append(e.compiledRegex, compiled)
			}
		}
	}

	group := e.Group
	if group == 0 {
		group = 1
	}

	for _, r := range e.compiledRegex {
		matches := r.FindStringSubmatch(body)
		if len(matches) > group {
			results[e.Name] = matches[group]
			fmt.Printf("  📤 Extracted [%s]: %s\n", e.Name, matches[group])
		}
	}

	return results
}

// allTrue checks if all booleans are true
func allTrue(bools []bool) bool {
	for _, b := range bools {
		if !b {
			return false
		}
	}
	return true
}

// Matcher defines detection logic for responses
type Matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Size      []string `yaml:"size,omitempty"`
	Condition string   `yaml:"condition"`
	Negative  bool     `yaml:"negative,omitempty"`

	compiledRegex []*regexp.Regexp
}

// Extractor extracts data from responses
type Extractor struct {
	Type  string   `yaml:"type"`
	Regex []string `yaml:"regex,omitempty"`
	Name  string   `yaml:"name"`
	Group int      `yaml:"group,omitempty"`

	compiledRegex []*regexp.Regexp
}
