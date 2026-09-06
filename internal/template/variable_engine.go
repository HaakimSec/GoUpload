package template

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// VariableEngine processes template variables
type VariableEngine struct {
	variables map[string]string
	rand      *rand.Rand
}

// NewVariableEngine creates a variable engine
func NewVariableEngine() *VariableEngine {
	return &VariableEngine{
		variables: make(map[string]string),
		rand:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ProcessVariables generates values for all variables
func (ve *VariableEngine) ProcessVariables(vars []Variable) error {
	for _, v := range vars {
		value, err := ve.generateValue(v)
		if err != nil {
			return err
		}
		ve.variables[v.Name] = value
	}
	return nil
}

// generateValue generates a value based on variable type
func (ve *VariableEngine) generateValue(v Variable) (string, error) {
	switch strings.ToLower(v.Type) {
	case "random_string", "rand_text_alpha":
		return ve.randomString(v.Length, false), nil

	case "random_alphanumeric", "rand_text_alphanumeric":
		return ve.randomString(v.Length, true), nil

	case "random_numeric", "rand_int":
		return ve.randomNumeric(v.Length), nil

	case "static":
		return v.Value, nil

	case "timestamp":
		return fmt.Sprintf("%d", time.Now().Unix()), nil

	default:
		return v.Value, nil
	}
}

// randomString generates random string of given length
func (ve *VariableEngine) randomString(length int, alphanumeric bool) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const alphanumericChars = "abcdefghijklmnopqrstuvwxyz0123456789"

	charset := letters
	if alphanumeric {
		charset = alphanumericChars
	}

	if length <= 0 {
		length = 8
	}

	result := make([]byte, length)
	for i := range result {
		result[i] = charset[ve.rand.Intn(len(charset))]
	}
	return string(result)
}

// randomNumeric generates random numeric string
func (ve *VariableEngine) randomNumeric(length int) string {
	if length <= 0 {
		length = 6
	}

	result := make([]byte, length)
	for i := range result {
		result[i] = byte('0' + ve.rand.Intn(10))
	}
	return string(result)
}

// Interpolate replaces {{variables}} in a string
func (ve *VariableEngine) Interpolate(input string) string {
	result := input

	for name, value := range ve.variables {
		placeholder := fmt.Sprintf("{{%s}}", name)
		result = strings.ReplaceAll(result, placeholder, value)
	}

	return result
}

// GetVariable returns a variable value
func (ve *VariableEngine) GetVariable(name string) string {
	return ve.variables[name]
}

// SetVariable sets a variable value
func (ve *VariableEngine) SetVariable(name, value string) {
	ve.variables[name] = value
}
