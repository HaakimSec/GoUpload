package discovery

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// HTMLFormParser parses HTML pages to discover upload forms
type HTMLFormParser struct {
	client *http.Client
	jar    http.CookieJar
}

// NewHTMLFormParser creates a new HTML form parser
func NewHTMLFormParser(client *http.Client) *HTMLFormParser {
	return &HTMLFormParser{
		client: client,
		jar:    client.Jar,
	}
}

// DiscoverFromURL fetches a URL and discovers upload forms
func (p *HTMLFormParser) DiscoverFromURL(pageURL string, headers map[string]string) (*DiscoveryResult, error) {
	// Parse the page URL
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("invalid page URL: %w", err)
	}

	// Fetch the page
	req, err := http.NewRequest("GET", pageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "GoUpload-Discovery/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse HTML
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Discover forms
	targets := p.extractForms(doc, parsedURL, resp.Cookies())

	return &DiscoveryResult{
		PageURL: pageURL,
		Targets: targets,
	}, nil
}

// DiscoverFromHTML parses HTML content directly
func (p *HTMLFormParser) DiscoverFromHTML(htmlContent string, pageURL string, cookies []*http.Cookie) (*DiscoveryResult, error) {
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("invalid page URL: %w", err)
	}

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	targets := p.extractForms(doc, parsedURL, cookies)

	return &DiscoveryResult{
		PageURL: pageURL,
		Targets: targets,
	}, nil
}

// extractForms walks the HTML tree and extracts upload forms
func (p *HTMLFormParser) extractForms(doc *html.Node, pageURL *url.URL, cookies []*http.Cookie) []UploadTarget {
	var targets []UploadTarget

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			if target := p.parseForm(n, pageURL, cookies); target != nil {
				targets = append(targets, *target)
			}
			return // Don't recurse into nested forms
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	return targets
}

// parseForm extracts upload target from a form element
func (p *HTMLFormParser) parseForm(form *html.Node, pageURL *url.URL, cookies []*http.Cookie) *UploadTarget {
	target := &UploadTarget{
		PageURL:       pageURL.String(),
		DiscoveryType: DiscoveryHTMLForm,
		Cookies:       cookies,
	}

	// Extract form attributes
	for _, attr := range form.Attr {
		switch strings.ToLower(attr.Key) {
		case "action":
			target.ActionURL = p.resolveURL(attr.Val, pageURL)
		case "method":
			target.Method = strings.ToUpper(attr.Val)
		case "enctype":
			target.Enctype = attr.Val
		}
	}

	// Default method
	if target.Method == "" {
		target.Method = "GET"
	}

	// Default action to current page URL (browser behavior)
	if target.ActionURL == "" {
		target.ActionURL = pageURL.String()
	}

	// Extract form fields
	p.extractFields(form, target)

	// Only return if form has file input
	if len(target.FileFields) == 0 {
		return nil
	}

	return target
}

// extractFields extracts all input fields from a form
func (p *HTMLFormParser) extractFields(form *html.Node, target *UploadTarget) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				p.parseInputField(n, target)
			case "textarea":
				p.parseTextArea(n, target)
			case "select":
				p.parseSelect(n, target)
			case "button":
				// Submit buttons
				p.parseButton(n, target)
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(form)
}

// parseInputField parses an input element
func (p *HTMLFormParser) parseInputField(n *html.Node, target *UploadTarget) {
	var name, inputType, value string
	var accept []string
	var multiple bool

	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "name":
			name = attr.Val
		case "type":
			inputType = strings.ToLower(attr.Val)
		case "value":
			value = attr.Val
		case "accept":
			accept = p.parseAccept(attr.Val)
		case "multiple":
			multiple = true
		}
	}

	if name == "" {
		return
	}

	switch inputType {
	case "file":
		target.FileFields = append(target.FileFields, FileField{
			Name:     name,
			Accept:   accept,
			Multiple: multiple,
		})
	case "hidden", "text", "password", "email", "number", "date", "tel", "url":
		target.FormFields = append(target.FormFields, FormField{
			Name:  name,
			Value: value,
			Type:  inputType,
		})
	case "submit", "image":
		if value != "" {
			target.FormFields = append(target.FormFields, FormField{
				Name:  name,
				Value: value,
				Type:  inputType,
			})
		}
	case "checkbox", "radio":
		// Check if checked attribute exists
		for _, attr := range n.Attr {
			if strings.ToLower(attr.Key) == "checked" {
				target.FormFields = append(target.FormFields, FormField{
					Name:  name,
					Value: value,
					Type:  inputType,
				})
				break
			}
		}
	}
}

// parseTextArea extracts textarea values
func (p *HTMLFormParser) parseTextArea(n *html.Node, target *UploadTarget) {
	var name string
	for _, attr := range n.Attr {
		if strings.ToLower(attr.Key) == "name" {
			name = attr.Val
			break
		}
	}

	if name == "" {
		return
	}

	// Get text content
	var value string
	if n.FirstChild != nil {
		value = n.FirstChild.Data
	}

	target.FormFields = append(target.FormFields, FormField{
		Name:  name,
		Value: value,
		Type:  "textarea",
	})
}

// parseSelect extracts select/option values
func (p *HTMLFormParser) parseSelect(n *html.Node, target *UploadTarget) {
	var name string
	for _, attr := range n.Attr {
		if strings.ToLower(attr.Key) == "name" {
			name = attr.Val
			break
		}
	}

	if name == "" {
		return
	}

	// Find selected option
	var selectedValue string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "option" {
			var val string
			isSelected := false
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "value":
					val = attr.Val
				case "selected":
					isSelected = true
				}
			}
			if isSelected || selectedValue == "" {
				selectedValue = val
				if n.FirstChild != nil {
					selectedValue = n.FirstChild.Data
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)

	target.FormFields = append(target.FormFields, FormField{
		Name:  name,
		Value: selectedValue,
		Type:  "select",
	})
}

// parseButton extracts button values
func (p *HTMLFormParser) parseButton(n *html.Node, target *UploadTarget) {
	var name, value string
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "name":
			name = attr.Val
		case "value":
			value = attr.Val
		}
	}

	if name != "" && value != "" {
		target.FormFields = append(target.FormFields, FormField{
			Name:  name,
			Value: value,
			Type:  "submit",
		})
	}
}

// parseAccept parses the accept attribute
func (p *HTMLFormParser) parseAccept(accept string) []string {
	if accept == "" {
		return nil
	}

	parts := strings.Split(accept, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// resolveURL resolves a URL relative to the page URL
func (p *HTMLFormParser) resolveURL(action string, pageURL *url.URL) string {
	if action == "" {
		return pageURL.String()
	}

	parsed, err := url.Parse(action)
	if err != nil {
		return action
	}

	resolved := pageURL.ResolveReference(parsed)
	return resolved.String()
}
