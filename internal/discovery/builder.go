package discovery

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
)

// RequestBuilder builds multipart upload requests from discovered targets
type RequestBuilder struct {
	client *http.Client
}

// NewRequestBuilder creates a new request builder
func NewRequestBuilder(client *http.Client) *RequestBuilder {
	return &RequestBuilder{client: client}
}

// BuildRequest creates an HTTP request from an UploadTarget with a payload
func (rb *RequestBuilder) BuildRequest(target *UploadTarget, fileFieldName string, filename string, body []byte, contentType string) (*http.Request, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}

	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)

	// Add form fields
	for _, field := range target.FormFields {
		if field.Type == "file" || field.Type == "submit" && field.Name == "" {
			continue
		}
		if err := writer.WriteField(field.Name, field.Value); err != nil {
			return nil, fmt.Errorf("failed to write form field %s: %w", field.Name, err)
		}
	}

	// Add file field with custom content-type if specified
	if contentType != "" {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fileFieldName, filename))
		h.Set("Content-Type", contentType)
		part, err := writer.CreatePart(h)
		if err != nil {
			return nil, fmt.Errorf("failed to create file part: %w", err)
		}
		if _, err := io.Copy(part, bytes.NewReader(body)); err != nil {
			return nil, fmt.Errorf("failed to write file content: %w", err)
		}
	} else {
		part, err := writer.CreateFormFile(fileFieldName, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to create form file: %w", err)
		}
		if _, err := io.Copy(part, bytes.NewReader(body)); err != nil {
			return nil, fmt.Errorf("failed to write file content: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Create request
	req, err := http.NewRequest(target.Method, target.ActionURL, &reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	// Add cookies
	for _, cookie := range target.Cookies {
		req.AddCookie(cookie)
	}

	return req, nil
}

// BuildRequestFromPayload builds a request using a Payload-compatible interface
func (rb *RequestBuilder) BuildRequestFromPayload(target *UploadTarget, fileFieldName string, filename string, body []byte, contentType string, additionalFields map[string]string) (*http.Request, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}

	var reqBody bytes.Buffer
	writer := multipart.NewWriter(&reqBody)

	// Add target form fields first
	for _, field := range target.FormFields {
		if field.Type == "file" {
			continue
		}
		if err := writer.WriteField(field.Name, field.Value); err != nil {
			return nil, fmt.Errorf("failed to write form field %s: %w", field.Name, err)
		}
	}

	// Add additional fields (from GoUpload's -d flag)
	for k, v := range additionalFields {
		if err := writer.WriteField(k, v); err != nil {
			return nil, fmt.Errorf("failed to write additional field %s: %w", k, err)
		}
	}

	// Add file
	if contentType != "" {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fileFieldName, filename))
		h.Set("Content-Type", contentType)
		part, err := writer.CreatePart(h)
		if err != nil {
			return nil, fmt.Errorf("failed to create file part: %w", err)
		}
		if _, err := io.Copy(part, bytes.NewReader(body)); err != nil {
			return nil, fmt.Errorf("failed to write file content: %w", err)
		}
	} else {
		part, err := writer.CreateFormFile(fileFieldName, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to create form file: %w", err)
		}
		if _, err := io.Copy(part, bytes.NewReader(body)); err != nil {
			return nil, fmt.Errorf("failed to write file content: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequest(target.Method, target.ActionURL, &reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	for _, cookie := range target.Cookies {
		req.AddCookie(cookie)
	}

	return req, nil
}

// DiscoverAndBuild discovers forms and builds requests for all file fields
func (rb *RequestBuilder) DiscoverAndBuild(pageURL string, headers map[string]string, payload []byte, contentType string) ([]*http.Request, error) {
	parser := NewHTMLFormParser(rb.client)
	result, err := parser.DiscoverFromURL(pageURL, headers)
	if err != nil {
		return nil, err
	}

	var requests []*http.Request
	for _, target := range result.Targets {
		for _, fileField := range target.FileFields {
			filename := "test.php"
			if len(fileField.Accept) > 0 {
				// Use the first accepted type's extension
				if strings.Contains(fileField.Accept[0], "image/") {
					filename = "test.php." + strings.TrimPrefix(fileField.Accept[0], "image/")
				}
			}

			req, err := rb.BuildRequest(&target, fileField.Name, filename, payload, contentType)
			if err != nil {
				continue
			}
			requests = append(requests, req)
		}
	}

	return requests, nil
}
