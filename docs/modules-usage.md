# GoUpload Module Usage Guide

## Overview

GoUpload has **13 attack modules** that test different file upload vulnerability types. Run them individually or combine them for comprehensive scanning.

## Quick Reference

```bash
# Run a single module
./GoUpload -u http://target.com/upload -p file --module extension

# Run multiple modules
./GoUpload -u http://target.com/upload -p file --module extension,content-type,graphql

# Run all modules (default)
./GoUpload -u http://target.com/upload -p file

# List all modules
./GoUpload --list-modules
```

---

## 1. Extension Evasion (`extension`)

Tests alternative extensions, case variations, and double extensions.

```bash
./GoUpload -u http://target.com/upload -p file --module extension
```

**Detects:**
- `.php5`, `.phtml`, `.phar` bypasses
- Case sensitivity (`.PhP`, `.AsPx`)
- Double extensions (`.php.jpg`, `.jpg.php`)

---

## 2. Content-Type Spoofing (`content-type`)

Tests MIME type manipulation to bypass client-side and server-side validation.

```bash
./GoUpload -u http://target.com/upload -p file --module content-type
```

**Detects:**
- PHP files disguised as `image/jpeg`
- JSP files disguised as `image/png`
- ASP files disguised as `application/pdf`

---

## 3. Magic Byte Injection (`magic-byte`)

Tests file signature spoofing to bypass content inspection.

```bash
./GoUpload -u http://target.com/upload -p file --module magic-byte
```

**Detects:**
- `GIF89a` + PHP webshell
- PNG header + PHP code
- JPEG magic + executable code
- PDF signature + payload

---

## 4. Filename Obfuscation (`filename`)

Tests filename sanitization weaknesses.

```bash
./GoUpload -u http://target.com/upload -p file --module filename
```

**Detects:**
- Trailing spaces/dots (`.php `, `.php.`)
- Null byte injection (`.php%00.jpg`)
- NTFS alternate data streams
- Special characters in filenames

---

## 5. Path Traversal (`path-traversal`)

Tests directory traversal in uploaded filenames.

```bash
./GoUpload -u http://target.com/upload -p file --module path-traversal
```

**Detects:**
- `../../../etc/passwd`
- URL-encoded traversal (`%2e%2e%2f`)
- WAF bypass (`....//....//`)
- Absolute paths (`/var/www/shell.php`)

---

## 6. GraphQL Uploads (`graphql`)

Tests GraphQL file upload mutations.

```bash
./GoUpload -u http://target.com/graphql --module graphql
```

**With custom mutation:**
```bash
./GoUpload -u http://target.com/graphql \
  --graphql-mutation 'mutation($file:Upload!){uploadFile(file:$file){id}}' \
  --module graphql
```

**Detects:**
- GraphQL multipart request vulnerabilities
- Mutation-specific file type bypasses
- GraphQL batch upload issues

---

## 7. Unicode & Encoding (`unicode`)

Tests Unicode-based filename bypasses.

```bash
./GoUpload -u http://target.com/upload -p file --module unicode
```

**Detects:**
- RTLO (Right-to-Left Override) attacks
- Zero-width character injection
- Homograph attacks
- Unicode whitespace confusion

---

## 8. Size Boundary (`size-boundary`)

Tests file size restrictions and limits.

```bash
./GoUpload -u http://target.com/upload -p file --module size-boundary
```

**Detects:**
- Empty file uploads
- 1KB, 1MB, 10MB boundaries
- Size limit bypasses
- Chunked upload edge cases

---

## 9. Race Condition (`race-condition`)

Tests TOCTOU (Time-of-Check Time-of-Use) vulnerabilities.

```bash
./GoUpload -u http://target.com/upload -p file --module race-condition -c 20
```

**Detects:**
- Concurrent same-filename uploads
- Extension check vs save race
- Temp file races
- Symlink races

**Note:** Use higher concurrency (`-c 20+`) for better race triggering.

---

## 10. Polyglot & Archives (`polyglot`)

Tests polyglot files and archive extraction attacks.

```bash
./GoUpload -u http://target.com/upload -p file --module polyglot
```

**Detects:**
- GIF+PHP+JS polyglots
- SVG with XSS
- ZIP Slip (path traversal in archives)
- ZIP bomb DoS

---

## 11. XXE Injection (`xxe`)

Tests XML External Entity vulnerabilities via uploaded files.

```bash
./GoUpload -u http://target.com/upload -p file --module xxe
```

**Detects:**
- SVG with XXE (file read)
- DOCX/XLSX with embedded XXE
- XML billion laughs (DoS)
- XXE with SSRF to cloud metadata

---

## 12. Server Configuration (`server-config`)

Tests server-specific upload tricks.

```bash
./GoUpload -u http://target.com/upload -p file --module server-config
```

**Detects:**
- Apache `.htaccess` overrides
- Nginx configuration injection
- IIS `web.config` upload
- Server misconfiguration exploits

---

## 13. Template Payloads (`template`)

Runs payloads from custom YAML templates.

```bash
./GoUpload -u http://target.com/upload -p file --module template \
  --template templates/labs/battle-lab.yaml
```

**Detects:**
- Custom attack scenarios
- Framework-specific vulnerabilities
- CVE-specific exploits

---

## Common Combinations

### Web Application Penetration Test
```bash
./GoUpload -u http://target.com/upload -p file \
  --module extension,content-type,magic-byte,filename,path-traversal \
  --allow-list .jpg,.png \
  --auto-detect
```

### API Security Test
```bash
./GoUpload -u http://target.com/api/upload -p file \
  --module graphql,xxe,server-config \
  --auto-detect
```

### Bug Bounty Quick Scan
```bash
./GoUpload -u http://target.com/upload -p file \
  --module extension,content-type,path-traversal \
  --allow-list .txt,.jpg \
  --no-validate \
  -c 10 \
  --output json --output-file results.json
```

### DVWA Testing
```bash
# Low security
./GoUpload -u http://localhost/DVWA/vulnerabilities/upload/ \
  -H "Cookie: PHPSESSID=xxx; security=low" \
  -p uploaded -d "MAX_FILE_SIZE=100000&Upload=Upload" \
  --module extension,content-type,magic-byte,filename \
  --allow-list .jpg,.png --no-validate

# Medium security
./GoUpload -u http://localhost/DVWA/vulnerabilities/upload/ \
  -H "Cookie: PHPSESSID=xxx; security=medium" \
  -p uploaded -d "MAX_FILE_SIZE=100000&Upload=Upload" \
  --module extension,content-type \
  --allow-list .jpg,.png --no-validate
```

### Battle Lab Testing
```bash
./GoUpload -u http://localhost:8080/api/upload/unrestricted \
  -p file --module extension,content-type,magic-byte \
  --allow-list .txt,.jpg --no-validate
```

---

## Output Examples

### Single Module Output
```
  🎯 Running modules: extension

  ┌─ MODULE A: Extension Evasion Matrix
  │
  ████████████████████ [100%] 20/20 (85ms)

  ⚠  FLAGGED RESULTS (20 items)
  ...
```

### JSON Output
```bash
./GoUpload -u http://target.com/upload --module extension --output json | jq '.findings[] | select(.verdict=="VULNERABLE")'
```

---

## Best Practices

1. **Start with `--module`** for targeted testing
2. **Use `--allow-list`** for baseline comparison
3. **Use `--auto-detect`** to filter payloads by tech stack
4. **Increase `-c` for race condition** testing
5. **Save results** with `--output json --output-file results.json`

---

## Module Matrix

| Module | Best For | Payloads |
|--------|----------|----------|
| extension | Blacklist bypass | 20+ |
| content-type | MIME validation bypass | 30+ |
| magic-byte | Content inspection bypass | 15+ |
| filename | Sanitization weaknesses | 25+ |
| path-traversal | Directory traversal | 20+ |
| graphql | GraphQL endpoints | 138+ |
| unicode | Encoding bypasses | 40+ |
| size-boundary | Size limits | 15+ |
| race-condition | TOCTOU | 30+ |
| polyglot | Complex payloads | 10+ |
| xxe | XML attacks | 15+ |
| server-config | Server-specific | 10+ |
| template | Custom scenarios | Varies |

---

**Total: 368+ attack payloads across 13 modules**
