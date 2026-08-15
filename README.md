# GoUpload 🚀

**Web Application File Upload Security Tester**

A high-performance, concurrent file upload vulnerability scanner written in Go. Tests for 368+ file upload vulnerabilities across 13 attack modules including extension bypass, content-type spoofing, magic bytes, path traversal, race conditions, XXE injection, GraphQL uploads, and more.

![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.7.0-blue)

## ⚡ Features

- 🎯 **Smart Fingerprinting** - Auto-detects target tech stack (PHP, ASP.NET, Java, Node.js, Python)
- 🧪 **368+ Payloads** - Comprehensive test matrix across 13 attack modules
- 📡 **GraphQL Support** - Tests GraphQL file upload mutations with custom mutation strings
- 🏃 **Race Condition Testing** - TOCTOU detection with synchronized burst execution
- 💉 **XXE Injection** - XML External Entity via SVG, DOCX, XLSX, JPEG uploads
- 🔍 **Upload Form Discovery** - Auto-discovers hidden upload endpoints in HTML forms
- 📊 **Risk Scoring** - CRITICAL/HIGH/MEDIUM/LOW/INFO classification
- 🎯 **Confidence Scoring** - 0-100% confidence per finding
- 📋 **Nuclei-Style Tables** - Professional findings table with summary cards
- 📄 **Template System** - YAML-based attack profiles with regex matchers
- 🔧 **Module Selection** - Run specific modules with `--module` flag
- 🚀 **Blazing Fast** - Concurrent testing (300+ tests in <1s)
- 🎨 **Beautiful Output** - Rainbow ASCII art with colored results
- ✅ **Target Validation** - Validates URLs before testing
- 🌍 **Cross-Platform** - Linux, Windows, macOS

## 📦 Installation

### Method 1: Go Install (Recommended)
```bash
go install -v github.com/HaakimSec/GoUpload@latest
```

### Post-Installation Setup (Add to PATH)
If your terminal says `GoUpload: command not found`:

#### For Bash:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

#### For Zsh:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc
```

#### Verification:
```bash
GoUpload -v
# Output: GoUpload v1.7.0
```

### Method 2: Build from Source
```bash
git clone https://github.com/HaakimSec/GoUpload.git
cd GoUpload
go build -o GoUpload main.go
sudo mv GoUpload /usr/local/bin/
```

### Method 3: Docker (Coming Soon)
```bash
docker pull haakimsec/goupload:latest
docker run --rm haakimsec/goupload -v
```

## 🛠️ Usage

### Quick Start
```bash
# Show version
GoUpload -v

# List all 13 modules
GoUpload --list-modules

# Basic scan
GoUpload -u http://target.com/upload -p file

# Auto-detect tech stack
GoUpload -u http://target.com/upload --auto-detect

# Run specific modules
GoUpload -u http://target.com/upload -p file --module extension,path-traversal

# Full scan with baseline
GoUpload -u http://target.com/upload -p file --allow-list ".txt,.jpg,.png" -c 20
```

### Module Selection
```bash
# Run single module
GoUpload -u http://target.com/upload --module xxe

# Run multiple modules
GoUpload -u http://target.com/upload --module extension,content-type,graphql

# Available modules:
# extension, content-type, magic-byte, filename, path-traversal,
# graphql, unicode, size-boundary, race-condition, polyglot,
# xxe, server-config, template
```

### JSON Output
```bash
GoUpload -u http://target.com/upload -p file \
  --output json --output-file results.json

# Pretty print with jq
cat results.json | jq '.summary'
cat results.json | jq '.findings[] | select(.verdict=="VULNERABLE")'
```

### Upload Form Discovery
```bash
# Discover upload forms on a page
GoUpload -u https://target.com/profile --discover

# Output:
# 🔍 Discovered 1 upload surface(s)
# [1] Upload Form
#     Method:       POST
#     Action:       /api/user/avatar
#     File field:   avatar
```

### Full Flag Reference
```text
Flags:
  -u, --url              Target upload endpoint URL (required)
  -p, --param            File parameter name (default: "file")
  -t, --tech             Tech stack: php, asp.net, java, nodejs, python, all, auto
      --auto-detect      Auto-detect tech stack
  -c, --concurrency      Concurrent workers (default: 10)
      --allow-list       Allowed extensions for baseline
  -H, --headers          Custom headers
  -d, --data             Additional form fields
      --check, -C        Validate target only
      --no-validate      Skip target validation
      --discover         Discover upload forms
      --module           Run specific modules
      --list-modules     List available modules
      --template         Template YAML file
      --output           Output format: table, json
      --output-file      Save output to file
  -v, --version          Show version
      --update           Update to latest version
```

## 📖 Documentation

The `docs/` directory contains detailed documentation:

| Document | Description |
|----------|-------------|
| [architecture.md](docs/architecture.md) | Package structure and data flow |
| [oracle-system.md](docs/oracle-system.md) | Detection engine explanation |
| [adding-new-templates.md](docs/adding-new-templates.md) | Template creation guide |
| [adding-new-payloads.md](docs/adding-new-payloads.md) | Payload module guide |
| [modules-usage.md](docs/modules-usage.md) | Module usage reference |
| [ROADMAP.md](ROADMAP.md) | Future implementation plan |

## 📊 Example Output

```
┌──────────────────────────────────────────────┐
│ XXE MODULE                                   │
├──────────────────────────────────────────────┤
│ Total Payloads      12                    │
│ Critical            0                     │
│ High                0                     │
│ Medium              12                    │
│ Low                 0                     │
│ Avg Response Time   20ms                  │
└──────────────────────────────────────────────┘

┌────┬──────────┬────────────┬──────────────────────────────┬─────────┬────────┐
│ ID │ Risk     │ Confidence │ Finding                      │ Status  │ Time   │
├────┼──────────┼────────────┼──────────────────────────────┼─────────┼────────┤
│ 01 │ MEDIUM   │ 80%        │ XXE via SVG: Read /etc/passwd│ 200 OK │ 19ms   │
│ 02 │ MEDIUM   │ 100%       │ XXE via SVG: SSRF to AWS     │ 200 OK │ 24ms   │
│ 03 │ MEDIUM   │ 100%       │ XXE via XML: Direct file read│ 200 OK │ 23ms   │
└────┴──────────┴────────────┴──────────────────────────────┴─────────┴────────┘
```

## 📚 Attack Modules

| Module | Description | Payloads |
|--------|-------------|:--------:|
| **Extension Evasion** | .php5, .phtml, case variations, double extensions | 20+ |
| **Content-Type Spoof** | MIME manipulation, magic byte injection | 30+ |
| **Filename Obfuscation** | Trailing spaces, null bytes, NTFS streams | 25+ |
| **Path Traversal** | Directory traversal, URL encoding | 28+ |
| **Race Condition** | TOCTOU, concurrent uploads, symlink races | 30+ |
| **XXE Injection** | SVG/XML/DOCX/XLSX external entities | 12+ |
| **GraphQL Uploads** | Mutations, batch uploads, module overwrite | 138+ |
| **Unicode Attacks** | RTLO, zero-width, homograph | 40+ |
| **Size Boundaries** | Edge cases, ZIP bombs, tiny shells | 15+ |
| **Polyglot & Archives** | GIF+PHP, SVG XSS, ZIP slip | 10+ |
| **Server Config** | .htaccess, web.config, nginx tricks | 10+ |
| **Template Payloads** | Custom YAML-based attacks | Varies |

**Total: 368+ attack payloads across 13 modules**

## 🎯 Vulnerability Detection

- ✅ Unrestricted file uploads
- ✅ Extension blacklist bypasses
- ✅ Content-Type validation bypasses
- ✅ Magic byte verification bypasses
- ✅ Double extension vulnerabilities
- ✅ Path traversal in filenames
- ✅ Null byte injection
- ✅ Race conditions (TOCTOU)
- ✅ XXE via SVG/XML/DOCX/XLSX
- ✅ GraphQL file upload mutations
- ✅ Unicode/RTLO evasion
- ✅ ZIP slip attacks
- ✅ Stored XSS via SVG upload
- ✅ Node.js module overwrite

## 🚀 Performance

- **368+ payloads** in <1s (localhost)
- **10 concurrent workers** by default
- **Scalable** to 50+ workers
- **Memory efficient** (<50MB)

## 📋 Requirements

- **Go 1.25** or higher
- **Internet connection** (for target access)

## 🤝 Contributing

- New payload modules
- Additional tech stack support
- Template contributions
- False positive reduction
- Documentation improvements

## 📄 License

MIT License - see [LICENSE](LICENSE)

## ⚠️ Disclaimer

This tool is for security professionals and penetration testers only. Always obtain proper authorization before testing any system. The author is not responsible for misuse or damage caused by this tool.

## 👤 Author

**@HaakimSec**
- GitHub: [github.com/HaakimSec](https://github.com/HaakimSec)

**⭐ If you find this tool useful, please star the repository!**
