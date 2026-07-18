# GoUpload 🚀

**Web Application File Upload Security Tester**

A high-performance, concurrent file upload vulnerability scanner written in Go. Tests for 200+ file upload vulnerabilities including extension bypass, content-type spoofing, magic bytes, path traversal, GraphQL uploads, and more.

![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.1.0-blue)

## ⚡ Features

- 🎯 **Smart Fingerprinting** - Auto-detects target tech stack (PHP, ASP.NET, Java, Node.js, Python)
- 🧪 **200+ Payloads** - Comprehensive test matrix across 8 attack modules
- 📡 **GraphQL Support** - Tests GraphQL file upload mutations with custom mutation strings
- 🔧 **Module Overwrite Attacks** - Node.js module overwrite for RCE via path traversal
- 🚀 **Blazing Fast** - Concurrent testing with configurable workers (200+ tests in <500ms)
- 🎨 **Beautiful Output** - Rainbow ASCII art banner with colored results
- 🔍 **Intelligent Detection** - Multi-flag oracle system with GraphQL-specific response analysis
- 📊 **Baseline Comparison** - Compares responses against legitimate uploads
- ✅ **Target Validation** - Validates URLs before testing to avoid wasted scans
- 🛡️ **WAF/CloudFront Aware** - Detects 504 errors and gateway timeouts
- 🌍 **Cross-Platform** - Works on Linux, Windows, and macOS

## 📦 Installation

### Method 1: Go Install (Recommended)
```bash
go install -v github.com/HaakimSec/GoUpload@latest
```

### Post-Installation Setup (Add to PATH)
If your terminal says `GoUpload: command not found` after installation, it means your Go binary directory is not in your system's PATH.

Run the appropriate command below for your terminal shell to fix this instantly:

#### For Bash (Default on Ubuntu/Debian):

```Bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

#### For Zsh (Default on Kali Linux/macOS):

```Bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc
```
##### Verification

To verify the installation worked, open a new terminal window and run:

```Bash
GoUpload -h
```

### Method 2: Build from Source

```bash 
# Clone the repository
git clone https://github.com/HaakimSec/GoUpload.git
cd GoUpload

# Build
go build -o GoUpload main.go

# Move to PATH (optional)
sudo mv GoUpload /usr/local/bin/
```

### Method 3: Download Binary

Download the pre-compiled binary from Releases:

```bash
# Linux (amd64)
wget https://github.com/HaakimSec/GoUpload/releases/download/v1.1.0/GoUpload_linux_amd64
chmod +x GoUpload_linux_amd64
sudo mv GoUpload_linux_amd64 /usr/local/bin/GoUpload

# macOS (amd64)
wget https://github.com/HaakimSec/GoUpload/releases/download/v1.1.0/GoUpload_darwin_amd64
chmod +x GoUpload_darwin_amd64
sudo mv GoUpload_darwin_amd64 /usr/local/bin/GoUpload
```

### Verify Installation

```bash
GoUpload --help
```
You should see the rainbow ASCII art banner! 🌈


## 🛠️ Usage

### Basic Scanning

```bash 
# Basic scan
GoUpload -u http://target.com/upload -p file

# Auto-detect tech stack (recommended)
GoUpload -u http://target.com/upload --auto-detect

# Target specific tech stack
GoUpload -u http://target.com/upload --tech nodejs

# Full scan with baseline comparison
GoUpload -u http://target.com/upload -p file --allow-list ".txt,.jpg,.png" -c 20

# Quick target validation only
GoUpload --check -u http://target.com/upload
```
### GraphQL Upload Testing

```bash
# Basic GraphQL mutation test
GoUpload -u https://api.target.com/graphql \
  --graphql-mutation 'mutation($file:Upload!){uploadFile(file:$file){id}}' \
  --graphql-variable "file"

# GraphQL with authentication
GoUpload -u https://api.target.com/graphql \
  -H "Cookie: jwt=TOKEN" \
  -H "Authorization: Bearer TOKEN" \
  --graphql-mutation 'mutation($file:Upload!){uploadFile(file:$file){id filename}}' \
  --tech nodejs

# GraphQL custom mutation with specific operation
GoUpload -u https://api.target.com/graphql \
  -H "Authorization: Bearer TOKEN" \
  --graphql-mutation 'mutation($input:FileInput!){importDocument(input:$input){id name}}' \
  --graphql-variable "input"

# GraphQL module overwrite attack
GoUpload -u https://api.target.com/graphql \
  -H "Cookie: jwt=TOKEN" \
  --graphql-mutation 'mutation($file:Upload!){uploadFile(file:$file){id}}' \
  --tech nodejs \
  --module-overwrite \
  --module-path "../../apps/" \
  --no-validate
```

### Advanced Usage 

```bash 
# With custom headers (JWT, API keys, bug bounty)
GoUpload -u http://target.com/upload \
  -H "Authorization: Bearer TOKEN" \
  -H "Bug-Bounty: researcher@example.com"

# Skip validation for external targets
GoUpload -u https://target.com/upload --no-validate

# High-concurrency scan
GoUpload -u http://target.com/upload -c 50 --auto-detect
```
### Full Flag Reference 

```text
Flags:
  -u, --url              Target upload endpoint URL (required)
  -p, --param            Name of the file parameter (default: "file")
  -t, --tech             Target tech stack: php, asp.net, java, nodejs, python, all, auto
      --auto-detect      Auto-detect tech stack before testing
  -c, --concurrency      Number of concurrent workers (default: 10)
      --allow-list       Comma-separated allowed extensions for baseline
  -H, --headers          Custom headers (key:value or JSON file)
  -d, --data             Additional form fields (key=value)
      --check, -C        Only validate target connectivity (no payloads)
      --no-validate      Skip target validation before testing
      --graphql-mutation Custom GraphQL mutation string
      --graphql-variable GraphQL variable name for file (default: "file")
      --module-overwrite Enable Node.js module overwrite payloads
      --module-path      Base path for module overwrite traversal (default: "../../")
  -h, --help             Show help
  ```

```plaintext
<pre align="center">
  ____        _   _       _                 _
 / ___| ___  | | | |_ __ | | ___   __ _  __| |
| |  _ / _ \ | | | | '_ \| |/ _ \ / _` |/ _` |
| |_| | (_) || |_| | |_) | | (_) | (_| | (_| |
 \____|\___/  \___/| .__/|_|\___/ \__,_/\__,_|
                   |_|

  ⚡ Web Application File Upload Security Tester ⚡
</pre>
```

```text
  🔍 Validating target...
  ✅ Target is reachable

  🎯 Targeting: NODEJS
  🧪 Payloads: 7 (filtered for nodejs stack)

  ┌─ MODULE A: Extension Evasion Matrix
  │
  ████████████████████ [100%] 7/7 (2m31s)

  SUMMARY
    Total Tests:           7
    Safe:                  0
    Suspect:               3
    Vulnerable:            4
    Errors:                0
    Avg Response Time:     21.566s
    Total Elapsed:         2m31s

  ⚠  Potential vulnerabilities detected — manual verification recommended!
  ```

  ## 📚 Attack Modules

| Module | Description | Payloads |
|--------|-------------|:--------:|
| 🔤 **A - Extension Evasion** | Alternative extensions (.php5, .phtml), case variations, double extensions | 20+ |
| 📋 **B - Content-Type Spoof** | MIME type manipulation, magic byte injection (GIF, PNG, JPEG, PDF) | 30+ |
| 🎭 **C - Filename Obfuscation** | Trailing spaces/dots, null bytes, special characters, NTFS streams | 25+ |
| 🗂️ **D - Path Traversal** | Directory traversal sequences, URL encoding, absolute paths | 20+ |
| 📏 **E - Size Boundaries** | File size edge cases, ZIP bombs, tiny shells | 15+ |
| 🦄 **F - Polyglot & Archives** | GIF+PHP polyglots, SVG XSS, ZIP slip attacks | 10+ |
| 🌍 **G - Unicode Attacks** | RTLO, zero-width chars, homograph attacks, normalization bypass | 40+ |
| 📡 **GraphQL Module** | Custom mutations, module overwrite, batch uploads, Content-Type spoofing | 138+ |

**Total: 298+ attack payloads across 8 modules**

## 🎯 Vulnerability Detection

**GoUpload detects:**

- ✅ Unrestricted file uploads

- ✅ Extension blacklist bypasses (.php5, .phtml, .phar)

- ✅ Content-Type validation bypasses

- ✅ Magic byte verification bypasses (GIF89a, PNG, JPEG, PDF)

- ✅ Double extension vulnerabilities

- ✅ Path traversal in filenames

- ✅ Null byte injection (.php%00.jpg)

- ✅ File size restriction bypasses

- ✅ Stored XSS via file upload (SVG, HTML)

- ✅ ZIP slip attacks

- ✅ Unicode/RTLO evasion

- ✅ GraphQL file upload mutations (NEW)

- ✅ Node.js module overwrite attacks (NEW)

- ✅ CloudFront/WAF gateway timeout detection (NEW)

## 🚀 Performance

- **200+ payloads** in ~500ms (localhost)

- **10 concurrent workers** by default

- **Scalable** to 50+ workers for network targets

- **Memory efficient** (<50MB for full scan)

- **GraphQL payloads** filtered by tech stack for faster scanning

## 📋 Requirements

- **Go 1.25** or higher

- **Internet connection** (for target access)

## 🤝 Contributing

- Contributions are welcome! Areas for improvement:

- New payload modules

- Additional tech stack support

- False positive reduction

- Output format options (JSON, XML, CSV)

- Template system for custom attack profiles

- Community template repository


## 📄 License
MIT License - see [LICENSE](https://license/) file

## ⚠️ Disclaimer
This tool is for security professionals and penetration testers only. Always obtain proper authorization before testing any system. The author is not responsible for misuse or damage caused by this tool.
  
## 👤 Author

@HaakimSec

GitHub: [github.com/HaakimSec](https://github.com/HaakimSec)

**⭐ If you find this tool useful, please star the repository!**

