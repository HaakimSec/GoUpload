# GoUpload 🚀

**Web Application File Upload Security Tester**

A high-performance, concurrent file upload vulnerability scanner written in Go. Tests for 107+ file upload vulnerabilities including extension bypass, content-type spoofing, magic bytes, path traversal, and more.

![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.0-blue)

## ⚡ Features

- 🎯 **Smart Fingerprinting** - Auto-detects target tech stack (PHP, ASP.NET, Java, Node.js)
- 🧪 **107+ Payloads** - Comprehensive test matrix across 7 attack modules
- 🚀 **Blazing Fast** - Concurrent testing with configurable workers (107 tests in <200ms)
- 🎨 **Beautiful Output** - Rainbow ASCII art banner with colored results
- 🔍 **Intelligent Detection** - Multi-flag oracle system for accurate vulnerability assessment
- 📊 **Baseline Comparison** - Compares responses against legitimate uploads
- 🌍 **Cross-Platform** - Works on Linux, Windows, and macOS

## 📦 Installation

### Method 1: Go Install (Recommended)
```bash
go install -v github.com/HaakimSec/GoUpload@latest
```
After installation, run:

```bash
GoUpload --help
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

Download the pre-compiled binary from [Releases](https://github.com/HaakimSec/GoUpload/releases):

```bash
# Linux (amd64)
wget https://github.com/HaakimSec/GoUpload/releases/download/v1.0.0/GoUpload_linux_amd64
chmod +x GoUpload_linux_amd64
sudo mv GoUpload_linux_amd64 /usr/local/bin/GoUpload

# macOS (amd64)
wget https://github.com/HaakimSec/GoUpload/releases/download/v1.0.0/goupload_darwin_amd64
chmod +x GoUpload_darwin_amd64
sudo mv GoUpload_darwin_amd64 /usr/local/bin/GoUpload

# Windows (amd64)
# Download GoUpload_windows_amd64.exe from Releases
```

### Verify Installation

```bash
GoUpload --help
```
You should see the rainbow ASCII art banner! 🌈

## 🛠️ Usage

```text
GoUpload -u <URL> -p <param> [flags]

Flags:
  -u, --url          Target upload endpoint URL (required)
  -p, --param        Name of the file parameter (default: "file")
  -t, --tech         Target tech stack: php, asp.net, java, nodejs, python, all, auto
      --auto-detect  Auto-detect tech stack before testing
  -c, --concurrency  Number of concurrent workers (default: 10)
      --allow-list   Comma-separated allowed extensions for baseline
  -H, --headers      Custom headers (key:value or JSON file)
  -d, --data         Additional form fields (key=value)
  -h, --help         Show help
  ```

  ## 🔍 Example Output

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

 SUMMARY
    Total Tests:           68
    Safe:                  0
    Suspect:               3
    Vulnerable:            65
    Errors:                0
    Avg Response Time:     0.010s
    Total Elapsed:         185ms

 ⚠  Potential vulnerabilities detected — manual verification recommended!
 ```
## 🎯 Vulnerability Detection


### GoUpload detects:

- ✅ Unrestricted file uploads

- ✅ Extension blacklist bypasses

- ✅ Content-Type validation bypasses

- ✅ Magic byte verification bypasses

- ✅ Double extension vulnerabilities

- ✅ Path traversal in filenames

- ✅ Null byte injection

- ✅ File size restriction bypasses

- ✅ Stored XSS via file upload

- ✅ ZIP slip attacks

- ✅ Unicode/RTLO evasion

## 🔬 Tested Against

- ✅ Custom Vulnerable Lab (PHP/Apache)

- ✅ DVWA (Damn Vulnerable Web Application)

- ✅ Juice Shop (OWASP)

- ✅ Upload-Labs (GitHub)


## 🏗️ Architecture

```text
GoUpload/
├── main.go                    # Entry point
├── internal/
│   ├── config/                # CLI parsing & configuration
│   ├── fingerprint/           # Tech stack auto-detection
│   ├── oracle/                # Vulnerability analysis engine
│   ├── output/                # Terminal output & formatting
│   ├── payload/               # Attack payloads (7 modules)
│   ├── types/                 # Data structures
│   └── worker/                # Concurrent HTTP worker pool
├── go.mod
└── go.sum
```

## 🚀 Performance

- **107 payloads** in ~200ms (localhost)

- **10 concurrent workers** by default

- **Scalable** to 50+ workers for network targets

- **Memory efficient** (<50MB for full scan)

## 📋 Requirements

- Go 1.25 or higher

- Internet connection (for target access)

## 🤝 Contributing
Contributions are welcome! Areas for improvement:

- New payload modules

- Additional tech stack support

- False positive reduction

- Output format options (JSON, XML, CSV)

## 📄 License
MIT License - see [LICENSE](https://license/) file

## ⚠️ Disclaimer

This tool is for security professionals and penetration testers only. Always obtain proper authorization before testing any system. The author is not responsible for misuse or damage caused by this tool.

## 👤 Author
**@haakimsec**


**GitHub**: github.com/HaakimSec

**⭐ If you find this tool useful, please star the repository!**
