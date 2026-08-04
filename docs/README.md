# GoUpload Documentation

## Quick Links

| Document | Description |
|----------|-------------|
| [USAGE.md](USAGE.md) | Full command reference and examples |
| [TEMPLATES.md](TEMPLATES.md) | How to write attack templates |
| [MODULES.md](MODULES.md) | Attack modules reference |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Quick Start

```bash
# Install
go install github.com/HaakimSec/GoUpload@latest

# Basic scan
GoUpload -u http://target.com/upload -p file --auto-detect

# With template
GoUpload --template templates/labs/battle-lab.yaml -u http://target.com/upload


