# Oracle System - Intelligent Vulnerability Detection

## Overview

The Oracle is GoUpload's decision engine that determines whether a file upload attempt was successful and exploitable. Unlike simple scanners that check only HTTP status codes, GoUpload uses a **baseline comparison model** inspired by scientific testing methodology.

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│ Oracle System                                           │
├─────────────────────────────────────────────────────────┤
│ Baseline Upload → Test Payloads                         │
│   (safe file)         (suspicious files)                │
│       ↓                       ↓                         │
│ Baseline Metrics      Response Metrics                  │
│ - Status Code         - Status Code                     │
│ - Response Length     - Response Length                 │
│ - Content-Type        - Content-Type                    │
│ - Body Snippet        - Body Snippet                    │
│       ↓                       ↓                         │
│ └──────────┬────────────┘                               │
│            │                                            │
│            ↓                                            │
│     Oracle Analysis                                     │
│     - Status comparison                                 │
│     - Length ratio                                      │
│     - Pattern matching                                  │
│     - Flag scoring                                      │
│            ↓                                            │
│         Verdict                                         │
│ VULNERABLE / SUSPECT / SAFE / ERROR                     │
└─────────────────────────────────────────────────────────┘
```

## How It Works

### 1. Baseline Establishment

```bash
# Establish baseline with safe file
./GoUpload -u http://target.com/upload --allow-list .txt,.jpg
```

The baseline uploads a benign file (e.g., baseline_test.txt) and records:

- HTTP Status Code

- Response Body Length

- Content-Type Header

- Body Content Snippet

### 2. Test Payload Comparison

Each test payload's response is compared against the baseline:

```go
// Response length similarity check
ratio := testResponse.Length / baseline.Length
if ratio > 0.9 && ratio < 1.1 {
    // Suspicious: same handler processed both files
}
```

### 3. Multi-Flag Analysis

The oracle checks 9 different indicators:

| Flag | Description |
| :--- | :--- |
| `suspicious-ext-accepted` | Executable extension returned success |
| `response-length-matches-baseline` | Same handler processed the file |
| `status-matches-baseline` | Same HTTP status as safe file |
| `json-indicates-success` | API returned success indicator |
| `filename-reflected-in-response` | Server echoed filename back |
| `html-indicates-success` | Page contains "uploaded successfully" |
| `filepath-disclosed` | Server revealed file storage path |
| `spoofed-content-accepted` | MIME spoof accepted |
| `traversal-filename-accepted` | Path traversal in filename accepted |

### 4. Verdict Determination

```text 
Flags collected → Confidence scoring → Verdict

VULNERABLE: High-confidence flags + supporting evidence
SUSPECT:    Some flags but low confidence
SAFE:       No suspicious flags
ERROR:      Request failed
```

### Without Baseline (Heuristic Mode)

When no `--allow-list` is provided, the oracle operates in heuristic mode:

```bash
./GoUpload -u http://target.com/upload -p file
# Uses pattern matching only (less accurate)
```

With baseline:

```bash
./GoUpload -u http://target.com/upload --allow-list .txt,.jpg
# Full comparative analysis (more accurate)
```

### Adding New Detection Rules

To add a new oracle check:

- Add flag constant in `oracle.go`

- Add detection logic in `Analyze()`

- Add flag to `determineVerdict()`

- Update confidence scoring

```Go
// Example: New check for redirect detection
if result.StatusCode == 302 && isSuspiciousExt {
    flags = append(flags, "redirect-with-suspicious-ext")
}
```

