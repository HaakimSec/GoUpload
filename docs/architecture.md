# GoUpload Architecture

## High-Level Overview

```text 
┌──────────────────────────────────────────────────────────┐
│ main.go │
│ (Entry Point) │
└──────────────────────┬───────────────────────────────────┘
│
┌──────────────────────▼───────────────────────────────────┐
│ internal/app/ │
│ (Application Orchestrator) │
└──────────────────────┬───────────────────────────────────┘
│
┌──────────────┼──────────────┐
▼ ▼ ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ config/ │ │ payload/ │ │ worker/ │
│ CLI │ │ Attack │ │ HTTP │
│ Parsing │ │ Modules │ │ Pool │
└──────────┘ └──────────┘ └──────────┘
│ │
┌──────┘ └──────┐
▼ ▼
┌──────────┐ ┌──────────┐
│ oracle/ │ │ output/ │
│ Analysis │ │ Results │
└──────────┘ └──────────┘
```


## Package Responsibilities

| Package | Purpose |
|---------|---------|
| `main.go` | Parse config, create App, handle exit codes |
| `app/` | Orchestrate scan flow, coordinate components |
| `config/` | CLI flag parsing, validation, configuration |
| `payload/` | Attack payload generation (8+ modules) |
| `worker/` | Concurrent HTTP request execution |
| `oracle/` | Response analysis and verdict determination |
| `output/` | Terminal output, JSON reports, formatting |
| `template/` | YAML template loading and matcher engine |
| `fingerprint/` | Tech stack auto-detection |
| `validator/` | Target reachability and endpoint validation |

## Data Flow

```text
Config → App.Run()
├── Validate Target
├── Fingerprint Tech Stack
├── Load Templates (optional)
├── Select Modules (optional)
├── Generate Payloads
├── Establish Baseline (optional)
├── Execute Tests (worker pool)
│ └── Oracle Analysis (per result)
├── Print Results
├── JSON Output (optional)
└── Exit Code
```


## Key Design Decisions

### 1. Worker Pool Pattern
- Configurable concurrency
- Buffered channels prevent blocking
- Result handler callback for real-time output

### 2. Baseline/Oracle System
- Scientific control group approach
- Multi-flag analysis for accuracy
- Works in heuristic mode without baseline

### 3. Template Engine
- YAML-based attack profiles
- Nuclei-style regex matchers
- Extractors for data extraction

### 4. Module System
- Each attack type isolated in own file
- Module registry for enable/disable
- Unique TestType per module
