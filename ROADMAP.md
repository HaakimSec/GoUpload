# GoUpload Feature Implementation Plan

## 🗺️ Roadmap Overview

| Version | Theme | Status |
|---------|-------|--------|
| v1.0.0 | Initial Release | ✅ Complete |
| v1.1.0 | GraphQL & Validation | ✅ Complete |
| v1.2.0 | Nuclei Templates | ✅ Complete |
| v1.3.0 | JSON Output & Module Selection | ✅ Complete |
| v1.4.0 | Race Condition & Advanced Attacks | 🔄 In Progress |
| v1.5.0 | Cloud & Storage | 🔲 Planned |
| v1.6.0 | AI & Automation | 🔲 Planned |
| v1.7.0 | Enterprise | 🔲 Planned |

---

## v1.4.0 - Advanced Attacks

### ✅ Feature 2.1: Race Condition Testing
**Status:** ✅ Complete
**Files:** `module.race.go`, `oracle.go`, `pool.go`, `app.go`

### 🔲 Feature 2.2: Chunked Upload Bypass
**Status:** 🔲 Not Started
**Files to Create/Modify:**
- `internal/worker/chunked.go` (NEW)
- `internal/payload/module.chunked.go` (NEW)

### 🔲 Feature 2.3: Image Metadata Payloads
**Status:** 🔲 Not Started
**Files to Create/Modify:**
- `internal/payload/module.metadata.go` (NEW)

### 🔲 Feature 2.4: Server-Specific Payloads
**Status:** 🔲 Not Started
**Files to Create/Modify:**
- `internal/payload/module.server_specific.go` (NEW)

---

## v1.5.0 - Cloud & Storage

### 🔲 Feature 3.1: S3 Bucket Testing
### 🔲 Feature 3.2: Azure Blob Testing
### 🔲 Feature 3.3: GCP Storage Testing
### 🔲 Feature 3.4: CloudFront/WAF Bypass
### 🔲 Feature 3.5: Signed URL Manipulation

---

## v1.6.0 - AI & Automation

### 🔲 Feature 4.1: Auto-Exploitation with Callbacks
### 🔲 Feature 4.2: AI-Powered Payload Generation
### 🔲 Feature 4.3: Intelligent Rate Limiting
### 🔲 Feature 4.4: Session Auto-Renewal
### 🔲 Feature 4.5: LLM Integration

---

## v1.7.0 - Enterprise

### 🔲 Feature 5.1: CI/CD Integration
### 🔲 Feature 5.2: Authentication Profiles
### 🔲 Feature 5.3: Multi-Target Scanning
### 🔲 Feature 5.4: Scheduled Scans
### 🔲 Feature 5.5: Role-Based Access

---

## 🎯 Immediate Priority (v1.4.0 Completion)

| # | Feature | Impact | Effort |
|---|---------|--------|--------|
| 1 | Chunked Upload Bypass | High | Medium |
| 2 | Image Metadata Payloads | High | Medium |
| 3 | Server-Specific Payloads | Medium | Low |
| 4 | WebSocket Upload Testing | Medium | Low |
| 5 | Auto-Exploitation Callbacks | Critical | High |

---

## 📋 Quick Reference

### Add New Module Checklist:
1. Create `internal/payload/module.X.go`
2. Add `TestType` to `generator.go`
3. Register in `modules.go`
4. Add to `AllPayloads()` in `generator.go`
5. Add to `moduleOrder` & `moduleNames` in `app.go`
6. Update oracle in `oracle.go`
7. Add to `--list-modules` in `config.go`
8. Add to `--module` flag description
