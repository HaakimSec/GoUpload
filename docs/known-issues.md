# Known Issues

## v1.7.0 Issues

### Server-Config Module (Empty)
- **Severity:** High
- **Impact:** Cannot test server configuration exploits
- **Reproduction:** `./GoUpload --module server-config` → 0 payloads
- **Fix:** Create `module.server_config.go`

### Polyglot Module (Empty)
- **Severity:** Medium
- **Impact:** Cannot test ImageMagick exploits
- **Reproduction:** `./GoUpload --module polyglot` → 0 payloads
- **Fix:** Verify module registration

## Fixed in v1.7.1
- [ ] Server-config module
- [ ] Polyglot module
