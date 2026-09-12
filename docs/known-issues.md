# Known Issues

## v1.8.2 - Resolved

### ✅ Server-Config Module (FIXED)
- **Root Cause:** `moduleServerConfig()` didn't exist and was never called in `AllPayloads()`
- **Fix:** Added `module.server_config.go` + wired in generator (tech-agnostic)
- **Payloads:** 42 (.htaccess, web.config, .user.ini, nginx, lighttpd, tomcat, nodejs)

### ✅ Polyglot Module (FIXED)
- **Root Cause:** `moduleF()` was only called for `php` and `default` tech stacks
- **Fix:** Moved polyglot out of the tech switch — now runs for all stacks
- **Payloads:** 11 (GIF/PNG/JPEG/WebP+PHP, SVG XSS/XXE, PDF JS, ZIP slip, ZIP bomb, HTML)

### ✅ GraphQL Registry (FIXED)
- **Root Cause:** Registry entry `graphql` pointed to `TestTypeExtensionEvasion`
- **Fix:** Corrected to `TestTypeGraphQL`
- **Impact:** `--module graphql` now correctly filters to GraphQL payloads

## v1.8.2 - Current

No known issues.