# Development Guide

## Adding a New Attack Module

1. Create `internal/payload/module.h.go`
2. Implement `moduleH() []*Payload` function
3. Register in `generator.go` → `AllPayloads()`
4. Add to `main.go` → `moduleOrder` & `moduleNames`

## Adding a New Template

1. Create YAML file in `templates/[category]/`
2. Follow [TEMPLATES.md](TEMPLATES.md) format
3. Test with `GoUpload --template templates/[category]/new.yaml`

## Adding a New Matcher Type

1. Add case to `evaluateMatcher()` in `matcher.go`
2. Implement `matchXxx()` function
3. Document in [TEMPLATES.md](TEMPLATES.md)

## Code Style

- Run `gofmt -w .` before committing
- Keep comments minimal (code should be self-documenting)
- Follow existing patterns for new modules
