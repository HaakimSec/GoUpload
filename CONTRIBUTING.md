# Contributing to GoUpload

Thanks for considering a contribution. GoUpload is developed and maintained by a small team, and community contributions — new payloads, bug fixes, documentation, and tech-stack support — are what keep it useful for the wider security community.

## Before you start

- **Authorization first.** This is an offensive security tool. Any code, payload, or example you contribute should assume it will only be run against systems the user is authorized to test. Don't add examples that reference real, non-test targets.
- **Check open issues** before starting significant work, to avoid duplicate effort. Small fixes (typos, obvious bugs) don't need an issue first.
- **For larger changes** (new modules, architectural changes, breaking changes to flags or output formats), open an issue to discuss the approach before submitting a PR. This saves you from doing work that might not fit the project's direction.

## Ways to contribute

- **New payload modules or additions to existing modules** — see [docs/adding-new-payloads.md](docs/adding-new-payloads.md)
- **New attack templates** (YAML-based) — see [docs/adding-new-templates.md](docs/adding-new-templates.md)
- **Additional tech-stack support** (fingerprinting signatures, stack-specific payloads)
- **Bug fixes** — check [docs/known-issues.md](docs/known-issues.md) and open GitHub issues for known, unclaimed bugs
- **False positive reduction** — improvements to `internal/oracle`'s detection heuristics
- **Documentation** — the `docs/` directory, this file, or the README
- **Tests** — several packages (e.g. `internal/validator`) currently have no test coverage; PRs adding tests are always welcome even without an accompanying feature change

## Development setup

```bash
git clone https://github.com/HaakimSec/GoUpload.git
cd GoUpload
go build ./...
```

Run the full test suite before submitting:

```bash
go test ./...
```

Scope tests to the package you're working on while iterating:

```bash
go test -v ./internal/oracle/...
```

Run `go vet ./...` and `gofmt -l .` before opening a PR — CI (or a reviewer) will flag anything these catch, so it's faster to check locally first.

## Project structure

A quick orientation before you dive in — see [docs/architecture.md](docs/architecture.md) for the full picture:

| Package | Responsibility |
|---|---|
| `internal/app` | Scan lifecycle orchestration |
| `internal/config` | CLI flag parsing and validation |
| `internal/payload` | Attack payload definitions and module registry |
| `internal/worker` | HTTP execution layer (the request pool) |
| `internal/oracle` | Detection heuristics and verdict/summary logic |
| `internal/types` | Shared result model passed between packages |
| `internal/output` | Terminal and JSON reporting |
| `internal/fingerprint` | Target tech-stack detection |
| `internal/validator` | Target reachability checks |
| `internal/discovery` | Upload form discovery via HTML parsing |
| `internal/template` | YAML attack template loading and matching |
| `internal/verifier` | RCE verification on flagged findings |
| `internal/ml` | ML client and feature extraction (optional, experimental) |

## Coding conventions

- Standard Go formatting (`gofmt`) — no exceptions.
- Wrap errors with context using `%w`, not `%v` — this preserves the error chain for callers and diagnostics. Don't discard an error's detail down to a bare boolean, count, or unwrapped string; if you're adding a new error path, make sure the caller can actually see what went wrong, not just that something did.
- Keep concurrency-sensitive code (anything touching the worker pool or shared printer state) guarded by the existing mutex patterns — don't introduce new shared state without a lock.
- New CLI flags: add both the `Config` struct field and the `flag.*Var` registration in the same PR, and document the flag in the README's flag reference table.
- New output fields (on `Result`, `SummaryStats`, or JSON structs): add appropriate `json:"...,omitempty"` tags so older consumers of `--output json` degrade gracefully rather than breaking.

## Submitting a pull request

1. Fork the repo and create a branch from `main` (`feature/your-change` or `fix/short-description`).
2. Keep PRs focused — one module, one bug fix, or one doc update per PR. Large, mixed PRs are harder to review and more likely to stall.
3. Include a short description of *what* changed and *why*, and how you tested it (a command you ran, a test you added, or a target/lab you validated against).
4. Make sure `go build ./...`, `go vet ./...`, and `go test ./...` all pass locally before opening the PR.
5. Be responsive to review feedback — most requests are about matching existing conventions (see above) rather than rejecting the contribution outright.

## Adding a new payload module

If you're adding an entirely new attack module (not just new payloads within an existing one), at minimum you'll touch:

- `internal/payload/modules.go` — register the module in `ModuleInfo` (name, description, `TestType`, enabled flag)
- The payload-generation function itself, wired into whatever dispatches `TestType` to its generator
- The README's module table and `--list-modules` output should match — if they don't, that's a bug (see the polyglot/server-config registration issue in `docs/known-issues.md` for a real example of what happens when this wiring is incomplete)

Full walkthrough: [docs/adding-new-payloads.md](docs/adding-new-payloads.md)

## Reporting bugs

Open a GitHub issue with:
- The command you ran (redact any real target URLs/tokens)
- What you expected vs. what happened
- Your Go version (`go version`) and OS
- If it's a crash or unexpected output, the relevant terminal output — run with `--debug` if the issue involves failed tests, since it surfaces the full error chain rather than just a summary count

## Questions

If something's unclear or you're not sure whether a change fits the project, open an issue and ask before investing significant time. That's what issues are for.

Thanks again for contributing.