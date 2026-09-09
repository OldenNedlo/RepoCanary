# RepoCanary Roadmap

RepoCanary aims to become a compact maintainer-side preflight tool rather than a replacement for full SAST, secret scanning, dependency security, or release platforms.

## v0.2 - structured maintainer output

- [x] SARIF output
- [x] repository policy file
- [x] release-readiness command
- [x] CI-friendly severity thresholds
- [x] maintainer/security documentation

## v0.3 - stronger release checks

- [ ] changelog/version consistency
- [ ] package metadata validation
- [ ] release artifact inventory
- [ ] configurable required community files
- [ ] path-scoped severity overrides

## v0.4 - ecosystem adapters

- [ ] Python lockfile and dependency-policy adapters
- [ ] Node package metadata adapter
- [ ] reusable GitHub Action
- [ ] optional remote Markdown link validation
- [ ] code-scanning upload example and integration tests

## v1.0 criteria

- stable configuration schema
- documented check IDs and severity semantics
- backward-compatible CLI contract
- reproducible release process
- tested Linux, macOS, and Windows behavior
- contributor-facing extension guide

Roadmap items are plans, not promises. Priorities may change based on maintainer and contributor feedback.
