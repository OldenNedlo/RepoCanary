# RepoCanary

[![CI](https://github.com/OldenNedlo/RepoCanary/actions/workflows/ci.yml/badge.svg)](https://github.com/OldenNedlo/RepoCanary/actions/workflows/ci.yml)

RepoCanary is a local-first repository health and release-readiness scanner for open-source maintainers. It turns common maintenance checks into one repeatable command, with output suitable for humans, automation, and security tooling.

RepoCanary is intentionally conservative: it is read-only, makes no network calls during a scan, and treats findings as review signals rather than proof of a vulnerability or defect.

## Why RepoCanary exists

Open-source maintainers routinely carry work that falls between feature development and dedicated security tooling: community-file hygiene, release preparation, CI review, dependency-policy checks, stale documentation, accidentally tracked sensitive files, and the small maintenance failures that accumulate until release day.

RepoCanary provides a lightweight first-pass guardrail that can run locally or in CI without requiring a hosted service.

## Current capabilities

- community-health checks for `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and code of conduct files
- suspicious sensitive-filename detection for common environment, credential, and private-key names
- broken relative Markdown-link detection
- GitHub Actions checks for moving refs such as `@main` and `@latest`
- unconstrained Python requirement detection
- large-file warnings
- TODO/FIXME inventory from comment lines
- configurable ignore patterns and severity policy via `.repocanary.json`
- JSON, Markdown, and SARIF 2.1.0 output
- release-readiness checks for changelog, CI, tests, version metadata, PR template, and dependency-maintenance configuration

## Install

RepoCanary requires Python 3.10 or newer and has no runtime dependencies outside the Python standard library.

```bash
python -m pip install -e .
```

## Quick start

```bash
repocanary scan .
repocanary scan . --json repocanary.json --markdown repocanary.md --sarif repocanary.sarif
repocanary release-check . --fail-on medium
```

Use a repository policy file named `.repocanary.json`:

```json
{
  "large_file_mib": 8,
  "fail_on": "medium",
  "ignore": ["vendor/**", "fixtures/**"]
}
```

## Maintainer workflows

RepoCanary is designed for pre-PR checks, CI gating, release preparation, security triage, and documentation maintenance. See [Maintainer Workflows](docs/MAINTAINER_WORKFLOWS.md).

## Design principles

- local-first and read-only by default
- no source-code upload required
- dependency-light operation
- explicit severity and CI exit behavior
- machine-readable output alongside human reports
- explainable checks with bounded scope
- false positives are review signals, not verdicts
- security tooling should fail visibly rather than silently rewriting a repository

See [Architecture](docs/ARCHITECTURE.md) and [Security Model](docs/SECURITY_MODEL.md).

## Development

```bash
python -m unittest discover -s tests -v
repocanary scan . --fail-on high
repocanary release-check . --fail-on medium
```

## Project status

RepoCanary is early-stage and actively being developed. The project does not claim large adoption or production use that has not been measured. See [ROADMAP.md](ROADMAP.md) and [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) and [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## License

MIT. See [LICENSE](LICENSE).
