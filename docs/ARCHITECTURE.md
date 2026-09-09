# Architecture

RepoCanary is deliberately small. The current architecture has four layers:

1. **CLI (`cli.py`)** resolves command-line arguments and output destinations.
2. **Policy (`config.py`)** loads optional repository-local configuration.
3. **Checks (`scanner.py`)** walk the repository and emit structured `Finding` objects.
4. **Release readiness (`release.py`)** composes the normal scan with release-specific repository checks.

## Data flow

```text
repository path
    |
    +--> optional .repocanary.json
    |
    +--> scanner --------------------+
    |                                |
    +--> release-check (optional)    |
                                     v
                               ScanResult
                                     |
                    +----------------+----------------+
                    |                |                |
                 console          JSON/MD           SARIF
```

## Check contract

Each finding carries a stable check identifier, severity, message, optional path/line, and optional remediation guidance.

Checks should remain deterministic where practical and avoid network access by default.

## Scope boundaries

RepoCanary does not claim to replace dedicated SAST, secret scanning, dependency-vulnerability scanning, or malware analysis. Its role is repository-maintenance preflight and release hygiene.

## Extension direction

Future checks should be small, testable, explainable, and independently disableable.
