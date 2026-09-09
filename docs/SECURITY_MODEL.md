# Security Model

RepoCanary is designed to inspect untrusted repositories with a narrow, read-only default posture.

## Current trust boundaries

- RepoCanary reads files under the repository path.
- It does not execute repository code as part of scanning.
- It does not make network requests during a scan.
- It does not rewrite or delete repository files.
- It does not require repository secrets or GitHub tokens for local use.

## Threats considered

### Accidental secret tracking

RepoCanary flags common credential/private-key filenames. This is a heuristic, not a full secret scanner.

### Malicious repository contents

RepoCanary treats repository text as data. Checks avoid `eval`, shell execution, and importing scanned project modules.

### Resource exhaustion

Very large repositories or files can increase scan time. The scanner skips common generated directories and exposes ignore patterns.

### Supply-chain risk

The runtime currently uses the Python standard library only. Build tooling still depends on the normal Python packaging toolchain.

## Reporting a vulnerability

Follow [SECURITY.md](../SECURITY.md).

## Non-goals

RepoCanary is not a substitute for dedicated secret scanning, SAST/DAST, dependency vulnerability databases, sandboxing untrusted executables, or professional security review.

A clean RepoCanary report is not a security guarantee.
