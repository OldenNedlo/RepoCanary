# Maintainer Workflows

RepoCanary is meant to remove small but recurring review chores from open-source maintenance.

## Pull-request preflight

```bash
repocanary scan . --fail-on high
```

## Stricter CI policy

Create `.repocanary.json`:

```json
{
  "fail_on": "medium",
  "large_file_mib": 8,
  "ignore": ["vendor/**", "fixtures/**"]
}
```

Then CI can run `repocanary scan .` and use the repository policy.

## Release preflight

```bash
repocanary release-check . --markdown release-readiness.md
```

This combines the normal scan with checks for CI, tests, changelog, version metadata, pull-request template, and dependency-maintenance configuration.

## Security tooling bridge

```bash
repocanary scan . --sarif repocanary.sarif
```

SARIF allows findings to move into compatible tooling without changing RepoCanary's local-first behavior.

## Triage philosophy

A RepoCanary finding is a review signal. Maintainers should confirm context before remediation. The project deliberately avoids silently editing a repository.
