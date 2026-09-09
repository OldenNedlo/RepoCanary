# RepoCanary

RepoCanary is a small, local-first command-line tool for open-source maintainers. It scans a repository for common maintenance and release-readiness problems without uploading repository contents.

## Checks

- missing `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`
- suspicious sensitive filenames such as `.env`, private keys, and credential files
- broken relative Markdown links
- GitHub Actions using moving refs such as `@main` or `@latest`
- unconstrained Python requirements
- unusually large files

## Install

Requires Python 3.10+.

```bash
python -m pip install -e .
```

## Use

```bash
repocanary scan .
repocanary scan . --json report.json
repocanary scan . --fail-on high
```

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).
