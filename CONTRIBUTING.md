# Contributing to RepoCanary

Contributions are welcome.

## Development setup

```bash
git clone https://github.com/OldenNedlo/RepoCanary.git
cd RepoCanary
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Pull requests

Please keep pull requests focused.

For new checks:

- explain the repository-maintenance problem
- include tests
- avoid destructive behavior
- keep the default scanner read-only
- document false-positive risks
- prefer the Python standard library when practical

## Reporting bugs

Please include your Python version, operating system, command used, expected result, actual result, and a minimal reproduction when possible.
