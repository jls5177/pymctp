<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# Development Guide

This guide covers development workflows for the pymctp monorepo.

## Table of Contents

- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Building Packages](#building-packages)
- [Testing](#testing)
- [Formatting and Linting](#formatting-and-linting)
- [Publishing](#publishing)

## Quick Start

### Option 1: Using the install script (Recommended)

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install all packages in development mode
./scripts/install-dev.sh
```

### Option 2: Using Hatch

```bash
# Install hatch if you don't have it
pip install hatch

# Create environment and install all packages
hatch shell

# Or run a specific script
hatch run install-all
```

### Option 3: Manual installation

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install build dependencies
pip install build hatch twine pytest pytest-cov ruff reuse

# Install packages in development mode (in dependency order)
pip install -e packages/pymctp
pip install -e packages/pymctp-sample-vendorextension
pip install -e packages/pymctp-exerciser-aardvark
pip install -e packages/pymctp-exerciser-qemu
pip install -e packages/pymctp-exerciser-serial
```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- git
- Optional: hatch (for streamlined workflows)

### Install Development Dependencies

The root `pyproject.toml` defines all development dependencies needed across packages:

```bash
# If using a virtual environment
pip install -e .

# Or install specific dependency groups
pip install build hatch twine pytest pytest-cov ruff
```

### Verify Installation

```bash
# Check installed packages
pip list | grep pymctp

# Test the CLI
pymctp --version
pymctp --help

# Run a quick test
python -c "from pymctp.layers import mctp; print('Import successful!')"
```

## Building Packages

### Build All Packages

```bash
# Using the build script
./scripts/build-all.sh

# Or using hatch
hatch run build-all

# Or manually
for pkg in packages/pymctp packages/pymctp-sample-vendorextension packages/pymctp-exerciser-*; do
    cd "$pkg"
    python -m build
    cd -
done
```

Build artifacts are placed in each package's `dist/` directory.

### Build Individual Package

```bash
cd packages/pymctp
python -m build
```

### Clean Build Artifacts

```bash
# Using the clean script
./scripts/clean.sh

# Or manually
find . -type d -name "dist" -exec rm -rf {} +
find . -type d -name "*.egg-info" -exec rm -rf {} +
find . -type d -name "__pycache__" -exec rm -rf {} +
```

## Testing

### Run All Tests

```bash
# Using pytest directly
pytest

# With coverage
pytest --cov=pymctp --cov-report=html --cov-report=term

# Using hatch
hatch run test:run
hatch run test:cov
```

### Run Tests for Specific Package

```bash
# Test specific module
pytest tests/layers/mctp/

# Test specific file
pytest tests/layers/mctp/test_transport.py

# Test specific function
pytest tests/layers/mctp/test_transport.py::test_transport_hdr_decode
```

### Test Coverage

```bash
# Generate coverage report
pytest --cov=pymctp --cov-report=html

# View report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

## Formatting and Linting

### Format Code

```bash
# Format all packages
hatch run format-all

# Or using ruff directly
ruff format packages/
ruff check --fix packages/
```

### Check Code Style

```bash
# Check without fixing
ruff check packages/

# Check specific package
ruff check packages/pymctp/
```

### License Headers

All source files must include SPDX license headers:

```bash
# Check license compliance
reuse lint

# Add license headers to new files
cd packages/pymctp
hatch run add-license path/to/new/file.py
```

## Publishing

### Test PyPI (Recommended First)

```bash
# Build all packages
./scripts/build-all.sh

# Upload to TestPyPI
for pkg in packages/pymctp packages/pymctp-sample-vendorextension packages/pymctp-exerciser-*; do
    python -m twine upload --repository testpypi "$pkg/dist/*"
done

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ pymctp
```

### Production PyPI

```bash
# Build all packages
./scripts/build-all.sh

# Upload to PyPI
for pkg in packages/pymctp packages/pymctp-sample-vendorextension packages/pymctp-exerciser-*; do
    python -m twine upload "$pkg/dist/*"
done
```

**Note**: The `pymctp-oem-microsoft` package is not published publicly.

## Common Development Tasks

### Adding a New Package

1. Create package structure in `packages/`:
```bash
mkdir -p packages/your-package/src/your_package
cd packages/your-package
```

2. Create `pyproject.toml`:
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "your-package"
version = "0.1.0"
dependencies = ["pymctp>=0.2.0"]
```

3. Add to `scripts/build-all.sh`

4. Add to `scripts/install-dev.sh`

5. Install in development mode:
```bash
pip install -e packages/your-package
```

### Updating Dependencies

1. Update `pyproject.toml` in the affected package

2. Reinstall in development mode:
```bash
pip install -e packages/pymctp --force-reinstall
```

3. Update lock files if using them

### Running Scripts

The `scripts/` directory contains helper scripts:

- `build-all.sh` - Build all public packages
- `clean.sh` - Remove build artifacts
- `install-dev.sh` - Install all packages in development mode

All scripts should be run from the repository root:

```bash
./scripts/build-all.sh
```

## Hatch Commands

If you prefer using Hatch for development:

```bash
# Create/activate development environment
hatch shell

# Run tests
hatch run test:run

# Format code
hatch run format-all

# Install all packages
hatch run install-all

# Build all packages
hatch run build-all
```

## Troubleshooting

### Import Errors

If you get import errors after installing:

```bash
# Reinstall in development mode
pip install -e packages/pymctp --force-reinstall

# Check installation
pip list | grep pymctp
```

### Version Conflicts

If you have conflicting versions:

```bash
# Uninstall all pymctp packages
pip uninstall pymctp pymctp-sample-vendorextension pymctp-exerciser-aardvark pymctp-exerciser-qemu pymctp-exerciser-serial -y

# Reinstall
./scripts/install-dev.sh
```

### Build Failures

If builds fail:

```bash
# Clean all artifacts
./scripts/clean.sh

# Update build tools
pip install --upgrade build hatch twine

# Try building again
./scripts/build-all.sh
```

## Git Workflow

### Creating a Feature

```bash
git checkout development
git pull
git checkout -b feature/your-feature-name

# Make changes
# ...

# Test
pytest

# Commit
git add .
git commit -m "Add feature: your feature description"

# Push
git push origin feature/your-feature-name

# Create PR to development branch
```

### Committing Changes

Follow the commit message guidelines in [CONTRIBUTING.md](CONTRIBUTING.md).

## IDE Setup

### VSCode

Recommended extensions:
- Python
- Pylance
- Ruff

Settings (`.vscode/settings.json`):
```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll": true,
      "source.organizeImports": true
    }
  }
}
```

### PyCharm

1. Mark `packages/*/src` as Sources Root
2. Set Python interpreter to `.venv/bin/python`
3. Enable pytest as test runner
4. Configure Ruff as external tool

## Additional Resources

- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [EXTENSIONS.md](EXTENSIONS.md) - Creating layer extensions
- [CLI-EXTENSIONS.md](CLI-EXTENSIONS.md) - Creating CLI extensions
- [GitHub Actions](.github/workflows/) - CI/CD configuration
