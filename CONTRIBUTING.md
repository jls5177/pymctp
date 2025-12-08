<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# Contributing to PyMCTP

Thank you for your interest in contributing to PyMCTP! This document provides guidelines and instructions for contributing to this monorepo.

## Table of Contents

- [Repository Structure](#repository-structure)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Building Packages](#building-packages)
- [Submitting Changes](#submitting-changes)
- [Package-Specific Guidelines](#package-specific-guidelines)

## Repository Structure

PyMCTP is organized as a monorepo containing multiple related packages:

```
pymctp/
├── packages/
│   ├── pymctp/                          # Core library
│   ├── pymctp-sample-vendorextension/   # Sample vendor extension (example/template)
│   ├── pymctp-exerciser-aardvark/       # Aardvark exerciser
│   ├── pymctp-exerciser-qemu/           # QEMU exercisers
│   └── pymctp-exerciser-serial/         # Serial exerciser
├── tests/                               # Shared tests
├── examples/                            # Example scripts
└── scripts/                             # Build and utility scripts
```

Each package is independently versioned and can be published separately to PyPI.

## Development Setup

For detailed development setup instructions, build procedures, and workflows, see [DEVELOPMENT.md](DEVELOPMENT.md).

### Quick Start

```bash
# Clone the repository
git clone https://github.com/jls5177/pymctp.git
cd pymctp

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install all packages in development mode
./scripts/install-dev.sh
```

For alternative installation methods, testing, building, and advanced workflows, see the [Development Guide](DEVELOPMENT.md).

## Making Changes

### Branching Strategy

- `main` - Stable releases
- `development` - Active development
- `feature/*` - New features
- `fix/*` - Bug fixes

### Workflow

1. Create a new branch from `development`:
   ```bash
   git checkout development
   git pull
   git checkout -b feature/your-feature-name
   ```

2. Make your changes in the appropriate package(s)

3. Test your changes (see [Testing](#testing))

4. Commit with clear messages:
   ```bash
   git add .
   git commit -m "Add feature X to pymctp-core"
   ```

5. Push and create a pull request to `development`

### Code Style

- Follow PEP 8 style guidelines
- Use `ruff` for linting and formatting
- Maximum line length: 120 characters
- Use type hints where appropriate

```bash
# Format code (in package directory)
cd packages/pymctp
hatch fmt

# Check formatting
hatch fmt --check
```

### License Headers

All source files must include SPDX license headers:

```python
# SPDX-FileCopyrightText: 2024 Your Name <your@email.com>
#
# SPDX-License-Identifier: MIT
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run tests for specific package
pytest tests/layers/

# Run with coverage
cd packages/pymctp
hatch run coverage:xml
```

### Writing Tests

- Place tests in the `tests/` directory, mirroring the package structure
- Use `pytest` for test framework
- Aim for high code coverage
- Include both unit and integration tests

Example test structure:
```
tests/
├── layers/
│   ├── mctp/
│   │   ├── test_transport.py
│   │   └── test_control.py
│   └── ipmi/
│       └── test_transport.py
└── exerciser/
    └── test_plugin_loader.py
```

## Building Packages

### Build All Packages

```bash
./scripts/build-all.sh
```

This creates wheel and source distributions in each package's `dist/` directory.

### Build Individual Package

```bash
cd packages/pymctp
python -m build
```

### Clean Build Artifacts

```bash
./scripts/clean.sh
```

## Submitting Changes

### Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Add entry to CHANGELOG (if applicable)
4. Create pull request with clear description
5. Link any related issues
6. Wait for code review

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code follows project style guidelines
- [ ] Documentation updated (if needed)
- [ ] License headers present on new files
- [ ] Commit messages are clear and descriptive
- [ ] No merge conflicts with target branch

### Code Review

- All PRs require at least one review
- Address review comments promptly
- Be open to feedback and suggestions
- Maintain professional and respectful communication

## Package-Specific Guidelines

### Core Package (pymctp)

- **Location**: `packages/pymctp/`
- **Purpose**: Core MCTP/IPMI/PLDM protocol implementations
- **Key Files**:
  - `src/pymctp/layers/` - Protocol layer definitions
  - `src/pymctp/exerciser/` - Exerciser plugin system

**Guidelines**:
- Maintain backward compatibility
- Follow DMTF specifications
- Use Scapy conventions for packet definitions
- Document all public APIs

### OEM Extensions

- **Example**: `packages/pymctp-sample-vendorextension/`
- **Purpose**: Vendor-specific protocol extensions

**Guidelines**:
- Import from `pymctp.layers` (not relative imports)
- Use auto-binding decorators where possible
- Include comprehensive README
- Register via entry points in `pyproject.toml`

### Exercisers

- **Examples**: `packages/pymctp-exerciser-*`
- **Purpose**: Hardware/virtual device interfaces

**Guidelines**:
- Subclass `scapy.supersocket.SuperSocket`
- Register via `pymctp.exerciser.register_exerciser()`
- Handle hardware errors gracefully
- Provide clear installation instructions for hardware dependencies

## Release Process

Releases are managed through GitHub Actions and tags.

### Creating a Release

1. Update version numbers in relevant packages
2. Update CHANGELOG
3. Create and push a version tag:
   ```bash
   git tag -a v0.2.0 -m "Release version 0.2.0"
   git push origin v0.2.0
   ```
4. GitHub Actions will automatically:
   - Build all packages
   - Run tests
   - Publish to PyPI (on tags)
   - Create GitHub release

### Version Numbers

Follow [Semantic Versioning](https://semver.org/):
- MAJOR version for incompatible API changes
- MINOR version for new functionality (backward compatible)
- PATCH version for bug fixes

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/jls5177/pymctp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jls5177/pymctp/discussions)
- **Documentation**: See package READMEs and [EXTENSIONS.md](EXTENSIONS.md)

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Focus on constructive feedback
- Assume good intentions
- Respect differing viewpoints

## License

By contributing to PyMCTP, you agree that your contributions will be licensed under the MIT License.
