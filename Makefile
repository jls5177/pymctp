# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

.PHONY: format-all format-check license-check license-add test test-cov test-xml build-all clean install-all

# Formatting
format-all:
	uv run ruff format packages/
	uv run ruff check --fix packages/

format-check:
	uv run ruff format --check packages/
	uv run ruff check packages/

# License compliance
license-check:
	uv run reuse lint

license-add:
	uv run reuse annotate -c "Justin Simon <justin@simonctl.com>" -l MIT --merge-copyrights -r

# Testing
test:
	uv run pytest tests/

test-cov:
	uv run pytest --cov=pymctp --cov-report=html --cov-report=term tests/

test-xml:
	uv run pytest --cov=pymctp --cov-report=xml tests/

# Building
build-all:
	bash scripts/build-all.sh

clean:
	bash scripts/clean.sh

# Installation
install-all:
	uv sync --all-extras
