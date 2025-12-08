#!/bin/bash
# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

# Clean build artifacts from all packages

set -e

echo "Cleaning build artifacts..."

# Find and remove build directories
find packages -type d \( -name "dist" -o -name "build" -o -name "*.egg-info" -o -name "__pycache__" -o -name ".pytest_cache" \) -exec rm -rf {} + 2>/dev/null || true

# Remove Python cache files
find packages -type f -name "*.pyc" -delete 2>/dev/null || true
find packages -type f -name "*.pyo" -delete 2>/dev/null || true

echo "✓ Clean complete!"
