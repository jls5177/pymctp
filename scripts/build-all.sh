#!/bin/bash
# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

# Build all pymctp packages

set -e

echo "Building all pymctp packages..."

PACKAGES=(
    "packages/pymctp"
    "packages/pymctp-sample-vendorextension"
    "packages/pymctp-exerciser-aardvark"
    "packages/pymctp-exerciser-qemu"
    "packages/pymctp-exerciser-serial"
)

for package in "${PACKAGES[@]}"; do
    echo ""
    echo "=========================================="
    echo "Building: $package"
    echo "=========================================="
    cd "$package"
    uv run python -m build
    cd - > /dev/null
done

echo ""
echo "=========================================="
echo "✓ All packages built successfully!"
echo "=========================================="
echo ""
echo "Distribution files:"
find packages/*/dist -name "*.whl" -o -name "*.tar.gz" | sort
