#!/bin/bash
# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

# Install all pymctp packages in development mode

set -e

echo "Installing pymctp packages in development mode..."

# Install in dependency order
PACKAGES=(
    "packages/pymctp"                          # Core must be first
    "packages/pymctp-sample-vendorextension"   # Extensions depend on core
    "packages/pymctp-exerciser-aardvark"
    "packages/pymctp-exerciser-qemu"
    "packages/pymctp-exerciser-serial"
)

for package in "${PACKAGES[@]}"; do
    echo ""
    echo "Installing: $package"
    pip install -e "$package"
done

echo ""
echo "=========================================="
echo "✓ All packages installed in development mode!"
echo "=========================================="
echo ""
echo "Installed packages:"
pip list | grep pymctp
