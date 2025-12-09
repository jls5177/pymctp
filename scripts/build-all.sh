#!/bin/bash
# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

# Build pymctp_oem_microsoft package

set -e

echo "Building pymctp-oem-microsoft package..."

PACKAGE="packages/pymctp-oem-microsoft"

echo ""
echo "=========================================="
echo "Building: $PACKAGE"
echo "=========================================="
cd "$PACKAGE"
uv run python -m build
cd - > /dev/null

echo ""
echo "=========================================="
echo "✓ Package built successfully!"
echo "=========================================="
echo ""
echo "Distribution files:"
find packages/pymctp_oem_microsoft/dist -name "*.whl" -o -name "*.tar.gz" | sort
