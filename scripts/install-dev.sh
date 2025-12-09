#!/bin/bash
# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

# Install pymctp_oem_microsoft package in development mode

set -e

echo "Installing pymctp-oem-microsoft package in development mode..."

PACKAGE="packages/pymctp-oem-microsoft"

echo ""
echo "Installing: $PACKAGE"
python -m pip install -e "$PACKAGE"

echo ""
echo "=========================================="
echo "✓ Package installed in development mode!"
echo "=========================================="
echo ""
echo "Installed pymctp packages:"
python -m pip list | grep pymctp
