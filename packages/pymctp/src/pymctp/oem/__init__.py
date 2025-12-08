# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""OEM-specific MCTP layer extensions.

This package serves as a namespace for OEM-specific extensions.
Extensions are automatically discovered and registered here via the
pymctp.extensions entry point mechanism.

Example:
    After installing pymctp-oem-microsoft:

    >>> from pymctp.oem.microsoft import MyCustomLayer
    >>> # or
    >>> import pymctp.oem.microsoft
"""

__path__ = __import__("pkgutil").extend_path(__path__, __name__)
