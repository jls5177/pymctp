# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for extension plugin loader and namespace integration."""

import sys
import pytest


class TestPluginLoader:
    """Test extension loading and namespace registration."""

    def test_extensions_loaded(self):
        """Test that extensions are discovered and loaded."""
        from pymctp.layers import __all_extensions__

        # Extensions should be loaded
        assert isinstance(__all_extensions__, list)
        # If sample-vendor extension is installed, it should be in the list
        # (This test will pass even if no extensions are installed)

    def test_oem_namespace_exists(self):
        """Test that pymctp.oem namespace package exists."""
        import pymctp

        assert hasattr(pymctp, "oem"), "pymctp.oem namespace should exist"

    def test_sample_vendor_namespace_integration(self):
        """Test that sample-vendor extension is accessible via pymctp.oem.sample_vendor."""
        from pymctp.layers import __all_extensions__

        if "sample-vendor" not in __all_extensions__:
            pytest.skip("sample-vendor extension not installed")

        import pymctp

        # Check that sample_vendor exists in oem namespace
        assert hasattr(pymctp.oem, "sample_vendor"), "pymctp.oem.sample_vendor should exist"

        # Test importing the module
        from pymctp.oem.sample_vendor import SampleVendorPacket

        assert SampleVendorPacket is not None
        # Verify it's the correct Scapy packet class
        assert hasattr(SampleVendorPacket, "fields_desc")

    def test_sample_vendor_module_import(self):
        """Test importing sample-vendor extension as a module."""
        from pymctp.layers import __all_extensions__

        if "sample-vendor" not in __all_extensions__:
            pytest.skip("sample-vendor extension not installed")

        import pymctp.oem.sample_vendor as sv

        # Check that expected classes are available
        assert hasattr(sv, "SampleVendorPacket")
        assert hasattr(sv, "SampleVendorGetVersionRequest")
        assert hasattr(sv, "SampleVendorGetVersionResponse")
        assert hasattr(sv, "SAMPLE_VENDOR_ID")

    def test_sample_vendor_in_sys_modules(self):
        """Test that sample-vendor extension is registered in sys.modules."""
        from pymctp.layers import __all_extensions__

        if "sample-vendor" not in __all_extensions__:
            pytest.skip("sample-vendor extension not installed")

        assert "pymctp.oem.sample_vendor" in sys.modules, "Extension should be in sys.modules"

    def test_extension_namespace_normalization(self):
        """Test that extension names with hyphens are normalized to underscores."""
        from pymctp.layers.plugin_loader import _register_extension_in_namespace
        import types
        import pymctp

        # Create a test module
        test_module = types.ModuleType("test_extension_module")
        test_module.test_value = "test"

        # Register it with a hyphenated name
        _register_extension_in_namespace("test-extension", test_module)

        # Should be accessible with underscores
        assert hasattr(pymctp.oem, "test_extension")
        assert pymctp.oem.test_extension.test_value == "test"

        # Clean up
        if hasattr(pymctp.oem, "test_extension"):
            delattr(pymctp.oem, "test_extension")
        if "pymctp.oem.test_extension" in sys.modules:
            del sys.modules["pymctp.oem.test_extension"]
