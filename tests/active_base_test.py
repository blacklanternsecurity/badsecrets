import asyncio
import unittest.mock as mock
import httpx
import respx
from badsecrets.base import (
    BadsecretsBase,
    BadsecretsActiveBase,
    _passive_subclasses,
    _active_subclasses,
    check_all_modules,
    yara_prefilter_scan,
    probe_all_modules,
    _compile_yara_prefilter_rules,
)
import badsecrets.base as base_module


def test_active_subclasses_returns_only_active():
    active = _active_subclasses()
    for cls in active:
        assert issubclass(cls, BadsecretsActiveBase)
        assert cls is not BadsecretsActiveBase


def test_passive_subclasses_excludes_active():
    passive = _passive_subclasses()
    for cls in passive:
        assert not issubclass(cls, BadsecretsActiveBase)
        assert issubclass(cls, BadsecretsBase)


def test_active_and_passive_are_disjoint():
    active = {c.__name__ for c in _active_subclasses()}
    passive = {c.__name__ for c in _passive_subclasses()}
    assert active.isdisjoint(passive)


def test_passive_functions_exclude_active():
    """check_all_modules/carve_all_modules/hashcat_all_modules should not invoke active modules."""
    # check_all_modules with a dummy value should not crash from active modules
    result = check_all_modules("not_a_real_secret")
    # It should return None (no match), not crash
    assert result is None


def test_yara_prefilter_compilation():
    """Prefilter rules should compile without error when active modules exist."""
    # Just calling yara_prefilter_scan triggers compilation
    result = yara_prefilter_scan("some random text")
    assert isinstance(result, dict)


def test_yara_prefilter_scan_match():
    """Scan text containing GlobalProtect indicators should match."""
    html = "<html><title>GlobalProtect Portal</title></html>"
    result = yara_prefilter_scan(html)
    assert "GlobalProtect_DefaultMasterKey" in result


def test_yara_prefilter_scan_no_match():
    """Scan text without any active module indicators should return empty."""
    html = "<html><title>My Cool Website</title></html>"
    result = yara_prefilter_scan(html)
    assert result == {}


def test_active_module_loaded():
    """Verify the GlobalProtect module is discovered in active_modules_loaded."""
    from badsecrets import active_modules_loaded

    assert "globalprotect" in active_modules_loaded
    cls = active_modules_loaded["globalprotect"]
    assert issubclass(cls, BadsecretsActiveBase)


def test_passive_modules_loaded_excludes_active():
    """Verify modules_loaded does not contain active modules."""
    from badsecrets import modules_loaded

    for _name, cls in modules_loaded.items():
        assert not issubclass(cls, BadsecretsActiveBase)


def test_active_base_check_secret_stub():
    """Active modules' check_secret stub returns None."""
    from badsecrets.modules.active.globalprotect import GlobalProtect_DefaultMasterKey

    gp = GlobalProtect_DefaultMasterKey()
    assert gp.check_secret("anything") is None


def test_active_base_carve_regex_stub():
    """Active modules' carve_regex stub returns None."""
    from badsecrets.modules.active.globalprotect import GlobalProtect_DefaultMasterKey

    gp = GlobalProtect_DefaultMasterKey()
    assert gp.carve_regex() is None


def test_yara_prefilter_pattern_fallback():
    """Active module with yara_prefilter_pattern (not rule) compiles correctly."""
    saved = base_module._compiled_yara_prefilter_rules

    class FakeModule(BadsecretsActiveBase):
        yara_prefilter_pattern = "test_pattern_xyz"
        yara_prefilter_rule = None
        description = {"product": "Test", "secret": "Test", "severity": "LOW"}

        async def probe(self, url, **kwargs):
            return []

    try:
        base_module._compiled_yara_prefilter_rules = None
        with mock.patch.object(base_module, "_active_subclasses", return_value=[FakeModule]):
            rules = _compile_yara_prefilter_rules()
            assert rules is not None
            matches = rules.match(data=b"test_pattern_xyz")
            assert len(matches) > 0
    finally:
        base_module._compiled_yara_prefilter_rules = saved


def test_yara_prefilter_no_active_modules():
    """When no active modules exist, yara_prefilter_scan returns {}."""
    saved = base_module._compiled_yara_prefilter_rules
    try:
        base_module._compiled_yara_prefilter_rules = None
        with mock.patch.object(base_module, "_active_subclasses", return_value=[]):
            _compile_yara_prefilter_rules()
            result = yara_prefilter_scan("anything")
            assert result == {}
    finally:
        base_module._compiled_yara_prefilter_rules = saved


def test_probe_all_modules_no_body_no_response():
    """probe_all_modules with no body and no response returns empty."""
    results = asyncio.run(probe_all_modules())
    assert results == []


@respx.mock
def test_probe_all_modules_url_from_response():
    """probe_all_modules extracts URL from httpx_response when url not provided."""
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    mock_response = httpx.Response(
        200,
        text="<html>GlobalProtect Portal</html>",
        request=httpx.Request("GET", "https://vpn.example.com/login"),
    )

    # url=None forces extraction from httpx_response.url
    results = asyncio.run(probe_all_modules(httpx_response=mock_response))
    assert len(results) >= 1
    assert results[0]["detecting_module"] == "GlobalProtect_DefaultMasterKey"


@respx.mock
def test_probe_all_modules_exception_in_probe():
    """Exception during active probe doesn't crash probe_all_modules."""

    class BrokenModule(BadsecretsActiveBase):
        yara_prefilter_rule = 'rule BrokenModule_prefilter { strings: $s = "BROKEN_TRIGGER" condition: $s }'
        description = {"product": "Broken", "secret": "Test", "severity": "LOW"}

        async def probe(self, url, **kwargs):
            raise RuntimeError("probe exploded")

    saved = base_module._compiled_yara_prefilter_rules
    try:
        base_module._compiled_yara_prefilter_rules = None
        with mock.patch.object(base_module, "_active_subclasses", return_value=[BrokenModule]):
            _compile_yara_prefilter_rules()
            results = asyncio.run(probe_all_modules(body="BROKEN_TRIGGER", url="https://example.com"))
            assert results == []
    finally:
        base_module._compiled_yara_prefilter_rules = saved
