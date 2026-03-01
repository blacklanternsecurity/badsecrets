from badsecrets.base import (
    BadsecretsBase,
    BadsecretsActiveBase,
    _passive_subclasses,
    _active_subclasses,
    check_all_modules,
    yara_prefilter_scan,
)


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
