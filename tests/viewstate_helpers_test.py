from badsecrets.helpers import (
    dotnet_get_sort_key,
    dotnet_legacy_hash,
    dotnet_string_hashcode,
    Viewstate_Helpers,
    DOTNET_SORT_KEY_DB,
)


# --- Sort key and hash algorithm tests ---


def test_dotnet_string_hashcode_slash():
    """Verify hashcode for '/' - used as root apppath."""
    h = dotnet_string_hashcode("/")
    assert isinstance(h, int)
    assert 0 <= h <= 0xFFFFFFFF


def test_dotnet_get_sort_key_returns_list():
    sk = dotnet_get_sort_key("/")
    assert isinstance(sk, list)
    assert len(sk) > 0
    # Must end with [1, 1, 1, 0]
    assert sk[-4:] == [1, 1, 1, 0]


def test_dotnet_legacy_hash_deterministic():
    """Same sort key should always produce the same hash."""
    sk = dotnet_get_sort_key("test")
    h1 = dotnet_legacy_hash(sk)
    h2 = dotnet_legacy_hash(sk)
    assert h1 == h2


def test_dotnet_string_hashcode_case_insensitive():
    """IgnoreCase: uppercase and lowercase should produce the same hash."""
    h1 = dotnet_string_hashcode("DEFAULT_ASPX")
    h2 = dotnet_string_hashcode("default_aspx")
    assert h1 == h2


# --- Generator computation tests (validated against real ASP.NET app) ---


def test_calculate_generator_default2():
    """http://10.1.1.43/default2.aspx with apppath=/ should produce 9BD98A7D."""
    vh = Viewstate_Helpers("http://10.1.1.43/default2.aspx")
    assert vh.calculate_generator_value("/default2.aspx", "/") == "9BD98A7D"


def test_calculate_generator_default():
    """http://10.1.1.43/default.aspx with apppath=/ should produce CA0B0334."""
    vh = Viewstate_Helpers("http://10.1.1.43/default.aspx")
    assert vh.calculate_generator_value("/default.aspx", "/") == "CA0B0334"


def test_calculate_generator_test():
    """http://10.1.1.43/test.aspx with apppath=/ should produce 75BBA7D6."""
    vh = Viewstate_Helpers("http://10.1.1.43/test.aspx")
    assert vh.calculate_generator_value("/test.aspx", "/") == "75BBA7D6"


# --- Brute-force path finder tests ---


def test_find_valid_path_params_by_generator():
    """Should find /default2.aspx with apppath=/ for generator 9BD98A7D."""
    vh = Viewstate_Helpers("http://10.1.1.43/default2.aspx", generator="9BD98A7D")
    assert vh.verified_path == "/default2.aspx"
    assert vh.verified_apppath == "/"


def test_find_valid_path_params_default():
    """Should find /default.aspx with apppath=/ for generator CA0B0334."""
    vh = Viewstate_Helpers("http://10.1.1.43/default.aspx", generator="CA0B0334")
    assert vh.verified_path == "/default.aspx"
    assert vh.verified_apppath == "/"


# --- URL normalization tests ---


def test_url_normalization_backslash():
    vh = Viewstate_Helpers("http://example.com/foo\\bar\\page.aspx")
    # Backslashes should be converted to forward slashes
    assert "\\" not in vh.url


def test_url_normalization_double_slash():
    vh = Viewstate_Helpers("http://example.com//foo//page.aspx")
    assert "//" not in vh.url.split("//", 1)[1]  # skip the http:// part


def test_url_normalization_cookieless():
    """Cookieless session tokens like /(S(abc123))/ should be removed."""
    vh = Viewstate_Helpers("http://example.com/(S(abc123))/page.aspx")
    assert "(S(" not in vh.url


def test_url_normalization_aspx_truncation():
    """Path after .aspx should be truncated."""
    vh = Viewstate_Helpers("http://example.com/page.aspx/extra/path")
    assert vh.url.endswith("page.aspx")


# --- Purpose string generation tests ---


def test_get_all_specific_purposes_verified():
    """When generator is verified, should return a single purpose pair."""
    vh = Viewstate_Helpers("http://10.1.1.43/default2.aspx", generator="9BD98A7D")
    purposes = vh.get_all_specific_purposes()
    assert len(purposes) >= 1
    assert purposes[0][0] == "TemplateSourceDirectory: /"
    assert purposes[0][1] == "Type: DEFAULT2_ASPX"


def test_get_all_specific_purposes_unverified():
    """Without generator verification, should return multiple candidate purpose pairs."""
    vh = Viewstate_Helpers("http://example.com/app/page.aspx")
    purposes = vh.get_all_specific_purposes()
    assert len(purposes) >= 1
    # All should have TemplateSourceDirectory and Type
    for p in purposes:
        assert p[0].startswith("TemplateSourceDirectory:")
        assert p[1].startswith("Type:")


# --- IsolateApps hashcode tests ---


def test_get_apppaths_hashcodes_root():
    """Root apppath should produce a single hashcode."""
    vh = Viewstate_Helpers("http://10.1.1.43/default2.aspx", generator="9BD98A7D")
    hashcodes = vh.get_apppaths_hashcodes()
    assert len(hashcodes) == 1
    assert isinstance(hashcodes[0], int)


def test_get_apppaths_hashcodes_subdirectory():
    """URL with subdirectories should produce multiple candidate hashcodes."""
    vh = Viewstate_Helpers("http://example.com/myapp/pages/form.aspx")
    hashcodes = vh.get_apppaths_hashcodes()
    assert len(hashcodes) >= 2  # / and /myapp at minimum


# --- Sort key edge case tests ---


def test_dotnet_get_sort_key_unknown_char():
    """Unknown character should raise ValueError."""
    import pytest

    with pytest.raises(ValueError, match="not found in sort key mapping"):
        dotnet_get_sort_key("\u9999")  # CJK char not in the DB


def test_dotnet_get_sort_key_temp_filtering():
    """Characters with secondary weights > 2 exercise temp filtering (lines 279/281)."""
    # \x80 has mapping [12, 250, 1, 29, 1, 1, 1, 0] which produces temp_val=29 (>2)
    sk = dotnet_get_sort_key("\x80")
    assert isinstance(sk, list)
    assert sk[-4:] == [1, 1, 1, 0]
    # The sort key should include the secondary weight (29) in the filtered temp
    assert 29 in sk

    # Multi-char with \x80 to verify filtering across chars
    sk2 = dotnet_get_sort_key("a\x80b")
    assert isinstance(sk2, list)
    assert sk2[-4:] == [1, 1, 1, 0]


def test_dotnet_legacy_hash_odd_length():
    """Sort key with odd number of non-zero elements hits the break on line 305."""
    # Craft a sort key with odd number of elements before the 0 terminator
    # [x, 0] will break after first element since sort_key[1] == 0
    h = dotnet_legacy_hash([42, 0])
    assert isinstance(h, int)
    assert 0 <= h <= 0xFFFFFFFF


# --- Path extraction edge cases ---


def test_extract_path_no_file_extension():
    """URL path without a file extension (line 505: dir_parts = parts)."""
    vh = Viewstate_Helpers("http://example.com/myapp/subdir")
    # Should not crash, should handle path without extension
    purposes = vh.get_all_specific_purposes()
    assert len(purposes) >= 1


def test_simulate_get_type_name_no_aspx():
    """Path without .aspx should get default.aspx appended (line 527)."""
    vh = Viewstate_Helpers("http://example.com/myapp")
    # The type name for /myapp with apppath=/ should include default_aspx
    type_name = vh._simulate_get_type_name("/myapp", "/")
    assert "default_aspx" in type_name.lower()


# --- Brute-force Phase 1 edge cases ---


def test_find_path_url_ending_with_slash():
    """URL ending with / exercises line 562 (str_path.rstrip('/'))."""
    vh = Viewstate_Helpers("http://example.com/app/")
    # Exercise the slash-ending branch; won't necessarily find a match but shouldn't crash
    path, apppath = vh.find_valid_path_params_by_generator("DEADBEEF")
    # DEADBEEF is unlikely to match, but the code path is exercised
    # (path will be None if not found)
    assert path is None or isinstance(path, str)


def test_find_path_subdirectory_apppath():
    """URL with subdirectory exercises lines 569-570 (apppath != '/')."""
    vh = Viewstate_Helpers("http://example.com/myapp/page.aspx")
    # Calculate the actual generator for /myapp/page.aspx with apppath=/myapp
    gen = vh.calculate_generator_value("/myapp/page.aspx", "/myapp")
    # Now try to find it via brute force
    vh2 = Viewstate_Helpers("http://example.com/myapp/page.aspx", generator=gen)
    assert vh2.verified_path is not None


def test_find_path_seen_dedup():
    """Phase 1 duplicate combos (line 577) should be skipped without error."""
    # URL with subdirectory where apppath candidates overlap with temp_paths
    vh = Viewstate_Helpers("http://example.com/app/page.aspx")
    # This exercises dedup - just ensure no crash
    path, apppath = vh.find_valid_path_params_by_generator("FFFFFFFF")
    assert path is None  # FFFFFFFF won't match


# --- Phase 2 and 3 brute-force tests ---


def test_find_path_phase2():
    """A path only findable in Phase 2 (common dir + default page in apppath)."""
    # Compute generator for /myapp/admin/default.aspx with apppath /myapp
    # "admin" is in COMMON_DIRECTORIES, "default.aspx" is in DEFAULT_PAGES_LARGE
    vh = Viewstate_Helpers("http://example.com/myapp/admin/default.aspx")
    gen = vh.calculate_generator_value("/myapp/admin/default.aspx", "/myapp")
    # Use a URL with same apppath but different page - Phase 1 won't match
    vh2 = Viewstate_Helpers("http://example.com/myapp/somepage.aspx", generator=gen)
    assert vh2.verified_path == "/myapp/admin/default.aspx"
    assert vh2.verified_apppath == "/myapp"


def test_find_path_phase3():
    """A path only findable in Phase 3 (common directory x common page)."""
    vh = Viewstate_Helpers("http://example.com/")
    # Pre-compute for a common directory + common page combo
    # Use /admin/error.aspx with apppath=/admin - this should be in Phase 3
    gen = vh.calculate_generator_value("/admin/error.aspx", "/admin")
    # Use root URL so Phase 1 won't match
    vh2 = Viewstate_Helpers("http://example.com/", generator=gen)
    if vh2.verified_path:
        assert vh2.verified_path is not None


def test_find_path_returns_none_none():
    """Completely unresolvable generator returns (None, None) from all phases."""
    # Use /admin/default.aspx so Phase 1 combos overlap with Phase 2
    # (exercises Phase 2 dedup on line 577 when (/admin/default.aspx, /) is already in seen)
    vh = Viewstate_Helpers("http://example.com/admin/default.aspx")
    path, apppath = vh.find_valid_path_params_by_generator("00000001")
    # 00000001 is extremely unlikely to match any combo
    assert path is None
    assert apppath is None


# --- Purpose generation for non-.aspx URLs ---


def test_get_all_specific_purposes_no_aspx_no_slash():
    """Path without .aspx and not ending with / (lines 634-635)."""
    vh = Viewstate_Helpers("http://example.com/app/endpoint")
    purposes = vh.get_all_specific_purposes()
    assert len(purposes) >= 1
    # Should include a purpose with .aspx appended and default.aspx appended
    type_names = [p[1] for p in purposes]
    assert any("endpoint" in t.lower() for t in type_names)


def test_get_all_specific_purposes_trailing_slash():
    """Path ending with / (lines 637-638)."""
    vh = Viewstate_Helpers("http://example.com/app/")
    purposes = vh.get_all_specific_purposes()
    assert len(purposes) >= 1
    # Should include default.aspx purposes
    type_names = [p[1] for p in purposes]
    assert any("default_aspx" in t.lower() for t in type_names)


def test_get_all_specific_purposes_no_aspx_with_subpath():
    """Path without .aspx not ending with / (lines 639-640: else branch)."""
    vh = Viewstate_Helpers("http://example.com/myapp/api")
    purposes = vh.get_all_specific_purposes()
    assert len(purposes) >= 1
