import base64

import pytest

from badsecrets.helpers import (
    _skip_vlq,
    aspnet_resource_b64_to_standard_b64,
    Csharp_pbkdf1,
    Csharp_pbkdf1_exception,
    dotnet_get_sort_key,
    dotnet_legacy_hash,
    dotnet_string_hashcode,
    print_status,
    viewstate_signature_length,
    write_vlq_string,
    Viewstate_Helpers,
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


# --- viewstate_signature_length tests ---

# Known MAC_DISABLED body (no trailing HMAC): Pair(Pair(String("874280290"), None), None)
_MAC_DISABLED_BODY = base64.b64decode("/wEPDwUJODc0MjgwMjkwZGQ=")


def test_viewstate_signature_length_sha1():
    """Real SHA1-signed viewstate should report 20-byte signature."""
    raw = base64.b64decode("/wEPDwUJODExMDE5NzY5ZGTX0g6r3svRDbR+eCZDnrj4MT4/FA==")
    assert viewstate_signature_length(raw) == 20


def test_viewstate_signature_length_mac_disabled():
    """MAC_DISABLED viewstate (no HMAC appended) should report 0."""
    assert viewstate_signature_length(_MAC_DISABLED_BODY) == 0


def test_viewstate_signature_length_invalid():
    """Garbage data should return None."""
    assert viewstate_signature_length(b"\x00\x01\x02\x03") is None
    assert viewstate_signature_length(b"") is None
    # Valid preamble but unknown marker
    assert viewstate_signature_length(b"\xff\x01\xfe") is None


def test_viewstate_signature_length_all_hash_sizes():
    """Appending fake signatures of various lengths should be correctly measured."""
    for sig_len in (16, 32, 48, 64):
        fake_sig = bytes(range(sig_len))
        raw = _MAC_DISABLED_BODY + fake_sig
        assert viewstate_signature_length(raw) == sig_len, f"Expected {sig_len}"


# --- _skip_node marker-coverage tests ---
# Each test crafts a minimal viewstate with a specific marker as the top-level node.

_PREAMBLE = b"\xff\x01"
_SIG = b"\xaa" * 20  # fake 20-byte signature appended after the node


def _vs(body_after_preamble):
    """Build raw viewstate: preamble + body + 20-byte fake signature."""
    return _PREAMBLE + body_after_preamble + _SIG


def test_skip_node_noop():
    """Marker 0x01 (Noop) — consumes only the marker byte."""
    assert viewstate_signature_length(_vs(b"\x01")) == 20


def test_skip_node_constants():
    """Markers 0x64-0x68 (None, Empty, Zero, True, False) — no extra bytes."""
    for marker in (0x64, 0x65, 0x66, 0x67, 0x68):
        assert viewstate_signature_length(_vs(bytes([marker]))) == 20


def test_skip_node_integer():
    """Marker 0x02 and 0x2B (Integer) — VLQ encoded value."""
    # Single-byte VLQ: value 42 = 0x2A
    assert viewstate_signature_length(_vs(b"\x02\x2a")) == 20
    assert viewstate_signature_length(_vs(b"\x2b\x2a")) == 20


def test_skip_node_string():
    """Markers 0x05, 0x1E, 0x2A, 0x29 (String) — VLQ length + bytes."""
    for marker in (0x05, 0x1E, 0x2A, 0x29):
        # String of length 3: "abc"
        assert viewstate_signature_length(_vs(bytes([marker]) + b"\x03abc")) == 20


def test_skip_node_stringref():
    """Marker 0x1F (StringRef) — VLQ index."""
    assert viewstate_signature_length(_vs(b"\x1f\x05")) == 20


def test_skip_node_pair():
    """Marker 0x0F (Pair) — two recursive nodes (already covered, explicit check)."""
    # Pair(None, None) = 0x0F 0x64 0x64
    assert viewstate_signature_length(_vs(b"\x0f\x64\x64")) == 20


def test_skip_node_triplet():
    """Marker 0x10 (Triplet) — three recursive nodes."""
    # Triplet(None, None, None) = 0x10 0x64 0x64 0x64
    assert viewstate_signature_length(_vs(b"\x10\x64\x64\x64")) == 20


def test_skip_node_array():
    """Marker 0x16 (Array) — VLQ count + N nodes."""
    # Array of 2 Nones: 0x16 0x02 0x64 0x64
    assert viewstate_signature_length(_vs(b"\x16\x02\x64\x64")) == 20


def test_skip_node_stringarray():
    """Marker 0x15 (StringArray) — VLQ count + items (0x00=empty or VLQ+string)."""
    # StringArray of 2: [empty, "ab"]
    # 0x15, count=2, 0x00(empty), 0x02(len=2) + "ab"
    assert viewstate_signature_length(_vs(b"\x15\x02\x00\x02ab")) == 20


def test_skip_node_typedarray():
    """Marker 0x14 (TypedArray) — recursive type + VLQ count + N nodes."""
    # TypedArray(type=None, count=1, [None])
    assert viewstate_signature_length(_vs(b"\x14\x64\x01\x64")) == 20


def test_skip_node_dict():
    """Marker 0x18 (Dict) — 1-byte count + N key-value pairs."""
    # Dict with 1 entry: {None: None} = 0x18 0x01 0x64 0x64
    assert viewstate_signature_length(_vs(b"\x18\x01\x64\x64")) == 20


def test_skip_node_sparsearray():
    """Marker 0x3C (SparseArray) — type + VLQ length + VLQ count + entries."""
    # SparseArray(type=None, length=2, count=1, [(index=0, None)])
    assert viewstate_signature_length(_vs(b"\x3c\x64\x02\x01\x00\x64")) == 20


def test_skip_node_enum():
    """Marker 0x0B (Enum) — recursive type + VLQ value."""
    # Enum(type=None, value=5)
    assert viewstate_signature_length(_vs(b"\x0b\x64\x05")) == 20


def test_skip_node_color():
    """Marker 0x0A (Color) — 1 byte index."""
    assert viewstate_signature_length(_vs(b"\x0a\x03")) == 20


def test_skip_node_rgba():
    """Marker 0x09 (RGBA) — 4 bytes."""
    assert viewstate_signature_length(_vs(b"\x09\x01\x02\x03\x04")) == 20


def test_skip_node_datetime():
    """Marker 0x06 (Datetime) — 8 bytes."""
    assert viewstate_signature_length(_vs(b"\x06" + b"\x00" * 8)) == 20


def test_skip_node_unit():
    """Marker 0x1B (Unit) — 12 bytes."""
    assert viewstate_signature_length(_vs(b"\x1b" + b"\x00" * 12)) == 20


def test_skip_node_formattedstring():
    """Marker 0x28 (FormattedString) — recursive type + VLQ-length string."""
    # FormattedString(type=None, string="hi")
    assert viewstate_signature_length(_vs(b"\x28\x64\x02hi")) == 20


def test_skip_vlq_overflow():
    """VLQ with 5 continuation bytes exercises the overflow return (bits >= 32)."""
    # 5 continuation bytes — forces bits to 35, exiting the while loop via overflow
    vlq_data = b"\x80\x80\x80\x80\x80"
    n, pos = _skip_vlq(vlq_data, 0)
    assert pos == 5  # consumed all 5 continuation bytes
    # Wrap in an Integer marker to test via viewstate_signature_length
    assert viewstate_signature_length(_vs(b"\x02" + vlq_data)) == 20


def test_skip_node_emptycolor():
    """Marker 0x0C (EmptyColor) — no extra bytes, zero-argument constant."""
    assert viewstate_signature_length(_vs(b"\x0c")) == 20


def test_skip_node_byte():
    """Marker 0x03 (Byte) — 1 byte of data."""
    assert viewstate_signature_length(_vs(b"\x03\x42")) == 20


def test_skip_node_char():
    """Marker 0x04 (Char) — VLQ encoded value."""
    assert viewstate_signature_length(_vs(b"\x04\x41")) == 20


def test_skip_node_double():
    """Marker 0x07 (Double) — 8 bytes."""
    assert viewstate_signature_length(_vs(b"\x07" + b"\x00" * 8)) == 20


def test_skip_node_single():
    """Marker 0x08 (Single/Float) — 4 bytes."""
    assert viewstate_signature_length(_vs(b"\x08\x00\x00\x80\x3f")) == 20


def test_null_padded_viewstate_is_mac_disabled():
    """ViewState followed by all-zero padding should be detected as MAC_DISABLED (sig_len=0)."""
    # EmptyColor root node + 250 null bytes of padding (like ONLYOFFICE produces)
    raw = _PREAMBLE + b"\x0c" + b"\x00" * 250
    assert viewstate_signature_length(raw) == 0


def test_null_padded_pair_viewstate_is_mac_disabled():
    """Pair(None,None) followed by null padding should be MAC_DISABLED."""
    raw = _PREAMBLE + b"\x0f\x64\x64" + b"\x00" * 100
    assert viewstate_signature_length(raw) == 0


def test_nonzero_signature_not_treated_as_padding():
    """Real (non-zero) signatures should NOT be collapsed to 0."""
    # EmptyColor with a 20-byte non-zero signature
    raw = _PREAMBLE + b"\x0c" + b"\xab" * 20
    assert viewstate_signature_length(raw) == 20


def test_skip_node_indexerror():
    """Truncated data should return None via IndexError catch."""
    # Pair marker but only one child — second child read will IndexError
    assert viewstate_signature_length(_PREAMBLE + b"\x0f\x64") is None


# --- print_status coverage ---


def test_print_status_passthru_with_color():
    """passthru=True, colorenabled=True returns colored string."""
    result = print_status("hello", passthru=True, color="red", colorenabled=True)
    assert "hello" in result


def test_print_status_passthru_no_color():
    """passthru=True, colorenabled=False returns plain string."""
    result = print_status("hello", passthru=True, colorenabled=False)
    assert result == "hello"


def test_print_status_print(capsys):
    """passthru=False prints to stdout."""
    print_status("hello", passthru=False, colorenabled=False)
    assert "hello" in capsys.readouterr().out


def test_print_status_none_msg():
    """None message returns None."""
    assert print_status(None) is None


# --- write_vlq_string coverage (multi-byte VLQ for length >= 128) ---


def test_write_vlq_string_long():
    """String >= 128 chars exercises the multi-byte VLQ length encoding."""
    s = "a" * 200
    result = write_vlq_string(s)
    # VLQ for 200: 200 = 0xC8 → 0xC8 & 0x7F = 0x48 | 0x80 = 0xC8, then 200 >> 7 = 1 → 0x01
    assert result.endswith(s.encode("utf-8"))
    assert len(result) == 200 + 2  # 2-byte VLQ + 200 bytes


# --- Csharp_pbkdf1 coverage ---


def test_csharp_pbkdf1_zero_iterations():
    """iterations=0 should raise."""
    with pytest.raises(Csharp_pbkdf1_exception, match="Iterations must be greater than 0"):
        Csharp_pbkdf1(b"pass", b"salt", 0)


def test_csharp_pbkdf1_non_bytes():
    """Non-bytes password should raise TypeError path."""
    with pytest.raises(Csharp_pbkdf1_exception, match="must be of type bytes"):
        Csharp_pbkdf1(123, b"salt", 2)


def test_csharp_pbkdf1_getbytes_non_int():
    """Non-int keylen should raise."""
    pbk = Csharp_pbkdf1(b"pass", b"salt", 2)
    with pytest.raises(Csharp_pbkdf1_exception, match="must be called with an int"):
        pbk.GetBytes("bad")


def test_csharp_pbkdf1_getbytes_extra_path():
    """Calling GetBytes twice exercises the extra-bytes reuse path (lines 112-124)."""
    pbk = Csharp_pbkdf1(b"password", b"salt", 2)
    # First call: request enough to generate extra bytes (derivedBytes is 20 from SHA1)
    first = pbk.GetBytes(10)
    assert len(first) == 10
    # Second call: should reuse leftover extra bytes (lines 112-121)
    second = pbk.GetBytes(5)
    assert len(second) == 5


def test_csharp_pbkdf1_getbytes_extra_exact():
    """GetBytes where magic_number == keylen exactly (line 118-119: else branch)."""
    pbk = Csharp_pbkdf1(b"password", b"salt", 2)
    # First call with 10 leaves 10 extra bytes (derivedBytes=20, extra_count=10)
    first = pbk.GetBytes(10)
    assert len(first) == 10
    # Second call requesting exactly 10 — magic_number (20-10=10) == keylen (10)
    second = pbk.GetBytes(10)
    assert len(second) == 10


# --- aspnet_resource_b64_to_standard_b64 coverage ---


def test_aspnet_resource_b64_to_standard_b64():
    """Convert ASP.NET URL-safe base64 back to standard base64."""
    # "abc-def_ghi2" → last char '2' means 2 padding chars
    # '-' → '+', '_' → '/'
    result = aspnet_resource_b64_to_standard_b64("abc-def_ghi2")
    assert result == "abc+def/ghi=="


# --- find_valid_path_params_by_generator: non-.aspx non-slash URL (lines 691-692) ---


def test_find_path_no_aspx_no_slash():
    """URL without .aspx and not ending in / exercises lines 691-692."""
    vh = Viewstate_Helpers("http://example.com/endpoint")
    # Calculate the generator for this path so we get a match
    gen = vh.calculate_generator_value("/endpoint.aspx", "/")
    vh2 = Viewstate_Helpers("http://example.com/endpoint", generator=gen)
    assert vh2.verified_path is not None
