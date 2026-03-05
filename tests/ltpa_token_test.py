from badsecrets import modules_loaded

LTPA_Token = modules_loaded["ltpa_token"]

# Test cookies generated from hazicatalin/Tehnologii-Java ltpa.keys with password WebAS
LIVE_LTPA2_COOKIE = (
    "Ol6StBNpmLFMvRAkuqwvkxZznLJANOw320SDogOvZvUTvNUFKQ9qkQNsGa/soD2wgOI7+UnzZxBXZJY7Zd8Knge3cOXma/m+8tr96eEhXBP5XcatOey5e8BOQEFNBHK/"
    "QvaEY/rpJfyef4dX+d+coJRdQvF3IRSnqRPubsXgbTx/R148gE++CkIGfuBMVPkEWJkYHpsYRJj7xiYWNbu1jGrwz8GlonX4SdC5JBsjmezWYeAtsoKWeDXX1rhyAyBBgE27nAQEJgi4VEi3be"
    "M1eMo+foxaDHxsCeAabrSGOfOf/yLFMEZr3KAZ7QvyhErT"
)

LIVE_LTPA1_COOKIE = (
    "GfyyfdP2ETNdRwOeYGmOso0sTLGFbOIOc48FJJVX3/4DJtZG6UlLHp3SLnPeqMFkM94cAyT7knxdRwOeYGmOstzwY30DWrJDIZSjFhxI6PTSX7bpP+MZjJQp4t7yW3j1"
    "w5a0c2x9rljA2Hxdu3TOZJPeGpD9IBA3K88X8tciGHeYD+60xnFA1PL/sl5UA8TWBsdKgsrU3RdldsYixJj8anwJ5SBkf+kOupAHgs1jPninQ/d9RjfzXvCnn2u6A/tZxGPQ8KkeOUrpXNCAA"
    "UN+s0Zqoojh0MuOYfd2mPP43T5AMjgvRXLzZhaweZAqlDYG"
)

TEST_SOURCE = "hazicatalin/Tehnologii-Java"
TEST_KEY_ID = "be8eb9c450ca"


def test_ltpa2_decrypt():
    x = LTPA_Token()
    result = x.check_secret(LIVE_LTPA2_COOKIE)
    assert result
    assert result["secret"] == f"LtpaToken2 key {TEST_KEY_ID} (see ltpa_keys.json)"


def test_ltpa2_details():
    x = LTPA_Token()
    result = x.check_secret(LIVE_LTPA2_COOKIE)
    assert result
    assert result["details"]["token_version"] == "2"
    assert result["details"]["source"] == "LtpaToken2 cookie"
    assert "AES" in result["details"]["info"]
    assert result["details"]["key_id"] == TEST_KEY_ID
    assert result["details"]["key_source"] == TEST_SOURCE


def test_ltpa1_decrypt():
    x = LTPA_Token()
    result = x.check_secret(LIVE_LTPA1_COOKIE)
    assert result
    assert TEST_KEY_ID in result["secret"]
    assert result["details"]["token_version"] == "1"
    assert "3DES" in result["details"]["info"]


def test_ltpa_negative():
    import base64
    import os

    x = LTPA_Token()
    # Random 128 bytes base64-encoded — won't match any key
    random_b64 = base64.b64encode(os.urandom(128)).decode()
    result = x.check_secret(random_b64)
    assert result is None


def test_ltpa_short_data():
    import base64

    x = LTPA_Token()
    # Only 16 bytes — too short
    short_b64 = base64.b64encode(b"\x00" * 16).decode()
    result = x.check_secret(short_b64)
    assert result is None


def test_ltpa_not_base64():
    x = LTPA_Token()
    result = x.check_secret("not-valid-base64!!!")
    assert result is None


def test_ltpa_identify():
    x = LTPA_Token()
    assert x.identify(LIVE_LTPA2_COOKIE)
    assert not x.identify("too-short")
    assert not x.identify("not valid base64!!!")


def test_ltpa_carve_cookies():
    x = LTPA_Token()
    results = x.carve(cookies={"LtpaToken2": LIVE_LTPA2_COOKIE})
    assert len(results) == 1
    assert results[0]["location"] == "cookies"
    assert results[0]["type"] == "SecretFound"
    assert TEST_KEY_ID in results[0]["secret"]


def test_ltpa_description():
    desc = LTPA_Token.get_description()
    assert desc["product"] == "IBM WebSphere LTPA"
    assert desc["secret"] == "LTPA Encryption Key"
    assert desc["severity"] == "HIGH"


def test_ltpa_validate_plaintext():
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT

    # Valid LTPA2 plaintext
    valid = b"expire:1234567890000$u:user\\:defaultRealm/admin%1234567890000%sig=="
    assert LT._validate_ltpa2_plaintext(valid)

    # Missing user attribute
    no_user = b"expire:1234567890000$host:server1%1234567890000%sig=="
    assert not LT._validate_ltpa2_plaintext(no_user)

    # Not UTF-8
    assert not LT._validate_ltpa2_plaintext(b"\xff\xfe\x00\x01")

    # No percent delimiter
    assert not LT._validate_ltpa2_plaintext(b"no delimiters here")


def test_ltpa_try_ltpa2_bad_padding():
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT

    # Data not aligned to AES block size
    result = LT._try_ltpa2(b"\x00" * 31, b"\x00" * 16, {"key_id": "test", "source": "test"})
    assert result is None


def test_ltpa_try_ltpa1_bad_padding():
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT

    # Data not aligned to DES block size
    result = LT._try_ltpa1(b"\x00" * 7, b"\x00" * 24, {"key_id": "test", "source": "test"})
    assert result is None


def test_ltpa_keys_cached():
    """Second call to _load_ltpa_keys returns cached result."""
    x = LTPA_Token()
    keys1 = x._load_ltpa_keys()
    keys2 = x._load_ltpa_keys()
    assert keys1 is keys2


def test_ltpa_try_ltpa2_bad_aes_key():
    """AES key of wrong length triggers ValueError."""
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT

    # 32 bytes aligned data, but 15-byte key (invalid for AES)
    result = LT._try_ltpa2(b"\x00" * 32, b"\x00" * 15, {"key_id": "test", "source": "test"})
    assert result is None


def test_ltpa_try_ltpa1_bad_des3_key():
    """DES3 key of wrong length triggers ValueError."""
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT

    # 16 bytes aligned data, but 15-byte key (invalid for DES3)
    result = LT._try_ltpa1(b"\x00" * 16, b"\x00" * 15, {"key_id": "test", "source": "test"})
    assert result is None


def test_ltpa_try_ltpa2_valid_padding_bad_plaintext():
    """Valid PKCS5 padding but plaintext fails validation."""
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    key = b"\x01" * 16
    # Plaintext with valid padding but no LTPA format (no % or u:)
    plaintext = b"this is not an ltpa token at all"
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    ct = cipher.encrypt(pad(plaintext, 16))
    result = LT._try_ltpa2(ct, key, {"key_id": "test", "source": "test"})
    assert result is None


def test_ltpa_try_ltpa1_valid_padding_bad_plaintext():
    """Valid PKCS5 padding but plaintext fails validation."""
    from badsecrets.modules.passive.ltpa_token import LTPA_Token as LT
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad

    # Use a key that doesn't degenerate to single DES
    key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10\x00\x11\x22\x33\x44\x55\x66\x77"
    plaintext = b"this is not an ltpa token at all"
    cipher = DES3.new(key, DES3.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext, 8))
    result = LT._try_ltpa1(ct, key, {"key_id": "test", "source": "test"})
    assert result is None


def test_ltpa_check_secret_not_base64():
    """check_secret with invalid base64 returns None (no identify guard)."""
    x = LTPA_Token()
    result = x.check_secret("not-valid-base64!!!")
    assert result is None


def test_ltpa_check_secret_too_short():
    """check_secret with valid base64 but too few decoded bytes returns None."""
    import base64

    x = LTPA_Token()
    # 16 bytes decoded — under the 32-byte minimum
    short_b64 = base64.b64encode(b"\x00" * 16).decode()
    result = x.check_secret(short_b64)
    assert result is None


def test_ltpa_carve_regex():
    """carve_regex returns None (cookie-only module)."""
    x = LTPA_Token()
    assert x.carve_regex() is None
