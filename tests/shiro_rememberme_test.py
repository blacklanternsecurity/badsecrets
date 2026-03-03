from badsecrets import modules_loaded

Shiro_RememberMe = modules_loaded["shiro_rememberme"]

LIVE_CBC_COOKIE = (
    "vTpNGrKtiiA5t5FLJWyVLHlOpNfF/7AeBEqYfvgHjccS5fjDBuRsR82FqRpmSZdPyN6GfjHTilBGN38h+6LjldUKjB0fhYBDsL9luW32Va3d+qbKb2pszstnllMR56pTBSKP"
    "K/xKY0uryuYPGafGi7clBnlWh5NwOaluQm11Pm+NZKkcjDVlBpNgfpoKSpaCYfzcUFUDeL/cfkpTKA3H/TWVnVfw8Cxp0tVEmMqF3YtNliwdNkeGD/0gWDNaF9Zw17Is1Mgi"
    "BiIRAQ/umDwxfdlKjVKgaLllPohV1ROhoP84zuMeXcsppwHC57ykUg/i8hdhaQwE4LUZQKnM7+sbU6FU2r5rv2i1Fb+KmeRZ9bbudNg8BMP7vEKnzImjD4qNFkXhVvq+APH9/"
    "SLsLJzUZo3bz9macPFb5NhLVJ/NMp+/2iPM9Ik5yNz1zq/X+QIoXzVSLavH5S2O6C42wk14F4msB1G1SvyfSP8/CjZQMecWPR+eHBb1P8LF0zLqwSoIuf1nJ3yDQ5Dbc6M+"
    "GBcsCQ=="
)
DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA=="

# Live AES-GCM cookie from Shiro 1.13.0 (docker/shiro-gcm) with default key
GCM_COOKIE = (
    "Ws4Sr3M5b5Kl9v1/2rh4QqSM8ywFPtwHR1xn5wC+WOJ4aV7rrbW+0gYRhwe09RtZmHNnDHWTx4I5Tq2BibNMg1HZmv5tdq4TPtA/udq2sjMzoXIUS2D8ulJvUN5H88aXxHUo"
    "wISAz/Oe3pNPWxUH2PtsmdDXddtS/ZXyp3kq82hSG4SfB/mSCZZSeCMCg4Z5BB+Huec4buZZ3Ub0N/c38OIc8ZnG+dOYb/BdAT/ZcahzG+g2gpi8zNbxu6L79D4Pv39zlmMSO7"
    "vYWZMYa59C4MtWYc2CRsr8ernhg4a5yVsyqv5zCSYeJF6tCkV8VH6Qtw2526is7l9dMOGzrLN0m6GSeRYDlLdqjC0QTRMHUQU0QebWe3Bc/Z8Y8oyLOqiVsN0nfi6/lqURLGSPN"
    "aIi7pUCVk2LWtSfyZwCK2HmPel2wUaKudSQAXGa8IWfjx09BdqiJOvPzlRJXO/w8E5fqERVhCoF6VxT9L9t9FIobeXSBI+IKmifxHj2ymDuRlcoDL27tEkufmJWjQICNPsypQp4"
    "4Txyri+FuQ=="
)


def test_shiro_cbc_decrypt():
    x = Shiro_RememberMe()
    result = x.check_secret(LIVE_CBC_COOKIE)
    assert result
    assert result["secret"] == DEFAULT_KEY


def test_shiro_details():
    x = Shiro_RememberMe()
    result = x.check_secret(LIVE_CBC_COOKIE)
    assert result
    assert result["details"]["source"] == "rememberMe cookie"
    assert result["details"]["mode"] == "CBC"
    assert "Apache Shiro" in result["details"]["info"]


def test_shiro_negative():
    import base64
    import os

    x = Shiro_RememberMe()
    # Random 128 bytes base64-encoded — won't match any key
    random_b64 = base64.b64encode(os.urandom(128)).decode()
    result = x.check_secret(random_b64)
    assert result is None


def test_shiro_short_data():
    import base64

    x = Shiro_RememberMe()
    # Only 16 bytes — too short (need >= 32)
    short_b64 = base64.b64encode(b"\x00" * 16).decode()
    result = x.check_secret(short_b64)
    assert result is None


def test_shiro_not_base64():
    x = Shiro_RememberMe()
    result = x.check_secret("not-valid-base64!!!")
    assert result is None


def test_shiro_identify():
    x = Shiro_RememberMe()
    assert x.identify(LIVE_CBC_COOKIE)
    assert not x.identify("too-short")
    assert not x.identify("not valid base64!!!")


def test_shiro_carve_cookies():
    x = Shiro_RememberMe()
    results = x.carve(cookies={"rememberMe": LIVE_CBC_COOKIE})
    assert len(results) == 1
    assert results[0]["secret"] == DEFAULT_KEY
    assert results[0]["location"] == "cookies"
    assert results[0]["type"] == "SecretFound"


def test_shiro_gcm_decrypt():
    x = Shiro_RememberMe()
    result = x.check_secret(GCM_COOKIE)
    assert result
    assert result["secret"] == DEFAULT_KEY
    assert result["details"]["mode"] == "GCM"
    assert "AES-GCM" in result["details"]["info"]


def test_shiro_try_cbc_directly():
    from badsecrets.modules.passive.shiro_rememberme import Shiro_RememberMe as SM

    # 32 bytes exactly — CBC decrypts but no magic bytes → returns None
    result = SM._try_cbc(b"\x00" * 32, b"\x00" * 16, "AAAAAAAAAAAAAAAAAAAAAA==")
    assert result is None


def test_shiro_try_gcm_short():
    from badsecrets.modules.passive.shiro_rememberme import Shiro_RememberMe as SM

    # 40 bytes — too short for GCM (needs >= 48)
    result = SM._try_gcm(b"\x00" * 40, b"\x00" * 16, "AAAAAAAAAAAAAAAAAAAAAA==")
    assert result is None


def test_shiro_try_gcm_bad_tag():
    from badsecrets.modules.passive.shiro_rememberme import Shiro_RememberMe as SM

    # 64 bytes — GCM decrypt_and_verify will raise ValueError (bad tag)
    result = SM._try_gcm(b"\x00" * 64, b"\x00" * 16, "AAAAAAAAAAAAAAAAAAAAAA==")
    assert result is None


def test_shiro_invalid_key_length():
    import base64

    # Craft a valid-looking base64 cookie (64 bytes) and use a custom resource
    # with a key of invalid length (15 bytes) to hit the continue branch
    import tempfile
    import os

    cookie = base64.b64encode(b"\xac\xed\x00\x05" + b"\x00" * 60).decode()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(base64.b64encode(b"\x00" * 15).decode() + "\n")  # 15-byte key — invalid
        f.flush()
        x2 = Shiro_RememberMe(custom_resource=f.name)
        result = x2.check_secret(cookie)
    os.unlink(f.name)
    assert result is None


def test_shiro_base64_decode_error():
    from unittest.mock import patch

    x = Shiro_RememberMe()
    # Bypass identify to hit the base64 decode error branch
    with patch.object(Shiro_RememberMe, "identify", return_value=True):
        result = x.check_secret("not!valid!base64!padding!")
        assert result is None


def test_shiro_short_raw_bytes():
    from unittest.mock import patch
    import base64

    x = Shiro_RememberMe()
    # 20 bytes — passes identify mock, valid base64, but raw < 32
    short = base64.b64encode(b"\x00" * 20).decode()
    with patch.object(Shiro_RememberMe, "identify", return_value=True):
        result = x.check_secret(short)
        assert result is None


def test_shiro_gcm_no_magic_after_decrypt():
    from badsecrets.modules.passive.shiro_rememberme import Shiro_RememberMe as SM
    from unittest.mock import patch, MagicMock

    # Simulate GCM decryption succeeding but plaintext not starting with magic
    fake_pt = b"\x00\x00\x00\x00" + b"\x01" * 60
    mock_cipher = MagicMock()
    mock_cipher.decrypt_and_verify.return_value = fake_pt

    with patch("badsecrets.modules.passive.shiro_rememberme.AES") as mock_aes:
        mock_aes.MODE_GCM = 7
        mock_aes.new.return_value = mock_cipher
        result = SM._try_gcm(b"\x00" * 64, b"\x00" * 16, "AAAAAAAAAAAAAAAAAAAAAA==")
        assert result is None


def test_shiro_description():
    desc = Shiro_RememberMe.get_description()
    assert desc["product"] == "Apache Shiro"
    assert desc["secret"] == "RememberMe AES Key"
    assert desc["severity"] == "CRITICAL"
