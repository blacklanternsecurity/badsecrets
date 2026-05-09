import asyncio
import base64
import unittest.mock as mock
from blasthttp.mock import BlasthttpMock, MockResponse
from badsecrets.base import yara_prefilter_scan, probe_all_modules, build_prefilter_text
from badsecrets.modules.active.shiro_rememberme import Shiro_RememberMe_Key, _SERIALIZED_PRINCIPAL


class FakeResponse:
    """Duck-typed HTTP response for build_prefilter_text/probe_all_modules tests."""

    def __init__(self, text="", headers=None, cookies=None, url=""):
        self.text = text
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.url = url


def _cookie_value(req):
    """Case-insensitive lookup of the Cookie header on a MockRequest."""
    for k, v in req.headers.items():
        if k.lower() == "cookie":
            return v
    return ""


SHIRO_LOGIN_HTML = """
<html>
<head><title>Login</title></head>
<body>
<form action="/doLogin" method="POST">
<input type="text" name="username" />
<input type="password" name="password" />
<input type="checkbox" name="rememberMe" /> Remember me
</form>
</body>
</html>
"""

UNRELATED_HTML = """
<html>
<head><title>My Website</title></head>
<body><p>Nothing to see here.</p></body>
</html>
"""


def test_prefilter_match_body():
    """YARA prefilter fires on body containing rememberMe."""
    result = yara_prefilter_scan(SHIRO_LOGIN_HTML)
    assert "Shiro_RememberMe_Key" in result


def test_prefilter_match_header():
    """YARA prefilter fires on Set-Cookie: rememberMe=deleteMe in headers."""
    header_text = "set-cookie: rememberMe=deleteMe; Path=/\n\n<html></html>"
    result = yara_prefilter_scan(header_text)
    assert "Shiro_RememberMe_Key" in result


def test_prefilter_miss():
    """YARA prefilter doesn't fire on unrelated content."""
    result = yara_prefilter_scan(UNRELATED_HTML)
    assert "Shiro_RememberMe_Key" not in result


def test_build_prefilter_text():
    """build_prefilter_text includes headers and body."""
    resp = FakeResponse(
        text="<html></html>",
        headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
        url="https://example.com",
    )
    text = build_prefilter_text(http_response=resp)
    assert "rememberMe=deleteMe" in text
    assert "<html></html>" in text


def test_encrypt_cbc():
    """encrypt_cbc produces valid IV + ciphertext."""
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    raw = Shiro_RememberMe_Key.encrypt_cbc(key, _SERIALIZED_PRINCIPAL)
    # 16 byte IV + ciphertext (padded to block size)
    assert len(raw) > 16
    assert len(raw) % 16 == 0


def test_encrypt_gcm():
    """encrypt_gcm produces nonce + ciphertext + tag."""
    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    raw = Shiro_RememberMe_Key.encrypt_gcm(key, _SERIALIZED_PRINCIPAL)
    # 16 byte nonce + ciphertext + 16 byte tag
    assert len(raw) > 48


def test_encrypt_decrypt_roundtrip_cbc():
    """CBC encrypt then decrypt recovers plaintext."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    raw = Shiro_RememberMe_Key.encrypt_cbc(key, _SERIALIZED_PRINCIPAL)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    assert pt == _SERIALIZED_PRINCIPAL


def test_encrypt_decrypt_roundtrip_gcm():
    """GCM encrypt then decrypt recovers plaintext."""
    from Crypto.Cipher import AES

    key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    raw = Shiro_RememberMe_Key.encrypt_gcm(key, _SERIALIZED_PRINCIPAL)
    nonce = raw[:16]
    tag = raw[-16:]
    ct = raw[16:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    assert pt == _SERIALIZED_PRINCIPAL


def test_probe_default_key_found_cbc():
    """Default key accepted (no deleteMe) in CBC mode -> SecretFound."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "rememberMe=1" in cookie_header:
            # Garbage cookie -> deleteMe (Shiro confirmation)
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        # Real encrypted cookie -> no deleteMe (key accepted!)
        return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) >= 1
    assert results[0]["type"] == "SecretFound"
    assert results[0]["details"]["is_default_key"] is True
    assert results[0]["details"]["cve"] == "CVE-2016-4437"
    assert "kPH+bIxk5D2deZiIxcaaaA==" in results[0]["secret"]


def test_probe_key_rejected():
    """All keys rejected (deleteMe every time) -> no results."""

    def always_delete_me(request):
        return MockResponse(
            text=SHIRO_LOGIN_HTML,
            headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
            status_code=200,
        )

    bh = BlasthttpMock()
    bh.add_callback(always_delete_me, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) == 0


def test_probe_not_shiro():
    """Confirmation step fails (no deleteMe for garbage cookie) -> no probes sent."""

    def no_delete_me(request):
        return MockResponse(text="<html>Not Shiro</html>", status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(no_delete_me, url="https://example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://example.com/login"))
    assert len(results) == 0


def test_probe_connection_error():
    """Connection error -> no crash, no result."""

    def _err(req):
        raise RuntimeError("Connection refused")

    bh = BlasthttpMock()
    bh.add_callback(_err, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) == 0


def test_probe_gcm_key_found():
    """CBC rejected but GCM accepted -> SecretFound with mode=GCM."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Confirmation: garbage cookie -> deleteMe
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        if call_count == 2:
            # CBC attempt -> rejected
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        # GCM attempt -> accepted!
        return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) == 1
    assert results[0]["details"]["mode"] == "GCM"
    assert results[0]["details"]["is_default_key"] is True


def test_probe_custom_key_found():
    """Custom key matches after default is rejected."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        if call_count <= 3:
            # Default key CBC + GCM -> rejected
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        if call_count == 4:
            # Custom key CBC -> accepted!
            return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)
        return MockResponse(
            text=SHIRO_LOGIN_HTML,
            headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
            status_code=200,
        )

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    custom_key = base64.b64encode(b"\x00" * 16).decode()
    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login", custom_keys=[custom_key]))
    assert len(results) == 1
    assert results[0]["details"]["is_default_key"] is False
    assert results[0]["details"]["key"] == custom_key


def test_probe_invalid_url():
    """Invalid URL returns empty results."""
    gp = Shiro_RememberMe_Key()
    results = asyncio.run(gp.probe("not-a-url"))
    assert results == []


def test_probe_with_http_client():
    """Probe uses provided http_client."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) >= 1


def test_probe_all_modules_integration():
    """Full flow: response with Shiro headers -> prefilter -> probe -> result."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    mock_response = FakeResponse(
        text=SHIRO_LOGIN_HTML,
        headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
        url="https://shiro.example.com/login",
    )

    results = asyncio.run(
        probe_all_modules(
            http_response=mock_response,
            url="https://shiro.example.com/login",
            http_client=bh,
        )
    )
    assert len(results) >= 1
    assert results[0]["detecting_module"] == "Shiro_RememberMe_Key"
    assert results[0]["type"] == "SecretFound"
    assert results[0]["description"]["product"] == "Apache Shiro"
    assert results[0]["description"]["severity"] == "CRITICAL"


def test_probe_all_modules_no_prefilter_match():
    """Unrelated response -> no prefilter match -> no probes fired."""
    mock_response = FakeResponse(text=UNRELATED_HTML, url="https://example.com")

    results = asyncio.run(
        probe_all_modules(
            http_response=mock_response,
            url="https://example.com",
        )
    )
    assert results == []


def test_description():
    """Module description is correct."""
    desc = Shiro_RememberMe_Key.get_description()
    assert desc["product"] == "Apache Shiro"
    assert desc["severity"] == "CRITICAL"


def test_probe_resource_file_missing():
    """Missing resource file doesn't crash — falls back to default key."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "rememberMe=1" in cookie_header:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    with mock.patch.object(gp, "load_resources", side_effect=FileNotFoundError):
        results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) >= 1
    assert results[0]["details"]["is_default_key"] is True


def test_probe_default_key_not_in_resources():
    """When resource file keys don't include default, default is prepended."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "rememberMe=1" in cookie_header:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        return MockResponse(text=SHIRO_LOGIN_HTML, status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    other_key = base64.b64encode(b"\x00" * 16).decode()
    gp = Shiro_RememberMe_Key(http_client=bh)
    with mock.patch.object(gp, "load_resources", return_value=[f"{other_key}\n"]):
        results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    # Default key is tried first and accepted
    assert len(results) >= 1
    assert results[0]["details"]["is_default_key"] is True


def test_probe_invalid_key_length():
    """Key that decodes to non-AES length is skipped."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "rememberMe=1" in cookie_header:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        return MockResponse(
            text=SHIRO_LOGIN_HTML,
            headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
            status_code=200,
        )

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    # 15 bytes is not a valid AES key length (need 16, 24, or 32)
    bad_key = base64.b64encode(b"\x00" * 15).decode()
    gp = Shiro_RememberMe_Key(http_client=bh)
    with mock.patch.object(gp, "load_resources", return_value=[f"{bad_key}\n"]):
        results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) == 0


def test_try_key_exception():
    """Exception in _try_key doesn't crash probe."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MockResponse(
                text=SHIRO_LOGIN_HTML,
                headers={"Set-Cookie": "rememberMe=deleteMe; Path=/"},
                status_code=200,
            )
        raise RuntimeError("timeout")

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://shiro.example.com/login")

    gp = Shiro_RememberMe_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://shiro.example.com/login"))
    assert len(results) == 0
