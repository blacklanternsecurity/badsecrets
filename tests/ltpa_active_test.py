import asyncio
from blasthttp.mock import BlasthttpMock, MockResponse
from badsecrets.base import yara_prefilter_scan, probe_all_modules
from badsecrets.modules.active.ltpa_token import LTPA_Token_Key, forge_ltpa2_token


class FakeResponse:
    """Duck-typed HTTP response for probe_all_modules tests."""

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


WEBSPHERE_LOGIN_HTML = """
<html>
<head><title>Integrated Solutions Console</title></head>
<body>
<h1>WebSphere Application Server</h1>
<form action="/ibm/console/j_security_check" method="POST">
<input type="text" name="j_username" />
<input type="password" name="j_password" />
<input type="submit" value="Log in" />
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
    """YARA prefilter fires on body containing WebSphere indicators."""
    result = yara_prefilter_scan(WEBSPHERE_LOGIN_HTML)
    assert "LTPA_Token_Key" in result


def test_prefilter_match_header():
    """YARA prefilter fires on LtpaToken2 in Set-Cookie header."""
    header_text = "set-cookie: LtpaToken2=abc123; Path=/\n\n<html></html>"
    result = yara_prefilter_scan(header_text)
    assert "LTPA_Token_Key" in result


def test_prefilter_miss():
    """YARA prefilter doesn't fire on unrelated content."""
    result = yara_prefilter_scan(UNRELATED_HTML)
    assert "LTPA_Token_Key" not in result


def test_probe_key_found():
    """Baseline 302, forged token 200 -> SecretFound."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "LtpaToken2=" in cookie_header:
            return MockResponse(text="<html>Admin Console</html>", status_code=200)
        return MockResponse(text="", status_code=302, headers={"Location": "/ibm/console/login"})

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://websphere.example.com/ibm/console")

    gp = LTPA_Token_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://websphere.example.com/ibm/console"))
    assert len(results) >= 1
    assert results[0]["type"] == "SecretFound"
    assert "LtpaToken2 key" in results[0]["secret"]
    assert "ltpa_active_keys.json" in results[0]["secret"]


def test_probe_key_rejected():
    """All keys rejected (always 302) -> no results."""

    def always_redirect(request):
        return MockResponse(text="", status_code=302, headers={"Location": "/ibm/console/login"})

    bh = BlasthttpMock()
    bh.add_callback(always_redirect, url="https://websphere.example.com/ibm/console")

    gp = LTPA_Token_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://websphere.example.com/ibm/console"))
    assert len(results) == 0


def test_probe_not_protected():
    """Baseline 200 (no auth required) -> no probes sent."""
    bh = BlasthttpMock()
    bh.add_response(url="https://example.com/app", text="<html>Public page</html>", status_code=200)

    gp = LTPA_Token_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://example.com/app"))
    assert len(results) == 0


def test_probe_connection_error():
    """Connection error -> no crash, no results."""

    def _err(req):
        raise RuntimeError("Connection refused")

    bh = BlasthttpMock()
    bh.add_callback(_err, url="https://websphere.example.com/ibm/console")

    gp = LTPA_Token_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://websphere.example.com/ibm/console"))
    assert len(results) == 0


def test_probe_invalid_url():
    """Invalid URL returns empty results."""
    gp = LTPA_Token_Key()
    results = asyncio.run(gp.probe("not-a-url"))
    assert results == []


def test_probe_all_modules_integration():
    """Full flow: response with WebSphere headers -> prefilter -> probe -> result."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "LtpaToken2=" in cookie_header:
            return MockResponse(text="<html>Admin Console</html>", status_code=200)
        return MockResponse(text="", status_code=302, headers={"Location": "/ibm/console/login"})

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://websphere.example.com/ibm/console")

    mock_response = FakeResponse(
        text=WEBSPHERE_LOGIN_HTML,
        headers={"Set-Cookie": "LtpaToken2=expired; Path=/"},
        url="https://websphere.example.com/ibm/console",
    )

    results = asyncio.run(
        probe_all_modules(
            http_response=mock_response,
            url="https://websphere.example.com/ibm/console",
            http_client=bh,
        )
    )
    assert len(results) >= 1
    assert results[0]["detecting_module"] == "LTPA_Token_Key"
    assert results[0]["type"] == "SecretFound"
    assert results[0]["description"]["product"] == "IBM WebSphere LTPA"
    assert results[0]["description"]["severity"] == "HIGH"


def test_probe_all_modules_no_prefilter_match():
    """Unrelated response -> no prefilter match -> no probes fired."""
    mock_response = FakeResponse(text=UNRELATED_HTML, url="https://example.com")

    results = asyncio.run(
        probe_all_modules(
            http_response=mock_response,
            url="https://example.com",
        )
    )
    # LTPA module should NOT be in results (but other modules might fire)
    ltpa_results = [r for r in results if r.get("detecting_module") == "LTPA_Token_Key"]
    assert len(ltpa_results) == 0


def test_description():
    """Module description is correct."""
    desc = LTPA_Token_Key.get_description()
    assert desc["product"] == "IBM WebSphere LTPA"
    assert desc["severity"] == "HIGH"


def test_forge_ltpa2_token():
    """forge_ltpa2_token produces valid base64 output."""
    import base64
    from Crypto.PublicKey import RSA

    # Generate a test RSA key
    rsa_key = RSA.generate(1024)
    aes_key = b"\x00" * 16

    token = forge_ltpa2_token(aes_key, rsa_key, "testRealm", "testuser")
    # Should be valid base64
    raw = base64.b64decode(token)
    assert len(raw) > 0
    assert len(raw) % 16 == 0  # AES block-aligned


def test_parse_ibm_private_key_too_short():
    """Key data shorter than minimum (133 bytes) returns None."""
    from badsecrets.modules.active.ltpa_token import _parse_ibm_private_key

    assert _parse_ibm_private_key(b"\x00" * 100) is None


def test_parse_ibm_private_key_bad_exponent():
    """Key with invalid public exponent returns None."""
    from badsecrets.modules.active.ltpa_token import _parse_ibm_private_key

    # 133 bytes (short format): 3 bytes e + 65 bytes p + 65 bytes q
    # Set e to 5 (not 3 or 65537)
    data = b"\x00\x00\x05" + b"\x00" * 130
    assert _parse_ibm_private_key(data) is None


def test_parse_ibm_private_key_short_format():
    """Short format (no d_length prefix) with valid RSA params."""
    from badsecrets.modules.active.ltpa_token import _parse_ibm_private_key
    from Crypto.Util.number import getPrime

    # Generate primes that fit in 65 bytes (520 bits)
    p = getPrime(512)
    q = getPrime(512)
    e = 65537

    # Build short format: [3 bytes e][65 bytes p][65 bytes q]
    e_bytes = e.to_bytes(3, "big")
    p_bytes = p.to_bytes(65, "big")
    q_bytes = q.to_bytes(65, "big")
    data = e_bytes + p_bytes + q_bytes

    result = _parse_ibm_private_key(data)
    assert result is not None
    # p/q may be swapped internally but n should match
    assert result.n == p * q


def test_parse_ibm_private_key_p_less_than_q():
    """When p < q, the parser swaps them so p > q (PyCryptodome requirement)."""
    from badsecrets.modules.active.ltpa_token import _parse_ibm_private_key
    from Crypto.Util.number import getPrime

    # Generate two primes and ensure p < q in the input
    a = getPrime(512)
    b = getPrime(512)
    small, big = sorted([a, b])

    e = 65537
    # Place the smaller prime in the p position, bigger in q position
    e_bytes = e.to_bytes(3, "big")
    p_bytes = small.to_bytes(65, "big")
    q_bytes = big.to_bytes(65, "big")
    data = e_bytes + p_bytes + q_bytes

    result = _parse_ibm_private_key(data)
    assert result is not None
    assert result.n == small * big
    # PyCryptodome stores p > q, so the swap should have happened
    assert result.p > result.q


def test_parse_ibm_private_key_long_format_bad_d_len():
    """Long format where d_length is invalid falls through to short format parse.

    When len > 133 but d_length check fails (d_len too large), the code falls
    through to try short-format parsing starting at byte 0. The first 4 bytes
    (the d_length field) are interpreted as the exponent, which won't be 3 or
    65537, so None is returned — this exercises lines 62-65.
    """
    from badsecrets.modules.active.ltpa_token import _parse_ibm_private_key

    # 140 bytes total (> 133), d_length = 999999 (too large)
    # Falls through to short format, reads bytes 0-2 as e = garbage -> None
    data = (999999).to_bytes(4, "big") + b"\x00" * 136
    result = _parse_ibm_private_key(data)
    assert result is None


def test_derive_keyset_bad_private_key():
    """_derive_keyset returns None when RSA key parse fails."""
    from badsecrets.modules.active.ltpa_token import _derive_keyset, _derive_password_key
    import base64

    password_key = _derive_password_key("WebAS")
    # Valid 3DESKey (24 bytes encrypted), but PrivateKey too short to parse
    from Crypto.Cipher import DES3

    cipher = DES3.new(password_key, DES3.MODE_ECB)
    fake_3des = base64.b64encode(cipher.encrypt(b"\x00" * 24)).decode()
    fake_priv = base64.b64encode(cipher.encrypt(b"\x00" * 8)).decode()

    entry = {"3DESKey": fake_3des, "PrivateKey": fake_priv, "Realm": "test"}
    result = _derive_keyset(entry, password_key)
    assert result is None


def test_probe_no_active_keys():
    """Probe returns empty when no active keys are available."""
    import unittest.mock as mock

    gp = LTPA_Token_Key()
    with mock.patch.object(gp, "_load_active_keys", return_value=[]):
        results = asyncio.run(gp.probe("https://websphere.example.com/ibm/console"))
    assert len(results) == 0


def test_probe_request_exception():
    """Exception during individual key probe doesn't crash."""

    def side_effect(request):
        cookie_header = _cookie_value(request)
        if "LtpaToken2=" in cookie_header:
            raise RuntimeError("timeout")
        return MockResponse(text="", status_code=302, headers={"Location": "/login"})

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://websphere.example.com/ibm/console")

    gp = LTPA_Token_Key(http_client=bh)
    results = asyncio.run(gp.probe("https://websphere.example.com/ibm/console"))
    assert len(results) == 0
