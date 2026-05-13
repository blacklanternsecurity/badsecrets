import asyncio
import unittest.mock as mock
from blasthttp.mock import BlasthttpMock, MockResponse
from badsecrets.base import yara_prefilter_scan, probe_all_modules
from badsecrets.modules.active.globalprotect import GlobalProtect_DefaultMasterKey


class FakeResponse:
    """Duck-typed HTTP response for probe_all_modules tests."""

    def __init__(self, text="", headers=None, cookies=None, url=""):
        self.text = text
        self.headers = headers if headers is not None else {}
        self.cookies = cookies if cookies is not None else {}
        self.url = url


# Sample HTML that looks like a GlobalProtect portal
GLOBALPROTECT_PORTAL_HTML = """
<html>
<head><title>GlobalProtect Portal</title></head>
<body>
<form action="/global-protect/login.esp" method="POST">
<input type="text" name="user" />
<input type="password" name="passwd" />
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


def test_prefilter_match():
    """YARA prefilter fires on GlobalProtect portal HTML."""
    result = yara_prefilter_scan(GLOBALPROTECT_PORTAL_HTML)
    assert "GlobalProtect_DefaultMasterKey" in result


def test_prefilter_match_case_insensitive():
    """YARA prefilter is case-insensitive."""
    html = "<html><body>globalprotect</body></html>"
    result = yara_prefilter_scan(html)
    assert "GlobalProtect_DefaultMasterKey" in result


def test_prefilter_miss():
    """YARA prefilter doesn't fire on unrelated HTML."""
    result = yara_prefilter_scan(UNRELATED_HTML)
    assert "GlobalProtect_DefaultMasterKey" not in result


def test_crypto_derive_key():
    """derive_aes_key() produces expected 32-byte key."""
    key = GlobalProtect_DefaultMasterKey.derive_aes_key("p1a2l3o4a5l6t7o8")
    assert isinstance(key, bytes)
    assert len(key) == 32
    # First 16 bytes should equal second 16 bytes (doubled MD5)
    assert key[:16] == key[16:]


def test_crypto_build_cookie():
    """build_auth_cookie() produces valid base64 token with separator."""
    aes_key = GlobalProtect_DefaultMasterKey.derive_aes_key("p1a2l3o4a5l6t7o8")
    cookie = GlobalProtect_DefaultMasterKey.build_auth_cookie(aes_key)
    assert isinstance(cookie, str)
    # Token format: base64_version + base64_sha1 + "-" + base64_ciphertext
    assert "-" in cookie
    # Starts with "AQ==" (base64 of \x01)
    assert cookie.startswith("AQ==")


def _mock_static(url, text, status=200, method="POST"):
    bh = BlasthttpMock()
    bh.add_response(url=url, method=method, text=text, status_code=status)
    return bh


def test_probe_default_key_found():
    """Mock /sslmgr returning 'Unable to find the configuration' -> SecretFound."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Unable to find the configuration")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com/global-protect/login.esp"))
    assert len(results) == 1
    assert results[0]["type"] == "SecretFound"
    assert results[0]["details"]["is_default_key"] is True
    assert results[0]["details"]["scep_configured"] is False
    assert "p1a2l3o4a5l6t7o8" in results[0]["secret"]


def test_probe_scep_enabled():
    """Mock returning 'Unable to generate client certificate' -> SecretFound with CVE."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Unable to generate client certificate")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 1
    assert results[0]["type"] == "SecretFound"
    assert results[0]["details"]["scep_configured"] is True
    assert results[0]["details"]["cve"] == "CVE-2021-3060"


def test_probe_key_rejected():
    """Mock returning 'Invalid Cookie' -> no result."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Invalid Cookie")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 0


def test_probe_connection_error():
    """Mock raising exception -> no crash, no result."""

    def _err(req):
        raise RuntimeError("Connection refused")

    bh = BlasthttpMock()
    bh.add_callback(_err, url="https://vpn.example.com/sslmgr")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 0


def test_probe_custom_key():
    """Custom key alongside default — default matches first."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Unable to find the configuration")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com", custom_keys=["mycustomkey123"]))
    assert len(results) >= 1
    assert results[0]["details"]["is_default_key"] is True


def test_probe_only_custom_key_matches():
    """Only custom key matches, default key is rejected."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (default key) -> rejected
            return MockResponse(text="Invalid Cookie", status_code=200)
        # Second call (custom key) -> found
        return MockResponse(text="Unable to find the configuration", status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://vpn.example.com/sslmgr")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com", custom_keys=["mycustomkey123"]))
    assert len(results) == 1
    assert results[0]["details"]["is_default_key"] is False
    assert results[0]["details"]["key"] == "mycustomkey123"


def test_probe_all_modules_integration():
    """Full flow: response -> prefilter -> probe -> result."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Unable to find the configuration")

    mock_response = FakeResponse(text=GLOBALPROTECT_PORTAL_HTML, url="https://vpn.example.com")

    results = asyncio.run(
        probe_all_modules(
            http_response=mock_response,
            url="https://vpn.example.com",
            http_client=bh,
        )
    )
    assert len(results) >= 1
    assert results[0]["detecting_module"] == "GlobalProtect_DefaultMasterKey"
    assert results[0]["type"] == "SecretFound"
    assert results[0]["description"]["product"] == "PAN-OS GlobalProtect"
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


def test_probe_invalid_url():
    """Probe with invalid URL returns empty results."""
    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("not-a-url"))
    assert results == []


def test_probe_with_http_client():
    """Probe uses provided http_client instead of creating its own."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Unable to find the configuration")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 1


def test_probe_unexpected_response():
    """Response with unexpected text triggers debug log, no result."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Something completely different")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 0


def test_probe_resource_file_extra_key():
    """Keys from resource file beyond the default key are tried."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return MockResponse(text="Invalid Cookie", status_code=200)
        return MockResponse(text="Unable to find the configuration", status_code=200)

    bh = BlasthttpMock()
    bh.add_callback(side_effect, url="https://vpn.example.com/sslmgr")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    with mock.patch.object(gp, "load_resources", return_value=["p1a2l3o4a5l6t7o8\n", "extra_key_from_file\n"]):
        results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 1
    assert results[0]["details"]["key"] == "extra_key_from_file"
    assert results[0]["details"]["is_default_key"] is False


def test_probe_resource_file_missing():
    """Missing resource file doesn't crash — falls back to default key only."""
    bh = _mock_static("https://vpn.example.com/sslmgr", "Unable to find the configuration")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    with mock.patch.object(gp, "load_resources", side_effect=FileNotFoundError):
        results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 1
    assert results[0]["details"]["is_default_key"] is True


def test_probe_exception_during_key_attempt():
    """Exception during key probe doesn't crash."""

    def _err(req):
        raise RuntimeError("timeout")

    bh = BlasthttpMock()
    bh.add_callback(_err, url="https://vpn.example.com/sslmgr")

    gp = GlobalProtect_DefaultMasterKey(http_client=bh)
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 0


class _StrictBodyClient:
    """Wraps BlasthttpMock to enforce real blasthttp's body=str requirement.

    BlasthttpMock silently accepts bytes for `body`, but the real
    blasthttp.BlastHTTP.request() raises TypeError on bytes. This wrapper
    mirrors that strictness so regressions are caught in tests.
    """

    def __init__(self, mock):
        self._mock = mock
        self.bodies = []

    async def request(self, url, **kwargs):
        body = kwargs.get("body")
        if body is not None and not isinstance(body, str):
            raise TypeError(f"argument 'body': '{type(body).__name__}' object cannot be cast as 'str'")
        self.bodies.append(body)
        return await self._mock.request(url, **kwargs)


def test_regression_probe_body_must_be_str():
    """Regression: blasthttp rejects bytes bodies.

    Before the fix, probe() built form_body with urlencode(...).encode(), which
    crashed real blasthttp with TypeError. BlasthttpMock-based tests missed it
    because the mock accepts bytes silently.
    """
    bh = BlasthttpMock()
    bh.add_response(
        url="https://vpn.example.com/sslmgr",
        text="Unable to find the configuration",
        status_code=200,
    )
    strict = _StrictBodyClient(bh)

    gp = GlobalProtect_DefaultMasterKey(http_client=strict)
    asyncio.run(gp.probe("https://vpn.example.com"))

    assert strict.bodies, "expected at least one request"
    for b in strict.bodies:
        assert isinstance(b, str), f"body must be str, got {type(b).__name__}"
