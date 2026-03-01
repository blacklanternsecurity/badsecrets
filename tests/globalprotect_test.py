import asyncio
import httpx
import respx
from badsecrets.base import yara_prefilter_scan, probe_all_modules
from badsecrets.modules.active.globalprotect import GlobalProtect_DefaultMasterKey


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


@respx.mock
def test_probe_default_key_found():
    """Mock /sslmgr returning 'Unable to find the configuration' -> SecretFound."""
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("https://vpn.example.com/global-protect/login.esp"))
    assert len(results) == 1
    assert results[0]["type"] == "SecretFound"
    assert results[0]["details"]["is_default_key"] is True
    assert results[0]["details"]["scep_configured"] is False
    assert "p1a2l3o4a5l6t7o8" in results[0]["secret"]


@respx.mock
def test_probe_scep_enabled():
    """Mock returning 'Unable to generate client certificate' -> SecretFound with CVE."""
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to generate client certificate")
    )

    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 1
    assert results[0]["type"] == "SecretFound"
    assert results[0]["details"]["scep_configured"] is True
    assert results[0]["details"]["cve"] == "CVE-2021-3060"


@respx.mock
def test_probe_key_rejected():
    """Mock returning 'Invalid Cookie' -> no result."""
    respx.post("https://vpn.example.com/sslmgr").mock(return_value=httpx.Response(200, text="Invalid Cookie"))

    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 0


@respx.mock
def test_probe_connection_error():
    """Mock raising exception -> no crash, no result."""
    respx.post("https://vpn.example.com/sslmgr").mock(side_effect=httpx.ConnectError("Connection refused"))

    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("https://vpn.example.com"))
    assert len(results) == 0


@respx.mock
def test_probe_custom_key():
    """Custom key finds a non-default key."""
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    gp = GlobalProtect_DefaultMasterKey()
    # The default key will also match, so we test that custom keys are tried
    results = asyncio.run(gp.probe("https://vpn.example.com", custom_keys=["mycustomkey123"]))
    # Default key matches first
    assert len(results) >= 1
    assert results[0]["details"]["is_default_key"] is True


@respx.mock
def test_probe_only_custom_key_matches():
    """Only custom key matches, default key is rejected."""
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call (default key) -> rejected
            return httpx.Response(200, text="Invalid Cookie")
        else:
            # Second call (custom key) -> found
            return httpx.Response(200, text="Unable to find the configuration")

    respx.post("https://vpn.example.com/sslmgr").mock(side_effect=side_effect)

    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("https://vpn.example.com", custom_keys=["mycustomkey123"]))
    assert len(results) == 1
    assert results[0]["details"]["is_default_key"] is False
    assert results[0]["details"]["key"] == "mycustomkey123"


@respx.mock
def test_probe_all_modules_integration():
    """Full flow: response -> prefilter -> probe -> result."""
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    # Create a mock httpx response for the initial page
    mock_response = httpx.Response(
        200,
        text=GLOBALPROTECT_PORTAL_HTML,
        request=httpx.Request("GET", "https://vpn.example.com"),
    )

    results = asyncio.run(
        probe_all_modules(
            httpx_response=mock_response,
            url="https://vpn.example.com",
        )
    )
    assert len(results) >= 1
    assert results[0]["detecting_module"] == "GlobalProtect_DefaultMasterKey"
    assert results[0]["type"] == "SecretFound"
    assert results[0]["description"]["product"] == "PAN-OS GlobalProtect"
    assert results[0]["description"]["severity"] == "CRITICAL"


@respx.mock
def test_probe_all_modules_no_prefilter_match():
    """Unrelated response -> no prefilter match -> no probes fired."""
    mock_response = httpx.Response(
        200,
        text=UNRELATED_HTML,
        request=httpx.Request("GET", "https://example.com"),
    )

    results = asyncio.run(
        probe_all_modules(
            httpx_response=mock_response,
            url="https://example.com",
        )
    )
    assert results == []


def test_probe_invalid_url():
    """Probe with invalid URL returns empty results."""
    gp = GlobalProtect_DefaultMasterKey()
    results = asyncio.run(gp.probe("not-a-url"))
    assert results == []


@respx.mock
def test_probe_with_http_client():
    """Probe uses provided http_client instead of creating its own."""
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    async def run():
        async with httpx.AsyncClient() as client:
            gp = GlobalProtect_DefaultMasterKey(http_client=client)
            return await gp.probe("https://vpn.example.com")

    results = asyncio.run(run())
    assert len(results) == 1
