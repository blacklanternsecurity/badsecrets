import gzip
import base64

from badsecrets import modules_loaded
from badsecrets.base import carve_all_modules

ASPNETcompressedviewstate = modules_loaded["aspnet_compressedviewstate"]

KNOWN_GOOD = "H4sIAAAAAAAEAPvPyJ/Cz8ppZGpgaWpgZmmYAgAAmCJNEQAAAA=="


def test_aspnet_compressedviewstate():
    x = ASPNETcompressedviewstate()
    found_key = x.check_secret(KNOWN_GOOD)
    assert found_key
    assert found_key["secret"] == "UNPROTECTED (compressed)"


def test_aspnet_compressedviewstate_details():
    x = ASPNETcompressedviewstate()
    found_key = x.check_secret(KNOWN_GOOD)
    assert found_key["details"]["source"] == KNOWN_GOOD
    assert "Unprotected" in found_key["details"]["info"]
    assert "Compressed" in found_key["details"]["info"]


def test_aspnet_compressedviewstate_bad_not_gzip():
    """Non-gzip base64 data should not match."""
    x = ASPNETcompressedviewstate()
    result = x.check_secret("dGhpcyBpcyBub3QgZ3ppcA==")
    assert result is None


def test_aspnet_compressedviewstate_bad_preamble():
    """Valid gzip but inner data doesn't start with ff01 viewstate preamble."""
    bad_data = b"this is not a viewstate"
    compressed = base64.b64encode(gzip.compress(bad_data)).decode()
    x = ASPNETcompressedviewstate()
    result = x.check_secret(compressed)
    assert result is None


def test_aspnet_compressedviewstate_not_base64():
    """Completely invalid input should return None."""
    x = ASPNETcompressedviewstate()
    result = x.check_secret("not-valid-at-all!!!")
    assert result is None


def test_aspnet_compressedviewstate_empty_string():
    """Empty string should not match identify regex."""
    x = ASPNETcompressedviewstate()
    result = x.check_secret("")
    assert result is None


def test_aspnet_compressedviewstate_identify():
    """Identify should match H4sI prefix."""
    assert ASPNETcompressedviewstate.identify(KNOWN_GOOD)
    assert not ASPNETcompressedviewstate.identify("dGhpcyBpcyBub3QgZ3ppcA==")
    assert not ASPNETcompressedviewstate.identify("not_base64")


def test_aspnet_compressedviewstate_carve_viewstate_field():
    """Carve from __VIEWSTATE hidden field."""
    body = f'<input type="hidden" name="__VIEWSTATE" value="{KNOWN_GOOD}">'
    x = ASPNETcompressedviewstate()
    results = x.carve(body=body)
    assert len(results) > 0
    assert results[0]["type"] == "SecretFound"
    assert results[0]["location"] == "body"


def test_aspnet_compressedviewstate_carve_vstate_field():
    """Carve from __VSTATE hidden field (HigherLogic variant)."""
    body = f'<input type="hidden" name="__VSTATE" value="{KNOWN_GOOD}">'
    x = ASPNETcompressedviewstate()
    results = x.carve(body=body)
    assert len(results) > 0
    assert results[0]["type"] == "SecretFound"


def test_aspnet_compressedviewstate_carve_compressedviewstate_field():
    """Carve from __COMPRESSEDVIEWSTATE hidden field."""
    body = f'<input type="hidden" name="__COMPRESSEDVIEWSTATE" value="{KNOWN_GOOD}">'
    x = ASPNETcompressedviewstate()
    results = x.carve(body=body)
    assert len(results) > 0
    assert results[0]["type"] == "SecretFound"


def test_aspnet_compressedviewstate_carve_bad_value():
    """Carve with a non-compressed value in the field should not return SecretFound."""
    body = '<input type="hidden" name="__VIEWSTATE" value="dGhpcyBpcyBub3QgZ3ppcA==">'
    x = ASPNETcompressedviewstate()
    results = x.carve(body=body)
    secret_results = [r for r in results if r["type"] == "SecretFound"]
    assert len(secret_results) == 0


def test_aspnet_compressedviewstate_carve_all_modules():
    """Ensure carve_all_modules picks up the compressed viewstate."""
    body = f'<input type="hidden" name="__COMPRESSEDVIEWSTATE" value="{KNOWN_GOOD}">'
    results = carve_all_modules(body=body)
    assert results
    found = [r for r in results if r["detecting_module"] == "ASPNET_compressedviewstate"]
    assert len(found) > 0


def test_aspnet_compressedviewstate_description():
    """Verify module description metadata."""
    desc = ASPNETcompressedviewstate.get_description()
    assert desc["product"] == "ASP.NET Compressed Viewstate"
    assert desc["severity"] == "CRITICAL"
