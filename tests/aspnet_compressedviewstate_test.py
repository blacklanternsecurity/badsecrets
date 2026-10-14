import gzip
import time
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


def test_aspnet_compressedviewstate_carve_compressed_vstate_field():
    """Carve from the __COMPRESSED_VSTATE (underscore) hidden field."""
    body = f'<input type="hidden" name="__COMPRESSED_VSTATE" id="__COMPRESSED_VSTATE" value="{KNOWN_GOOD}" />'
    x = ASPNETcompressedviewstate()
    results = x.carve(body=body)
    assert len(results) > 0
    assert results[0]["type"] == "SecretFound"
    assert results[0]["location"] == "body"


def test_aspnet_compressedviewstate_carve_not_shadowed_by_empty_viewstate():
    """An empty __VIEWSTATE field must not hide a real payload, in either document order."""
    payload = f'<input type="hidden" name="__COMPRESSED_VSTATE" id="__COMPRESSED_VSTATE" value="{KNOWN_GOOD}" />'
    empty = '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="" />'
    x = ASPNETcompressedviewstate()
    for body in (payload + empty, empty + payload):
        results = x.carve(body=body)
        secret_results = [r for r in results if r["type"] == "SecretFound"]
        assert len(secret_results) == 1, f"missed payload for body order: {body[:60]}"
        assert secret_results[0]["product"] == KNOWN_GOOD


def test_aspnet_compressedviewstate_carve_all_modules_compressed_vstate():
    """__COMPRESSED_VSTATE next to an empty __VIEWSTATE, as seen in the wild."""
    body = (
        '<form name="aspnetForm" method="post" action="./Error.aspx" id="aspnetForm">\n'
        f'<input type="hidden" name="__COMPRESSED_VSTATE" id="__COMPRESSED_VSTATE" value="{KNOWN_GOOD}" />\n'
        '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="" />\n'
        "</form>"
    )
    results = carve_all_modules(body=body)
    found = [r for r in results if r["detecting_module"] == "ASPNET_compressedviewstate"]
    assert len(found) == 1
    assert found[0]["type"] == "SecretFound"
    assert found[0]["description"]["severity"] == "CRITICAL"


def test_aspnet_compressedviewstate_carve_attribute_between_name_and_value():
    """Unrelated attributes between name= and value= must not defeat the carve."""
    body = f'<input type="hidden" name="__COMPRESSED_VSTATE" class="x" data-y="z" value="{KNOWN_GOOD}" />'
    x = ASPNETcompressedviewstate()
    results = x.carve(body=body)
    assert len(results) > 0
    assert results[0]["type"] == "SecretFound"


def test_aspnet_compressedviewstate_carve_does_not_cross_tag_boundary():
    """A name in one tag must not pair with a value in the next."""
    body = '<input type="hidden" name="__VIEWSTATE"><input type="hidden" value="junk">'
    x = ASPNETcompressedviewstate()
    assert x.carve(body=body) == []


def test_aspnet_compressedviewstate_carve_regex_no_catastrophic_backtracking():
    """Many name hits in one unclosed tag must stay linear, not O(n^2)."""
    body = "<input " + ('name="__VIEWSTATE" ' * 8000) + "x"
    x = ASPNETcompressedviewstate()
    start = time.perf_counter()
    x.carve_regex().search(body)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"carve regex took {elapsed:.2f}s on 150KB of adversarial input"


def test_aspnet_compressedviewstate_carve_viewstategenerator_not_matched():
    """__VIEWSTATEGENERATOR must not be mistaken for a viewstate field."""
    body = f'<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="{KNOWN_GOOD}" />'
    x = ASPNETcompressedviewstate()
    assert x.carve(body=body) == []


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
