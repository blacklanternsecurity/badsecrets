from badsecrets import modules_loaded

ASPNETcompressedviewstate = modules_loaded["aspnet_compressedviewstate"]


def test_aspnet_compressedviewstate():
    x = ASPNETcompressedviewstate()
    found_key = x.check_secret("H4sIAAAAAAAEAPvPyJ/Cz8ppZGpgaWpgZmmYAgAAmCJNEQAAAA==")
    assert found_key
    assert found_key["secret"] == "UNPROTECTED (compressed)"
