from badsecrets import modules_loaded

ASPNETVstate = modules_loaded["aspnet_vstate"]


def test_aspnet_vstate():
    x = ASPNETVstate()
    found_key = x.check_secret("H4sIAAAAAAAEAPvPyJ/Cz8ppZGpgaWpgZmmYAgAAmCJNEQAAAA==")
    assert found_key
    assert found_key["secret"] == "UNPROTECTED (compressed)"
