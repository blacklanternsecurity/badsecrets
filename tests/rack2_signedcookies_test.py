from badsecrets import modules_loaded

Rack2_SignedCookies = modules_loaded["rack2_signedcookies"]

tests = [
    (
        "BAh7B0kiD3Nlc3Npb25faWQGOgZFVG86HVJhY2s6OlNlc3Npb246OlNlc3Npb25JZAY6D0BwdWJsaWNfaWRJIkU5YmI3ZDUyODUyNTAwMDYzMGE2NjMxYTA5MjBlMjYzMzFmOGE0MjBhNTdhYWIxNzVkZTFmM2FjMDQ3NmI1NDQzBjsARkkiCmNvdW50BjsARmkG--3a983fbc58911c5266d7748a6a55165f74d412f4",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
]


def test_rack2_signedcookies():
    x = Rack2_SignedCookies()
    for test in tests:
        found_key = x.check_secret(test[0])
        assert found_key
        assert found_key["secret"] == test[1]
