from badsecrets import modules_loaded

ExpressSignedCookies_ES = modules_loaded["express_signedcookies_es"]
ExpressSignedCookies_CS = modules_loaded["express_signedcookies_cs"]

es_tests = [
    (
        "your-session-secret-key",
        "s%3A2eb4SvnuYufiFoKr0DLB-5gWD_YtlQhs.mGdwi%2F4pdFZkuraF%2FCit68TmBkpALzPSbCyDGEfpJjo",
    ),
    ("Shh, its a secret!", "s%3ABh8oG0qgMyJc4qq8A47I0MTwcNiu7ue8.hXhPs8q9AN4ATeh2KrjuzvSbJA7cqbkP5cUUT34bZKA"),
]


cs_tests = [
    (
        "your-secret-key",
        ("foo=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==", "zOQU7v7aTe_3zu7tnVuHi1MJ2DU"),
    ),
    ("your-secret-key", ("foo=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==", "zOQU7v7aTe_3zu7tnVuHi1MJ2DU")),
]


def test_express_es():
    x = ExpressSignedCookies_ES()
    for test in es_tests:
        found_key = x.check_secret(test[1])
        assert found_key
        assert found_key["secret"] == test[0]


def test_express_es_bad():
    x = ExpressSignedCookies_ES()
    for test in es_tests:
        found_key = x.check_secret("s%3A%2F%2Fsomeorg.org%2Flocations%2Fnorth")
        assert not found_key


def test_express_cs():
    x = ExpressSignedCookies_CS()
    for test in cs_tests:
        found_key = x.check_secret(test[1][0], test[1][1])
        assert found_key
        assert found_key["secret"] == test[0]
