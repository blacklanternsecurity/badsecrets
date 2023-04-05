from badsecrets import modules_loaded

ExpressSignedCookies = modules_loaded["express_signedcookies"]

tests = [
    (
        "your-session-secret-key",
        "s%3A2eb4SvnuYufiFoKr0DLB-5gWD_YtlQhs.mGdwi%2F4pdFZkuraF%2FCit68TmBkpALzPSbCyDGEfpJjo",
    ),
    ("Shh, its a secret!", "s%3ABh8oG0qgMyJc4qq8A47I0MTwcNiu7ue8.hXhPs8q9AN4ATeh2KrjuzvSbJA7cqbkP5cUUT34bZKA"),
]


def test_express():
    x = ExpressSignedCookies()
    for test in tests:
        found_key = x.check_secret(test[1])
        assert found_key
        assert found_key["secret"] == test[0]
