from badsecrets import modules_loaded

FlaskSignedCookies = modules_loaded["flask_signedcookies"]

tests = [
    ("CHANGEME", "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA"),
    ("Attack at dawn!", "eyJsb2dnZWRfaW4iOnRydWV9.ZCONag.j2PHXgeT2B62qlYH72PKVuqjPvE"),
]


def test_flask():
    x = FlaskSignedCookies()
    for test in tests:
        found_key = x.check_secret(test[1])
        assert found_key
        assert found_key["secret"] == test[0]
