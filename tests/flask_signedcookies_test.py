from badsecrets import modules_loaded

FlaskSignedCookies = modules_loaded["flask_signedcookies"]

tests = [("CHANGEME", "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA")]


def test_flask():
    x = FlaskSignedCookies()
    for test in tests:
        found_key = x.check_secret(test[1])
        assert found_key
        assert found_key["secret"] == test[0]
