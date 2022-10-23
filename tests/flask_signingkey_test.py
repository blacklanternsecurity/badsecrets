from badsecrets import modules_loaded

FlaskSigningKey = modules_loaded["flask_signingkey"]

tests = [("CHANGEME", "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA")]


def test_flask():
    x = FlaskSigningKey()
    for test in tests:
        found_key = x.check_secret(test[1])
        assert found_key
        assert found_key["flask_password"] == test[0]
