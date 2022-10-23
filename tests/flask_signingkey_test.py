from badsecrets import modules_loaded

FlaskSigningKey = modules_loaded["flask_signingkey"]

tests = [("CHANGEME", "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA")]


def test_flask():
    for test in tests:
        assert FlaskSigningKey.identify(test[1])
        x = FlaskSigningKey(test[1])
        found_key = x.check_secret()
        assert found_key == True
        assert x.output_parameters["flask_password"] == test[0]
