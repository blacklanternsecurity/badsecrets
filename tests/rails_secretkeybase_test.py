from badsecrets import modules_loaded

Rails_SecretKeyBase = modules_loaded["rails_secretkeybase"]

tests = [
    (
        "hash_algorithm",
        "SHA1",
        "4698bc5d99f3103ca76ab57f28a6b8f75f5f0768aab4f2e3f3743383594ad91f43e78c1b86138602f5859a811927698180ebfae7c490333f37b87521ca5a5f8c",
        "eyJfcmFpbHMiOnsibWVzc2FnZSI6IklraGxiR3h2TENCSklHRnRJR0VnYzJsbmJtVmtJSEpoYVd4ek5pQkRiMjlyYVdVaElnPT0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5zaWduZWQifX0%3D--eb1ea3ddc55deb16ffc58ac165edfbb554067edc",
    ),
    (
        "encryption_algorithm",
        "AES_CBC",
        "6f9c2bdad527137950bd62e9688c6cd6a3f3ccc1bbd2972c2d9dbdc4bccbfeb38c2832804cfc62fc662ed54b15f8731083cc090b352168b335569cc4375a4696",
        "dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWLS15L00xME1nVFp2ZTlmUWcxZVlpelpnPT0=--7efe7919a5210cfd1ac4c6228e3ff82c0600d841",
    ),
    (
        "encryption_algorithm",
        "AES_GCM",
        "4698bc5d99f3103ca76ab57f28a6b8f75f5f0768aab4f2e3f3743383594ad91f43e78c1b86138602f5859a811927698180ebfae7c490333f37b87521ca5a5f8c",
        "fuP54C4UxMudlZRR6j25zJfkevHVZ6IJR6Hp1B3rW6sAW5Aqc1j2Ri0XgcyLRvuSNVLwzq6cqeWlVhwU13xMS8scjU%2BSGGi%2Bta4jQU7oYujKdxynHSEiYOmeNFW4onXoF3KLlmr7ODmtIaHm1zIEP11TT%2FmRqZuxxecjz0VIxUDhvHYEFQ%3D%3D--ZclUs5zZFu3JPKnx--%2Fc0Q4ufTHqqmMxoin0mRtQ%3D%3D",
    ),
]


negative_tests = [
    (
        "hash_algorithm",
        "SHA1",
        "4698bc5d99f3103ca76ab57f28a6b8f75f5f0768aab4f2e3f3743383594ad91f43e78c1b86138602f5859a811927698180ebfae7c490333f37b87521ca5a5f8c",
        "eyJfcmFpbHMiOnsibWVzc2FnZSI6IklraGxiR3h2TENCSklHRnRJR0VnYzJsbmJtVmtJSEpoYVd4ek5pQkRiMjlyYVdVaElnPT0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5zaWduZWQifX0%3D--BADSECRETS5deb16ffc58ac165edfbb554067edc",
    ),
    (
        "encryption_algorithm",
        "AES_CBC",
        "6f9c2bdad527137950bd62e9688c6cd6a3f3ccc1bbd2972c2d9dbdc4bccbfeb38c2832804cfc62fc662ed54b15f8731083cc090b352168b335569cc4375a4696",
        "dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWLS15$%^&&xME1nVFp2ZTlmUWcxZVlpelpnPT0=--7efe7919a5210cfd1ac4c6228e3ff82c0600d841",
    ),
    (
        "encryption_algorithm",
        "AES_CBC",
        "6f9c2bdad527137950bd62e9688c6cd6a3f3ccc1bbd2972c2d9dbdc4bccbfeb38c2832804cfc62fc662ed54b15f8731083cc090b352168b335569cc4375a4696",
        "UEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWLS15$%^&&xME1nVFp2ZTlmUWcxZVlpelpnPT0=--7efe7919a5210cfd1ac4c6228e3ff82c0600d841",
    ),
]


def test_rails():
    x = Rails_SecretKeyBase()
    for test in tests:
        print(test)
        found_key = x.check_secret(test[3])
        assert found_key
        assert found_key["secret"] == test[2]
        assert found_key["details"][test[0]] == test[1]


def test_rails_negative():
    x = Rails_SecretKeyBase()
    for test in negative_tests:
        print(test)
        found_key = x.check_secret(test[3])
        assert not found_key


def test_rails_malformed():
    x = Rails_SecretKeyBase()
    found_key = x.check_secret("AAECAwQF--AAECAwQF")
    assert not found_key


def test_rails_error_unicode():
    x = Rails_SecretKeyBase()
    found_key = x.check_secret(
        "dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWeS9NMTBNZ1RadmU5ZlFnMWVZaXpaZz09--7efe7919a5210cfd1ac4c6228e3ff82c0600d841"
    )
    assert not found_key


def test_rails_error_binascii():
    x = Rails_SecretKeyBase()
    found_key = x.check_secret(
        "dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWeS9NMTBNZ1RadmU5ZlFnMWV%20XpaZz09--7efe7919a5210cfd1ac4c6228e3ff82c0600d841"
    )
    assert not found_key
