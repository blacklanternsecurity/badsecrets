from badsecrets import modules_loaded

Peoplesoft_PSToken = modules_loaded["peoplesoft_pstoken"]

tests = [
    (
        "badsecrets",
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABSpxUdcNT67zqSLW1wY5/FHQd1U6mgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
    ),
    (
        "badsecrets",
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT5mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
    ),
]


def test_peoplesoft():
    for test in tests:
        assert Peoplesoft_PSToken.identify(test[1])
        x = Peoplesoft_PSToken(test[1])
        found_key = x.check_secret()
        assert found_key == True
        assert x.output_parameters["username"] == test[0]
        assert x.output_parameters["PS_TOKEN_password"] != None
