from badsecrets import modules_loaded

Peoplesoft_PSToken = modules_loaded["peoplesoft_pstoken"]

tests = [
    (
        "badsecrets",
        "BLANK PASSWORD!",
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABSpxUdcNT67zqSLW1wY5/FHQd1U6mgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
    ),
    (
        "badsecrets",
        "password",
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT5mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
    ),
]


def test_peoplesoft():
    x = Peoplesoft_PSToken()
    for test in tests:

        found_key = x.check_secret(test[2])
        assert found_key["username"] == test[0]
        assert found_key["PS_TOKEN_password"] == test[1]
