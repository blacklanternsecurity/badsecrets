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


def test_peoplesoft_negative():

    # Token doesn't decode properly
    x = Peoplesoft_PSToken()
    found_key = x.check_secret(
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT5mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBADSECRETS2c9MjCmJKLSR/u+laUGuzwdaGw3o"
    )
    assert not found_key

    # Proper token with non-matching key
    x = Peoplesoft_PSToken()
    found_key = x.check_secret(
        "owAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4Abwg4AC4AMQAwABRSZ/l0LBytKLW6TUnZ9GVFdgtqjWMAAAAFAFNkYXRhV3icJYhLDkAwFEVPSwztRFO0gw4lvgMimFuCDVqc17o3OffzAHmmlZJ8NUnlzklHz8rCRjEIpv8dubiZOXANlkZcUUuLbIWWgMFLGtmxh2SPk80Hk6gLyA=="
    )
    assert not found_key
