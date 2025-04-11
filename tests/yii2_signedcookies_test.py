from badsecrets import modules_loaded

Yii2_SignedCookies = modules_loaded["yii2_signedcookies"]
yii2_tests = [
    (
        "secret",
        "0bb72f36d041a3a022f231eebe114889ee442092ee350242ffb2d4bb53887a81a%3A2%3A%7Bi%3A0%3Bs%3A4%3A%22lang%22%3Bi%3A1%3Bs%3A7%3A%22English%22%3B%7D",
    ),
]


def test_yii2_valid():
    x = Yii2_SignedCookies()
    for test in yii2_tests:
        found_key = x.check_secret(test[1])
        assert found_key
        assert found_key["secret"] == test[0]


def test_yii2_bad():
    x = Yii2_SignedCookies()
    found_key = x.check_secret("not_a_valid_cookie_value")
    assert not found_key


def test_yii2_carve():
    x = Yii2_SignedCookies()
    header_value = f"lang={yii2_tests[0][1]}; expires=Sat, 11-Apr-2026"
    results = x.carve(headers={"Set-Cookie": header_value})
    assert len(results) > 0
    assert results[0]["type"] == "SecretFound"
    assert results[0]["secret"] == yii2_tests[0][0]
