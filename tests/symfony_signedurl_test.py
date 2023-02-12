from badsecrets import modules_loaded

Symfony_SignedURL = modules_loaded["symfony_signedurl"]


# sha256
def test_symfony_sha256():
    s = "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=Xnsvx/yLVQaimEd1CfepgH0rEXr422JnRSn/uaCE3gs="
    x = Symfony_SignedURL()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "50c8215b436ebfcc1d568effb624a40e"


# sha1
def test_symfony_sha1():
    s = "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=x3nyAneZB74G5S9L66d5ftJVNnk="
    x = Symfony_SignedURL()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "50c8215b436ebfcc1d568effb624a40e"


def test_symfony_negative():
    s = "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=Xnsvx/yLVQaimEd1CfepgH0rEXr422JnRSn/uaCE3gd="
    x = Symfony_SignedURL()
    r = x.check_secret(s)
    assert not r
