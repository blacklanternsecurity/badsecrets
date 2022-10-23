from badsecrets import modules_loaded

ASPNETViewstate = modules_loaded["aspnet_viewstate"]

tests = [
    (
        "DES+SHA1",
        "DES",
        "SHA1",
        "jxwpcd5AwfMUcwXM5rJFA9dtrSgoT3ezfxneYLjsXW7pB/TjlgNbzsx3dY/P+FlXTZReIQ==",
    ),
    (
        "3DES+SHA1",
        "3DES",
        "SHA1",
        "Sku67tgd5zl62MFTQS6R5/o3UAFb3RcqLRKRbq1QmH8o0VN+eaFOlONe3Gz1j82CEcYFb/1qdebQa3JrRwtUSAi/LIs=",
    ),
    ("NOENC+MD5", None, "MD5", "/wEPDwUJODExMDE5NzY5ZGQz6LniPbNSFqk5H12BoEzV"),
    (
        "DES+MD5",
        "DES",
        "MD5",
        "1XOCV7CXQNzADZdkLqNpPqvxvsIcTZ0XJixsYCrvMKEgJupViGbO2LmtwaaugHN0",
    ),
    (
        "3DES+MD5",
        "3DES",
        "MD5",
        "0dedDrYqTxJOEbq5qtd1ZOHYiLnIC+9BmUYylkxxIBgYWgL+4MSp5CGZWCG6XiJMJMhFpqjrWZ215KlNVwcZsA==",
    ),
    (
        "AES+MD5",
        "AES",
        "MD5",
        "WxNI1vVPDgeXofN0JqRMsjlKLjj/KtMsqNBOQnkcHdXD/v8yqd5hih8WdRFD4NRggBDgeZbFu6eME8/IN9OPkw==",
    ),
    (
        "NOENC+SHA1",
        None,
        "SHA1",
        "/wEPDwUJODExMDE5NzY5ZGSglOSr1rG6xN5rzh/4C9UEuwa64w==",
    ),
    (
        "AES+SHA1",
        "AES",
        "SHA1",
        "QhNlfAmxL3x1eiDHXDyjc8Nv7IsFX/OsUgF2hrtevccYC3a56XmssuVxjhHAYqgBNSOMlN1IztaNEGRMl56UOofadCc=",
    ),
    (
        "NOENC+SHA256",
        None,
        "SHA256",
        "/wEPDwUJODExMDE5NzY5ZGScGv/wvQQvxzX/syyICaMJbvdEU3+6rpkkQNkouaLjoQ==",
    ),
    (
        "DES+SHA256",
        "DES",
        "SHA256",
        "dn/WEP+ogagnOcePgsXoPRe05wss0YIyAZdzFHJuWJejTRbDNDEqes7fBwNY4IqTmT7kTB0o9f8fRSpRXaMcyg==",
    ),
    (
        "3DES+SHA256",
        "3DES",
        "SHA256",
        "srngJkNh2In1EWmsw8hEp1z89ZBR1yh4CjPSGSgvI03jlkOc2yxIICypYMeIACGj1SIiFbj4YM8Kv3HpIZtypfgDaEea7YPdS/CtQRCW8BY=",
    ),
    (
        "AES+SHA256",
        "AES",
        "SHA256",
        "KLox5XeGYfb7Lo8zFzr1YepUagXuixcxX55lpFht+rrW6VGheZi831vdusH6DCMfxIhsLG1EPU3OuPvqN2XBc/fj0ew15TQ1zBmmKWJVns4=",
    ),
    (
        "NOENC+SHA384",
        None,
        "SHA384",
        "/wEPDwUJODExMDE5NzY5ZGSvS8eCdcZ+Ew7D1z78IlDE4Lc2o/zuWUjw1edxcTD4rJCKK0Uo+Pg5zM884Lw9JFs=",
    ),
    (
        "DES+SHA384",
        "DES",
        "SHA384",
        "XG/Uc5BN9XeN9lMJMu0hVNgf5IpIIagJ7xU0LOh71Xzy0NQXog6PHKR5bzwGsu/UyXd7L6dHeVG42w1ImYIVmvlncw+ebOIoSc3sMuJvzMc=",
    ),
    (
        "3DES+SHA384",
        "3DES",
        "SHA384",
        "m4ZardfRO6Vw0dSbl2DrosXQcPfR46pt9u9ArBBJXpZKbXxi/DLfZ7+zEFzszuOA7iz4CbrUMb3T6yBHf25FJtYwqW3CWnbwayJBPgMyAP65wEjhNVY8OZhK2x+AbQKB",
    ),
    (
        "AES+SHA384",
        "AES",
        "SHA384",
        "M78GijcQ54KnBK7kvyyVX5G67PaUsYnzvSCWBNEdhFm9MkH6jhVgT5vF9QQejFZ3+0eRh8pos0NMaEcPSTA5a+glvcV+a3XiYpaqw4471mz5X9K4r/0Jzt3BhE0aAg2L",
    ),
    (
        "NOENC+SHA512",
        None,
        "SHA512",
        "/wEPDwUJODExMDE5NzY5ZGTzMnovqnviYYRupyQcUQBrV7bKilFBlBtYNubWdoJzlrFPMwcL+5owir3cJvvYIthTkTaW6J2rw5ZcA0NcgMZn",
    ),
    (
        "DES+SHA512",
        "DES",
        "SHA512",
        "vX0SmvO4l3IoiegvpJTBgs4HWLOCywTFU5/5iQr1x7KZFB4PtltnWpLwYvy4+cPdABOHdxgYpW3mAqs+gOwqgiYaGo2nuFnd5prOdPi2LGxBtGVrr8S8fzVA51X/FdXS",
    ),
    (
        "3DES+SHA512",
        "3DES",
        "SHA512",
        "9nfDnyarfH1kpayLGDxJc1gP41dwZnd2628oPoPAFLtgTUzJf2gWrGE7QyZZbVb5mDbGQnbb+pScC4i2SDRLdm5G98OCIY9ZqSghKzXCWvHd+ABrmb5Nk8iKYybHRZkb0Q0jUHq2SEclIewYJiGMlw==",
    ),
    (
        "AES+SHA512",
        "AES",
        "SHA512",
        "SluTZh8rToF/i+GY2bN8Pt7n0sqGmTBsWwOceMq4xiLsGuXoB1pF2KsXrc4FTWnGnnOVxN9x/WL7rYmULKeYbDwAmfL0xbxdZ5NT+eY56JXnP0RTAecR66Llp5+I5jId64V8tJ9rAfHZOKEakHFGeQ==",
    ),
]

"""
Using the following test keys:

Encryption: B47D3CD1E780CF30C739A080995B9B10B64354AA135A2D78
Validation: F5144F1A581A57BA3B60311AF7562A855998F7DD203CD8A71405599B980D8694B5C986C888BE4FC0E6571C2CE600D58CE82B8FA13106B17D77EA4CECDDBBEC1B

Viewstates taken from query.aspx page, so modified should be constant (EDD8C9AE)
"""

enc_key = "B47D3CD1E780CF30C739A080995B9B10B64354AA135A2D78"
validation_key = "F5144F1A581A57BA3B60311AF7562A855998F7DD203CD8A71405599B980D8694B5C986C888BE4FC0E6571C2CE600D58CE82B8FA13106B17D77EA4CECDDBBEC1B"
modifier = "EDD8C9AE"


def test_viewstates():

    x = ASPNETViewstate()

    for test in tests:

        print(test[0])

        found_key = x.check_secret(test[3], modifier)
        assert found_key
        assert found_key["validationKey"] == validation_key
        assert found_key["validationAlgo"] == test[2]

        if "NOENC" not in test[0]:
            print(test)
            assert found_key["encryptionKey"] == enc_key
            assert found_key["encryptionAlgo"] == test[1]

    # negative test

    found_key = x.check_secret("Ad5AwfMUcwXM5rJFA9dtrSgoT3ezfxneYLjsXW7pB/TjlgNbzsx3dY/P+FlXTZReIA==", "AAAAAAAA")
    assert not found_key
