import os
import pytest
import viewstate
from badsecrets import modules_loaded
from viewstate.exceptions import ViewStateException

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


def test_bad_sourcefile():
    x = ASPNETViewstate(
        custom_resource=f"{os.path.dirname(os.path.abspath(__file__))}/../tests/resources/aspnet_viewstate_bad.txt"
    )

    found_key = x.check_secret(
        "KLox5XeGYfb7Lo8zFzr1YepUagXuixcxX55lpFht+rrW6VGheZi831vdusH6DCMfxIhsLG1EPU3OuPvqN2XBc/fj0ew15TQ1zBmmKWJVns4=",
        "AAAAAAAA",
    )
    assert not found_key

    found_key = x.check_secret(
        "QhNlfAmxL3x1eiDHXDyjc8Nv7IsFX/OsUgF2hrtevccYC3a56XmssuVxjhHAYqgBNSOMlN1IztaNEGRMl56UOofadCc="
    )
    assert not found_key

    found_key = x.check_secret(
        "9nfDnyarfH1kpayLGDxJc1gP41dwZnd2628oPoPAFLtgTUzJf2gWrGE7QyZZbVb5mDbGQnbb+pScC4i2SDRLdm5G98OCIY9ZqSghKzXCWvHd+ABrmb5Nk8iKYybHRZkb0Q0jUHq2SEclIewYJiGMlw=="
    )
    assert not found_key


def test_viewstate_negative():

    x = ASPNETViewstate()
    found_key = x.check_secret(
        "KLox5XeGYfb7Lo8zFzr1YepUagXuixcxX55lpFht+rrW6VGheZi831vdusH6DCMfxIhsLG1EPU3BadSecretsXBc/fj0ew15TQ1zBmmKWJVns4=",
        "AAAAAAAA",
    )
    assert not found_key


def test_viewstate_alt_keys():

    x = ASPNETViewstate()
    alt_val_key = "1072571233BFEF38A826132393CE26DAA961DC1B690B717AC7F163307C3621423A57BD0ACD88414E7DD1C9A09BDCC7AC62CB70A01636FFB3DB3B105962AC3AB3"
    alt_enc_key = "D25D27814E26F3911BF59FDCC86B20EAB603E7F0265E3756C0A121790B169167"

    print("Alternate Key SHA1+AES")
    found_key = x.check_secret(
        "P+3D4YDL6eY1+Wv7BELihCm0W3UrrWZi1j9N60Oli5MdZie+DaPDnSakzKnNSQtiMJkzjYuSfAE2bPZ/pnvxifJzmytFGTbkjUrH/VvXQHEF83US",
        modifier,
    )
    assert found_key
    print(found_key)
    assert found_key["validationKey"] == alt_val_key
    assert found_key["validationAlgo"] == "SHA1"
    assert found_key["encryptionKey"] == alt_enc_key
    assert found_key["encryptionAlgo"] == "AES"

    found_key = x.check_secret("tBfCi5Y/zYSviC1i0SBK9U+ZYZbzPwJomXaDenkuSWc4WLiaY+W/aKkPeCtEoH+Utlgg0Q==", modifier)
    assert found_key
    print(found_key)
    assert found_key["validationKey"] == alt_val_key
    assert found_key["validationAlgo"] == "SHA1"
    assert found_key["encryptionKey"] == alt_enc_key
    assert found_key["encryptionAlgo"] == "DES"


def test_viewstate_handle_decode_error():
    x = ASPNETViewstate()

    found_key = x.check_secret(
        "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aXRvcjEFMWN0bDAwJENvbnRlbnRQbGFjZWhvbGRlcjEkUmFkRWRpdG9yMSRkaWFsb2dPcGVuZXIFOGN0bDAwJENvbnRlbnRQbGFjZWhvbGRlcjEkUmFkRWRpdG9yMSRkaWFsb2dPcGVuZXIkV2luZG93BTNjdGwwMCRDb250ZW50UGxhY2Vob2xkZXIxJFJhZEVkaXRvcjEkUmFkQ29udGV4dE1lbnUFO2N0bDAwJENvbmZpZ3VyYXRvclBsYWNlaG9sZGVyJENvbmZpZ3VyYXRpb25QYW5lbDEkbXVsdGlQYWdlBUhjdGwwMCRDb25maWd1cmF0b3JQbGFjZWhvbGRlciRDb25maWd1cmF0aW9uUGFuZWwxJENoZWNrQm94TGlzdEVkaXRNb2RlJDAFSGN0bDAwJENvbmZpZ3VyYXRvclBsYWNlaG9sZGVyJENvbmZpZ3VyYXRpb25QYW5lbDEkQ2hlY2tCb3hMaXN0RWRpdE1vZGUkMQVIY3RsMDAkQ29uZmlndXJhdG9yUGxhY2Vob2xkZXIkQ29uZmlndXJhdGlvblBhbmVsMSRDaGVja0JveExpc3RFZGl0TW9kZSQyBUhjdGwwMCRDb25maWd1cmF0b3JQbGFjZWhvbGRlciRDb25maWd1cmF0aW9uUGFuZWwxJENoZWNrQm94TGlzdEVkaXRNb2RlJDIFQ2N0bDAwJENvbmZpZ3VyYXRvclBsYWNlaG9sZGVyJENvbmZpZ3VyYXRpb25QYW5lbDEkQ2hvb3NlVG9vbGJhck1vZGUFR2N0bDAwJENvbmZpZ3VyYXRvclBsYWNlaG9sZGVyJENvbmZpZ3VyYXRpb25QYW5lbDEkQ2hlY2tCb3hMaXN0TW9kdWxlcyQwBUdjdGwwMCRDb25maWd1cmF0b3JQbGFjZWhvbGRlciRDb25maWd1cmF0aW9uUGFuZWwxJENoZWNrQm94TGlzdE1vZHVsZXMkMQVHY3RsMDAkQ29uZmlndXJhdG9yUGxhY2Vob2xkZXIkQ29uZmlndXJhdGlvblBhbmVsMSRDaGVja0JveExpc3RNb2R1bGVzJDIFR2N0bDAwJENvbmZpZ3VyYXRvclBsYWNlaG9sZGVyJENvbmZpZ3VyYXRpb25QYW5lbDEkQ2hlY2tCb3hMaXN0TW9kdWxlcyQyBSJjdGwwMCRDb2RlVmlld2VyJFRvb2xCYXJEZW1vU291cmNlBUNjdGwwMCRDb25maWd1cmF0b3JQbGFjZWhvbGRlciRDb25maWd1cmF0aW9uUGFuZWwxJENob29zZVRvb2xiYXJNb2RlDxQrAAIFB0RlZmF1bHQFB0RlZmF1bHRkBSBjdGwwMCRRU0ZTa2luQ2hvb3NlciRTa2luQ2hvb3Nlcg8UKwACZQUEU2lsa2ShRyr2Sm8xKb+NDZ/ym+W/j/TDUVVN0aE4AU9eKLEfeQ==",
        "4C69204D",
    )
    assert found_key == None
