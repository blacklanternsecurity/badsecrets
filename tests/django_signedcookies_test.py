from badsecrets import modules_loaded

DjangoSignedCookies = modules_loaded["django_signedcookies"]

tests = [
    (
        ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis",
        "d86e01d10e66d199e5f5cb92e0c3d9f4a03140068183b5c9387232c4d32cff4e",
    )
]


def test_django():
    x = DjangoSignedCookies()
    for test in tests:
        found_key = x.check_secret(test[0])
        assert found_key
        assert found_key["details"]["_auth_user_hash"] == test[1]


def test_django_negative():
    x = DjangoSignedCookies()
    found_key = x.check_secret(
        ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCBADSECRETSMM3-UypscEN57ECtXis"
    )
    assert not found_key
