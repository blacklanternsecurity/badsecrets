from badsecrets import modules_loaded

DjangoSignedCookies = modules_loaded["django_signedcookies"]

tests = [
    (
        ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis",
        "d86e01d10e66d199e5f5cb92e0c3d9f4a03140068183b5c9387232c4d32cff4e",
    )
]


def test_django():
    for test in tests:
        assert DjangoSignedCookies.identify(test[0])
        x = DjangoSignedCookies(test[0])
        found_key = x.check_secret()
        assert found_key == True
        assert x.output_parameters["_auth_user_hash"] == test[1]
