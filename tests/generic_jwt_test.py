from badsecrets import modules_loaded

Generic_JWT = modules_loaded["generic_jwt"]


def test_generic_jwt_hmac():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
    )
    assert found_key
    assert found_key["secret"] == "1234"


def test_generic_jwt_rsa():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJSUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.VY5gbfqc1nrTMz7oCFvFBZtHE_gb97dWBAsOG9NJeeXJhASEBe2srxVqbWw1HTGcyZc1oxzJU6o-fpPAEpNO4QhFEJNZbWYJBLMtggiu_MKBEHGHgrAOE9gtH2qUKZ6zMWq5hO3JA0QuIWKE3g342C-beBNoLJ8ph02yrrqYuCWg2smExg6wL_LK0gnpsNLBXRcJ2dYSlEn9tz9Aim5TioZVJZK1DVtBX8k4xA0k47i9DGNwII7R9SU2cqqDOXBd7oo8AYwGP1U4kWtzeTKBBIAEjwGh11yKIMkZrL1SkctWEY1ogFlxBG9dWn0BcrYCVJaIxTSMCGmpjRSUKPnkTg"
    )
    assert found_key
    assert found_key["secret"] == f"Private key Name: 1"


def test_generic_jwt_rsa_bad():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJSUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.VY5gbfqc1nrTMz7oCFvFBZtHE_gb97dWBAsOG9NJeeXJhASEBe2srxVqbWw1HTGcyZc1oxzJU6o-fpPAEpNO4QhFEJNZbWYJBLMtggiu_MKBEHGHgrAOE9gtH2qUKZ6zMWq5hO3JA0QuIWKE3g342C-beBNoLJ8ph02yrrqYuCWg2smExg6wL_LK0gnpsNLBXRcJ2dYSlEn9tz9Aim5TioZVJZK1DVtBX8k4xA0k47i9DGNwII7R9SU2cqqDOXBd7oo8AYwGP1U4kWtzeTKBBIAEjwGh11yKIMkZrL1SkctWEY1ogFlxBG9dWn0BcrYCVJaIxTSMCGmpjRSUKPnkTf"
    )
    assert not found_key


def test_generic_jwt_negative():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJIGzI4NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVcEVEbEFtESI6IkJhZFNlE3JldHMiLCJlEHAiOjE1OTMxMzE0ODMsImlhdEI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
    )
    assert not found_key


def test_generic_jwt_xmldsig():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNobWFjLXNoYTI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert found_key


def test_generic_jwt_hmac_with_aud():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiYXVkIjoibXktYXBwIiwicm9sZSI6ImFkbWluIn0.t9-1JUdynKdC1ZBGxtj70ySnD-0npSocNUVXmqo2-8s"
    )
    assert found_key
    assert found_key["secret"] == "1234"


def test_generic_jwt_hmac_with_iss():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoiZXZpbC1jb3JwIiwicm9sZSI6ImFkbWluIn0.VR43bXZc6k5ZAZwp4mRr-D18NkQ8EN9D46EQsV8Vazw"
    )
    assert found_key
    assert found_key["secret"] == "1234"


def test_generic_jwt_hmac_with_nbf():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmJmIjo5OTk5OTk5OTk5LCJyb2xlIjoiYWRtaW4ifQ.aZlX94Q-6bOXZHARHTEMqVZZKz0kmQ4XEZziz6rh9vw"
    )
    assert found_key
    assert found_key["secret"] == "1234"


def test_generic_jwt_loadfail():
    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhYWFhYWFsZyI6IkhTMjU2IiwiYWFhYWF0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY"
    )
    assert not found_key


# Genuine URI-algorithm tokens: HMACed over their own header, the way an
# implementation that spells "alg" as an XMLDSIG URI actually signs. Secret is
# "secret". Rewriting the header to its JWS short name changes the signing
# input, so these only verify if the original token is the one checked.
xmldsig_genuine = [
    "eyJhbGciOiJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNobWFjLXNoYTI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.334b-YxrhILrVMUHfRmT-7GI5qYkwSTkHppzbQXqX_U",
    "eyJhbGciOiJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNobWFjLXNoYTUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.0NosEp6cMqj1b2c9q6O4FZLJIQeKZ9Eh8KeFdgIC5E9PKkEtb1mEoHQ0XKTVAHpfkW2wIIT3FalHxAQG1uO-yQ",
]


def test_generic_jwt_xmldsig_genuine_token_cracks():
    x = Generic_JWT()
    for JWT in xmldsig_genuine:
        found_key = x.check_secret(JWT)
        assert found_key
        assert found_key["secret"] == "secret"


def test_generic_jwt_xmldsig_genuine_token_wrong_secret_rejected():
    # the signing input is what makes the above meaningful, so prove a
    # mismatched token is still refused
    x = Generic_JWT()
    header, payload, signature = xmldsig_genuine[0].split(".")
    tampered = f"{header}.{payload[:-4]}zzzz.{signature}"
    assert not x.check_secret(tampered)


# The token from test_generic_jwt_hmac, with the final signature character
# nudged. A 43-character base64url signature carries two unused trailing bits,
# so "o", "p", "q" and "r" all decode to the same signature bytes: these are
# the same token cryptographically, and were crackable until pyjwt 2.14 began
# rejecting every spelling but the canonical one.
jwt_hmac_canonical = "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
jwt_hmac_non_canonical = [
    "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCp",
    "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCq",
    "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCr",
]


def test_generic_jwt_non_canonical_signature_decodes_identically():
    # the premise the other two tests rest on
    import base64

    def signature_bytes(JWT):
        signature = JWT.rsplit(".", 1)[1]
        return base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))

    for JWT in jwt_hmac_non_canonical:
        assert jwt_hmac_canonical != JWT
        assert signature_bytes(JWT) == signature_bytes(jwt_hmac_canonical)


def test_generic_jwt_non_canonical_signature_still_cracks():
    x = Generic_JWT()
    for JWT in jwt_hmac_non_canonical:
        found_key = x.check_secret(JWT)
        assert found_key
        assert found_key["secret"] == "1234"


def test_generic_jwt_hashcat_quotes_product_verbatim():
    # a rewritten token in a finding is worse than no finding, so whatever
    # jwtLoad hands pyjwt must never reach the reported command
    x = Generic_JWT()
    xmldsig = "eyJhbGciOiJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNobWFjLXNoYTI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    for JWT in [jwt_hmac_canonical, *jwt_hmac_non_canonical, xmldsig]:
        commands = x.get_hashcat_commands(JWT)
        assert commands
        assert f" {JWT} " in commands[0]["command"]
