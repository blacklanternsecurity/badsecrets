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
