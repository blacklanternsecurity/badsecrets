from badsecrets import modules_loaded

Generic_JWT = modules_loaded["generic_jwt"]

tests = [
    (
        "jwt_private_key_index",
        "1",
        "eyJhbGciOiJSUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.VY5gbfqc1nrTMz7oCFvFBZtHE_gb97dWBAsOG9NJeeXJhASEBe2srxVqbWw1HTGcyZc1oxzJU6o-fpPAEpNO4QhFEJNZbWYJBLMtggiu_MKBEHGHgrAOE9gtH2qUKZ6zMWq5hO3JA0QuIWKE3g342C-beBNoLJ8ph02yrrqYuCWg2smExg6wL_LK0gnpsNLBXRcJ2dYSlEn9tz9Aim5TioZVJZK1DVtBX8k4xA0k47i9DGNwII7R9SU2cqqDOXBd7oo8AYwGP1U4kWtzeTKBBIAEjwGh11yKIMkZrL1SkctWEY1ogFlxBG9dWn0BcrYCVJaIxTSMCGmpjRSUKPnkTg",
    ),
    (
        "jwt_secret",
        "1234",
        "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo",
    ),
]


def test_generic_jwt():
    x = Generic_JWT()
    for test in tests:
        found_key = x.check_secret(test[2])
        assert found_key
        assert found_key[test[0]] == test[1]


def test_generic_jwt_negative():

    x = Generic_JWT()
    found_key = x.check_secret(
        "eyJhbGciOiJIGzI4NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVcEVEbEFtESI6IkJhZFNlE3JldHMiLCJlEHAiOjE1OTMxMzE0ODMsImlhdEI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
    )
    assert not found_key
