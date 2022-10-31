from badsecrets import modules_loaded
import badsecrets.errors
import random
import string
import os

# Handle bad custom resource
def test_handle_bad_resource():
    for module_name, mod in modules_loaded.items():
        try:
            rand_string = "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            mod(custom_resource=f"/tmp/{rand_string}")
            assert False
        except badsecrets.errors.LoadResourceException:
            assert True


# Ensure a good custom resource gets loaded properly
def test_load_resource():
    for module_name, mod in modules_loaded.items():
        try:
            mod(custom_resource="/etc/passwd")
            assert True
        except badsecrets.errors.LoadResourceException:
            assert False


def test_use_custom_resource():

    Generic_JWT = modules_loaded["generic_jwt"]

    x = Generic_JWT(
        custom_resource=f"{os.path.dirname(os.path.abspath(__file__))}/../badsecrets/resources/jwt_secrets.txt"
    )
    r = x.check_secret(
        "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
    )
    assert r


def test_identity_non_match():

    Generic_JWT = modules_loaded["generic_jwt"]
    x = Generic_JWT()
    r = x.check_secret("N0T_Val1D")
    assert r == None
