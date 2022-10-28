from badsecrets import modules_loaded
import badsecrets.errors
import random
import string

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
