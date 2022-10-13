import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from popsecrets import FlaskSigningKey

tests = [("CHANGEME","eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA")]

def test_flask():
    for test in tests:

        x = FlaskSigningKey(test[1])
        found_key = x.check_secret()
        assert found_key == True
        assert x.output_parameters["flask_password"] == test[0]





