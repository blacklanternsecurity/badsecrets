import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from popsecrets import Peoplesoft_PSToken

tests = [
    (
        "popsecrets",
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABRhZGwcBykRPNQv++kTK0KePPqVVGgAAAAFAFNkYXRhXHicHYc7DkBQAATnIUqVa3jxLRzApxJBrxA18bmdw1l2k9nZG/Bcxxjt4/An3NnYOVlZOMRL7ld0NAQ9IzUTMy0DeUpMqkYkso+ZGFNiKbRW//Pyb0Guzwtozw4Q",
    ),
    (
        "popsecrets",
        "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABR4TTHt0Umy1Cy8qZgJHJLdV/U0FWgAAAAFAFNkYXRhXHicHYc7DkBQAATnIUqVa3jxLRzApxJBrxA18bmdw1l2k9nZG/Bcxxjt4/An3NnYOVlZOMRL7ld0NAQ9IzUTMy0DeUpMqkYkso+ZGFNiKbRW//Pyb0Guzwtozw4Q",
    ),
]


def test_peoplesoft():
    for test in tests:
        assert Peoplesoft_PSToken.identify(test[1])
        x = Peoplesoft_PSToken(test[1])
        found_key = x.check_secret()
        assert found_key == True
        assert x.output_parameters["username"] == test[0]
        assert x.output_parameters["PS_TOKEN_password"] != None
