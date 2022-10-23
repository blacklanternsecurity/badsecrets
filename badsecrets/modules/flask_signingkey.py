import re
from flask_unsign import verify as flaskVerify
from badsecrets.base import BadsecretsBase


class Flask_SigningKey(BadsecretsBase):

    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")

    def __init__(self, flask_cookie):
        self.flask_cookie = flask_cookie

    def check_secret(self):
        for l in self.load_resource("flask_passwords.txt"):
            password = l.rstrip()
            r = flaskVerify(value=self.flask_cookie, secret=password)
            if r:
                self.output_parameters = {"flask_password": password}
                return True
        return False
