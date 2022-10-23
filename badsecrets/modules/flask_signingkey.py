import re
from flask_unsign import verify as flaskVerify
from badsecrets.base import BadsecretsBase


class Flask_SigningKey(BadsecretsBase):

    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")

    def check_secret(self, flask_cookie):
        for l in self.load_resource("flask_passwords.txt"):
            password = l.rstrip()
            r = flaskVerify(value=flask_cookie, secret=password)
            if r:
                return {"flask_password": password}
        return None
