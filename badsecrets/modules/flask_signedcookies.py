import re
from flask_unsign import verify as flaskVerify
from badsecrets.base import BadsecretsBase


class Flask_SignedCookies(BadsecretsBase):
    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")
    description = {"Product": "Flask Signed Cookie", "Secret": "Flask Password"}

    def check_secret(self, flask_cookie):
        if not self.identify(flask_cookie):
            return None
        for l in self.load_resource("top_10000_passwords.txt"):
            password = l.rstrip()
            r = flaskVerify(value=flask_cookie, secret=password)
            if r:
                return {"secret": password, "details": r}
        return None
