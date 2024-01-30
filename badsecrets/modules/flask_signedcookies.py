# flask_secret_keys wordlist shamelessly copied from https://github.com/Paradoxis/Flask-Unsign <3 <3 <3

import re
from flask_unsign import verify as flaskVerify
from badsecrets.base import BadsecretsBase


class Flask_SignedCookies(BadsecretsBase):
    identify_regex = re.compile(r"\.?e[Jy](?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")
    description = {"product": "Flask Signed Cookie", "secret": "Flask Password", "severity": "HIGH"}

    def check_secret(self, flask_cookie):
        if not self.identify(flask_cookie):
            return None
        for l in set(list(self.load_resources(["flask_secret_keys.txt", "top_100000_passwords.txt"]))):
            password = l.rstrip()
            r = flaskVerify(value=flask_cookie, secret=password)
            if r:
                return {"secret": password, "details": r}
        return None

    def get_hashcat_commands(self, flask_cookie, *args):
        return [
            {
                "command": f"hashcat -m 29100 -a 0 {flask_cookie} <dictionary_file>",
                "description": f"Flask Signed Cookie",
                "severity": "HIGH",
            }
        ]
