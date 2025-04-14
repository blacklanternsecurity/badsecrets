# flask_secret_keys wordlist shamelessly copied from https://github.com/Paradoxis/Flask-Unsign <3 <3 <3

import re
from badsecrets.base import BadsecretsBase
import hmac
from hashlib import sha256
from urllib.parse import unquote


class Yii2_SignedCookies(BadsecretsBase):
    # Match 64 hex chars (SHA256) followed by PHP serialized data
    identify_regex = re.compile(r"^[a-fA-F0-9]{64}a%3A[a-zA-Z0-9%]+$")
    description = {"product": "Yii2 Signed Cookie", "secret": "Yii2 cookieValidationKey", "severity": "HIGH"}

    def verify_yii2_cookie(self, cookie_value, validation_key):

        # URL decode the whole value first
        decoded_cookie = unquote(cookie_value)

        # Split decoded value into signature and data
        signature = decoded_cookie[:64]
        data = decoded_cookie[64:].encode("utf-8")

        # Calculate HMAC-SHA256 using raw key
        mac = hmac.new(validation_key.encode("utf-8"), data, sha256)
        expected_signature = mac.hexdigest()
        return signature.lower() == expected_signature.lower()

    def check_secret(self, yii2_cookie):
        if not self.identify(yii2_cookie):
            return None

        for password in set(self.load_resources(["yii2_cookieValidationKeys.txt", "top_100000_passwords.txt"])):
            password = password.rstrip()
            if self.verify_yii2_cookie(yii2_cookie, password):
                return {"secret": password, "details": "Valid cookieValidationKey found"}

    def get_hashcat_commands(self, yii2_cookie, *args):
        return [
            {
                "command": f"hashcat -m 19700 -a 0 {yii2_cookie} <dictionary_file>",
                "description": "Yii2 Cookie Validation Key",
                "severity": "HIGH",
            }
        ]

    def carve_regex(self):
        return re.compile(r"[^=]+=([a-fA-F0-9]{64}a%3A[^;]+)")
