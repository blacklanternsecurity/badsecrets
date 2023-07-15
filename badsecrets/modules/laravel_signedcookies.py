import re
import json
import hashlib
import hmac
import base64
import binascii
import urllib.parse
from Crypto.Cipher import AES
from contextlib import suppress
from badsecrets.helpers import unpad
from badsecrets.base import BadsecretsBase


class LaravelSignedCookies(BadsecretsBase):
    def laravelDecrypt(self, json_value, raw_secret):
        mac = json_value["mac"]
        value = bytes(json_value["value"], "utf-8")
        iv = bytes(json_value["iv"], "utf-8")

        if mac == hmac.new(raw_secret, iv + value, hashlib.sha256).hexdigest():
            aes_crypt = AES.new(key=raw_secret, mode=AES.MODE_CBC, IV=base64.b64decode(iv))
            decrypted = unpad(aes_crypt.decrypt(base64.b64decode(value)))
            return decrypted
        return None

    identify_regex = re.compile(r"eyJ(?:[\w-])*")
    description = {"product": "Laravel Signed Cookie", "secret": "Laravel APP_KEY", "severity": "HIGH"}

    def laravelVerify(self, value, secret):
        # attempt to decode laravel cookie and load contents into JSON object
        try:
            json_value = json.loads(base64.b64decode(urllib.parse.unquote(value)))

            if not all(key in json_value.keys() for key in ["mac", "value", "iv"]):
                return False

        except (binascii.Error, json.decoder.JSONDecodeError, UnicodeDecodeError):
            return False

        # in the future, support may be added for older, non-base64 keys
        if secret.startswith("base64:"):
            with suppress(binascii.Error):
                raw_secret = base64.b64decode(secret.split(":")[1])
                decryptedData = self.laravelDecrypt(json_value, raw_secret)
                if decryptedData:
                    return {"decryptedData": decryptedData.decode()}
        return False

    def check_secret(self, laravel_signed_cookie):
        if not self.identify(laravel_signed_cookie):
            return None

        for l in self.load_resources(["laravel_app_keys.txt"]):
            app_key = l.rstrip()
            r = self.laravelVerify(value=laravel_signed_cookie, secret=app_key)
            if r:
                return {"secret": app_key, "details": r}
        return None
