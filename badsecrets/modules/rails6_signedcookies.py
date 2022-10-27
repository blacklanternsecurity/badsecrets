import re
import hmac
import json
import base64
import binascii
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from badsecrets.base import BadsecretsBase


class Rails6_SignedCookies(BadsecretsBase):

    identify_regex = re.compile(r"^[\.a-zA-z-0-9\%]+--[\.a-zA-z-0-9%]+$")

    def rails6(self, rails6_cookie, secret_key_base):
        split_rails6_cookie = urllib.parse.unquote(rails6_cookie).split("--")
        data = split_rails6_cookie[0]

        # Cookie is likely signed but not encrypted
        if split_rails6_cookie[0][0:3] == "eyJ":
            signature = split_rails6_cookie[1]
            hash_alg = self.search_dict(self.hash_sizes, len(binascii.unhexlify(signature)))[0]
            hmac_secret = PBKDF2(secret_key_base, "signed cookie", 64, 1000)
            h = hmac.new(hmac_secret, data.encode(), hash_alg)
            if h.hexdigest() == signature:

                return {"secret_key_base": secret_key_base, "data": base64.b64decode(data), "hash_algorithm": hash_alg}

        # Cookie is likely Rails 5 AES-CBC Cookie
        elif len(split_rails6_cookie) == 2:

            try:
                encrypted_data = base64.b64decode(data).decode()
                iv = encrypted_data.split("--")[1]
                data = encrypted_data.split("--")[0]
            except (UnicodeDecodeError, IndexError):
                return

            if len(base64.b64decode(iv)) == 16:
                aes_secret = PBKDF2(secret_key_base, "encrypted cookie", 64, 1000)
                cipher = AES.new(aes_secret[:32], AES.MODE_CBC, base64.b64decode(iv))
                try:
                    dec = unpad(cipher.decrypt(base64.b64decode(data)), 16)
                    json_data = json.loads(dec.decode())
                    return {"secret_key_base": secret_key_base, "data": json_data, "encryption_algorithm": "AES_CBC"}
                except ValueError:
                    pass

        # Cookie is likey Rails 6 AES-GCM
        elif len(split_rails6_cookie) == 3:
            iv = split_rails6_cookie[1]
            aes_secret = PBKDF2(secret_key_base, "authenticated encrypted cookie", 64, 1000)
            cipher = AES.new(aes_secret[:32], AES.MODE_GCM, nonce=base64.b64decode(iv))

            try:
                dec = cipher.decrypt(base64.b64decode(data))
                json_data = json.loads(dec.decode())
                return {"secret_key_base": secret_key_base, "data": json_data, "encryption_algorithm": "AES_GCM"}
            except ValueError:
                return None

        else:
            return None

    def check_secret(self, rails6_cookie):
        for l in self.load_resource("rails6_secret_key_base.txt"):
            secret_key_base = l.rstrip()
            r = self.rails6(rails6_cookie, secret_key_base)
            if r:
                return r
        return None
