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


class Rails_SecretKeyBase(BadsecretsBase):
    identify_regex = re.compile(r"^[\.a-zA-z-0-9\%=]{32,}--[\.a-zA-z-0-9%=]{16,}$")
    description = {"Product": "Rails Signed Cookie", "Secret": "Rails secret_key_base"}

    def rails(self, rails_cookie, secret_key_base):
        split_rails_cookie = urllib.parse.unquote(rails_cookie).split("--")
        data = split_rails_cookie[0]

        # Cookie is likely signed but not encrypted
        if split_rails_cookie[0].startswith("eyJ"):
            signature = split_rails_cookie[1]
            try:
                hash_alg = self.search_dict(self.hash_sizes, len(binascii.unhexlify(signature)))[0]
            except binascii.Error:
                return None
            hmac_secret = PBKDF2(secret_key_base, "signed cookie", 64, 1000)
            h = hmac.new(hmac_secret, data.encode(), hash_alg)
            if h.hexdigest() == signature:
                return {"json_data": base64.b64decode(data), "hash_algorithm": hash_alg}

        # Cookie is likely Rails 4/5/6 AES-CBC Cookie
        elif len(split_rails_cookie) == 2:
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
                    return {"json_data": json_data, "encryption_algorithm": "AES_CBC"}
                except ValueError:
                    pass

        # Cookie is likey Rails 6 AES-GCM
        elif len(split_rails_cookie) == 3:
            iv = split_rails_cookie[1]
            aes_secret = PBKDF2(secret_key_base, "authenticated encrypted cookie", 64, 1000)
            cipher = AES.new(aes_secret[:32], AES.MODE_GCM, nonce=base64.b64decode(iv))

            try:
                dec = cipher.decrypt(base64.b64decode(data))
                json_data = json.loads(dec.decode())
                return {"json_data": json_data, "encryption_algorithm": "AES_GCM"}
            except ValueError:
                return None

    def check_secret(self, rails_cookie):
        if not self.identify(rails_cookie):
            return None
        for l in self.load_resource("rails_secret_key_base.txt"):
            secret_key_base = l.rstrip()
            r = self.rails(rails_cookie, secret_key_base)
            if r:
                return {"secret": secret_key_base, "details": r}
        return None
