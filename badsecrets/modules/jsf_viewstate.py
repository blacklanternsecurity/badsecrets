import re
import gzip
import hmac
import base64
import hashlib
import binascii
import urllib.parse
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad
from badsecrets.helpers import Java_sha1prng
from badsecrets.base import BadsecretsBase, generic_base64_regex


class Jsf_viewstate(BadsecretsBase):

    identify_regex = generic_base64_regex
    description = {"Product": "Java Server Faces Viewstate", "Secret": "com.sun.faces.ClientStateSavingPassword"}

    @staticmethod
    def attempt_decompress(value):
        try:
            uncompressed = gzip.decompress(base64.b64decode(value))
        except (gzip.BadGzipFile, binascii.Error, ValueError):
            return False
        return uncompressed

    def carve_regex(self):
        return re.compile(r"<input.+name=\"javax\.faces\.ViewState\".+value=\"([^\"]*)\"")

    # Mojarra 1.2.x - 2.0.3
    def DES3_decrypt(self, ct, password):

        x = Java_sha1prng(password)
        derivedKey = x.get_sha1prng_key(24)
        cipher = DES3.new(
            derivedKey, DES3.MODE_CBC, iv=b"AAAAAAAA"
        )  # Theres no way to determine the IV, as it lives in server memory. So, we can pass anything in - we can still decrypt all except for block #1
        try:
            decrypted = cipher.decrypt(base64.b64decode(ct))
            if b"java." in decrypted:
                return True
        except (ValueError, binascii.Error):
            return False
        return False

    # Mojarra 2.2.6 - 2.3.x
    def AES_decrypt(self, ct, password_bytes):
        try:
            ct_bytes = base64.b64decode(ct)
        except (binascii.Error, ValueError):
            return False

        sig = ct_bytes[:32]
        iv = ct_bytes[32:48]
        data = ct_bytes[48:]
        h = hmac.new(password_bytes, digestmod=hashlib.sha256)
        h.update(iv)
        h.update(data)
        # We really only have to check the signature to know we can decrypt, since the HMAC and AES keys are derived from the same password
        if h.digest() == sig:
            # We decrypt anyway, just so we can determine compression
            cipher = AES.new(password_bytes, AES.MODE_CBC, iv)
            pt_b64 = unpad(cipher.decrypt(data), AES.block_size)
            return pt_b64

    def check_secret(self, jsf_viewstate_value):

        jsf_viewstate_value = urllib.parse.unquote(jsf_viewstate_value)

        if jsf_viewstate_value.startswith("rO0"):
            return {
                "secret": "UNPROTECTED",
                "details": {
                    "source": jsf_viewstate_value,
                    "info": "JSF Viewstate (Unprotected)",
                    "compression": False,
                },
            }

        uncompressed = self.attempt_decompress(jsf_viewstate_value)
        if uncompressed:
            if b"java.lang.Object" in uncompressed:
                return {
                    "secret": "UNPROTECTED",
                    "details": {
                        "source": jsf_viewstate_value,
                        "info": "JSF Viewstate (Unprotected)",
                        "compression": True,
                    },
                }
            else:
                jsf_viewstate_value = base64.b64encode(uncompressed)

        for l in self.load_resource("jsf_viewstate_passwords.txt"):
            password = l.rstrip()
            print(password)
            if self.DES3_decrypt(jsf_viewstate_value, password):
                return {
                    "secret": password,
                    "details": {
                        "source": jsf_viewstate_value,
                        "info": "JSF Viewstate (Mojarra 1.2.x - 2.0.3) 3DES Encrypted",
                        "compression": True if uncompressed else False,
                    },
                }

        for l in self.load_resource("jsf_viewstate_passwords_b64.txt"):
            password_bytes = base64.b64decode(l.rstrip())
            print(password)
            decrypted = self.AES_decrypt(jsf_viewstate_value, password_bytes)

            if decrypted:
                uncompressed = self.attempt_decompress(base64.b64encode(decrypted))
                if uncompressed:
                    if b"java." in uncompressed:
                        decrypted = uncompressed

                decrypted_b64 = base64.b64encode(decrypted).decode()
                if decrypted_b64.startswith("rO0"):
                    return {
                        "secret": base64.b64encode(password_bytes).decode(),
                        "details": {
                            "source": jsf_viewstate_value,
                            "info": "JSF Viewstate (Mojarra 2.2.6 - 2.3.x) AES Encrypted",
                            "compression": True if uncompressed else False,
                        },
                    }
