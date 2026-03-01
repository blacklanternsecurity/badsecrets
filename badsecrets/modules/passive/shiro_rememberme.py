import re
import base64
import binascii
from contextlib import suppress
from Crypto.Cipher import AES
from badsecrets.base import BadsecretsBase

JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"


class Shiro_RememberMe(BadsecretsBase):
    # Base64 pattern, minimum 44 chars (32 bytes = 16 IV + 16 ciphertext minimum)
    identify_regex = re.compile(r"^(?:[A-Za-z0-9+/]{4}){11,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    description = {"product": "Apache Shiro", "secret": "RememberMe AES Key", "severity": "CRITICAL"}
    carve_locations = ("cookies",)

    def check_secret(self, cookie_value):
        if not self.identify(cookie_value):
            return None

        try:
            raw = base64.b64decode(cookie_value)
        except (binascii.Error, ValueError):
            return None

        # Need at least 16 bytes IV + 16 bytes ciphertext
        if len(raw) < 32:
            return None

        for line in self.load_resources(["shiro_keys.txt"]):
            with suppress(ValueError, binascii.Error):
                key = base64.b64decode(line.strip())
                if len(key) not in (16, 24, 32):
                    continue

                # Try AES-CBC: first 16 bytes = IV, rest = ciphertext
                result = self._try_cbc(raw, key, line.strip())
                if result:
                    return result

                # Try AES-GCM: first 16 bytes = nonce, last 16 bytes = tag, middle = ciphertext
                result = self._try_gcm(raw, key, line.strip())
                if result:
                    return result

        return None

    @staticmethod
    def _try_cbc(raw, key, key_b64):
        iv = raw[:16]
        ct = raw[16:]
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            pt = cipher.decrypt(ct)
        except (ValueError, KeyError):
            return None
        if pt[:4] == JAVA_SERIALIZATION_MAGIC:
            return {
                "secret": key_b64,
                "details": {
                    "source": "rememberMe cookie",
                    "info": "Apache Shiro RememberMe (AES-CBC)",
                    "mode": "CBC",
                },
            }
        return None

    @staticmethod
    def _try_gcm(raw, key, key_b64):
        # GCM: 16-byte nonce | ciphertext | 16-byte tag
        if len(raw) < 48:  # 16 nonce + 16 min ciphertext + 16 tag
            return None
        nonce = raw[:16]
        tag = raw[-16:]
        ct = raw[16:-16]
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            pt = cipher.decrypt_and_verify(ct, tag)
        except (ValueError, KeyError):
            return None
        if pt[:4] == JAVA_SERIALIZATION_MAGIC:
            return {
                "secret": key_b64,
                "details": {
                    "source": "rememberMe cookie",
                    "info": "Apache Shiro RememberMe (AES-GCM)",
                    "mode": "GCM",
                },
            }
        return None
