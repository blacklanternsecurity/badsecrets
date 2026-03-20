import os
import re
import json
import base64
import hashlib
import binascii
from contextlib import suppress
from Crypto.Cipher import DES3, AES
from badsecrets.base import BadsecretsBase

DEFAULT_PASSWORD = "WebAS"


def _derive_password_key(password):
    """SHA-1(password) padded to 24 bytes with 0x00 — the 3DES key used to decrypt ltpa.keys values."""
    sha1 = hashlib.sha1(password.encode("utf-8")).digest()
    return sha1 + b"\x00" * 4


def _des3_ecb_decrypt(key_24, data):
    """3DES-ECB decrypt (no padding removal)."""
    cipher = DES3.new(key_24, DES3.MODE_ECB)
    return cipher.decrypt(data)


class LTPA_Token(BadsecretsBase):
    # Base64 pattern — LTPA tokens are typically 100+ bytes base64-encoded
    identify_regex = re.compile(r"^(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    description = {"product": "IBM WebSphere LTPA", "secret": "LTPA Encryption Key", "severity": "HIGH"}
    carve_locations = ("cookies",)

    def __init__(self, custom_resource=None, **kwargs):
        super().__init__(custom_resource=custom_resource, **kwargs)
        self._derived_keys = None

    def _load_ltpa_keys(self):
        """Load and derive AES/3DES keys from ltpa_keys.json. Cached after first call."""
        if self._derived_keys is not None:
            return self._derived_keys

        self._derived_keys = []
        resource_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "..",
            "resources",
            "ltpa_keys.json",
        )
        with suppress(FileNotFoundError):
            with open(resource_path) as f:
                entries = json.load(f)
            password_key = _derive_password_key(DEFAULT_PASSWORD)
            for entry in entries:
                with suppress(Exception):
                    enc_3des = base64.b64decode(entry["3DESKey"])
                    master_key = _des3_ecb_decrypt(password_key, enc_3des)
                    aes_key = master_key[:16]
                    des3_key = master_key[:24]
                    self._derived_keys.append(
                        {
                            "aes_key": aes_key,
                            "des3_key": des3_key,
                            "key_id": entry.get("key_id", "unknown"),
                            "source": entry.get("source", "unknown"),
                        }
                    )
        return self._derived_keys

    @staticmethod
    def _validate_ltpa2_plaintext(pt_bytes):
        """Check if decrypted bytes look like a valid LTPA2 token plaintext."""
        try:
            text = pt_bytes.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return False
        # Format: body%expire%signature
        if "%" not in text:
            return False
        # Body should contain user attribute with $ delimiters
        body = text.split("%")[0]
        if "u:" not in body:
            return False
        return True

    @staticmethod
    def _try_ltpa2(raw, aes_key, entry):
        """Try AES-128-CBC decryption (IV = key). Returns result dict or None."""
        if len(raw) < 32 or len(raw) % 16 != 0:
            return None
        iv = aes_key
        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
            pt = cipher.decrypt(raw)
        except (ValueError, KeyError):
            return None
        # Check PKCS5 padding
        pad_len = pt[-1]
        if not (1 <= pad_len <= 16 and all(b == pad_len for b in pt[-pad_len:])):
            return None
        pt_unpadded = pt[:-pad_len]
        if not LTPA_Token._validate_ltpa2_plaintext(pt_unpadded):
            return None
        return {
            "secret": f"LtpaToken2 key {entry['key_id']} (see ltpa_keys.json)",
            "details": {
                "source": "LtpaToken2 cookie",
                "info": "IBM LTPA2 Token (AES-128-CBC)",
                "token_version": "2",
                "key_id": entry["key_id"],
                "key_source": entry["source"],
            },
        }

    @staticmethod
    def _try_ltpa1(raw, des3_key, entry):
        """Try 3DES-ECB decryption. Returns result dict or None."""
        if len(raw) < 16 or len(raw) % 8 != 0:
            return None
        try:
            cipher = DES3.new(des3_key, DES3.MODE_ECB)
            pt = cipher.decrypt(raw)
        except (ValueError, KeyError):
            return None
        # Check PKCS5 padding
        pad_len = pt[-1]
        if not (1 <= pad_len <= 8 and all(b == pad_len for b in pt[-pad_len:])):
            return None
        pt_unpadded = pt[:-pad_len]
        if not LTPA_Token._validate_ltpa2_plaintext(pt_unpadded):
            return None
        return {
            "secret": f"LtpaToken key {entry['key_id']} (see ltpa_keys.json)",
            "details": {
                "source": "LtpaToken cookie",
                "info": "IBM LTPA Token (3DES-ECB)",
                "token_version": "1",
                "key_id": entry["key_id"],
                "key_source": entry["source"],
            },
        }

    def check_secret(self, cookie_value):
        try:
            raw = base64.b64decode(cookie_value)
        except (binascii.Error, ValueError):
            return None

        if len(raw) < 32:
            return None

        derived_keys = self._load_ltpa_keys()
        for entry in derived_keys:
            # Try LtpaToken2 (AES-CBC) first — more common
            result = self._try_ltpa2(raw, entry["aes_key"], entry)
            if result:
                return result
            # Try LtpaToken v1 (3DES-ECB)
            result = self._try_ltpa1(raw, entry["des3_key"], entry)
            if result:
                return result

        return None

    def carve_regex(self):
        return None
