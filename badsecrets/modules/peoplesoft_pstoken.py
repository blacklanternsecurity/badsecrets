import zlib
import base64
import hashlib
from badsecrets.base import BadsecretsBase, generic_base64_regex


class Peoplesoft_PSToken(BadsecretsBase):
    identify_regex = generic_base64_regex
    description = {"product": "Peoplesoft PS_TOKEN", "secret": "Peoplesoft Secret", "severity": "HIGH"}

    def peoplesoft_load(self, PS_TOKEN_B64):
        PS_TOKEN = base64.b64decode(PS_TOKEN_B64)
        SHA1_mac = PS_TOKEN[44:64]
        try:
            PS_TOKEN_DATA = zlib.decompress(PS_TOKEN[76:])
        except zlib.error:
            return None, None
        return PS_TOKEN_DATA, SHA1_mac

    def check_secret(self, PS_TOKEN_B64):
        if not self.identify(PS_TOKEN_B64):
            return None

        PS_TOKEN_DATA, SHA1_mac = self.peoplesoft_load(PS_TOKEN_B64)
        if not PS_TOKEN_DATA or not SHA1_mac:
            return None

        username = PS_TOKEN_DATA[21 : 21 + PS_TOKEN_DATA[20]].replace(b"\x00", b"").decode()

        # try no password
        h = hashlib.sha1(PS_TOKEN_DATA)
        if h.digest() == SHA1_mac:
            return {"secret": f"Username: {username} Password: BLANK PASSWORD!", "details": None}

        for l in set(list(self.load_resources(["peoplesoft_passwords.txt", "top_100000_passwords.txt"]))):
            password = l.strip()

            h = hashlib.sha1(PS_TOKEN_DATA + password.encode("utf_16_le", errors="ignore"))
            if h.digest() == SHA1_mac:
                return {"secret": f"Username: {username} Password: {password}", "details": None}

        return None

    def get_hashcat_commands(self, PS_TOKEN_B64, *args):
        PS_TOKEN_DATA, SHA1_mac = self.peoplesoft_load(PS_TOKEN_B64)

        if not PS_TOKEN_DATA or not SHA1_mac:
            return None
        return [
            {
                "command": f"hashcat -m 13500 -a 0 {SHA1_mac.hex()}:{PS_TOKEN_DATA.hex()}  <dictionary_file>",
                "description": f"Peoplesoft PS_TOKEN Password",
            }
        ]
