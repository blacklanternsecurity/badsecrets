import re
import hmac
import base64
from badsecrets.base import BadsecretsBase
from urllib.parse import unquote


class Rack2_SignedCookies(BadsecretsBase):

    identify_regex = re.compile(r"^BAh[\.a-zA-z-0-9\%=]{32,}--[\.a-zA-z-0-9%=]{16,}$")
    description = {
        "product": "Rack 2.x Signed Cookie (Ruby Serialized Object)",
        "secret": "Rack 2.x secret key",
        "severity": "HIGH",
    }

    def carve_regex(self):
        return re.compile(r"session=(BAh[\.a-zA-z-0-9\%=]{32,}--[\.a-zA-z-0-9%=]{16,})")

    def rack2(self, rack_cookie, secret_key):
        # Split the cookie into data and signature
        data, signature = rack_cookie.rsplit("--", 1)

        # Create the HMAC using the secret key
        h = hmac.new(secret_key.encode(), data.encode(), digestmod="sha1")

        # Verify the signature
        if h.hexdigest() != signature:
            return None

        # Decode the data from base64
        decoded_data = base64.b64decode(data)

        if decoded_data.startswith(b"\x04\x08"):
            return {"hash_algorithm": "SHA1"}

    def check_secret(self, rack_cookie):
        if not self.identify(rack_cookie):
            return None
        for l in self.load_resources(
            ["rails_secret_key_base.txt", "top_100000_passwords.txt", "rack_secret_keys.txt"]
        ):
            secret_key_base = l.rstrip()
            r = self.rack2(rack_cookie, secret_key_base)
            if r:
                return {"secret": secret_key_base, "details": r}

        return None

    def get_hashcat_commands(self, rack_cookie, *args):
        rack_cookie_split = rack_cookie.rsplit("--", 1)
        return [
            {
                "command": f"hashcat -m 150 -a 0 {rack_cookie_split[1]}:{base64.b64decode(unquote(rack_cookie_split[0])).hex()} --hex-salt  <dictionary_file>",
                "description": "Rack 2.x Signed Cookie (HMAC-SHA1)",
            }
        ]
