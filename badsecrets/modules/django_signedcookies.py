import re
import zlib
import base64
from django.core.signing import loads as djangoLoads, BadSignature
from badsecrets.base import BadsecretsBase


def _base64_decode(s):
    # Django strips the base64 padding (if any)
    # So, we need to add it back to be able to decode
    padding = '=' * (4 - (len(s) % 4))
    return base64.urlsafe_b64decode(s + padding)


class DjangoSignedCookies(BadsecretsBase):
    identify_regex = re.compile(r"^[\.a-zA-z-0-9]+:[\.a-zA-z-0-9:]+$")
    description = {"product": "Djangno Signed Cookie", "secret": "Django secret_key"}

    def check_secret(self, django_signed_cookie):
        if not self.identify(django_signed_cookie):
            return False
        for l in set(
            list(self.load_resource("django_secret_keys.txt")) + list(self.load_resource("top_10000_passwords.txt"))
        ):
            secret_key = l.rstrip()
            try:
                r = djangoLoads(
                    django_signed_cookie,
                    key=secret_key,
                    fallback_keys="",
                    salt="django.contrib.sessions.backends.signed_cookies",
                )
            except BadSignature:
                continue
            if r:
                return {"secret": secret_key, "details": r}


### ACCOUNT FOR SHA1!!!

### JUST GIVE A WARNING IF ITS TOO BIG!!!
    def get_hashcat_commands(self, django_signed_cookie):

        message, timestamp, signature = django_signed_cookie.split(":")
        signature_decoded = _base64_decode(signature)
        print(len(signature_decoded))
        if len(signature_decoded) == 32:
            mode == "1450" #SHA-256
        elif len(signature_decoded) == 20:
            mode = "140" #SHA1
        else:
            return None

        if message.startswith('.'):
            decompressed_msg = _base64_decode(message[1:])
            message = zlib.decompress(decompressed_msg)

        else:
            message = _base64_decode(message)

        message_hex = message.hex()
        full_message = f'{message_hex}:{timestamp}'

        signature_hex = signature_decoded.hex()
        hashcat_input = f"{signature_hex}:{message_hex}"

        return [
            {
                "command": f"hashcat -m {mode} -a 0 {hashcat_input} <dictionary_file>",
                "description": f"Django Signed Cookie",
            }
        ]
