import re
import hmac
import base64
import binascii
import urllib.parse
from contextlib import suppress
from badsecrets.base import BadsecretsBase


def no_padding_urlsafe_base64_decode(enc):
    return base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))


def no_padding_urlsafe_base64_encode_es(enc):
    return base64.urlsafe_b64encode(enc).decode().rstrip("=").replace("-", "+").replace("_", "/")


class ExpressSignedCookies_ES(BadsecretsBase):
    identify_regex = re.compile(r"^s%3[Aa][^\.]+\.(?!.*%20|.*%22)[a-zA-Z0-9%]{20,90}$")
    description = {
        "product": "Express.js Signed Cookie (express-session)",
        "secret": "Express.js SESSION_SECRET (express-session)",
        "severity": "LOW",
    }

    def carve_regex(self):
        return re.compile(r"(?<!http)(s%3[Aa][^.]+\.(?![^ ]*%20|[^ ]*%22)[a-zA-Z0-9%]{20,90})")

    def expressHMAC(self, payload, secret, hash_algorithm):
        return no_padding_urlsafe_base64_encode_es(
            hmac.HMAC(secret.encode(), payload.encode(), hash_algorithm).digest()
        )

    def expressVerify_es(self, value, secret):
        payload, signature = value.split(".")[0][4:], urllib.parse.unquote(value.split(".")[1])

        with suppress(binascii.Error):
            signature_candidates = self.search_dict(self.hash_sizes, len(no_padding_urlsafe_base64_decode(signature)))
            if not signature_candidates:
                return False
            else:
                for hash_algorithm_str in signature_candidates:
                    hash_algorithm = self.hash_algs[hash_algorithm_str]
                    generated_hash = self.expressHMAC(payload, secret, hash_algorithm)
                    if generated_hash == signature:
                        return {
                            "hash algorithm": hash_algorithm.__name__.split("openssl_")[1],
                        }
        return False

    def check_secret(self, express_signed_cookie):
        if not self.identify(express_signed_cookie):
            return False

        for l in set(list(self.load_resources(["express_session_secrets.txt", "top_100000_passwords.txt"]))):
            session_secret = l.rstrip()

            r = self.expressVerify_es(express_signed_cookie, session_secret)

            if r:
                return {"secret": session_secret, "details": r}
