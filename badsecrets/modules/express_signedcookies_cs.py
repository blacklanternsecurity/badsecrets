import re
import hmac
import base64
import binascii
from contextlib import suppress
from badsecrets.base import BadsecretsBase


def no_padding_urlsafe_base64_decode(enc):
    return base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))


def no_padding_urlsafe_base64_encode_cs(enc):
    return base64.urlsafe_b64encode(enc).decode().rstrip("=").replace("+", "-").replace("/", "_")


class ExpressSignedCookies_CS(BadsecretsBase):
    check_secret_args = 2
    identify_regex = re.compile(r"\w{1,200}\=eyJ[A-Za-z0-9=\\_]{4,512}")
    signature_regex = re.compile(r"^[A-Za-z0-9_-]{27}$")
    description = {
        "product": "Express.js Signed Cookie (cookie-session)",
        "secret": "Express.js Secret (cookie-session)",
        "severity": "HIGH",
    }

    def carve_regex(self):
        return re.compile(r"(\w{1,64})=([^;]{4,512});.{0,100}?\1\.sig=([^;]{27,86})")

    def get_product_from_carve(self, regex_search):
        return f"Data Cookie: [{regex_search.groups()[0]}={regex_search.groups()[1]}] Signature Cookie: [{regex_search.groups()[2]}]"

    def carve_to_check_secret(self, s):
        if len(s.groups()) == 3:
            r = self.check_secret(f"{s.groups()[0]}={s.groups()[1]}", s.groups()[2])
            return r

    def expressHMAC(self, payload, secret, hash_algorithm):
        return no_padding_urlsafe_base64_encode_cs(
            hmac.HMAC(secret.encode(), payload.encode(), hash_algorithm).digest()
        )

    def expressVerify_cs(self, payload, signature, secret):
        with suppress(binascii.Error):
            for hash_algorithm_str in self.search_dict(
                self.hash_sizes, len(no_padding_urlsafe_base64_decode(signature))
            ):
                hash_algorithm = self.hash_algs[hash_algorithm_str]
                generated_hash = self.expressHMAC(payload, secret, hash_algorithm)
                if generated_hash == signature:
                    return {
                        "hash algorithm": hash_algorithm.__name__.split("openssl_")[1],
                    }
        return False

    def check_secret(self, express_signed_cookie_data, *args):
        if not self.identify(express_signed_cookie_data):
            return None

        sig = self.resolve_args(args)

        if not sig:
            return False

        for l in set(list(self.load_resources(["express_session_secrets.txt", "top_100000_passwords.txt"]))):
            secret = l.rstrip()
            r = self.expressVerify_cs(express_signed_cookie_data, sig, secret)
            if r:
                return {
                    "secret": secret,
                    "details": r,
                    "product": f"Data Cookie: [{express_signed_cookie_data}] Signature Cookie: [{sig}]",
                }

    def resolve_args(self, args):
        if len(args) != 1:
            return None

        if self.signature_regex.match(args[0]):
            return args[0]
