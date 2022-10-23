import re
import os
import hashlib

generic_base64_regex = re.compile(
    r"^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
)


class BadsecretsBase:

    identify_regex = re.compile(r".+")

    hash_sizes = {"SHA1": 20, "MD5": 16, "SHA256": 32, "SHA384": 48, "SHA512": 64}
    hash_algs = {
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "AES": hashlib.sha1,
        "3DES": hashlib.sha1,
    }

    output_parameters = None

    def check_secret(self, secret):
        if not self.identify(secret):
            return None

    def load_resource(self, resource):
        with open(f"{os.path.dirname(os.path.abspath(__file__))}/resources/{resource}") as r:
            for l in r.readlines():
                if len(l) > 0:
                    yield l

    @classmethod
    def identify(self, secret):
        if re.match(self.identify_regex, secret):
            return True
        return False


def check_all_modules(secret):
    for m in BadsecretsBase.__subclasses__():
        x = m()
        r = x.check_secret(secret)
        if r:
            r["detecting_module"] = m.__name__
            return r
    return None


# class all_modules(BadSecretsBase):
#    def __init__(self):
#        self
