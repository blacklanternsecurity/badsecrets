import re
import os
import hashlib
import badsecrets.errors
from abc import abstractmethod

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

    def __init__(self, **kwargs):
        setattr(self, "custom_resource", kwargs.get("custom_resource", None))

        if self.custom_resource:
            if not os.path.exists(self.custom_resource):
                raise badsecrets.errors.LoadResourceException(
                    f"Custom resource [{self.custom_resource}] does not exist"
                )

    @abstractmethod
    def check_secret(self, secret):
        raise NotImplementedError

    def load_resource(self, resource):

        if self.custom_resource:
            filepath = self.custom_resource
        else:
            filepath = f"{os.path.dirname(os.path.abspath(__file__))}/resources/{resource}"
        with open(filepath) as r:
            for l in r.readlines():
                if len(l) > 0:
                    yield l

    @classmethod
    def identify(self, secret):
        if re.match(self.identify_regex, secret):
            return True
        return False

    @staticmethod
    def search_dict(d, query):
        items = [key for key, value in d.items() if query == value]
        if items:
            return items


def check_all_modules(secret):
    for m in BadsecretsBase.__subclasses__():
        x = m()
        r = x.check_secret(secret)
        if r:
            r["detecting_module"] = m.__name__
            return r
    return None
