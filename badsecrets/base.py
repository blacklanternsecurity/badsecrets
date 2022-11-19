import re
import os
import hashlib
import requests
import badsecrets.errors
from abc import abstractmethod

generic_base64_regex = re.compile(
    r"^(?:[A-Za-z0-9+\/]{4}){8,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
)


class BadsecretsBase:

    identify_regex = re.compile(r".+")
    description = {"Product": "Undefined", "Secret": "Undefined"}

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

    @classmethod
    def get_description(self):
        return self.description

    def load_resource(self, resource):

        if self.custom_resource:
            filepath = self.custom_resource
        else:
            filepath = f"{os.path.dirname(os.path.abspath(__file__))}/resources/{resource}"
        with open(filepath) as r:
            for l in r.readlines():
                if len(l) > 0:
                    yield l

    def carve_to_check_secret(self, s):
        if s.groups():
            r = self.check_secret(s.groups()[0])
            return r

    @abstractmethod
    def carve_regex(self):
        return None

    def carve(self, body=None, cookies=None, requests_response=None):

        results = []

        if not body and not cookies and not requests_response:
            raise badsecrets.errors.CarveException("Either body/cookies or requests_response required")

        if requests_response:

            if body or cookies:
                raise badsecrets.errors.CarveException("Body/cookies and requests_response cannot both be set")

            if type(requests_response) == requests.models.Response:
                body = requests_response.text
                cookies = dict(requests_response.cookies)
            else:
                raise badsecrets.errors.CarveException("requests_response must be a requests.models.Response object")

        if cookies:
            if type(cookies) != dict:
                raise badsecrets.errors.CarveException("Header argument must be type dict")
            for k, v in cookies.items():
                r = self.check_secret(v)
                if r:
                    r["type"] = "SecretFound"
                    r["source"] = v
                    results.append(r)
        if body:
            if type(body) != str:
                raise badsecrets.errors.CarveException("Body argument must be type str")
            if self.carve_regex():

                s = re.search(self.carve_regex(), body)
                if s:
                    r = self.carve_to_check_secret(s)
                    if r:
                        r["type"] = "SecretFound"
                    else:
                        r = {"type": "IdentifyOnly"}
                    r["source"] = s.groups()[0]
                    results.append(r)

        for r in results:
            r["description"] = self.get_description()
        return results

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


def carve_all_modules(**kwargs):
    results = []
    for m in BadsecretsBase.__subclasses__():
        x = m()
        r_list = x.carve(**kwargs)
        if len(r_list) > 0:
            for r in r_list:
                r["detecting_module"] = m.__name__
                results.append(r)
    if results:
        return results
