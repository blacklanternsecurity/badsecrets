import re
import os
import gzip
import base64
import hashlib
import binascii
import requests
import badsecrets.errors
from abc import abstractmethod

generic_base64_regex = re.compile(
    r"^(?:[A-Za-z0-9+\/]{4}){8,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
)


class BadsecretsBase:
    identify_regex = re.compile(r".+")
    description = {"product": "Undefined", "secret": "Undefined", "severity": "Undefined"}

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

    check_secret_args = 1

    def __init__(self, custom_resource=None, **kwargs):
        self.custom_resource = custom_resource

        if self.custom_resource:
            if not os.path.exists(self.custom_resource):
                raise badsecrets.errors.LoadResourceException(
                    f"Custom resource [{self.custom_resource}] does not exist"
                )

    @abstractmethod
    def check_secret(self, secret):
        raise NotImplementedError

    @staticmethod
    def attempt_decompress(value):
        try:
            uncompressed = gzip.decompress(base64.b64decode(value))
        except (gzip.BadGzipFile, binascii.Error, ValueError):
            return False
        return uncompressed

    @classmethod
    def get_description(self):
        return self.description

    def get_product_from_carve(self, regex_search):
        return regex_search.groups()[0]

    def get_hashcat_commands(self, s):
        return None

    def load_resources(self, resource_list):
        filepaths = []
        if self.custom_resource:
            filepaths.append(self.custom_resource)
        for r in resource_list:
            filepaths.append(f"{os.path.dirname(os.path.abspath(__file__))}/resources/{r}")
        for filepath in filepaths:
            with open(filepath) as r:
                for l in r.readlines():
                    if len(l) > 0:
                        yield l

    def carve_to_check_secret(self, s, **kwargs):
        if s.groups():
            r = self.check_secret(s.groups()[0])
            return r

    @abstractmethod
    def carve_regex(self):
        return None

    def carve(self, body=None, cookies=None, headers=None, requests_response=None, **kwargs):
        results = []

        if not body and not cookies and not headers and requests_response == None:
            raise badsecrets.errors.CarveException("Either body/headers/cookies or requests_response required")

        if requests_response != None:
            if body or cookies or headers:
                raise badsecrets.errors.CarveException("Body/cookies/headers and requests_response cannot both be set")

            if type(requests_response) == requests.models.Response:
                body = requests_response.text
                cookies = dict(requests_response.cookies)
                headers = requests_response.headers
            else:
                raise badsecrets.errors.CarveException("requests_response must be a requests.models.Response object")

        if cookies:
            if type(cookies) != dict:
                raise badsecrets.errors.CarveException("Header argument must be type dict")
            for k, v in cookies.items():
                r = self.check_secret(v)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = v
                    r["location"] = "cookies"
                    results.append(r)

        if headers:
            for header_value in headers.values():
                # Check if we have a match outright
                r = self.check_secret(header_value)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = header_value
                    r["location"] = "headers"
                    results.append(r)
                # If we dont, we will only be able to add context if we have a match with carve_regex()
                elif self.carve_regex():
                    s = re.search(self.carve_regex(), header_value)
                    if s:
                        r = self.carve_to_check_secret(s)
                        if r:
                            r["type"] = "SecretFound"
                        # the carve regex hit but no secret was found
                        else:
                            r = {"type": "IdentifyOnly"}
                            r["hashcat"] = self.get_hashcat_commands(s.groups()[0])
                        if "product" not in r.keys():
                            r["product"] = self.get_product_from_carve(s)
                        r["location"] = "headers"
                        results.append(r)

        if body:
            if type(body) != str:
                raise badsecrets.errors.CarveException("Body argument must be type str")
            if self.carve_regex():
                s = re.search(self.carve_regex(), body)
                if s:
                    r = self.carve_to_check_secret(s, url=kwargs.get("url", None))
                    if r:
                        r["type"] = "SecretFound"
                    else:
                        r = {"type": "IdentifyOnly"}
                        r["hashcat"] = self.get_hashcat_commands(s.groups()[0])
                    if "product" not in r.keys():
                        r["product"] = self.get_product_from_carve(s)
                    r["location"] = "body"
                    results.append(r)

        for r in results:
            r["description"] = self.get_description()

        # Don't report an IdentifyOnly result if we have a SecretFound result for the same 'product'
        secret_found_results = set(d["product"] for d in results if d["type"] == "SecretFound")
        return [d for d in results if not (d["type"] == "IdentifyOnly" and d["product"] in secret_found_results)]

    @classmethod
    def identify(self, product):
        if re.match(self.identify_regex, product):
            return True
        return False

    @staticmethod
    def search_dict(d, query):
        items = [key for key, value in d.items() if query == value]
        if items:
            return items


def hashcat_all_modules(product, detecting_module=None, *args):
    hashcat_candidates = []
    for m in BadsecretsBase.__subclasses__():
        if detecting_module == m.__name__ or detecting_module == None:
            x = m()
            if x.identify(product):
                hashcat_commands = x.get_hashcat_commands(product)
                if hashcat_commands:
                    for hcc in hashcat_commands:
                        z = {
                            "detecting_module": m.__name__,
                            "hashcat_command": hcc["command"],
                            "hashcat_description": hcc["description"],
                        }
                        hashcat_candidates.append(z)
    return hashcat_candidates


def check_all_modules(*args, **kwargs):
    for m in BadsecretsBase.__subclasses__():
        x = m(custom_resource=kwargs.get("custom_resource", None))
        r = x.check_secret(*args[0 : x.check_secret_args])
        if r:
            r["detecting_module"] = m.__name__
            r["description"] = x.get_description()

            # allow the module to provide an amended product, if needed
            if "product" not in r.keys():
                r["product"] = args[0]
            r["location"] = "manual"
            return r
    return None


def carve_all_modules(**kwargs):
    results = []
    for m in BadsecretsBase.__subclasses__():
        x = m(custom_resource=kwargs.get("custom_resource", None))
        r_list = x.carve(**kwargs)
        if len(r_list) > 0:
            for r in r_list:
                r["detecting_module"] = m.__name__
                results.append(r)
    if results:
        return results
