import re
import hmac
import base64
import binascii
import urllib.parse
from badsecrets.base import BadsecretsBase


class Telerik_HashKey(BadsecretsBase):

    identify_regex = re.compile(r"^(?:[A-Za-z0-9+\/=%]+)$")

    def __init__(self, dialogParameters_raw):

        dialogParametersB64 = urllib.parse.unquote(dialogParameters_raw)

        self.dp_enc = dialogParametersB64[:-44].encode()
        self.dp_hash = dialogParametersB64[-44:].encode()

    def prepare_keylist(self):
        for l in self.load_resource("aspnet_machinekeys.txt"):
            try:
                vkey, ekey = l.rstrip().split(",")
                yield vkey
            except ValueError:
                continue
        for l in self.load_resource("telerik_hash_keys.txt"):
            vkey = l.strip()
            yield vkey

    def check_secret(self):

        for vkey in self.prepare_keylist():
            try:
                h = hmac.new(vkey.encode(), self.dp_enc, self.hash_algs["SHA256"])
                if base64.b64encode(h.digest()) == self.dp_hash:
                    self.output_parameters = {"Telerik.Upload.ConfigurationHashKey": vkey}
                    return True
            except binascii.Error:
                continue
        return False
