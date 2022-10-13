import re
import os
import hmac
import zlib
import struct
import base64
import hashlib
import binascii
import urllib.parse
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from viewstate import ViewState
from flask_unsign import verify as flaskVerify

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

unpad = lambda s: s[: -ord(s[len(s) - 1 :])]

generic_base64_regex = re.compile(
    r"^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
)


def search_dict(d, query):
    items = [key for key, value in d.items() if query == value]
    if not items:
        return None
    return items


class PopsecretsBase:

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

    def check_secret(self):
        pass

    def load_resource(self, resource):
        with open(f"{SCRIPT_DIR}/resources/{resource}") as r:
            for l in r.readlines():
                if len(l) > 0:
                    yield l

    @classmethod
    def identify(self, secret):
        if re.match(self.identify_regex, secret):
            return True
        return False


class Peoplesoft_PSToken(PopsecretsBase):

    identify_regex = generic_base64_regex

    def __init__(self, PS_TOKEN_B64):
        self.PS_TOKEN = base64.b64decode(PS_TOKEN_B64)

    def check_secret(self):

        SHA1_mac = self.PS_TOKEN[44:64]
        try:
            PS_TOKEN_DATA = zlib.decompress(self.PS_TOKEN[76:])
        except zlib.error:
            return False

        username = PS_TOKEN_DATA[21 : 21 + PS_TOKEN_DATA[20]].replace(b"\x00", b"").decode()

        # try no password
        h = hashlib.sha1(PS_TOKEN_DATA)
        if h.digest() == SHA1_mac:
            self.output_parameters = {"PS_TOKEN_password": "BLANK PASSWORD!", "username": username}
            return True

        for l in self.load_resource("peoplesoft_passwords.txt"):
            password = l.strip()

            h = hashlib.sha1(PS_TOKEN_DATA + password.encode("utf_16_le", errors="ignore"))
            if h.digest() == SHA1_mac:
                self.output_parameters = {"PS_TOKEN_password": password, "username": username}
                return True

        return False


class FlaskSigningKey(PopsecretsBase):

    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")

    def __init__(self, flask_cookie):
        self.flask_cookie = flask_cookie

    def check_secret(self):
        for l in self.load_resource("flask_passwords.txt"):
            password = l.rstrip()
            r = flaskVerify(value=self.flask_cookie, secret=password)
            if r:
                self.output_parameters = {"flask_password": password}
                return True
        return False


class TelerikUploadConfigurationHashKey(PopsecretsBase):

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


class ASPNETViewstate(PopsecretsBase):

    identify_regex = generic_base64_regex

    def __init__(self, viewstate_B64, generator="0000"):

        self.generator = struct.pack("<I", int(generator, 16))
        self.viewstate = viewstate_B64
        self.viewstate_bytes = base64.b64decode(viewstate_B64)
        if self.valid_preamble(self.viewstate_bytes):
            self.encrypted = False
        else:
            self.encrypted = True

    @staticmethod
    def valid_preamble(sourcebytes):
        if sourcebytes[0:2] == b"\xff\x01":
            return True
        return False

    def viewstate_decrypt(self, ekey, hash_alg):

        try:
            ekey_bytes = binascii.unhexlify(ekey)
        except binascii.Error:
            return

        vs_size = len(self.viewstate_bytes)
        dec_algos = set()
        hash_size = self.hash_sizes[hash_alg]

        if (vs_size - hash_size) % AES.block_size == 0:
            dec_algos.add("AES")
        if (vs_size - hash_size) % DES.block_size == 0:
            dec_algos.add("DES")
            dec_algos.add("3DES")

        for dec_algo in list(dec_algos):
            if dec_algo == "AES":
                block_size = AES.block_size
                iv = self.viewstate_bytes[0:block_size]
                try:
                    cipher = AES.new(ekey_bytes, AES.MODE_CBC, iv)
                except ValueError:
                    continue
                blockpadlen = 8

            elif dec_algo == "3DES":
                block_size = DES3.block_size
                iv = self.viewstate_bytes[0:block_size]
                try:
                    cipher = DES3.new(ekey_bytes[:24], DES3.MODE_CBC, iv)
                except ValueError:
                    continue
                blockpadlen = 16

            elif dec_algo == "DES":
                block_size = DES.block_size
                iv = self.viewstate_bytes[0:block_size]
                try:
                    cipher = DES.new(ekey_bytes[:8], DES.MODE_CBC, iv)
                except ValueError:
                    continue
                blockpadlen = 0

            encrypted_raw = self.viewstate_bytes[block_size:-hash_size]
            decrypted_raw = cipher.decrypt(encrypted_raw)
            decrypt = unpad(decrypted_raw[blockpadlen:])

            if self.valid_preamble(decrypt):
                return dec_algo
        return None

    def viewstate_validate(self, vkey):
        if self.encrypted:
            candidate_hash_algs = list(self.hash_sizes.keys())

        else:
            vs = ViewState(self.viewstate)
            vs.decode()
            signature_len = len(vs.signature)
            candidate_hash_algs = search_dict(self.hash_sizes, signature_len)

        for hash_alg in candidate_hash_algs:
            viewstate_data = self.viewstate_bytes[: -self.hash_sizes[hash_alg]]
            signature = self.viewstate_bytes[-self.hash_sizes[hash_alg] :]
            if hash_alg == "MD5":
                try:
                    md5_bytes = viewstate_data + binascii.unhexlify(vkey)
                    if not self.encrypted:
                        md5_bytes += b"\x00" * 4
                    h = hashlib.md5(md5_bytes)
                except binascii.Error:
                    continue
            else:
                try:
                    vs_data_bytes = viewstate_data
                    if not self.encrypted:
                        vs_data_bytes += self.generator
                    h = hmac.new(
                        binascii.unhexlify(vkey),
                        vs_data_bytes,
                        self.hash_algs[hash_alg],
                    )
                except binascii.Error:
                    continue

            if h.digest() == signature:
                return hash_alg

        return None

    def check_secret(self):
        for l in self.load_resource("aspnet_machinekeys.txt"):
            try:
                vkey, ekey = l.rstrip().split(",")
            except ValueError:
                continue

            validationAlgo = self.viewstate_validate(vkey)
            if validationAlgo:

                confirmed_ekey = None
                decryptionAlgo = None
                if self.encrypted:
                    decryptionAlgo = self.viewstate_decrypt(ekey, validationAlgo)
                    if decryptionAlgo:
                        confirmed_ekey = ekey

                self.output_parameters = {
                    "validationKey": vkey,
                    "validationAlgo": validationAlgo,
                    "encryptionKey": confirmed_ekey,
                    "encryptionAlgo": decryptionAlgo,
                }
                return True
        return False


def check_all_modules(secret):
    for m in PopsecretsBase.__subclasses__():
        if m.identify(secret):
            x = m(secret)
            if x.check_secret():
                return x.output_parameters
    return False
