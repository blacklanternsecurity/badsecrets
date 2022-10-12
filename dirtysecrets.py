import os
import hmac
import base64
import hashlib
import struct
import binascii
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from viewstate import ViewState

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

unpad = lambda s: s[: -ord(s[len(s) - 1 :])]

def search_dict(d, query):
    items = [key for key, value in d.items() if query == value]
    if not items:
        return None
    return items

class DirtySecretsBase:

    output_parameters = None

    def check_secret(self):
        pass

    def load_resource(self, resource):
        with open(f"{SCRIPT_DIR}/resources/{resource}") as r:
            for l in r.readlines():
                if len(l) > 0:
                    yield l

class ASPNETViewstate(DirtySecretsBase):

    hash_algs = {
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5,
        "SHA256": hashlib.sha256,
        "SHA384": hashlib.sha384,
        "SHA512": hashlib.sha512,
        "AES": hashlib.sha1,
        "3DES": hashlib.sha1,
    }
    hash_sizes = {"SHA1": 20, "MD5": 16, "SHA256": 32, "SHA384": 48, "SHA512": 64}

    def __init__(self, viewstate_B64, generator):

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
            print(hash_alg)
            print(self.hash_sizes[hash_alg])
            viewstate_data = self.viewstate_bytes[: -self.hash_sizes[hash_alg]]
            signature = self.viewstate_bytes[-self.hash_sizes[hash_alg] :]
            if hash_alg == "MD5":
                try:
                    md5_bytes = viewstate_data + binascii.unhexlify(vkey)
                    if not self.encrypted:
                        md5_bytes += b"\x00" * 4
                    h = hashlib.md5(md5_bytes)
                    print(h.digest())
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
