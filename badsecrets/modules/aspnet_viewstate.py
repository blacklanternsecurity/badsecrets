import hmac
import struct
import base64
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from viewstate import ViewState
from contextlib import suppress
from badsecrets.base import BadsecretsBase, generic_base64_regex

unpad = lambda s: s[: -ord(s[len(s) - 1 :])]


class ASPNET_Viewstate(BadsecretsBase):

    identify_regex = generic_base64_regex

    @staticmethod
    def valid_preamble(sourcebytes):
        if sourcebytes[0:2] == b"\xff\x01":
            return True
        return False

    def viewstate_decrypt(self, ekey, hash_alg, viewstate_B64):

        viewstate_bytes = base64.b64decode(viewstate_B64)

        try:
            ekey_bytes = binascii.unhexlify(ekey)
        except binascii.Error:
            return

        vs_size = len(viewstate_bytes)
        dec_algos = set()
        hash_size = self.hash_sizes[hash_alg]

        if (vs_size - hash_size) % AES.block_size == 0:
            dec_algos.add("AES")
        if (vs_size - hash_size) % DES.block_size == 0:
            dec_algos.add("DES")
            dec_algos.add("3DES")

        for dec_algo in list(dec_algos):
            with suppress(ValueError):
                if dec_algo == "AES":
                    block_size = AES.block_size
                    iv = viewstate_bytes[0:block_size]
                    cipher = AES.new(ekey_bytes, AES.MODE_CBC, iv)
                    blockpadlen = 8

                elif dec_algo == "3DES":
                    block_size = DES3.block_size
                    iv = viewstate_bytes[0:block_size]
                    cipher = DES3.new(ekey_bytes[:24], DES3.MODE_CBC, iv)
                    blockpadlen = 16

                elif dec_algo == "DES":
                    block_size = DES.block_size
                    iv = viewstate_bytes[0:block_size]
                    cipher = DES.new(ekey_bytes[:8], DES.MODE_CBC, iv)
                    blockpadlen = 0

            encrypted_raw = viewstate_bytes[block_size:-hash_size]
            decrypted_raw = cipher.decrypt(encrypted_raw)
            decrypt = unpad(decrypted_raw[blockpadlen:])

            if self.valid_preamble(decrypt):
                return dec_algo

    def viewstate_validate(self, vkey, encrypted, viewstate_B64, generator):
        viewstate_bytes = base64.b64decode(viewstate_B64)

        if encrypted:
            candidate_hash_algs = list(self.hash_sizes.keys())

        else:
            vs = ViewState(viewstate_B64)
            vs.decode()
            signature_len = len(vs.signature)
            candidate_hash_algs = self.search_dict(self.hash_sizes, signature_len)

        for hash_alg in candidate_hash_algs:
            viewstate_data = viewstate_bytes[: -self.hash_sizes[hash_alg]]
            signature = viewstate_bytes[-self.hash_sizes[hash_alg] :]
            if hash_alg == "MD5":
                try:
                    md5_bytes = viewstate_data + binascii.unhexlify(vkey)
                    if not encrypted:
                        md5_bytes += b"\x00" * 4
                    h = hashlib.md5(md5_bytes)
                except binascii.Error:
                    continue
            else:
                try:
                    vs_data_bytes = viewstate_data
                    if not encrypted:
                        vs_data_bytes += generator
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

    def check_secret(self, viewstate_B64, generator="0000"):

        if not self.identify(viewstate_B64):
            return None

        generator = struct.pack("<I", int(generator, 16))
        if self.valid_preamble(base64.b64decode(viewstate_B64)):
            encrypted = False
        else:
            encrypted = True

        for l in self.load_resource("aspnet_machinekeys.txt"):
            try:
                vkey, ekey = l.rstrip().split(",")
            except ValueError:
                continue
            validationAlgo = self.viewstate_validate(vkey, encrypted, viewstate_B64, generator)
            if validationAlgo:
                confirmed_ekey = None
                decryptionAlgo = None
                if encrypted:
                    decryptionAlgo = self.viewstate_decrypt(ekey, validationAlgo, viewstate_B64)
                    if decryptionAlgo:
                        confirmed_ekey = ekey

                return {
                    "validationKey": vkey,
                    "validationAlgo": validationAlgo,
                    "encryptionKey": confirmed_ekey,
                    "encryptionAlgo": decryptionAlgo,
                }
        return None
