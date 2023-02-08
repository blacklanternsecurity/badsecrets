import re
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
from badsecrets.helpers import unpad
from viewstate.exceptions import ViewStateException
from badsecrets.base import BadsecretsBase, generic_base64_regex


class ASPNET_Viewstate(BadsecretsBase):
    check_secret_args = 2

    identify_regex = generic_base64_regex
    description = {"Product": "ASP.NET Viewstate", "Secret": "ASP.NET MachineKey"}

    def carve_regex(self):
        return re.compile(
            r"<input.+__VIEWSTATE\"\svalue=\"(.+)\"[\S\s]+<input.+__VIEWSTATEGENERATOR\"\svalue=\"(\w+)\""
        )

    def carve_to_check_secret(self, s):
        if len(s.groups()) == 2:
            r = self.check_secret(s.groups()[0], generator=s.groups()[1])
            return r

    @staticmethod
    def valid_preamble(sourcebytes):
        if sourcebytes[0:2] == b"\xff\x01":
            return True
        return False

    def viewstate_decrypt(self, ekey_bytes, hash_alg, viewstate_B64):
        viewstate_bytes = base64.b64decode(viewstate_B64)

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
                    blockpadlen_raw = len(ekey_bytes) % AES.block_size
                    if blockpadlen_raw == 0:
                        blockpadlen = block_size
                    else:
                        blockpadlen = blockpadlen_raw

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

            with suppress(TypeError):
                decrypt = unpad(decrypted_raw[blockpadlen:])

                if self.valid_preamble(decrypt):
                    return dec_algo
                else:
                    continue

    def viewstate_validate(self, vkey, encrypted, viewstate_B64, generator):
        viewstate_bytes = base64.b64decode(viewstate_B64)

        if encrypted:
            candidate_hash_algs = list(self.hash_sizes.keys())

        else:
            vs = ViewState(viewstate_B64)
            try:
                vs.decode()
            except ViewStateException:
                return None
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
                    with suppress(binascii.Error):
                        ekey_bytes = binascii.unhexlify(ekey)
                        decryptionAlgo = self.viewstate_decrypt(ekey_bytes, validationAlgo, viewstate_B64)
                        if decryptionAlgo:
                            confirmed_ekey = ekey

                result = f"validationKey: {vkey} validationAlgo: {validationAlgo}"
                if confirmed_ekey:
                    result += f" encryptionKey: {confirmed_ekey} encryptionAlgo: {decryptionAlgo}"
                return {"secret": result, "details": None}
        return None
