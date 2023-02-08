import re
import gzip
import hmac
import base64
import hashlib
import binascii
import urllib.parse
from Crypto.Cipher import DES3, AES, DES
from Crypto.Util.Padding import unpad
from badsecrets.helpers import Java_sha1prng
from badsecrets.base import BadsecretsBase, generic_base64_regex


class Jsf_viewstate(BadsecretsBase):
    myfaces_candidate_decryption_algorithms = [DES3, AES, DES]

    identify_regex = generic_base64_regex
    description = {"Product": "Java Server Faces Viewstate", "Secret": "com.sun.faces.ClientStateSavingPassword"}

    @staticmethod
    def attempt_decompress(value):
        try:
            uncompressed = gzip.decompress(base64.b64decode(value))
        except (gzip.BadGzipFile, binascii.Error, ValueError):
            return False
        return uncompressed

    def carve_regex(self):
        return re.compile(r"<input.+?name=\"javax\.faces\.ViewState\".+?value=\"([^\"]*)\"")

    # Mojarra 1.2.x - 2.0.3
    def DES3_decrypt(self, ct, password):
        x = Java_sha1prng(password)
        derivedKey = x.get_sha1prng_key(24)
        cipher = DES3.new(
            derivedKey, DES3.MODE_CBC, iv=b"AAAAAAAA"
        )  # Theres no way to determine the IV, as it lives in server memory. So, we can pass anything in - we can still decrypt all except for block #1
        try:
            decrypted = cipher.decrypt(base64.b64decode(ct))
            if b"java." in decrypted:
                return True
        except (ValueError, binascii.Error):
            return False
        return False

    # Mojarra 2.2.6 - 2.3.x
    def AES_decrypt(self, ct, password_bytes):
        try:
            ct_bytes = base64.b64decode(ct)
        except (binascii.Error, ValueError):
            return False

        sig = ct_bytes[:32]
        iv = ct_bytes[32:48]
        data = ct_bytes[48:]
        h = hmac.new(password_bytes, digestmod=hashlib.sha256)
        h.update(iv)
        h.update(data)

        # We really only have to check the signature to know we can decrypt, since the HMAC and AES keys are derived from the same password
        if h.digest() == sig:
            # We decrypt anyway, just so we can determine compression
            cipher = AES.new(password_bytes, AES.MODE_CBC, iv)
            pt_b64 = unpad(cipher.decrypt(data), AES.block_size)
            return pt_b64

    def myfaces_mac(self, ct_bytes, password_bytes):
        candidate_hash_algs = list(self.hash_sizes.keys())
        for hash_alg in candidate_hash_algs:
            data = ct_bytes[: -self.hash_sizes[hash_alg]]
            sig = ct_bytes[-self.hash_sizes[hash_alg] :]

            h = hmac.new(password_bytes, data, hash_alg)
            if sig == h.digest():
                return (password_bytes, hash_alg)
            else:
                continue
        return (None, None)

    def myfaces_validate_decrypt(self, decrypted):
        uncompressed = self.attempt_decompress(base64.b64encode(decrypted))
        if uncompressed:
            if b"java." in uncompressed:
                decrypted = uncompressed

        if b"java." in decrypted:
            # instead of b64 encoding and looking for rO0, stay in bytes and look for as many as you can
            if b"\xAC\xED\x00\x05" in decrypted and ord(bytes([decrypted[4]])) in list(range(112, 126)):
                return (True, True, uncompressed)
            else:
                return (True, False, uncompressed)
        return (None, None, None)

    def myfaces_decrypt(self, ct_bytes, password_bytes, dec_algos, hash_sizes):
        invalid_iv_match = None
        for hash_size in hash_sizes:
            encrypted_data = ct_bytes[:-hash_size]

            for dec_algo in dec_algos:
                if str(dec_algo.__name__) == "Crypto.Cipher.DES" and len(password_bytes) != 8:
                    continue

                if str(dec_algo.__name__) == "Crypto.Cipher.DES3" and len(password_bytes) != 24:
                    continue

                if str(dec_algo.__name__) == "Crypto.Cipher.AES" and len(password_bytes) not in [16, 32, 64]:
                    continue

                for cipher_mode in ["CBC", "ECB"]:
                    if cipher_mode == "ECB":
                        cipher = dec_algo.new(password_bytes, dec_algo.MODE_ECB)
                        try:
                            decrypted = unpad(cipher.decrypt(encrypted_data), dec_algo.block_size)
                        except (ValueError, binascii.Error):
                            continue

                        validation_result, first_block_valid, uncompressed = self.myfaces_validate_decrypt(decrypted)
                        if validation_result and first_block_valid:
                            return (
                                password_bytes,
                                dec_algo.__name__.replace("Crypto.Cipher.", ""),
                                cipher_mode,
                                None,
                                True if uncompressed else False,
                            )

                    elif cipher_mode == "CBC":
                        iv_guesses = []
                        # the most common misconfiguration will be setting the key as the IV
                        # Todo: Include other common IV possiblities
                        if dec_algo.__name__ == "Crypto.Cipher.DES3" or dec_algo.__name__ == "Crypto.Cipher.DES":
                            iv_guesses.append(password_bytes[:8])
                        else:
                            iv_guesses.append(password_bytes[:16])

                        iv_guesses.append(dec_algo.block_size * b"\x00")
                        iv_guesses.append(dec_algo.block_size * b"\xFF")
                        iv_guesses.append(dec_algo.block_size * b"\x61")
                        iv_guesses.append(dec_algo.block_size * b"\x41")
                        iv_guesses.append(dec_algo.block_size * b"\x30")
                        iv_guesses.append(dec_algo.block_size * b"\x31")

                        for iv in iv_guesses:
                            cipher = dec_algo.new(password_bytes, dec_algo.MODE_CBC, iv=iv)
                            try:
                                decrypted = unpad(cipher.decrypt(encrypted_data), dec_algo.block_size)
                            except (ValueError, binascii.Error):
                                continue
                            validation_result, first_block_valid, uncompressed = self.myfaces_validate_decrypt(
                                decrypted
                            )
                            if validation_result:
                                if first_block_valid:
                                    return (
                                        password_bytes,
                                        dec_algo.__name__.replace("Crypto.Cipher.", ""),
                                        cipher_mode,
                                        iv,
                                        True if uncompressed else False,
                                    )
                                else:
                                    invalid_iv_match = (
                                        password_bytes,
                                        dec_algo.__name__.replace("Crypto.Cipher.", ""),
                                        cipher_mode,
                                        b"INVALID",
                                        True if uncompressed else False,
                                    )
                                    continue

        # The decryption key was valid, but the first block was not - this indicates that the mode is CBC and the IV is incorrect
        if invalid_iv_match:
            return invalid_iv_match
        else:
            return (None, None, None, None, None)

    def check_secret(self, jsf_viewstate_value):
        jsf_viewstate_value = urllib.parse.unquote(jsf_viewstate_value)

        if jsf_viewstate_value.startswith("rO0"):
            return {
                "secret": "UNPROTECTED",
                "details": {
                    "source": jsf_viewstate_value,
                    "info": "JSF Viewstate (Unprotected)",
                    "compression": False,
                },
            }

        uncompressed = self.attempt_decompress(jsf_viewstate_value)
        if uncompressed:
            if b"java." in uncompressed:
                return {
                    "secret": "UNPROTECTED (COMPRESSED)",
                    "details": {
                        "source": jsf_viewstate_value,
                        "info": "JSF Viewstate (Unprotected, Compressed)",
                        "compression": True,
                    },
                }
            else:
                jsf_viewstate_value = base64.b64encode(uncompressed)

        for l in list(self.load_resource("jsf_viewstate_passwords.txt")) + list(
            self.load_resource("top_10000_passwords.txt")
        ):
            password = l.rstrip()
            if self.DES3_decrypt(jsf_viewstate_value, password):
                return {
                    "secret": password,
                    "details": {
                        "source": jsf_viewstate_value,
                        "info": "JSF Viewstate (Mojarra 1.2.x - 2.0.3) 3DES Encrypted",
                        "compression": True if uncompressed else False,
                    },
                }

        # Mojarra decryption
        for l in self.load_resource("jsf_viewstate_passwords_b64.txt"):
            password_bytes = base64.b64decode(l.rstrip())
            decrypted = self.AES_decrypt(jsf_viewstate_value, password_bytes)

            if decrypted:
                uncompressed = self.attempt_decompress(base64.b64encode(decrypted))
                if uncompressed:
                    if b"java." in uncompressed:
                        decrypted = uncompressed

                decrypted_b64 = base64.b64encode(decrypted).decode()
                if decrypted_b64.startswith("rO0"):
                    return {
                        "secret": base64.b64encode(password_bytes).decode(),
                        "details": {
                            "source": jsf_viewstate_value,
                            "info": "JSF Viewstate (Mojarra 2.2.6 - 2.3.x) AES Encrypted",
                            "compression": True if uncompressed else False,
                        },
                    }

        # myfaces decryption / mac

        myfaces_solved_mac_key = None
        myfaces_solved_mac_algo = None
        myfaces_solved_decryption_key = None
        myfaces_solved_decryption_algo = None
        myfaces_solved_decryption_mode = None
        myfaces_solved_decryption_iv = None

        try:
            ct_bytes = base64.b64decode(jsf_viewstate_value)
        except (binascii.Error, ValueError):
            return False

        # Attempt to solve mac_key
        for l in self.load_resource("jsf_viewstate_passwords_b64.txt"):
            password_bytes = base64.b64decode(l.rstrip())
            myfaces_solved_mac_key, myfaces_solved_mac_algo = self.myfaces_mac(ct_bytes, password_bytes)
            if myfaces_solved_mac_key:
                break

        # Attempt to solve encryption_key
        dec_algos = set()
        if myfaces_solved_mac_algo:
            hash_size = self.hash_sizes[myfaces_solved_mac_algo]
            hash_sizes = [hash_size]
            for algo in self.myfaces_candidate_decryption_algorithms:
                if (len(ct_bytes) - hash_size) % algo.block_size == 0:
                    dec_algos.add(algo)
        else:
            dec_algos = set(self.myfaces_candidate_decryption_algorithms)
            hash_sizes = self.hash_sizes.values()

        for l in self.load_resource("jsf_viewstate_passwords_b64.txt"):
            password_bytes = base64.b64decode(l.rstrip())
            (
                myfaces_solved_decryption_key,
                myfaces_solved_decryption_algo,
                myfaces_solved_decryption_mode,
                myfaces_solved_decryption_iv,
                compression,
            ) = self.myfaces_decrypt(ct_bytes, password_bytes, dec_algos, hash_sizes)
            if myfaces_solved_decryption_key:
                break

        if myfaces_solved_mac_key or myfaces_solved_decryption_key:
            if myfaces_solved_decryption_key:
                myfaces_solved_decryption_key = base64.b64encode(myfaces_solved_decryption_key).decode()
            if myfaces_solved_mac_key:
                myfaces_solved_mac_key = base64.b64encode(myfaces_solved_mac_key).decode()
            if myfaces_solved_decryption_iv:
                if myfaces_solved_decryption_iv == b"INVALID":
                    myfaces_solved_decryption_iv = "INVALID"
                else:
                    myfaces_solved_decryption_iv = base64.b64encode(myfaces_solved_decryption_iv).decode()
            return {
                "secret": {
                    "Hash Key": myfaces_solved_mac_key,
                    "Hash Algo": myfaces_solved_mac_algo,
                    "Decryption Key": myfaces_solved_decryption_key,
                    "Decryption Algo": myfaces_solved_decryption_algo,
                    "Decryption Mode": myfaces_solved_decryption_mode,
                    "Decryption IV": myfaces_solved_decryption_iv,
                },
                "details": {
                    "source": jsf_viewstate_value,
                    "info": "JSF Viewstate (Myfaces)",
                    "compression": compression,
                },
            }
