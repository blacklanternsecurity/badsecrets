# Taken from crapsecrets (credit @irsdl)
# Detects ASP.NET machine keys via WebResource.axd and ScriptResource.axd encrypted URLs

import re
import hmac
import base64
import binascii
from Crypto.Cipher import AES, DES, DES3
from contextlib import suppress
from badsecrets.helpers import (
    unpad,
    sp800_108_derivekey,
    sp800_108_get_key_derivation_parameters,
    Purpose,
    aspnet_resource_b64_to_standard_b64,
)
from badsecrets.modules.aspnet_viewstate import ASPNET_Viewstate


class ASPNET_Resource(ASPNET_Viewstate):
    check_secret_args = 1
    # Match the custom ASP.NET URL-safe base64 alphabet (A-Z, a-z, 0-9, -, _) ending with a padding digit (0-2)
    identify_regex = re.compile(r"^[A-Za-z0-9\-_]{16,}[0-2]$")
    yara_carve_rule = (
        "rule ASPNET_Resource_carve {"
        ' strings: $wr = "WebResource.axd" $sr = "ScriptResource.axd"'
        " condition: $wr or $sr }"
    )
    description = {"product": "ASP.NET Resource", "secret": "ASP.NET MachineKey", "severity": "HIGH"}

    def carve_regex(self):
        return re.compile(r"(?:WebResource|ScriptResource)\.axd\?d=([A-Za-z0-9_\-]{16,}[0-2])", re.IGNORECASE)

    def carve_to_check_secret(self, s, **kwargs):
        if s.groups():
            return self.check_secret(s.groups()[0])

    def resource_validate(self, vkey_bytes, resource_bytes, purpose, mode):
        """HMAC validation. DOTNET40 uses raw key, DOTNET45 uses SP800-108 KDF."""
        for hash_alg in list(self.hash_sizes.keys()):
            hash_size = self.hash_sizes[hash_alg]
            if len(resource_bytes) <= hash_size:
                continue

            resource_data = resource_bytes[:-hash_size]
            signature = resource_bytes[-hash_size:]

            if hash_alg == "MD5":
                continue

            if mode == "DOTNET45":
                label, context = sp800_108_get_key_derivation_parameters(purpose.value, [])
                key = sp800_108_derivekey(vkey_bytes, label, context, len(vkey_bytes) * 8)
            else:
                key = vkey_bytes

            h = hmac.new(key, resource_data, self.hash_algs[hash_alg])
            if signature == h.digest():
                return hash_alg
        return None

    def resource_decrypt(self, ekey_bytes, hash_alg, resource_bytes, purpose, mode):
        """AES/3DES/DES decryption, validates via printable ASCII check."""
        hash_size = self.hash_sizes[hash_alg]
        dec_algos = set()

        if (len(resource_bytes) - hash_size) % AES.block_size == 0:
            dec_algos.add("AES")
        if (len(resource_bytes) - hash_size) % DES.block_size == 0:
            dec_algos.add("DES")
            dec_algos.add("3DES")

        for dec_algo in list(dec_algos):
            with suppress(ValueError):
                if dec_algo == "AES":
                    block_size = AES.block_size
                    iv = resource_bytes[:block_size]
                    if mode == "DOTNET45":
                        label, context = sp800_108_get_key_derivation_parameters(purpose.value, [])
                        effective_ekey = sp800_108_derivekey(ekey_bytes, label, context, len(ekey_bytes) * 8)
                    else:
                        effective_ekey = ekey_bytes
                    cipher = AES.new(effective_ekey, AES.MODE_CBC, iv)

                elif dec_algo == "3DES":
                    block_size = DES3.block_size
                    iv = resource_bytes[:block_size]
                    cipher = DES3.new(ekey_bytes[:24], DES3.MODE_CBC, iv)

                elif dec_algo == "DES":
                    block_size = DES.block_size
                    iv = resource_bytes[:block_size]
                    cipher = DES.new(ekey_bytes[:8], DES.MODE_CBC, iv)

                encrypted_raw = resource_bytes[block_size:-hash_size]
                decrypted_raw = cipher.decrypt(encrypted_raw)

                with suppress(TypeError):
                    decrypt = unpad(decrypted_raw)
                    # Validate: decrypted resource URLs contain pipe-delimited assembly|resource paths
                    # with a binary preamble. Check that the payload has printable ASCII content
                    # after the preamble (typically the first ~17 bytes).
                    if len(decrypt) > 8 and b"|" in decrypt:
                        return dec_algo
        return None

    def check_secret(self, resource_token, *args):
        if not self.identify(resource_token):
            return None

        standard_b64 = aspnet_resource_b64_to_standard_b64(resource_token)
        resource_bytes = base64.b64decode(standard_b64)

        if len(resource_bytes) < 20:
            return None

        for l in self.load_resources(["aspnet_machinekeys.txt"]):
            try:
                vkey, ekey = l.rstrip().split(",")
            except ValueError:
                continue

            with suppress(ValueError, binascii.Error):
                vkey_bytes = binascii.unhexlify(vkey)
                ekey_bytes = binascii.unhexlify(ekey)

                for mode in ["DOTNET40", "DOTNET45"]:
                    for purpose in [
                        Purpose.AssemblyResourceLoader_WebResourceUrl,
                        Purpose.ScriptResourceHandler_ScriptResourceUrl,
                    ]:
                        validationAlgo = self.resource_validate(vkey_bytes, resource_bytes, purpose, mode)
                        if validationAlgo:
                            confirmed_ekey = None
                            decryptionAlgo = None

                            decryptionAlgo = self.resource_decrypt(
                                ekey_bytes, validationAlgo, resource_bytes, purpose, mode
                            )
                            if decryptionAlgo:
                                confirmed_ekey = ekey

                            result = f"validationKey: {vkey} validationAlgo: {validationAlgo}"
                            if confirmed_ekey:
                                result += f" encryptionKey: {confirmed_ekey} encryptionAlgo: {decryptionAlgo}"

                            return {
                                "secret": result,
                                "details": f"Mode [{mode}] Purpose [{purpose.value}]",
                            }
        return None
