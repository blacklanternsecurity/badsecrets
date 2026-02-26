import re
import hmac
import struct
import base64
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from contextlib import suppress
from urllib.parse import urlsplit
from badsecrets.helpers import (
    Purpose,
    Viewstate_Helpers,
    isolate_app_process,
    unpad,
    sp800_108_derivekey,
    sp800_108_get_key_derivation_parameters,
    viewstate_signature_length,
)
from badsecrets.base import BadsecretsBase


class ASPNET_Viewstate(BadsecretsBase):
    check_secret_args = 3
    # Lower minimum than generic_base64_regex (8 groups) to match short MAC_DISABLED viewstates
    identify_regex = re.compile(
        r"^(?:[A-Za-z0-9+\/]{4}){4,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
    )
    yara_carve_rule = (
        "rule ASPNET_Viewstate_carve {"
        ' strings: $vs = "__VIEWSTATE"'
        " condition: $vs }"
    )
    description = {"product": "ASP.NET Viewstate", "secret": "ASP.NET MachineKey", "severity": "CRITICAL"}

    # Regex for normal viewstate (non-split)
    _carve_re_normal = re.compile(
        r'<input[^>]+__VIEWSTATE"[^>]*\svalue="([^"]+)"'
        r"[\S\s]+?"
        r'<input[^>]+?__VIEWSTATEGENERATOR"[^>]*\svalue="(\w+)"'
    )

    # Regex for split viewstate: capture field count, then we reassemble in carve_to_check_secret
    _carve_re_split = re.compile(
        r'<input[^>]+__VIEWSTATEFIELDCOUNT"[^>]*\svalue="(\d+)"'
        r"[\S\s]+?"
        r'<input[^>]+__VIEWSTATEGENERATOR"[^>]*\svalue="(\w+)"'
    )

    # Regex to extract individual __VIEWSTATE and __VIEWSTATE{N} fields
    _carve_re_viewstate_fields = re.compile(r'<input[^>]+__VIEWSTATE(\d*)"[^>]*\svalue="([^"]*)"')

    # Regex for viewstate without generator (e.g. MobilePage)
    _carve_re_no_generator = re.compile(r'<input[^>]+__VIEWSTATE"[^>]*\svalue="([^"]+)"')

    # Regex for __VIEWSTATE_KEY hidden field
    _carve_re_viewstate_key = re.compile(r'<input[^>]+__VIEWSTATE_KEY"[^>]*\svalue="([^"]*)"')

    # Pre-compiled regexes for resolve_args
    _url_pattern = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    _generator_pattern = re.compile(r"^[A-F0-9]{8}$")

    def carve_regex(self):
        return self._carve_re_normal

    def carve(self, body=None, cookies=None, headers=None, httpx_response=None, _yara_body_hit=None, **kwargs):
        """Override carve to handle split viewstate detection before the normal regex path."""
        results = []

        if not body and not cookies and not headers and httpx_response is None:
            from badsecrets.errors import CarveException

            raise CarveException("Either body/headers/cookies or httpx_response required")

        if httpx_response is not None:
            if body or cookies or headers:
                from badsecrets.errors import CarveException

                raise CarveException("Body/cookies/headers and httpx_response cannot both be set")

            import httpx

            if isinstance(httpx_response, httpx.Response):
                if not cookies:
                    cookies = dict(httpx_response.cookies)
                if not headers:
                    headers = httpx_response.headers
                if not body and hasattr(httpx_response, "text"):
                    body = httpx_response.text
            else:
                from badsecrets.errors import CarveException

                raise CarveException("httpx_response must be an httpx.Response object")

        # Check cookies and headers via parent class logic
        if cookies:
            if type(cookies) != dict:
                from badsecrets.errors import CarveException

                raise CarveException("Header argument must be type dict")
            for k, v in cookies.items():
                r = self.check_secret(v)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = v
                    r["location"] = "cookies"
                    results.append(r)

        if headers:
            for header_value in headers.values():
                r = self.check_secret(header_value)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = header_value
                    r["location"] = "headers"
                    results.append(r)
                elif self.carve_regex():
                    s = re.search(self.carve_regex(), header_value)
                    if s:
                        if not self.validate_carve or self.identify(s.groups()[0]):
                            r = self.carve_to_check_secret(
                                s, url=kwargs.get("url", None), body=body, cookies=cookies, headers=headers
                            )
                            if r:
                                r["type"] = "SecretFound"
                            else:
                                r = {"type": "IdentifyOnly"}
                                r["hashcat"] = self.get_hashcat_commands(s.groups()[0])
                            if "product" not in r.keys():
                                r["product"] = self.get_product_from_carve(s)
                            r["location"] = "headers"
                            results.append(r)

        if body:
            if type(body) != str:
                from badsecrets.errors import CarveException

                raise CarveException("Body argument must be type str")

            from badsecrets.base import yara_carve_scan

            if _yara_body_hit is None:
                _yara_body_hit = type(self).__name__ in yara_carve_scan(body)

            if _yara_body_hit:
                # Try split viewstate first
                split_match = re.search(self._carve_re_split, body)
                if split_match:
                    viewstate, generator = self._reassemble_split_viewstate(body, split_match)
                    if viewstate and generator:
                        # Build a synthetic regex match for carve_to_check_secret
                        r = self._carve_to_check_secret_direct(
                            viewstate,
                            generator,
                            url=kwargs.get("url", None),
                            body=body,
                            cookies=cookies,
                            headers=headers,
                        )
                        if r:
                            r["type"] = "SecretFound"
                        else:
                            r = {"type": "IdentifyOnly"}
                            r["hashcat"] = self.get_hashcat_commands(viewstate)
                        if "product" not in r:
                            r["product"] = viewstate
                        r["location"] = "body"
                        results.append(r)
                # Try normal viewstate regex (requires __VIEWSTATEGENERATOR)
                elif self.carve_regex():
                    s = re.search(self.carve_regex(), body)
                    if s:
                        if not self.validate_carve or self.identify(s.groups()[0]):
                            r = self.carve_to_check_secret(
                                s, url=kwargs.get("url", None), body=body, cookies=cookies, headers=headers
                            )
                            if r:
                                r["type"] = "SecretFound"
                            else:
                                r = {"type": "IdentifyOnly"}
                                r["hashcat"] = self.get_hashcat_commands(s.groups()[0])
                            if "product" not in r.keys():
                                r["product"] = self.get_product_from_carve(s)
                            r["location"] = "body"
                            results.append(r)
                    # Fallback: viewstate without generator (e.g. MobilePage)
                    elif not results:
                        s = re.search(self._carve_re_no_generator, body)
                        if s:
                            viewstate = s.group(1)
                            if not self.validate_carve or self.identify(viewstate):
                                r = self._carve_no_generator(
                                    viewstate,
                                    url=kwargs.get("url", None),
                                    body=body,
                                    cookies=cookies,
                                    headers=headers,
                                )
                                if r:
                                    r["type"] = "SecretFound"
                                else:
                                    r = {"type": "IdentifyOnly"}
                                    r["hashcat"] = self.get_hashcat_commands(viewstate)
                                if "product" not in r:
                                    r["product"] = viewstate
                                r["location"] = "body"
                                results.append(r)

        for r in results:
            r["description"] = self.get_description()

        secret_found_results = set(d["product"] for d in results if d["type"] == "SecretFound")
        return [d for d in results if not (d["type"] == "IdentifyOnly" and d["product"] in secret_found_results)]

    def _reassemble_split_viewstate(self, body, split_match):
        """Reassemble split viewstate from __VIEWSTATEFIELDCOUNT and __VIEWSTATE{N} fields."""
        try:
            field_count = int(split_match.group(1))
        except (ValueError, IndexError):
            return None, None

        generator = split_match.group(2)

        # Extract all __VIEWSTATE fields
        fields = {}
        for m in self._carve_re_viewstate_fields.finditer(body):
            suffix = m.group(1)
            value = m.group(2)
            idx = int(suffix) if suffix else 0
            fields[idx] = value

        # Reassemble: __VIEWSTATE (idx 0) + __VIEWSTATE1 + ... + __VIEWSTATE{N-1}
        parts = []
        for i in range(field_count):
            if i not in fields:
                return None, None
            parts.append(fields[i])

        return "".join(parts), generator

    def carve_to_check_secret(self, s, url=None, **kwargs):
        if len(s.groups()) == 2:
            viewstate = s.groups()[0]
            generator = s.groups()[1]
            return self._carve_to_check_secret_direct(viewstate, generator, url=url, **kwargs)

    def _carve_to_check_secret_direct(self, viewstate, generator, url=None, **kwargs):
        """Core carve logic: try multiple ViewStateUserKey candidates."""
        # Build candidate list for ViewStateUserKey
        userkey_candidates = [None, "", "mono"]

        cookies = kwargs.get("cookies")
        if cookies and hasattr(cookies, "get"):
            possible_userkey_cookies = [
                "ASP.NET_SessionId",
                "__AntiXsrfToken",
                "ASPSESSIONID",
                "__AntiXsrfUsername",
            ]
            for cookie_name in possible_userkey_cookies:
                if cookie_name in cookies:
                    val = cookies.get(cookie_name)
                    if val and val not in userkey_candidates:
                        userkey_candidates.append(val)
            # Check for ASP.NET session ID format cookies (24 lowercase alphanumeric)
            for cookie_name, cookie_value in cookies.items():
                if cookie_value and re.match(r"^[a-z0-5]{24}$", cookie_value):
                    if cookie_value not in userkey_candidates:
                        userkey_candidates.append(cookie_value)

        # Check for __VIEWSTATE_KEY hidden field in body
        body = kwargs.get("body")
        if body:
            vsk_match = self._carve_re_viewstate_key.search(body)
            if vsk_match:
                vsk_value = vsk_match.group(1)
                if vsk_value and vsk_value not in userkey_candidates:
                    userkey_candidates.append(vsk_value)

        # Try each candidate
        for userkey in userkey_candidates:
            if userkey is None:
                r = self.check_secret(viewstate, generator, url)
            else:
                r = self.check_secret(viewstate, generator, url, userkey)
            if r:
                return r
        return None

    def _carve_no_generator(self, viewstate, url=None, **kwargs):
        """Handle viewstate carve when no __VIEWSTATEGENERATOR is present (e.g. MobilePage).

        Computes generator candidates from the URL and tries each one.
        """
        generator_candidates = self._compute_generators_from_url(url) if url else []
        # Also try the default "00000000" as fallback
        if "00000000" not in generator_candidates:
            generator_candidates.append("00000000")

        for gen_hex in generator_candidates:
            r = self._carve_to_check_secret_direct(viewstate, gen_hex, url=url, **kwargs)
            if r:
                return r
        return None

    @staticmethod
    def _compute_generators_from_url(url):
        """Compute all possible __VIEWSTATEGENERATOR hex values from a URL's path/apppath combos."""
        from badsecrets.helpers import Viewstate_Helpers, DOTNET_SORT_KEY_DB

        vh = Viewstate_Helpers.__new__(Viewstate_Helpers)
        vh.url = Viewstate_Helpers._normalize_url(url)
        vh.db = DOTNET_SORT_KEY_DB
        path, apppaths = vh._extract_path_and_apppaths(vh.url)

        generators = []
        seen = set()
        for apppath in apppaths:
            gen = vh.calculate_generator_value(path, apppath)
            if gen not in seen:
                seen.add(gen)
                generators.append(gen)
        return generators

    @staticmethod
    def valid_preamble(sourcebytes):
        if sourcebytes[0:2] == b"\xff\x01":
            return True
        return False

    def viewstate_decrypt(self, ekey_bytes, hash_alg, viewstate_bytes, specific_purposes, mode):
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
                derived_ekey = ekey_bytes
                if dec_algo == "AES":
                    block_size = AES.block_size
                    iv = viewstate_bytes[0:block_size]
                    if mode == "DOTNET45" and specific_purposes:
                        label, context = sp800_108_get_key_derivation_parameters(
                            Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value,
                            specific_purposes,
                        )
                        derived_ekey = sp800_108_derivekey(ekey_bytes, label, context, (len(ekey_bytes) * 8))
                    cipher = AES.new(derived_ekey, AES.MODE_CBC, iv)
                    blockpadlen_raw = len(derived_ekey) % AES.block_size
                    if blockpadlen_raw == 0:
                        blockpadlen = block_size
                    else:
                        blockpadlen = blockpadlen_raw

                elif dec_algo == "3DES":
                    block_size = DES3.block_size
                    iv = viewstate_bytes[0:block_size]
                    cipher = DES3.new(derived_ekey[:24], DES3.MODE_CBC, iv)
                    blockpadlen = 16

                elif dec_algo == "DES":
                    block_size = DES.block_size
                    iv = viewstate_bytes[0:block_size]
                    cipher = DES.new(derived_ekey[:8], DES.MODE_CBC, iv)
                    blockpadlen = 0

                encrypted_raw = viewstate_bytes[block_size:-hash_size]
                decrypted_raw = cipher.decrypt(encrypted_raw)

                with suppress(TypeError):
                    if mode == "DOTNET45":
                        decrypt = unpad(decrypted_raw)
                    else:
                        decrypt = unpad(decrypted_raw[blockpadlen:])

                    if self.valid_preamble(decrypt):
                        return dec_algo
                    else:
                        continue

    def viewstate_validate(
        self,
        vkey_bytes,
        encrypted,
        viewstate_bytes,
        generator,
        specific_purposes,
        mode,
        viewstate_userkey=None,
        signature_len=None,
    ):
        original_vkey_bytes = vkey_bytes

        if encrypted:
            candidate_hash_algs = list(self.hash_sizes.keys())
        else:
            candidate_hash_algs = self.search_dict(self.hash_sizes, signature_len)

        modifier_bytes = b"\x00" * 4
        if viewstate_userkey and viewstate_userkey.strip():
            modifier_bytes += viewstate_userkey.encode("utf-16le")
        for hash_alg in candidate_hash_algs:
            vkey_bytes = original_vkey_bytes
            viewstate_data = viewstate_bytes[: -self.hash_sizes[hash_alg]]
            signature = viewstate_bytes[-self.hash_sizes[hash_alg] :]
            if hash_alg == "MD5":
                if not encrypted:
                    md5_bytes = viewstate_data + vkey_bytes + modifier_bytes
                else:
                    md5_bytes = viewstate_data + vkey_bytes
                h = hashlib.md5(md5_bytes)
            else:
                vs_data_bytes = viewstate_data
                if not encrypted:
                    vs_data_bytes += generator
                    vs_data_bytes += modifier_bytes[4:]
                if mode == "DOTNET45" and specific_purposes:
                    label, context = sp800_108_get_key_derivation_parameters(
                        Purpose.WebForms_HiddenFieldPageStatePersister_ClientState.value,
                        specific_purposes,
                    )
                    vkey_bytes = sp800_108_derivekey(vkey_bytes, label, context, (len(vkey_bytes) * 8))
                h = hmac.new(
                    vkey_bytes,
                    vs_data_bytes,
                    self.hash_algs[hash_alg],
                )

            if signature == h.digest():
                return hash_alg

        return None

    def resolve_args(self, args):
        url = None
        viewstate_userkey = None
        generator = "0000"

        for arg in args:
            if arg:
                if self._generator_pattern.match(arg):
                    generator = arg
                elif self._url_pattern.match(arg):
                    url = arg
                else:
                    viewstate_userkey = arg
        # Remove query string from the URL, if any
        if url:
            url = urlsplit(url)._replace(query="").geturl()
        return generator, url, viewstate_userkey

    def check_secret(self, viewstate_B64, *args):
        generator_hex, url, viewstate_userkey = self.resolve_args(args)

        # Try to decode for MAC_DISABLED check (before identify, since MAC_DISABLED viewstates can be short)
        try:
            viewstate_bytes = base64.b64decode(viewstate_B64)
        except Exception:
            return None

        signature_len = None
        if self.valid_preamble(viewstate_bytes):
            encrypted = False
            sig_len = viewstate_signature_length(viewstate_bytes)
            if sig_len is None:
                return None

            # Passive MAC_DISABLED detection: viewstate decodes but has no HMAC signature
            if sig_len == 0:
                return {
                    "secret": "MAC is disabled - no secret needed, use LosFormatter from YSoSerial.Net",
                    "details": "MAC_DISABLED",
                }
            signature_len = sig_len
        else:
            encrypted = True

        # For key-search path, require minimum base64 length
        if not self.identify(viewstate_B64):
            return None

        generator = struct.pack("<I", int(generator_hex, 16))

        # Set up Viewstate_Helpers for purpose computation
        viewstate_helpers = None
        dotnet45_purposes = [None]
        dotnet40_hashcodes = []
        if url:
            viewstate_helpers = Viewstate_Helpers(url, generator_hex)
            dotnet45_purposes = viewstate_helpers.get_all_specific_purposes()
            dotnet40_hashcodes = viewstate_helpers.get_apppaths_hashcodes()

        for line in self.load_resources(["aspnet_machinekeys.txt"]):
            try:
                vkey, ekey = line.rstrip().split(",")
            except ValueError:
                continue
            with suppress(ValueError):
                confirmed_ekey = None
                decryptionAlgo = None

                for mode in ["DOTNET40", "DOTNET45"]:
                    all_purposes = dotnet45_purposes if mode == "DOTNET45" and viewstate_helpers else [None]

                    for specific_purposes in all_purposes:
                        vkey_hex_to_use = vkey

                        # IsolateApps support for DOTNET40
                        vkey_variants = [vkey_hex_to_use]
                        if mode == "DOTNET40" and dotnet40_hashcodes:
                            for hashcode in dotnet40_hashcodes:
                                isolated = isolate_app_process(vkey_hex_to_use, hashcode)
                                if isolated:
                                    vkey_variants.append(
                                        isolated.decode() if isinstance(isolated, bytes) else isolated
                                    )

                        for vk in vkey_variants:
                            validationAlgo = self.viewstate_validate(
                                binascii.unhexlify(vk),
                                encrypted,
                                viewstate_bytes,
                                generator,
                                specific_purposes,
                                mode,
                                viewstate_userkey,
                                signature_len,
                            )
                            if validationAlgo:
                                if encrypted:
                                    with suppress(binascii.Error):
                                        ekey_bytes = binascii.unhexlify(ekey)
                                        decryptionAlgo = self.viewstate_decrypt(
                                            ekey_bytes, validationAlgo, viewstate_bytes, specific_purposes, mode
                                        )
                                        if decryptionAlgo:
                                            confirmed_ekey = ekey

                                result = f"validationKey: {vk} validationAlgo: {validationAlgo}"
                                if confirmed_ekey:
                                    result += f" encryptionKey: {confirmed_ekey} encryptionAlgo: {decryptionAlgo}"

                                product_string = f"Viewstate: {viewstate_B64}"
                                if generator != b"\x00\x00\x00\x00":
                                    product_string += f" Generator: {generator[::-1].hex().upper()}"
                                if viewstate_userkey:
                                    product_string += f" ViewStateUserKey: {viewstate_userkey}"
                                return {"secret": result, "product": product_string, "details": f"Mode [{mode}]"}
        return None
