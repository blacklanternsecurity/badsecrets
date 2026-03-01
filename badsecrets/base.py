import re
import os
import gzip
import base64
import hashlib
import binascii
import logging
import httpx
import yara
import badsecrets.errors
from abc import abstractmethod

log = logging.getLogger(__name__)

generic_base64_regex = re.compile(
    r"^(?:[A-Za-z0-9+\/]{4}){8,}(?:[A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}={2})$"
)


class BadsecretsBase:
    identify_regex = re.compile(r".+")
    yara_carve_pattern = None
    yara_carve_rule = None  # Full custom YARA rule string for compound carve conditions
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
    validate_carve = True
    carve_locations = ("headers", "cookies", "body")

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
    def get_description(cls):
        return cls.description

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
                for line in r.readlines():
                    if len(line) > 0:
                        yield line

    def carve_to_check_secret(self, s, **kwargs):
        if s.groups():
            r = self.check_secret(s.groups()[0])
            return r

    @abstractmethod
    def carve_regex(self):
        return None

    def carve(self, body=None, cookies=None, headers=None, httpx_response=None, _yara_body_hit=None, **kwargs):
        results = []

        if not body and not cookies and not headers and httpx_response is None:
            raise badsecrets.errors.CarveException("Either body/headers/cookies or httpx_response required")

        if httpx_response is not None:
            if body or cookies or headers:
                raise badsecrets.errors.CarveException("Body/cookies/headers and httpx_response cannot both be set")

            if isinstance(httpx_response, httpx.Response):
                if not cookies:
                    cookies = dict(httpx_response.cookies)
                if not headers:
                    headers = httpx_response.headers
                if not body and hasattr(httpx_response, "text"):
                    body = httpx_response.text
            else:
                raise badsecrets.errors.CarveException("httpx_response must be an httpx.Response object")

        if cookies and "cookies" in self.carve_locations:
            if not isinstance(cookies, dict):
                raise badsecrets.errors.CarveException("Header argument must be type dict")
            for _k, v in cookies.items():
                r = self.check_secret(v)
                if r:
                    r["type"] = "SecretFound"
                    r["product"] = v
                    r["location"] = "cookies"
                    results.append(r)

        if headers and "headers" in self.carve_locations:
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
                        if not self.validate_carve or self.identify(s.groups()[0]):
                            r = self.carve_to_check_secret(s)
                            if r:
                                r["type"] = "SecretFound"
                            # the carve regex hit but no secret was found
                            else:
                                r = {"type": "IdentifyOnly"}
                                r["hashcat"] = self.get_hashcat_commands(s.groups()[0])
                            if "product" not in r:
                                r["product"] = self.get_product_from_carve(s)
                            r["location"] = "headers"
                            results.append(r)

        if body and "body" in self.carve_locations:
            if not isinstance(body, str):
                raise badsecrets.errors.CarveException("Body argument must be type str")
            if _yara_body_hit is None:
                _yara_body_hit = type(self).__name__ in yara_carve_scan(body)
            if _yara_body_hit:
                results.extend(self._carve_body(body, cookies, headers, **kwargs))

        for r in results:
            r["description"] = self.get_description()

        # Don't report an IdentifyOnly result if we have a SecretFound result for the same 'product'
        secret_found_results = {d["product"] for d in results if d["type"] == "SecretFound"}
        return [d for d in results if not (d["type"] == "IdentifyOnly" and d["product"] in secret_found_results)]

    def _carve_body(self, body, cookies, headers, **kwargs):
        """Extract secrets from HTML body text. Override in subclasses for custom body carving."""
        results = []
        if self.carve_regex():
            s = re.search(self.carve_regex(), body)
            if s:
                if not self.validate_carve or self.identify(s.groups()[0]):
                    r = self.carve_to_check_secret(
                        s, url=kwargs.get("url"), body=body, cookies=cookies, headers=headers
                    )
                    if r:
                        r["type"] = "SecretFound"
                    else:
                        r = {"type": "IdentifyOnly"}
                        r["hashcat"] = self.get_hashcat_commands(s.groups()[0])
                    if "product" not in r:
                        r["product"] = self.get_product_from_carve(s)
                    r["location"] = "body"
                    results.append(r)
        return results

    @classmethod
    def identify(cls, product):
        if re.match(cls.identify_regex, product):
            return True
        return False

    @staticmethod
    def search_dict(d, query):
        items = [key for key, value in d.items() if query == value]
        if items:
            return items


class BadsecretsActiveBase(BadsecretsBase):
    """Base class for active probe modules that send crafted requests."""

    active = True
    # YARA pattern to pre-filter HTTP responses (decides if probe should fire)
    yara_prefilter_pattern = None
    yara_prefilter_rule = None  # Full custom YARA rule for compound conditions
    description = {"product": "Undefined", "secret": "Undefined", "severity": "Undefined"}

    def __init__(self, custom_resource=None, http_client=None, **kwargs):
        super().__init__(custom_resource=custom_resource, **kwargs)
        self.http_client = http_client

    @abstractmethod
    async def probe(self, url, **kwargs):
        """Send active probe to target URL. Returns list of result dicts or empty list."""
        raise NotImplementedError

    # Active modules don't use passive carving — stub out abstract methods
    def check_secret(self, secret):
        return None

    def carve_regex(self):
        return None


def _all_subclasses(cls):
    """Recursively collect all subclasses of cls."""
    result = []
    for sub in cls.__subclasses__():
        result.append(sub)
        result.extend(_all_subclasses(sub))
    return result


def _passive_subclasses():
    """Return all passive (non-active) subclasses of BadsecretsBase."""
    return [cls for cls in _all_subclasses(BadsecretsBase) if not issubclass(cls, BadsecretsActiveBase)]


def _active_subclasses():
    """Return all active subclasses."""
    return list(_all_subclasses(BadsecretsActiveBase))


_compiled_yara_carve_rules = None


def _compile_yara_carve_rules():
    """Compile YARA rules from all loaded modules' yara_carve_pattern/yara_carve_rule attributes."""
    global _compiled_yara_carve_rules
    rules_parts = []
    for cls in _passive_subclasses():
        custom_rule = getattr(cls, "yara_carve_rule", None)
        if custom_rule:
            rules_parts.append(custom_rule)
        else:
            pattern = getattr(cls, "yara_carve_pattern", None)
            if pattern:
                rule = f"rule {cls.__name__}_carve {{ strings: $carve = /{pattern}/ condition: $carve }}"
                rules_parts.append(rule)

    if rules_parts:
        source = "\n".join(rules_parts)
        _compiled_yara_carve_rules = yara.compile(source=source)
    return _compiled_yara_carve_rules


def get_yara_carve_rules():
    """Get compiled YARA carve rules, compiling on first call."""
    global _compiled_yara_carve_rules
    if _compiled_yara_carve_rules is None:
        _compile_yara_carve_rules()
    return _compiled_yara_carve_rules


def yara_carve_scan(text):
    """Scan text against all YARA carve rules simultaneously.

    Returns dict of {module_name: [{'offset': int, 'data': str}, ...]}
    """
    rules = get_yara_carve_rules()
    if not rules:
        return {}

    data = text.encode("utf-8") if isinstance(text, str) else text
    matches = rules.match(data=data)

    result = {}
    for match in matches:
        # Strip _carve suffix from rule name to get module name
        module_name = match.rule.removesuffix("_carve")
        instances = []
        for string_match in match.strings:
            for instance in string_match.instances:
                instances.append(
                    {
                        "offset": instance.offset,
                        "data": instance.matched_data.decode("utf-8", errors="replace"),
                    }
                )
        result[module_name] = instances
    return result


# Active YARA prefilter system

_compiled_yara_prefilter_rules = None


def _compile_yara_prefilter_rules():
    """Compile YARA rules from active modules' yara_prefilter_pattern/rule attributes."""
    global _compiled_yara_prefilter_rules
    rules_parts = []
    for cls in _active_subclasses():
        custom_rule = getattr(cls, "yara_prefilter_rule", None)
        if custom_rule:
            rules_parts.append(custom_rule)
        else:
            pattern = getattr(cls, "yara_prefilter_pattern", None)
            if pattern:
                rule = f"rule {cls.__name__}_prefilter {{ strings: $prefilter = /{pattern}/ nocase condition: $prefilter }}"
                rules_parts.append(rule)
    if rules_parts:
        source = "\n".join(rules_parts)
        _compiled_yara_prefilter_rules = yara.compile(source=source)
    return _compiled_yara_prefilter_rules


def get_yara_prefilter_rules():
    global _compiled_yara_prefilter_rules
    if _compiled_yara_prefilter_rules is None:
        _compile_yara_prefilter_rules()
    return _compiled_yara_prefilter_rules


def yara_prefilter_scan(text):
    """Scan text against active module prefilter YARA rules.
    Returns dict of {module_name: [{'offset': int, 'data': str}, ...]}
    """
    rules = get_yara_prefilter_rules()
    if not rules:
        return {}
    data = text.encode("utf-8") if isinstance(text, str) else text
    matches = rules.match(data=data)
    result = {}
    for match in matches:
        module_name = match.rule.removesuffix("_prefilter")
        instances = []
        for string_match in match.strings:
            for instance in string_match.instances:
                instances.append(
                    {
                        "offset": instance.offset,
                        "data": instance.matched_data.decode("utf-8", errors="replace"),
                    }
                )
        result[module_name] = instances
    return result


def hashcat_all_modules(product, detecting_module=None, *args):
    hashcat_candidates = []
    for m in _passive_subclasses():
        if detecting_module == m.__name__ or detecting_module is None:
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
    for m in _passive_subclasses():
        x = m(custom_resource=kwargs.get("custom_resource"))
        r = x.check_secret(*args[0 : x.check_secret_args])
        if r:
            r["detecting_module"] = m.__name__
            r["description"] = x.get_description()

            # allow the module to provide an amended product, if needed
            if "product" not in r:
                r["product"] = args[0]
            r["location"] = "manual"
            return r
    return None


def carve_all_modules(**kwargs):
    results = []

    # Determine body text for YARA pre-scanning
    scan_body = kwargs.get("body")
    httpx_resp = kwargs.get("httpx_response")
    if not scan_body and httpx_resp is not None and isinstance(httpx_resp, httpx.Response):
        scan_body = getattr(httpx_resp, "text", None)

    # Run YARA pre-filter on body text (single pass, all rules)
    yara_body_matches = set()
    if scan_body:
        yara_results = yara_carve_scan(scan_body)
        yara_body_matches = set(yara_results.keys())

    for m in _passive_subclasses():
        x = m(custom_resource=kwargs.get("custom_resource"))

        yara_hit = m.__name__ in yara_body_matches
        r_list = x.carve(_yara_body_hit=yara_hit, **kwargs)
        if len(r_list) > 0:
            for r in r_list:
                r["detecting_module"] = m.__name__
                results.append(r)
    if results:
        return results


async def probe_all_modules(httpx_response=None, url=None, body=None, active_keys_map=None, **kwargs):
    """Run active probes against modules whose YARA prefilter matches the response.

    Args:
        httpx_response: The passive HTTP response to prefilter against
        url: Target URL for active probes (extracted from httpx_response if not provided)
        body: Response body text (extracted from httpx_response if not provided)
        active_keys_map: Dict of {module_class_name: [key1, key2, ...]} for per-module custom keys
    Returns:
        List of result dicts from active probes, or empty list
    """
    results = []
    if active_keys_map is None:
        active_keys_map = {}

    # Extract body for prefilter scanning
    scan_body = body
    if not scan_body and httpx_response is not None:
        scan_body = getattr(httpx_response, "text", None)
    if not scan_body:
        return results

    # Extract URL from response if not provided
    if not url and httpx_response is not None:
        url = str(httpx_response.url)

    # Run YARA prefilter
    prefilter_matches = yara_prefilter_scan(scan_body)
    if not prefilter_matches:
        return results

    # Fire matching active modules
    for cls in _active_subclasses():
        if cls.__name__ in prefilter_matches:
            custom_keys = active_keys_map.get(cls.__name__, [])
            module = cls()
            try:
                probe_results = await module.probe(url, custom_keys=custom_keys, **kwargs)
            except Exception as e:
                log.debug(f"Error running active probe {cls.__name__}: {e}")
                continue
            if probe_results:
                for r in probe_results:
                    r["detecting_module"] = cls.__name__
                    r["description"] = cls.get_description()
                    results.append(r)
    return results
