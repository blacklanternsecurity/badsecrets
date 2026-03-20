import os
import re
import base64
import binascii
import logging
from contextlib import suppress
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from badsecrets.base import BadsecretsActiveBase

log = logging.getLogger(__name__)

JAVA_SERIALIZATION_MAGIC = b"\xac\xed\x00\x05"

# Pre-serialized SimplePrincipalCollection (principal="admin", realm="org.vulhub.shirodemo.MainRealm_0").
# This deserializes successfully on any Shiro instance regardless of realm name — the realm string
# is just stored as a map key and doesn't get validated during deserialization.
_SERIALIZED_PRINCIPAL = base64.b64decode(
    "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhK"
    "AwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBzcgAXamF2YS51dGlsLkxpbmtlZEhhc2hN"
    "YXA0wE5cEGzA+wIAAVoAC2FjY2Vzc09yZGVyeHIAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2Fk"
    "RmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAADHcIAAAAEAAAAAF0ACBvcmcudnVsaHViLnNoaXJvZGVtby5NYWlu"
    "UmVhbG1fMHNyABdqYXZhLnV0aWwuTGlua2VkSGFzaFNldNhs11qV3SoeAgAAeHIAEWphdmEudXRpbC5IYXNoU2V0"
    "ukSFlZa4tzQDAAB4cHcMAAAAED9AAAAAAAABdAAFYWRtaW54eAB3AQFxAH4ABXg="
)


class Shiro_RememberMe_Key(BadsecretsActiveBase):
    # YARA prefilter: detect Shiro presence in headers + body
    yara_prefilter_rule = (
        "rule Shiro_RememberMe_Key_prefilter {"
        " strings:"
        '  $s1 = "rememberMe=deleteMe" nocase'
        '  $s2 = "rememberMe" nocase'
        '  $s3 = "org.apache.shiro" nocase'
        '  $s4 = "shiroLoginFailure" nocase'
        " condition: any of them"
        "}"
    )

    description = {
        "product": "Apache Shiro",
        "secret": "RememberMe AES Key",
        "severity": "CRITICAL",
    }

    DEFAULT_KEY = "kPH+bIxk5D2deZiIxcaaaA=="

    @staticmethod
    def encrypt_cbc(key_bytes, plaintext):
        """Encrypt plaintext with AES-CBC. Returns IV + ciphertext."""
        iv = os.urandom(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ct

    @staticmethod
    def encrypt_gcm(key_bytes, plaintext):
        """Encrypt plaintext with AES-GCM. Returns nonce + ciphertext + tag."""
        nonce = os.urandom(16)
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ct + tag

    @staticmethod
    def _has_delete_me(response):
        """Check if response contains rememberMe=deleteMe in Set-Cookie."""
        return any("rememberMe=deleteMe" in value for value in response.headers.get_list("set-cookie"))

    async def probe(self, url, custom_keys=None, **kwargs):
        """Probe for known Shiro rememberMe keys by sending crafted cookies.

        Strategy:
        1. Send garbage rememberMe cookie to confirm Shiro is present (expects deleteMe)
        2. For each candidate key, encrypt a SimplePrincipalCollection with AES-CBC then AES-GCM
        3. If response does NOT contain deleteMe, the key is correct
        """
        import httpx

        results = []
        base = re.match(r"(https?://[^/]+)", url)
        if not base:
            return results
        target_url = url

        # Build key list: default key first, then resource file keys, then custom keys
        keys_to_try = []
        try:
            for line in self.load_resources(["shiro_active_keys.txt"]):
                key_b64 = line.strip()
                if key_b64 and key_b64 not in keys_to_try:
                    keys_to_try.append(key_b64)
        except FileNotFoundError:
            pass
        # Ensure default key is first
        if self.DEFAULT_KEY not in keys_to_try:
            keys_to_try.insert(0, self.DEFAULT_KEY)
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
            # Step 1: Confirm Shiro is present by sending garbage cookie
            try:
                confirm_resp = await client.get(
                    target_url,
                    headers={"Cookie": "rememberMe=1"},
                    follow_redirects=True,
                )
                if not self._has_delete_me(confirm_resp):
                    log.debug(f"Shiro confirmation failed: no deleteMe in response from {target_url}")
                    return results
            except Exception as e:
                log.debug(f"Error confirming Shiro at {target_url}: {e}")
                return results

            # Step 2: Try each key
            for key_b64 in keys_to_try:
                with suppress(ValueError, binascii.Error):
                    key_bytes = base64.b64decode(key_b64)
                    if len(key_bytes) not in (16, 24, 32):
                        continue

                    # Try CBC mode first (Shiro < 1.4.2)
                    result = await self._try_key(client, target_url, key_bytes, key_b64, mode="CBC")
                    if result:
                        results.append(result)
                        continue

                    # Try GCM mode (Shiro >= 1.4.2)
                    result = await self._try_key(client, target_url, key_bytes, key_b64, mode="GCM")
                    if result:
                        results.append(result)

        finally:
            if should_close:
                await client.aclose()

        return results

    async def _try_key(self, client, url, key_bytes, key_b64, mode="CBC"):
        """Try a single key in the given mode. Returns result dict or None."""
        try:
            if mode == "CBC":
                raw = self.encrypt_cbc(key_bytes, _SERIALIZED_PRINCIPAL)
            else:
                raw = self.encrypt_gcm(key_bytes, _SERIALIZED_PRINCIPAL)

            cookie_value = base64.b64encode(raw).decode()

            response = await client.get(
                url,
                headers={"Cookie": f"rememberMe={cookie_value}"},
                follow_redirects=True,
            )

            if not self._has_delete_me(response):
                is_default = key_b64 == self.DEFAULT_KEY
                return {
                    "type": "SecretFound",
                    "product": url,
                    "secret": f"{'default' if is_default else key_b64} rememberMe key ({key_b64})",
                    "location": "active_probe",
                    "details": {
                        "key": key_b64,
                        "is_default_key": is_default,
                        "mode": mode,
                        "cve": "CVE-2016-4437",
                    },
                }
            else:
                log.debug(f"Key '{key_b64}' ({mode}) rejected by {url}")

        except Exception as e:
            log.debug(f"Error probing {url} with key '{key_b64}' ({mode}): {e}")

        return None
