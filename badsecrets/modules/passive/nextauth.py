import re
import json
from badsecrets.base import BadsecretsBase
from badsecrets.helpers import b64url_decode, parse_jwe_compact, hkdf_sha256, jwe_decrypt

# NextAuth (v4) derives with an empty salt and this info string; v4 is the only variant that emits
# A256GCM.
V4_INFO = "NextAuth.js Generated Encryption Key"

# Auth.js (v5) uses the session-cookie name as the HKDF salt and interpolates it into the info
# string. check_secret() only receives the cookie value, not its name, so we try each default
# name; custom cookie names are not covered. v5 always emits A256CBC-HS512.
V5_COOKIE_NAMES = ("authjs.session-token", "__Secure-authjs.session-token")

# (salt, info, key_length) derivations, precomputed once since the info strings never change.
_GCM_DERIVATIONS = ((b"", V4_INFO, 32),)
_CBC_DERIVATIONS = tuple((name.encode(), f"Auth.js Generated Encryption Key ({name})", 64) for name in V5_COOKIE_NAMES)
# Auth.js v5 hardcodes enc=A256CBC-HS512 on encode, so a cookie-name-salt + A256GCM token cannot be
# produced without patching Auth.js. A256GCM is therefore always v4 (empty salt) — there is no real
# v5-GCM combination to try.
_DERIVATIONS_BY_ENC = {"A256GCM": _GCM_DERIVATIONS, "A256CBC-HS512": _CBC_DERIVATIONS}


class NextAuth(BadsecretsBase):
    # A `dir` JWE has an empty encrypted-key segment, so the token is `header..iv.ct.tag`. The
    # double dot is the tell that separates it from a 3-segment signed JWT.
    identify_regex = re.compile(r"^eyJ[\w-]+\.\.[\w-]+\.[\w-]+\.[\w-]+$")
    description = {
        "product": "NextAuth.js / Auth.js Session Token",
        "secret": "NEXTAUTH_SECRET / AUTH_SECRET",
        "severity": "HIGH",
    }
    carve_locations = ("cookies",)

    def carve(self, body=None, cookies=None, headers=None, http_response=None, **kwargs):
        # NextAuth splits large session tokens across `<name>.0`, `<name>.1`, ... Reassemble those
        # chunks before the normal carve so the full JWE is seen as one value.
        if cookies:
            cookies = self._reassemble_chunks(cookies)
        return super().carve(body=body, cookies=cookies, headers=headers, http_response=http_response, **kwargs)

    @staticmethod
    def _reassemble_chunks(cookies):
        chunk_regex = re.compile(r"^(?P<base>.*session-token)\.(?P<idx>\d+)$")
        chunks = {}
        result = {}
        for name, value in cookies.items():
            match = chunk_regex.match(name)
            if match:
                chunks.setdefault(match.group("base"), {})[int(match.group("idx"))] = value
            else:
                result[name] = value
        for base, parts in chunks.items():
            result[base] = "".join(parts[i] for i in sorted(parts))
        return result

    def _parse_token(self, token):
        # Everything here is secret-independent, so check_secret() does it once rather than per
        # candidate. Returns (protected_b64, enc, iv, ciphertext, tag, derivations) or None.
        parsed = parse_jwe_compact(token)
        if not parsed:
            return None
        protected_b64, _, iv_b64, ct_b64, tag_b64 = parsed
        try:
            header = json.loads(b64url_decode(protected_b64))
            iv = b64url_decode(iv_b64)
            ciphertext = b64url_decode(ct_b64)
            tag = b64url_decode(tag_b64)
        except (ValueError, json.JSONDecodeError):
            return None
        if header.get("alg") != "dir":
            return None
        derivations = _DERIVATIONS_BY_ENC.get(header.get("enc"))
        if not derivations:
            return None
        return protected_b64, header["enc"], iv, ciphertext, tag, derivations

    def check_secret(self, token):
        if not self.identify(token):
            return None
        parsed = self._parse_token(token)
        if not parsed:
            return None
        protected_b64, enc, iv, ciphertext, tag, derivations = parsed
        for l in self.load_resources(["nextauth_secrets.txt", "top_250000_passwords.txt"]):
            secret = l.strip()
            if not secret:
                continue
            for salt, info, keylen in derivations:
                cek = hkdf_sha256(secret, salt, info, keylen)
                plaintext = jwe_decrypt(protected_b64, enc, cek, iv, ciphertext, tag)
                if plaintext is not None:
                    try:
                        session = json.loads(plaintext)
                    except (ValueError, json.JSONDecodeError):
                        session = plaintext.decode(errors="replace")
                    return {"secret": secret, "details": {"session": session, "enc": enc}}
        return None
