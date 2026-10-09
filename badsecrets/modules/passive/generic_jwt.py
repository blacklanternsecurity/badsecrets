import re
import logging
import warnings
import jwt as j
import json
import base64
from jwt.algorithms import get_default_algorithms
from badsecrets.base import BadsecretsBase

log = logging.getLogger(__name__)

# XMLDSIG Translation Table

XMLDSIG_table = {
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256": "HS256",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384": "HS384",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512": "HS512",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "RS256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "RS384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "RS512",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "ES256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": "ES384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": "ES512",
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": "PS256",
    "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": "PS384",
    "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": "PS512",
}


def _xmldsig_decoder():
    """A pyjwt instance that accepts the XMLDSIG URIs as algorithm names.

    Tokens that spell "alg" as a URI are signed over that header, so the
    signature only checks out against the token as it was issued. Teaching
    pyjwt the extra names lets us verify the original bytes; rewriting the
    header to the JWS short name would change the signing input and never
    match. The instance is private so that registering these names cannot
    affect anything else in the process that imports pyjwt.
    """
    decoder = j.PyJWT()
    algorithms = get_default_algorithms()
    for uri, name in XMLDSIG_table.items():
        if name in algorithms:
            decoder._jws.register_algorithm(uri, algorithms[name])
    return decoder


xmldsig_decoder = _xmldsig_decoder()


class Generic_JWT(BadsecretsBase):
    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")
    yara_carve_pattern = r"eyJ[\w\-]+\.[\w\-]+\.[\w\-]+"
    description = {"product": "JSON Web Token (JWT)", "secret": "HMAC/RSA Key", "severity": "HIGH"}

    @staticmethod
    def swap_algorithm(jwt, headers, algorithm):
        header = {**headers, "alg": algorithm}
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        )
        _, payload, signature = jwt.split(".")
        new_jwt = f"{header_encoded}.{payload}.{signature}"
        return new_jwt

    def carve_regex(self):
        return re.compile(r"(eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*)")

    def jwtVerify(self, JWT, key, algorithm):
        decoder = xmldsig_decoder if algorithm in XMLDSIG_table else j
        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=j.warnings.InsecureKeyLengthWarning)
                r = decoder.decode(
                    JWT,
                    key,
                    algorithms=[algorithm],
                    options={"verify_exp": False, "verify_aud": False, "verify_nbf": False},
                )
            return r
        except j.exceptions.InvalidSignatureError:
            return None
        except j.exceptions.DecodeError as e:
            log.debug(f"Could not decode JWT for verification ({algorithm}): {e}")
            return None
        except j.exceptions.InvalidKeyError as e:
            log.debug(f"Invalid key for JWT verification ({algorithm}): {e}")
            return None

    @staticmethod
    def read_header(JWT):
        """Decode the header segment without handing the whole token to pyjwt.

        pyjwt decodes all three segments just to hand back the header, and
        since 2.14 it rejects any segment that is not canonically base64url
        encoded. A sloppily encoded signature would otherwise hide a perfectly
        readable header.
        """
        header_segment = JWT.partition(".")[0]
        try:
            header = json.loads(base64.urlsafe_b64decode(header_segment + "=" * (-len(header_segment) % 4)))
        except Exception:
            return None
        if not isinstance(header, dict):
            return None
        return header

    @staticmethod
    def canonicalize_signature(JWT):
        """Re-encode the signature segment canonically for pyjwt's benefit.

        A base64url signature has unused trailing bits, so several encodings
        decode to the same bytes. pyjwt rejects all but the canonical one since
        2.14, which would drop tokens we are perfectly able to crack. Only the
        signature segment is touched: the decoded signature and the signing
        input are both unchanged, so verification is unaffected.

        The result is for verification only and is never reported, so that
        findings always quote the product exactly as it was found.
        """
        header, _, remainder = JWT.partition(".")
        payload, _, signature = remainder.partition(".")
        try:
            decoded = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        except Exception:
            return JWT
        return f"{header}.{payload}.{base64.urlsafe_b64encode(decoded).rstrip(b'=').decode()}"

    def jwtLoad(self, JWT):
        jwt_headers = self.read_header(JWT)
        # if the JWT is not well formed, stop here
        if not jwt_headers:
            return (None, None, None)
        try:
            algorithm = jwt_headers["alg"]

        # It could be a JWT-like token that is actually a different format, for example a flask cookie
        except KeyError:
            return (None, None, None)

        return jwt_headers, algorithm, JWT

    def get_hashcat_commands(self, JWT, *args):
        jwt_headers, header_algorithm, JWT = self.jwtLoad(JWT)
        if jwt_headers and header_algorithm and JWT:
            algorithm = XMLDSIG_table.get(header_algorithm, header_algorithm)
            if algorithm[0].lower() != "h":
                return None

            return [
                {
                    "command": f"hashcat -m 16500 -a 0 {JWT}  <dictionary_file>",
                    "description": f"JSON Web Token (JWT) Algorithm: {algorithm}",
                }
            ]

    def check_secret(self, JWT):
        if not self.identify(JWT):
            return None

        jwt_headers, header_algorithm, JWT = self.jwtLoad(JWT)
        if not jwt_headers or not header_algorithm or not JWT:
            return None

        # the URI spellings name the same families, and decide which wordlist
        # to walk, but verification still uses the name in the header
        algorithm = XMLDSIG_table.get(header_algorithm, header_algorithm)

        # Check the token as it was issued. A URI-spelled header can also be a
        # rewrite of a token signed under the JWS short name, in which case the
        # signature covers that header instead, so try it too rather than miss
        # a recoverable key.
        verification_JWT = self.canonicalize_signature(JWT)
        verification_forms = [(verification_JWT, header_algorithm)]
        if header_algorithm in XMLDSIG_table:
            verification_forms.append((self.swap_algorithm(verification_JWT, jwt_headers, algorithm), algorithm))

        if algorithm[0].lower() == "h":
            for l in self.load_resources(["jwt_secrets.txt", "top_250000_passwords.txt"]):
                key = l.strip()

                for candidate, candidate_algorithm in verification_forms:
                    r = self.jwtVerify(candidate, key, candidate_algorithm)
                    if r:
                        r["jwt_headers"] = jwt_headers
                        return {"secret": key, "details": r}

        elif algorithm[0].lower() == "r":
            for l in self.load_resources(["jwt_rsakeys_public.txt"]):
                private_key_name = l.split(":")[0]
                public_key = f"{l.split(':')[1]}".rstrip().encode().replace(b"\\n", b"\n")
                for candidate, candidate_algorithm in verification_forms:
                    r = self.jwtVerify(candidate, public_key, candidate_algorithm)
                    if r:
                        r["jwt_headers"] = jwt_headers
                        return {"secret": f"Private key Name: {private_key_name}", "details": r}

        return None
