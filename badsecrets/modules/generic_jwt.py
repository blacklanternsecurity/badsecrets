import re
import jwt as j
import json
import base64
from badsecrets.base import BadsecretsBase

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


class Generic_JWT(BadsecretsBase):
    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")
    description = {"product": "JSON Web Token (JWT)", "secret": "HMAC/RSA Key", "severity": "HIGH"}

    @staticmethod
    def swap_algorithm(jwt, algorithm):
        header = j.get_unverified_header(jwt)
        header["alg"] = algorithm
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        )
        _, payload, signature = jwt.split(".")
        new_jwt = f"{header_encoded}.{payload}.{signature}"
        return new_jwt

    def carve_regex(self):
        return re.compile(r"(eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*)")

    def jwtVerify(self, JWT, key, algorithm):
        try:
            r = j.decode(JWT, key, algorithms=[algorithm], options={"verify_exp": False})
            return r
        except j.exceptions.InvalidSignatureError:
            return None

    def jwtLoad(self, JWT):
        try:
            jwt_headers = j.get_unverified_header(JWT)
        # if the JWT is not well formed, stop here
        except j.exceptions.DecodeError:
            return (None, None, None)
        try:
            algorithm = jwt_headers["alg"]

        # It could be a JWT-like token that is actually a different format, for example a flask cookie
        except KeyError:
            return (None, None, None)

        if algorithm in XMLDSIG_table.keys():
            algorithm = XMLDSIG_table[algorithm]
            JWT = self.swap_algorithm(JWT, algorithm)

        return jwt_headers, algorithm, JWT

    def get_hashcat_commands(self, JWT, *args):
        jwt_headers, algorithm, JWT = self.jwtLoad(JWT)
        if jwt_headers and algorithm and JWT:
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

        jwt_headers, algorithm, JWT = self.jwtLoad(JWT)
        if not jwt_headers or not algorithm or not JWT:
            return None

        if algorithm[0].lower() == "h":
            for l in self.load_resources(["jwt_secrets.txt", "top_100000_passwords.txt"]):
                key = l.strip()

                r = self.jwtVerify(JWT, key, algorithm)
                if r:
                    r["jwt_headers"] = jwt_headers
                    return {"secret": key, "details": r}

        elif algorithm[0].lower() == "r":
            for l in self.load_resources(["jwt_rsakeys_public.txt"]):
                private_key_name = l.split(":")[0]
                public_key = f"{l.split(':')[1]}".rstrip().encode().replace(b"\\n", b"\n")
                r = self.jwtVerify(JWT, public_key, algorithm)
                if r:
                    r["jwt_headers"] = jwt_headers
                    return {"secret": f"Private key Name: {private_key_name}", "details": r}

        return None
