import re
import jwt as j
from badsecrets.base import BadsecretsBase


class Generic_JWT(BadsecretsBase):

    identify_regex = re.compile(r"eyJ(?:[\w-]*\.)(?:[\w-]*\.)[\w-]*")

    def jwtVerify(self, JWT, key, algorithm):
        try:
            r = j.decode(JWT, key, algorithms=[algorithm], options={"verify_exp": False})
            return r
        except j.exceptions.InvalidSignatureError:
            return None

    def check_secret(self, JWT):
        if not self.identify(JWT):
            return None

        try:
            jwt_headers = j.get_unverified_header(JWT)

        # if the JWT is not well formed, stop here
        except j.exceptions.DecodeError:
            return

        algorithm = jwt_headers["alg"]

        if algorithm[0].lower() == "h":

            for l in self.load_resource("jwt_secrets.txt"):
                key = l.strip()

                r = self.jwtVerify(JWT, key, algorithm)
                if r:
                    return {"jwt_secret": key, "jwt_headers": jwt_headers, "jwt_data": r}

        elif algorithm[0].lower() == "r":
            for l in self.load_resource("jwt_rsakeys_public.txt"):
                private_key_name = l.split(":")[0]
                public_key = l.split(":")[1]
            private_key_name = private_key_name
            public_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6cs10W3XKnr1MDoO0Ngf\nYEixdQy5e3m/E4POPC5t6yyc/eZZayytrA6CfaZXBKnYU4YKD06sJULj30qw/TJJ\nwphhb2a5s3sjXejL4KW2WTdP6F+DbSaokzvKVdaZ97GnLtiei8n6gnSE1xSsJ15+\nd9JHImekuW/ggksVbI26UTiXvfv7LUJ8ntt6wG1UQHWOvYbG81TTpZjItvZsYu1t\npekjNpOwCsIbO//S1JOiSgpuKp7HwCnQwABNEWyMuIAMlymMyocbTdQHcClogZC9\nbwokxTPZGmD9xZ+meaeVD5HONqASIJ1tOoFGsnwwwlEhwsul0FRs7qehuhJmKE5Z\nbwIDAQAB\n-----END PUBLIC KEY-----"
            r = self.jwtVerify(JWT, public_key, algorithm)
            if r:
                return {"jwt_private_key_index": private_key_name, "jwt_headers": jwt_headers, "jwt_data": r}

        return None
