import re
from django.core.signing import loads as djangoLoads, BadSignature
from badsecrets.base import BadsecretsBase


class DjangoSignedCookies(BadsecretsBase):
    identify_regex = re.compile(r"^[\.a-zA-z-0-9]+:[\.a-zA-z-0-9:]+$")
    description = {"Product": "Djangno Signed Cookie", "Secret": "Django secret_key"}

    def check_secret(self, django_signed_cookie):
        if not self.identify(django_signed_cookie):
            return False
        for l in set(
            list(self.load_resource("django_secret_keys.txt")) + list(self.load_resource("top_10000_passwords.txt"))
        ):
            secret_key = l.rstrip()
            try:
                r = djangoLoads(
                    django_signed_cookie,
                    key=secret_key,
                    fallback_keys="",
                    salt="django.contrib.sessions.backends.signed_cookies",
                )
            except BadSignature:
                continue
            if r:
                return {"secret": secret_key, "details": r}
