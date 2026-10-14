import re
from django.core.signing import loads as djangoLoads, BadSignature
from badsecrets.base import BadsecretsBase


class DjangoSignedCookies(BadsecretsBase):
    identify_regex = re.compile(r"^\.?[a-zA-Z0-9_-]+(?::[a-zA-Z0-9_-]{4,8})?:[a-zA-Z0-9_-]{27,}$")
    description = {"product": "Django Signed Cookie", "secret": "Django secret_key", "severity": "HIGH"}
    carve_locations = ("cookies",)

    def check_secret(self, django_signed_cookie):
        if not self.identify(django_signed_cookie):
            return False
        for l in self.load_resources(["django_secret_keys.txt", "top_250000_passwords.txt"]):
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
