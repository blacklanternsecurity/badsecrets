import re
from django.core.signing import loads as djangoLoads, BadSignature
from badsecrets.base import BadsecretsBase


class DjangoSignedCookies(BadsecretsBase):

    identify_regex = re.compile(r"^[\.a-zA-z-0-9]+:[\.a-zA-z-0-9:]+$")

    def check_secret(self, django_signed_cookie):
        if not self.identify(django_signed_cookie):
            return False
        for l in self.load_resource("django_secret_keys.txt"):
            secret_key = l.rstrip()
            try:
                r = djangoLoads(
                    django_signed_cookie,
                    key=secret_key,
                    fallback_keys="",
                    salt="django.contrib.sessions.backends.signed_cookies",
                )
            except BadSignature:
                return None
            if r:
                r["secret_key"] = secret_key
                return dict(r)
        return None
