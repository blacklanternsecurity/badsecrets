import re
from django.core.signing import loads as djangoLoads
from badsecrets.base import BadsecretsBase


class DjangoSignedCookies(BadsecretsBase):

    identify_regex = re.compile(r"^[\.a-zA-z-0-9]+:[\.a-zA-z-0-9:]+$")

    def __init__(self, django_signed_cookie):
        self.django_signed_cookie = django_signed_cookie

    def check_secret(self):
        if not self.identify(self.django_signed_cookie):
            return False
        for l in self.load_resource("django_secret_keys.txt"):
            secret_key = l.rstrip()
            r = djangoLoads(
                self.django_signed_cookie,
                key=secret_key,
                fallback_keys="",
                salt="django.contrib.sessions.backends.signed_cookies",
            )

            if r:
                r["secret_key"] = secret_key
                self.output_parameters = r
                return True
        return False
