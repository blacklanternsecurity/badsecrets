import re

from badsecrets.base import BadsecretsBase
from badsecrets.modules.aspnet_viewstate import ASPNET_Viewstate

# Reference: https://blog.sorcery.ie/posts/higherlogic_rce/


class ASPNET_vstate(BadsecretsBase):
    identify_regex = re.compile(r"^H4sI.+$")
    description = {"product": "ASP.NET Compressed Vstate", "secret": "unprotected", "severity": "CRITICAL"}

    def carve_regex(self):
        return re.compile(r"<input[^>]+__VSTATE\"\s*value=\"(.*?)\"")

    def get_product_from_carve(self, regex_search):
        product = regex_search.groups()[0]
        if len(product) == 0:
            return "EMPTY '__VSTATE' FORM FIELD"
        return product

    def check_secret(self, compressed_vstate):
        if not self.identify(compressed_vstate):
            return None

        uncompressed = self.attempt_decompress(compressed_vstate)
        if uncompressed and ASPNET_Viewstate.valid_preamble(uncompressed):
            r = {"source": compressed_vstate, "info": "ASP.NET Vstate (Unprotected, Compressed)"}
            return {"secret": "UNPROTECTED (compressed)", "details": r}
