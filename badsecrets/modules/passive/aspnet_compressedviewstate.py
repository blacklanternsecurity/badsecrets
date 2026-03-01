import re

from badsecrets.base import BadsecretsBase
from badsecrets.modules.passive.aspnet_viewstate import ASPNET_Viewstate

# Reference: https://blog.sorcery.ie/posts/higherlogic_rce/


class ASPNET_compressedviewstate(BadsecretsBase):
    identify_regex = re.compile(r"^H4sI.+$")
    # Alternation: any of the viewstate-like input names
    yara_carve_rule = (
        "rule ASPNET_compressedviewstate_carve {"
        ' strings: $vs = "__VIEWSTATE" $vstate = "__VSTATE" $cvs = "__COMPRESSEDVIEWSTATE"'
        " condition: $vs or $vstate or $cvs }"
    )
    description = {"product": "ASP.NET Compressed Viewstate", "secret": "unprotected", "severity": "CRITICAL"}
    carve_locations = ("body",)

    def carve_regex(self):
        return re.compile(r"<input[^>]+__(?:VIEWSTATE|VSTATE|COMPRESSEDVIEWSTATE)\"\s*value=\"(.*?)\"")

    def check_secret(self, compressed_viewstate):
        if not self.identify(compressed_viewstate):
            return None

        uncompressed = self.attempt_decompress(compressed_viewstate)
        if uncompressed and ASPNET_Viewstate.valid_preamble(uncompressed):
            r = {"source": compressed_viewstate, "info": "Custom ASP.NET Viewstate (Unprotected, Compressed)"}
            return {"secret": "UNPROTECTED (compressed)", "details": r}
