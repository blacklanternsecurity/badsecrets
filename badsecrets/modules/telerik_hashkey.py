import re
import hmac
import base64
import binascii
import urllib.parse
from contextlib import suppress
from badsecrets.base import BadsecretsBase


class Telerik_HashKey(BadsecretsBase):

    identify_regex = re.compile(r"^(?:[A-Za-z0-9+\/=%]{32,})$")
    description = {"Product": "Telerik DialogParameters", "Secret": "Telerik.Upload.ConfigurationHashKey"}

    def carve_regex(self):
        return re.compile(r"{\"SerializedParameters\":\"([^\"]*)\"")

    def prepare_keylist(self, include_machinekeys=True):

        if include_machinekeys:
            for l in self.load_resource("aspnet_machinekeys.txt"):
                try:
                    vkey, ekey = l.rstrip().split(",")
                    yield vkey
                except ValueError:
                    continue
        for l in self.load_resource("telerik_hash_keys.txt"):
            vkey = l.strip()
            yield vkey

    def check_secret(self, dialogParameters_raw):
        if not self.identify(dialogParameters_raw):
            return None

        dialogParametersB64 = urllib.parse.unquote(dialogParameters_raw)
        dp_enc = dialogParametersB64[:-44].encode()
        dp_hash = dialogParametersB64[-44:].encode()

        for vkey in self.prepare_keylist():
            with suppress(binascii.Error):
                h = hmac.new(vkey.encode(), dp_enc, self.hash_algs["SHA256"])
                if base64.b64encode(h.digest()) == dp_hash:
                    return {"secret": vkey, "details": None}
        return None

    def hashkey_probe_generator(self, include_machinekeys=False):
        test_string = b"EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;IsSkinTouch,False,3,False;ScriptManagerProperties,False,0,CgoKCkZhbHNlCjAKCgoK;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAxOC4xLjExNy40NSwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,False"
        dp_enc = base64.b64encode(test_string)
        for vkey in self.prepare_keylist(include_machinekeys=include_machinekeys):
            h = hmac.new(vkey.encode(), dp_enc, self.hash_algs["SHA256"])
            yield (f"{dp_enc.decode()}{base64.b64encode(h.digest()).decode()}", vkey)

    def sign_enc_dialog_params(self, hash_key, enc_dialog_params):
        dp_enc = enc_dialog_params.encode()
        h = hmac.new(hash_key.encode(), dp_enc, self.hash_algs["SHA256"])
        return f"{dp_enc.decode()}{base64.b64encode(h.digest()).decode()}"
