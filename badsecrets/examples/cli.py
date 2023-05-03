#!/usr/bin/env python3
# badsecrets - example command line interface
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

from badsecrets.base import check_all_modules, carve_all_modules
import requests
import argparse
import sys
import os
import re

from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


class BaseReport:
    def __init__(self, x):
        self.x = x

    def print_report(self, report_message):
        print("***********************")
        print(report_message)
        print(f"Detecting Module: {self.x['detecting_module']}\n")
        print(f"Product Type: {self.x['description']['Product']}")
        print(f"Product: {self.x['source']}")
        print(f"Secret Type: {self.x['description']['Secret']}")
        print(f"Location: {self.x['location']}")


class ReportSecret(BaseReport):
    def report(self):
        self.print_report("Known Secret Found!\n")
        print(f"Secret: {self.x['secret']}")
        print(f"Details: {self.x['details']}")


class ReportIdentify(BaseReport):
    def report(self):
        self.print_report("Cryptographic Product Identified (no vulnerability)\n")

        if self.x["hashcat"] is not None:
            print(f"Hashcat Command: {self.x['hashcat']}")


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
    parser = argparse.ArgumentParser(description="Check cryptographic tokens against badsecrets library")
    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="Use URL Mode. Specified the URL of the page to access and attempt to check for secrets",
    )
    parser.add_argument("secret", nargs="*", type=str)

    parser.add_argument(
        "-p",
        "--proxy",
        help="In URL mode, Optionally specify an HTTP proxy",
    )

    parser.add_argument(
        "-a",
        "--user-agent",
        help="In URL mode, Optionally set a custom user-agent",
    )

    args = parser.parse_args()

    print("badsecrets - example command line interface\n")

    if not args.url and not args.secret:
        parser.error(
            "Either supply the secret as a positional argument (supply all secrets for multi-secret modules), or use --url mode with a valid URL"
        )
        return

    if args.url and args.secret:
        parser.error("In --url mode, no positional arguments should be used")
        return

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    if args.url:
        headers = {}
        if args.user_agent:
            headers["User-agent"] = args.user_agent

        try:
            res = requests.get(args.url, proxies=proxies, headers=headers, verify=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            print(f"Error connecting to URL: [{args.url}]")
            return

        r_list = carve_all_modules(requests_response=res)
        if r_list:
            for r in r_list:
                if r["type"] == "SecretFound":
                    report = ReportSecret(r)
                else:
                    report = ReportIdentify(r)
                report.report()
        else:
            print("No secrets found :(")

    else:
        x = check_all_modules(*args.secret)
        if x:
            ReportSecret(x)
        else:
            print("No secrets found :(")


if __name__ == "__main__":
    main()
