#!/usr/bin/env python3
# badsecrets - example command line interface
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

from badsecrets.base import check_all_modules, carve_all_modules, hashcat_all_modules
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
        print(f"Product Type: {self.x['description']['product']}")
        print(f"Product: {self.x['product']}")
        print(f"Secret Type: {self.x['description']['secret']}")
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
            print_hashcat_results(self.x["hashcat"])


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


def print_hashcat_results(hashcat_candidates):
    print("\nPotential matching hashcat commands:\n")
    for hc in hashcat_candidates:
        print(f"Module: [{hc['detecting_module']}] {hc['hashcat_description']} Command: [{hc['hashcat_command']}]")


def main():
    parser = argparse.ArgumentParser(description="Check cryptographic tokens against badsecrets library")
    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="Use URL Mode. Specified the URL of the page to access and attempt to check for secrets",
    )

    parser.add_argument(
        "-hc",
        "--hashcat",
        action="store_true",
        help="Get the hashcat command for the provided crytopgrahic product and exit. This option is mutually exclusive with the --url option.",
    )

    parser.add_argument("product", nargs="*", type=str, help="Cryptographic product to check for known secrets")

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

    if args.hashcat and args.url:
        parser.error("The --hashcat option is mutually exclusive with the --url option.")
        return

    if not args.url and not args.product and not args.hashcat:
        parser.error(
            "Either supply the product as a positional argument (supply all products for multi-product modules), use --hashcat followed by the product as a positional argument, or use --url mode with a valid URL"
        )
        return

    if args.url and args.product:
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
                    hashcat_candidates = hashcat_all_modules(r["product"])
                    if hashcat_candidates:
                        r["hashcat"] = hashcat_candidates
                    report = ReportIdentify(r)
                report.report()
        else:
            print("No secrets found :(")

    elif args.hashcat:
        hashcat_candidates = hashcat_all_modules(*args.product)

        if hashcat_candidates:
            print_hashcat_results(hashcat_candidates)
        else:
            print("No matching hashcat commands found :/")

    else:
        x = check_all_modules(*args.product)
        if x:
            report = ReportSecret(x)
            report.report()
        else:
            print("No secrets found :(")

            hashcat_candidates = hashcat_all_modules(*args.product)
            if hashcat_candidates:
                print_hashcat_results(hashcat_candidates)


if __name__ == "__main__":
    main()
