#!/usr/bin/env python3
# badsecrets - command line interface
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

from badsecrets.base import check_all_modules, carve_all_modules, hashcat_all_modules
import pkg_resources
import requests
import argparse
import sys
import os
import re
from colorama import Fore, Style, init

init(autoreset=True)  # Automatically reset the color to default after each print statement

from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

ascii_art_banner = """
 __ )              |                                |         
 __ \    _` |   _` |   __|   _ \   __|   __|   _ \  __|   __| 
 |   |  (   |  (   | \__ \   __/  (     |      __/  |   \__ \ 
____/  \__,_| \__,_| ____/ \___| \___| _|    \___| \__| ____/ 
"""


def print_version():
    version = pkg_resources.get_distribution("badsecrets").version
    if version == "0.0.0":
        version = "Version Unknown (Running w/poetry?)"
    print(f"v{version}\n")


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        self.exit(1)


class BaseReport:
    def __init__(self, x):
        self.x = x

    def print_report(self, report_message):
        print(report_message)
        print(f"Detecting Module: {self.x['detecting_module']}\n")
        print(f"Product Type: {self.x['description']['product']}")
        print(f"Product: {self.x['product']}")
        print(f"Secret Type: {self.x['description']['secret']}")
        print(f"Location: {self.x['location']}")


class ReportSecret(BaseReport):
    def report(self):
        self.print_report(print_status("Known Secret Found!\n", color=Fore.GREEN, passthru=True))
        print_status(f"Secret: {self.x['secret']}", color=Fore.GREEN)
        print(f"Severity: {self.x['description']['severity']}")
        print(f"Details: {self.x['details']}")


class ReportIdentify(BaseReport):
    def report(self):
        self.print_report(
            print_status("Cryptographic Product Identified (no vulnerability)\n", color=Fore.YELLOW, passthru=True)
        )
        if self.x["hashcat"] is not None:
            print_hashcat_results(self.x["hashcat"])


def print_status(msg, passthru=False, color=Fore.WHITE):
    if msg:
        if colorenabled:
            msg = f"{color}{msg}{Style.RESET_ALL}"
        if passthru:
            return msg
        else:
            print(msg)


def validate_url(
    arg_value,
    pattern=re.compile(
        r"^https?://((?:[A-Z0-9_]|[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_])[\.]?)+(?:[A-Z0-9_][A-Z0-9\-_]*[A-Z0-9_]|[A-Z0-9_])(?::[0-9]{1,5})?.*$",
        re.IGNORECASE,
    ),
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError(print_status("URL is not formatted correctly", color=Fore.RED))
    return arg_value


def validate_file(file):
    if not os.path.exists(file):
        raise argparse.ArgumentTypeError(print_status(f"The file {file} does not exist!", color=Fore.RED))
    if not os.path.isfile(file):
        raise argparse.ArgumentTypeError(print_status(f"{file} is not a valid file!", color=Fore.RED))
    if os.path.getsize(file) > 100 * 1024:  # size in bytes
        raise argparse.ArgumentTypeError(
            print_status(f"The file {file} exceeds the maximum limit of 100KB!", color=Fore.RED)
        )
    return file


def print_hashcat_results(hashcat_candidates):
    print_status("\nPotential matching hashcat commands:\n", color=Fore.YELLOW)
    for hc in hashcat_candidates:
        print(f"Module: [{hc['detecting_module']}] {hc['hashcat_description']} Command: [{hc['hashcat_command']}]")


def main():
    global colorenabled
    colorenabled = False
    color_parser = argparse.ArgumentParser(add_help=False)

    color_parser.add_argument(
        "-nc",
        "--no-color",
        action="store_true",
        help="Disable color message in the console",
    )

    args, unknown_args = color_parser.parse_known_args()
    colorenabled = not args.no_color

    parser = CustomArgumentParser(
        description="Check cryptographic products against badsecrets library", parents=[color_parser]
    )

    if colorenabled:
        print_status(ascii_art_banner, color=Fore.GREEN)

    else:
        print(ascii_art_banner)
    print_version()

    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="Use URL Mode. Specified the URL of the page to access and attempt to check for secrets",
    )

    parser.add_argument(
        "-nh",
        "--no-hashcat",
        action="store_true",
        help="Skip the check for compatable hashcat commands when secret isn't found",
    )

    parser.add_argument(
        "-c",
        "--custom-secrets",
        type=validate_file,
        help="include a custom secrets file to load along with the default secrets",
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

    args = parser.parse_args(unknown_args)

    if not args.url and not args.product:
        parser.error(
            print_status(
                "Either supply the product as a positional argument (supply all products for multi-product modules), use --hashcat followed by the product as a positional argument, or use --url mode with a valid URL",
                color=Fore.RED,
            )
        )
        return

    if args.url and args.product:
        parser.error(print_status("In --url mode, no positional arguments should be used", color=Fore.RED))
        return

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    custom_resource = None
    if args.custom_secrets:
        custom_resource = args.custom_secrets
        print_status(f"Including custom secrets list [{custom_resource}]\n", color=Fore.YELLOW)

    if args.url:
        headers = {}
        if args.user_agent:
            headers["User-agent"] = args.user_agent

        try:
            res = requests.get(args.url, proxies=proxies, headers=headers, verify=False)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            print_status(f"Error connecting to URL: [{args.url}]", color=Fore.RED)
            return

        r_list = carve_all_modules(requests_response=res, custom_resource=custom_resource, url=args.url)
        if r_list:
            for r in r_list:
                if r["type"] == "SecretFound":
                    report = ReportSecret(r)
                else:
                    if not args.no_hashcat:
                        hashcat_candidates = hashcat_all_modules(r["product"], detecting_module=r["detecting_module"])
                        if hashcat_candidates:
                            r["hashcat"] = hashcat_candidates
                    report = ReportIdentify(r)
                report.report()
        else:
            print_status("No secrets found :(", color=Fore.RED)

    else:
        x = check_all_modules(*args.product, custom_resource=custom_resource)
        if x:
            report = ReportSecret(x)
            report.report()
        else:
            print_status("No secrets found :(", color=Fore.RED)
            if not args.no_hashcat:
                hashcat_candidates = hashcat_all_modules(*args.product)
                if hashcat_candidates:
                    print_hashcat_results(hashcat_candidates)


if __name__ == "__main__":
    main()
