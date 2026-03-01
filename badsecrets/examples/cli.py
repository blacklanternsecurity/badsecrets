#!/usr/bin/env python3
# badsecrets - command line interface
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

from badsecrets.base import (
    check_all_modules,
    carve_all_modules,
    hashcat_all_modules,
    probe_all_modules,
    _active_subclasses,
    yara_prefilter_scan,
)
from badsecrets.helpers import print_status, validate_url
import httpx
import asyncio
import argparse
import difflib
import json as json_module
import sys
import os
from importlib.metadata import version, PackageNotFoundError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

ascii_art_banner = r"""
 __ )              |                                |
 __ \    _` |   _` |   __|   _ \   __|   __|   _ \  __|   __|
 |   |  (   |  (   | \__ \   __/  (     |      __/  |   \__ \
____/  \__,_| \__,_| ____/ \___| \___| _|    \___| \__| ____/
"""


def print_version():
    try:
        version_str = version("badsecrets")
    except PackageNotFoundError:
        version_str = "Unknown (Running w/poetry?)"
    print(f"Version - {version_str}\n")


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"error: {message}\n")


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
        self.print_report(print_status("Known Secret Found!\n", color="green", passthru=True))
        print_status(f"Secret: {self.x['secret']}", color="green")
        severity = self.x["description"]["severity"]
        if severity in ["CRITICAL", "HIGH"]:
            severity_color = "red"
        elif severity in ["LOW", "MEDIUM"]:
            severity_color = "yellow"
        elif severity == "INFO":
            severity_color = "blue"
        print_status(f"Severity: {self.x['description']['severity']}", color=severity_color)
        print(f"Details: {self.x['details']}\n")


class ReportIdentify(BaseReport):
    def report(self):
        self.print_report(
            print_status("Cryptographic Product Identified (no vulnerability)\n", color="yellow", passthru=True)
        )
        if self.x["hashcat"] is not None:
            print_hashcat_results(self.x["hashcat"])


def validate_file(file):
    if not os.path.exists(file):
        raise argparse.ArgumentTypeError(print_status(f"The file {file} does not exist!", color="red"))
    if not os.path.isfile(file):
        raise argparse.ArgumentTypeError(print_status(f"{file} is not a valid file!", color="red"))
    if os.path.getsize(file) > 100 * 1024:  # size in bytes
        raise argparse.ArgumentTypeError(
            print_status(f"The file {file} exceeds the maximum limit of 100KB!", color="red")
        )
    return file


def print_hashcat_results(hashcat_candidates):
    if hashcat_candidates:
        print_status("\nPotential matching hashcat commands:\n", color="yellow")
        for hc in hashcat_candidates:
            print(
                f"Module: [{hc['detecting_module']}] {hc['hashcat_description']} Command: [{hc['hashcat_command']}]\n"
            )


def validate_active_keys(active_keys_args):
    """Parse and validate --active-keys arguments.
    Returns dict: {module_class_name: [key1, key2, ...]}
    """
    if not active_keys_args:
        return {}

    # Build lookup of valid module names (case-insensitive)
    valid_names = {cls.__name__.upper(): cls.__name__ for cls in _active_subclasses()}

    result = {}
    for arg in active_keys_args:
        if ":" not in arg:
            raise argparse.ArgumentTypeError(f"Invalid --active-keys format: '{arg}'. Expected MODULE:keys_or_file")
        module_name, value = arg.split(":", 1)
        upper_name = module_name.upper()

        if upper_name not in valid_names:
            candidates = list(valid_names.values())
            close = difflib.get_close_matches(module_name, candidates, n=1, cutoff=0.4)
            suggestion = f" Did you mean '{close[0]}'?" if close else ""
            available = ", ".join(candidates)
            raise argparse.ArgumentTypeError(
                f"No active module found for '{module_name}'.{suggestion} Available active modules: {available}"
            )

        canonical_name = valid_names[upper_name]

        # Auto-detect: if value is an existing file path, read keys from it
        if os.path.isfile(value):
            with open(value) as f:
                keys = [line.strip() for line in f if line.strip()]
        else:
            # Otherwise treat as comma-separated inline keys
            keys = [k.strip() for k in value.split(",") if k.strip()]

        if canonical_name not in result:
            result[canonical_name] = []
        result[canonical_name].extend(keys)

    return result


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

    color_parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results as JSON only (no banner, no color). Outputs nothing on no detection",
    )

    args, unknown_args = color_parser.parse_known_args()
    json_mode = args.json
    colorenabled = not args.no_color and not json_mode

    parser = CustomArgumentParser(
        description="Check cryptographic products against badsecrets library", parents=[color_parser]
    )

    if not json_mode:
        if colorenabled:
            print_status(ascii_art_banner, color="green")
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

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        help="Custom header (e.g., -H 'Cookie: foo=bar'). Can be specified multiple times",
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output (request URL, response status, headers, etc.)",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "-P",
        "--passive-only",
        action="store_true",
        help="Disable active probing in URL mode (only run passive analysis)",
    )

    parser.add_argument(
        "--active-keys",
        action="append",
        metavar="MODULE:KEYS_OR_FILE",
        help=(
            "Custom keys for a specific active module. Format: MODULE:value where value is "
            "a file path (if it exists on disk) or a comma-separated list of keys. "
            "Can be specified multiple times for different modules. "
            "Example: --active-keys GlobalProtect_DefaultMasterKey:my_keys.txt "
            "or --active-keys GlobalProtect_DefaultMasterKey:key1,key2,key3"
        ),
    )

    args = parser.parse_args(unknown_args)

    if not args.url and not args.product:
        parser.error(
            print_status(
                "Either supply the product as a positional argument (supply all products for multi-product modules), use --hashcat followed by the product as a positional argument, or use --url mode with a valid URL",
                color="red",
            )
        )
        return

    if args.url and args.product:
        parser.error(print_status("In --url mode, no positional arguments should be used", color="red"))
        return

    if args.passive_only and args.active_keys:
        parser.error(print_status("--passive-only and --active-keys are mutually exclusive", color="red"))
        return

    if not args.url and (args.passive_only or args.active_keys):
        parser.error(print_status("--passive-only and --active-keys are only valid in --url mode", color="red"))
        return

    proxy = None
    if args.proxy:
        proxy = args.proxy

    custom_resource = None
    if args.custom_secrets:
        custom_resource = args.custom_secrets
        if not json_mode:
            print_status(f"Including custom secrets list [{custom_resource}]\n", color="yellow")

    if args.url:
        headers = {}
        if args.user_agent:
            headers["User-agent"] = args.user_agent
        if args.header:
            for h in args.header:
                if ":" in h:
                    name, value = h.split(":", 1)
                    headers[name.strip()] = value.strip()

        if args.debug and not json_mode:
            print_status(f"[DEBUG] Request URL: {args.url}", color="blue")

        # Fetch initial response without following redirects, then follow if needed.
        # Both passive and active phases evaluate every response we collect.
        try:
            res = httpx.get(
                args.url,
                proxy=proxy,
                headers=headers,
                verify=False,
                follow_redirects=False,
                timeout=args.timeout,
            )
        except (httpx.ConnectError, httpx.ConnectTimeout):
            if not json_mode:
                print_status(f"Error connecting to URL: [{args.url}]", color="red")
            return

        responses = [(res, args.url)]

        # If the initial response is a redirect, also fetch the followed page
        if res.is_redirect:
            try:
                followed = httpx.get(
                    args.url,
                    proxy=proxy,
                    headers=headers,
                    verify=False,
                    follow_redirects=True,
                    timeout=args.timeout,
                )
                if args.debug and not json_mode:
                    print_status(
                        f"[DEBUG] Followed redirect to: {followed.url} (status {followed.status_code})",
                        color="blue",
                    )
                responses.append((followed, str(followed.url)))
            except (httpx.ConnectError, httpx.ConnectTimeout):
                pass

        # Passive phase: carve all responses
        all_passive_results = []
        for resp, resp_url in responses:
            if args.debug and not json_mode:
                print_status(f"[DEBUG] Response status: {resp.status_code} ({resp_url})", color="blue")
                print_status(f"[DEBUG] Response headers: {dict(resp.headers)}", color="blue")
                if resp.cookies:
                    print_status(f"[DEBUG] Cookies: {list(resp.cookies.keys())}", color="blue")
                print_status(f"[DEBUG] Response body length: {len(resp.text)} chars", color="blue")

            r_list = carve_all_modules(httpx_response=resp, custom_resource=custom_resource, url=resp_url)
            if r_list:
                all_passive_results.extend(r_list)

        if args.debug and not json_mode:
            if all_passive_results:
                modules_hit = {r["detecting_module"] for r in all_passive_results}
                secret_count = sum(1 for r in all_passive_results if r["type"] == "SecretFound")
                identify_count = sum(1 for r in all_passive_results if r["type"] == "IdentifyOnly")
                print_status(
                    f"[DEBUG] Carve results: {len(all_passive_results)} total ({secret_count} secrets, {identify_count} identify-only) from modules: {', '.join(modules_hit)}",
                    color="blue",
                )
            else:
                print_status("[DEBUG] Carve results: none", color="blue")

        if all_passive_results:
            if json_mode:
                print(json_module.dumps(all_passive_results))
            else:
                for r in all_passive_results:
                    if r["type"] == "SecretFound":
                        report = ReportSecret(r)
                    else:
                        if not args.no_hashcat:
                            hashcat_candidates = hashcat_all_modules(
                                r["product"], detecting_module=r["detecting_module"]
                            )
                            if hashcat_candidates:
                                r["hashcat"] = hashcat_candidates
                        report = ReportIdentify(r)
                    report.report()
        else:
            if not json_mode:
                print_status("No secrets found :(", color="red")

        # Active probes (on by default in URL mode, unless --passive-only)
        if not args.passive_only:
            if not json_mode:
                print_status("Active probes are enabled. Use --passive-only to disable.", color="yellow")

            active_keys_map = validate_active_keys(args.active_keys)

            # Check every collected response against prefilters, probe each match once
            active_results = []
            seen_modules = set()
            for resp, resp_url in responses:
                scan_body = resp.text
                if not scan_body:
                    continue
                prefilter_matches = yara_prefilter_scan(scan_body)
                new_matches = {k: v for k, v in prefilter_matches.items() if k not in seen_modules}
                if new_matches and not json_mode:
                    for module_name in new_matches:
                        print_status(
                            f"Detected {module_name} signature. Sending active probe...",
                            color="yellow",
                        )
                if new_matches:
                    results = asyncio.run(
                        probe_all_modules(
                            body=scan_body,
                            url=resp_url,
                            active_keys_map=active_keys_map,
                        )
                    )
                    active_results.extend(results)
                seen_modules.update(prefilter_matches.keys())

            if active_results:
                if json_mode:
                    print(json_module.dumps(active_results))
                else:
                    for r in active_results:
                        report = ReportSecret(r)
                        report.report()
            elif args.debug and not json_mode:
                print_status("[DEBUG] No active findings.", color="blue")

    else:
        if args.debug and not json_mode:
            print_status(f"[DEBUG] Checking product(s): {args.product}", color="blue")
        x = check_all_modules(*args.product, custom_resource=custom_resource)
        if args.debug and not json_mode:
            if x:
                print_status(f"[DEBUG] Match found by module: {x.get('detecting_module', 'unknown')}", color="blue")
            else:
                print_status("[DEBUG] No match from any module", color="blue")
        if x:
            if json_mode:
                print(json_module.dumps(x))
            else:
                report = ReportSecret(x)
                report.report()
        else:
            if not json_mode:
                print_status("No secrets found :(", color="red")
                if not args.no_hashcat:
                    hashcat_candidates = hashcat_all_modules(*args.product)
                    if hashcat_candidates:
                        print_hashcat_results(hashcat_candidates)


if __name__ == "__main__":
    main()
