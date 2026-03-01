#!/usr/bin/env python3
# badsecrets - command line interface
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

from badsecrets.base import (
    check_all_modules,
    carve_all_modules,
    hashcat_all_modules,
    probe_all_modules,
    build_prefilter_text,
    _passive_subclasses,
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


def _all_module_names():
    """Build case-insensitive lookup of all module class names (passive + active)."""
    names = {}
    for cls in _passive_subclasses():
        names[cls.__name__.upper()] = cls.__name__
    for cls in _active_subclasses():
        names[cls.__name__.upper()] = cls.__name__
    return names


def _active_module_names():
    """Set of active module class names."""
    return {cls.__name__ for cls in _active_subclasses()}


def parse_custom_secrets(custom_secrets_args):
    """Parse --custom-secrets arguments into global files and per-module keys.

    Supports two formats:
      --custom-secrets FILE              → global file for all modules
      --custom-secrets MODULE:FILE_OR_KEYS → targeted to specific module

    Returns:
        global_files: list of file paths to apply to all modules
        module_keys: dict of {module_class_name: [key1, key2, ...]}
    """
    global_files = []
    module_keys = {}

    if not custom_secrets_args:
        return global_files, module_keys

    all_names = _all_module_names()

    for arg in custom_secrets_args:
        if ":" not in arg:
            # No module prefix → treat as global file
            validate_file(arg)
            global_files.append(arg)
        else:
            module_name, value = arg.split(":", 1)
            upper_name = module_name.upper()

            if upper_name not in all_names:
                candidates = list(set(all_names.values()))
                close = difflib.get_close_matches(module_name, candidates, n=1, cutoff=0.4)
                suggestion = f" Did you mean '{close[0]}'?" if close else ""
                available = ", ".join(sorted(candidates))
                raise argparse.ArgumentTypeError(
                    f"No module found for '{module_name}'.{suggestion} Available modules: {available}"
                )

            canonical_name = all_names[upper_name]

            # Auto-detect: if value is an existing file path, read keys from it
            if os.path.isfile(value):
                with open(value) as f:
                    keys = [line.strip() for line in f if line.strip()]
            else:
                # Otherwise treat as comma-separated inline keys
                keys = [k.strip() for k in value.split(",") if k.strip()]

            if canonical_name not in module_keys:
                module_keys[canonical_name] = []
            module_keys[canonical_name].extend(keys)

    return global_files, module_keys


def list_modules():
    """Print all available modules with their descriptions."""
    print("\nPassive modules (analyze existing cryptographic products):\n")
    for cls in sorted(_passive_subclasses(), key=lambda c: c.__name__):
        desc = cls.get_description()
        print(f"  {cls.__name__}")
        print(f"    Product: {desc['product']}")
        print(f"    Secret:  {desc['secret']}")
        print(f"    Severity: {desc['severity']}")
        print()

    active = sorted(_active_subclasses(), key=lambda c: c.__name__)
    if active:
        print("Active modules (send targeted probes to detect default/known keys):\n")
        for cls in active:
            desc = cls.get_description()
            print(f"  {cls.__name__}")
            print(f"    Product: {desc['product']}")
            print(f"    Secret:  {desc['secret']}")
            print(f"    Severity: {desc['severity']}")
            print()


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
        action="append",
        metavar="FILE_OR_MODULE:KEYS",
        help=(
            "Custom secrets to check. Can be specified multiple times. "
            "Without a module prefix, the file is loaded for all modules. "
            "With a module prefix (MODULE:value), keys are targeted to that module only. "
            "Value can be a file path or comma-separated inline keys. "
            "Example: -c my_keys.txt  or  -c Shiro_RememberMe_Key:key1,key2  "
            "or  -c GlobalProtect_DefaultMasterKey:keys.txt"
        ),
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
        "-l",
        "--list-modules",
        action="store_true",
        help="List all available modules with descriptions and exit",
    )

    args = parser.parse_args(unknown_args)

    if args.list_modules:
        list_modules()
        return

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

    if not args.url and args.passive_only:
        parser.error(print_status("--passive-only is only valid in --url mode", color="red"))
        return

    proxy = None
    if args.proxy:
        proxy = args.proxy

    # Parse unified --custom-secrets
    try:
        global_files, module_keys = parse_custom_secrets(args.custom_secrets)
    except argparse.ArgumentTypeError as e:
        parser.error(str(e))
        return

    # Global custom resource for passive modules (first global file, backward compatible)
    custom_resource = global_files[0] if global_files else None

    # Build active_keys_map: start with module-targeted keys for active modules
    active_names = _active_module_names()
    active_keys_map = {k: v for k, v in module_keys.items() if k in active_names}

    # Also load keys from global files for active modules
    if global_files:
        for f in global_files:
            with open(f) as fh:
                keys_from_file = [line.strip() for line in fh if line.strip()]
            if keys_from_file:
                for active_cls in _active_subclasses():
                    name = active_cls.__name__
                    if name not in active_keys_map:
                        active_keys_map[name] = []
                    active_keys_map[name].extend(keys_from_file)

    if custom_resource and not json_mode:
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

            # Check every collected response against prefilters, probe each match once
            active_results = []
            seen_modules = set()
            for resp, resp_url in responses:
                scan_text = build_prefilter_text(httpx_response=resp)
                if not scan_text:
                    continue
                prefilter_matches = yara_prefilter_scan(scan_text)
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
                            body=scan_text,
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
