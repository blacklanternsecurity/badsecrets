import re
import os
import sys
import argparse
import requests
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from badsecrets import modules_loaded

ASPNET_Viewstate = modules_loaded["aspnet_viewstate"]


def check_viewstate(viewstate, generator):
    bs_vs = ASPNET_Viewstate()
    r = bs_vs.check_secret(viewstate, generator=generator)
    return r


def print_result(r):
    print("Matching MachineKeys found!")
    print(f"Validation Key: {r['validationKey']}")
    print(f"Validation Algo: {r['validationAlgo']}")
    print(f"Encryption Key: {r['encryptionKey']}")
    print(f"Encryption Algo: {r['encryptionAlgo']}")


def validate_viewstate(arg_value, pattern=re.compile(r"^(?:[A-Za-z0-9+\/=%]+)$")):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("Viewstate is not formatted correctly")
    return arg_value


def validate_generator(arg_value, pattern=re.compile(r"^(?:[A-Fa-f0-9]+)$")):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("Generator is not formatted correctly")
    return arg_value


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

    viewstate = None
    generator = "0000"

    generator_regex = re.compile(r'<input.+__VIEWSTATEGENERATOR"\svalue="(\w+)"')
    viewstate_regex = re.compile(r'<input.+__VIEWSTATE"\svalue="(.+)"')

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--url",
        type=validate_url,
        help="The URL of the page to access and attempt to pull viewstate and generator from",
    )
    parser.add_argument("-v", "--viewstate", type=validate_viewstate)
    parser.add_argument("-g", "--generator", type=validate_generator)
    args = parser.parse_args()

    if (args.url and args.viewstate) or (args.url and args.generator):
        parser.error("--viewstate/--generator options and --url option are mutually exclusive")
        return

    if args.url:
        try:
            res = requests.get(args.url)
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout):
            print(f"Error connecting to URL: [{args.url}]")
            return
        resp_body = urllib.parse.unquote(res.text)
        generator_match = generator_regex.search(resp_body)
        viewstate_match = viewstate_regex.search(resp_body)
        if generator_match and viewstate_match:
            viewstate = viewstate_match.group(1)
            generator = generator_match.group(1)
        else:
            print(f"Did not find viewstate in repsonse from URL [{args.url}]")
            return

    elif args.viewstate:
        viewstate = args.viewstate
        if args.generator:
            generator = args.generator
        else:
            print("Warning: non-encrypted viewstates will fail without --generator value")
    else:
        parser.error("One of --url or --viewstate is required")

    if viewstate:
        r = check_viewstate(viewstate, generator)
        if r:
            print_result(r)
        else:
            print("Matching MachineKeys NOT found")


if __name__ == "__main__":
    main()
