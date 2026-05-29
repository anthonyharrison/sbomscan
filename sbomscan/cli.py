# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import textwrap
from collections import ChainMap

from sbomscan.scanner import SBOMScanner
from sbomscan.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbomscan"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent("""
            SBOMscan scans a Software Bill of Materials for vulnerabilities
            """),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="filename of SBOM",
    )
    input_group.add_argument(
        "--url",
        action="store",
        default="",
        help="endpoint for vulnerability database",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="text",
        choices=["text", "json", "markdown"],
        help="specify format of vulnerability report (default: text)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "url": "",
        "output_file": "",
        "debug": False,
        "format": "text",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    sbom_name = args["input_file"]

    # Must specify a SBOM file
    if sbom_name == "":
        print("[ERROR] Must specify a SBOM file")
        sys.exit(1)

    # Check the SBOM file exist
    if not os.path.exists(sbom_name) or os.path.getsize(sbom_name) == 0:
        print(f"[ERROR] SBOM file {sbom_name} not found or empty")
        sys.exit(1)

    if args["output_file"] != "" and args["format"] == "text":
        print("[ERROR] Text format not supported for output file.")
        sys.exit(1)

    if os.getenv("VULNCODE") is None:
        print(
            "[ERROR] API key not found. Get an API key here: https://public.vulnerablecode.io/account/request_api_key/"
        )
        sys.exit(1)

    if args["debug"]:
        print("SBOM file:", sbom_name)
        print("Vulnerability Endpoint", args["url"])
        print("Output file:", args["output_file"])
        print("Output Format:", args["format"])

    sbom_scanner = SBOMScanner(url=args["url"], debug=args["debug"])
    sbom_scanner.process_sbom(sbom_file=sbom_name)
    sbom_scanner.generate_report(
        output_file=args["output_file"], output_format=args["format"]
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
