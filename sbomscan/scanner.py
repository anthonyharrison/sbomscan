# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
from datetime import datetime

import requests
import tldextract
from lib4sbom.parser import SBOMParser
from packageurl import PackageURL
from requests.exceptions import RequestException, Timeout
from sbom2doc.docbuilder.consolebuilder import ConsoleBuilder
from sbom2doc.docbuilder.jsonbuilder import JSONBuilder
from sbom2doc.docbuilder.markdownbuilder import MarkdownBuilder


class SBOMScanner:

    VULNDATABASE_ENDPOINT = "https://public.vulnerablecode.io/api/packages/bulk_search"
    TIMEOUT = 5

    def __init__(self, url="", debug=False):
        self.url = self.VULNDATABASE_ENDPOINT if url == "" else url
        self.debug = debug
        self.modules = []

    def process_sbom(self, sbom_file):
        sbom_parser = SBOMParser()
        # Load SBOM - will autodetect SBOM type
        sbom_parser.parse_file(sbom_file)
        self.sbom_file = os.path.abspath(sbom_file)
        self.sbom_type = sbom_parser.get_type()
        # Identify all packages
        self.packages = [x for x in sbom_parser.get_sbom()["packages"].values()]
        for package in self.packages:
            # Find PURL identifier. PURLs are stored as exernal references
            ext_ref = package.get("externalreference")
            if ext_ref is not None:
                for ref in ext_ref:
                    if ref[1] == "purl":
                        self.modules.append(ref[2])

    def find_vulnerabilities(self):
        if len(self.modules) > 0:
            request_body = {
                "purls": self.modules,
            }
            token = os.getenv("VULNCODE")
            if self.debug:
                print(f"Message Body: {request_body}")
                print(f"API Token: {token}")
            try:
                response = requests.post(
                    self.url,
                    json=request_body,
                    headers={"Authorization": f"{token}"},
                    timeout=self.TIMEOUT,
                )
                # An HTTPError is raised if the response code was 4xx or 5xx
                response.raise_for_status()
                vulnerability_json = response.json()
            except Timeout:
                # Handle API timeout
                if self.debug:
                    print(f"Request timed out after {self.TIMEOUT} seconds.")
                vulnerability_json = None
            except RequestException as e:
                # Handle other errors (connection, DNS, etc.)
                if self.debug:
                    print(f"An error occurred: {e}")
                vulnerability_json = None
            return vulnerability_json
        return None

    def generate_report(self, output_file, output_format):
        resp = self.find_vulnerabilities()
        if resp is not None:
            # Select document builder based on format
            if output_format == "markdown":
                sbom_document = MarkdownBuilder()
            elif output_format == "json":
                sbom_document = JSONBuilder()
            else:
                sbom_document = ConsoleBuilder()
            # Build SBOM summary
            sbom_document.heading(1, "SBOM Scan Summary")
            sbom_document.createtable(["Item", "Details"], [20, 35])
            sbom_document.addrow(
                ["Scan Date", datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")]
            )
            sbom_document.addrow(["SBOM File", self.sbom_file])
            sbom_document.addrow(["SBOM Type", self.sbom_type])
            sbom_document.addrow(["Number of Packages", str(len(self.packages))])
            sbom_document.addrow(["Number of PURLs", str(len(self.modules))])
            sbom_document.showtable(widths=[5, 9])

            sbom_document.heading(1, "Vulnerabilities")
            sbom_document.createtable(
                [
                    "Package",
                    "Version",
                    "Vulnerability",
                    "Source",
                    "CVSS Score",
                    "Severity",
                    "EPSS Probability",
                    "EPSS Percentile",
                ],
                [10, 10, 10, 10, 10, 10, 10],
            )
            for r in resp:
                purl_info = PackageURL.from_string(r["purl"]).to_dict()
                for v in r["affected_by_vulnerabilities"]:
                    cvss3_score = ""
                    cvss31_score = ""
                    cvss4_score = ""
                    cvss_severity = ""
                    epss_prob = ""
                    epss_percent = ""
                    vuln_source = []
                    vuln_identifier = {}
                    for ref in v["references"]:
                        if self.debug:
                            print(ref)
                        # Extract source
                        extracted = tldextract.extract(ref["reference_url"])
                        source = extracted.domain
                        vuln_id = ref["reference_id"]
                        # Only record vulnerabilities with an allocated ID
                        if (
                            vuln_id != ""
                            and not vuln_id.isdigit()
                            and not vuln_id.startswith("cpe")
                        ):
                            # Filter out bugzilla identifiers and non vulnerability identifier (CPE)
                            if source not in vuln_source:
                                if len(source) > 0:
                                    vuln_source.append(source.lower())
                            if vuln_identifier.get(source) is None:
                                vuln_identifier[source] = [vuln_id]
                            else:
                                vuln_identifier[source].append(vuln_id)
                        if len(ref["scores"]) > 0:
                            for score in ref["scores"]:
                                score_type = score["scoring_system"]
                                score_value = score["value"]
                                if score_type == "cvssv3":
                                    if cvss3_score == "" or score_value > cvss3_score:
                                        cvss3_score = score_value
                                elif score_type == "cvssv3.1":
                                    if cvss31_score == "" or score_value > cvss31_score:
                                        cvss31_score = score_value
                                elif score_type == "cvssv4":
                                    if cvss4_score == "" or score_value > cvss4_score:
                                        cvss4_score = score_value
                                elif score_type in ["generic_textual", "cvssv3.1_qr"]:
                                    cvss_severity = score_value
                                elif score_type == "epss":
                                    if epss_prob == "" or score_value > epss_prob:
                                        epss_prob = score_value
                                    # extract additional data
                                    percent = score["scoring_elements"]
                                    if epss_percent == "" or percent > epss_percent:
                                        epss_percent = percent
                        elif self.debug:
                            print(f"No score data found for {r['purl']}")
                    # Return most recent CVSS score

                    if cvss4_score != "":
                        cvss_score = f"{cvss4_score} (v4)"
                    elif cvss31_score != "":
                        cvss_score = f"{cvss31_score} (v3.1)"
                    elif cvss3_score != "":
                        cvss_score = f"{cvss3_score} (v3)"
                    else:
                        cvss_score = ""
                    if self.debug:
                        print(f"Vulnerability Alias: {vuln_identifier}")
                    # Use NVD identifier where possible
                    if vuln_identifier.get("nist") is not None:
                        source = "NVD"
                        vuln_id = vuln_identifier["nist"][0]
                    else:
                        # Use alternative (non NVD) identifier
                        if len(vuln_source) > 0:
                            source = vuln_source[0]
                            vuln_id = vuln_identifier[source][0]
                        else:
                            source = "unknown"
                    if source != "unknown":
                        sbom_document.addrow(
                            [
                                purl_info["name"],
                                purl_info["version"],
                                vuln_id,
                                source.upper(),
                                cvss_score,
                                cvss_severity,
                                epss_prob,
                                epss_percent,
                            ]
                        )
                    elif self.debug:
                        print(
                            f"Unable to determine vulnerability source for {r['purl']}"
                        )

            sbom_document.showtable(widths=[5, 9])
            sbom_document.publish(output_file)
