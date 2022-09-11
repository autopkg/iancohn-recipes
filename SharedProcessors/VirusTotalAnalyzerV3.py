#!/usr/bin/python
#
# Copyright 2022 Ian Cohn
# https://www.github.com/iancohn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Factored for Python 3
from __future__ import absolute_import

import hashlib
import json
import time
from array import array
from operator import itemgetter
from os import path
from sys import int_info

from autopkglib import Processor, ProcessorError, URLDownloader  # , URLGetter

__all__ = ["VirusTotalAnalyzerV3"]

VT_API_V3_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_PAUSE_INTERVAL = 15  # Virus Total default rate limits at 4 requests per minute.
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_MAX_REPORT_AGE = 7
DEFAULT_CODE_SIGN_VERIFICATION_CONFIG = {
    "code_signing_checks": {
        # "expected_authority_names": []
    },
    "continue_on_failure": False,
}


class VirusTotalAnalyzerV3(URLDownloader):
    description = "Checks Virus Total for an analysis of the file; optionally checks the signing; submits the file as needed. Uses Virus Total API V3."

    input_variables = {
        "file_path": {
            "required": False,
            "description": "The path to the file you wish to submit. Defaults to %pathname%",
        },
        "max_report_age_days": {
            "required": False,
            "description": (
                "Int representing the maximum age in days of the available report in VirusTotal. "
                "If the existing report is older than this value, the file/url will be rescanned. "
                "A value of 0 will effectively force a rescan."
            ),
            "default": str(DEFAULT_MAX_REPORT_AGE),
        },
        "pause_interval": {
            "required": False,
            "description": "Number of seconds to wait between requests to the Virus Total api to avoid rate limiting.",
            "default": str(DEFAULT_PAUSE_INTERVAL),
        },
        "max_retry_attempts": {
            "required": False,
            "description": "Number of times to attempt to retrieve Virus Total analysis results. Enter 0 to retry indefinitely.",
            "default": str(DEFAULT_MAX_ATTEMPTS),
        },
        "code_sign_verification_config": {
            "required": False,
            "description": (
                "A nested dictionary of the configuration to use to validate "
                "the signature on the provided upload. Example value:"
                """
<key>code_signing_checks</key>
<dict>
    <key>expected_authority_names</key>
    <array>
        <string>Dell Inc</string>
        <string>Entrust Code Signing CA - OVCS2</string>
        <string>Entrust Code Signing Root Certification Authority - CSBR1</string>
        <string>Entrust.net</string>
    </array>
</dict>
"""
            ),
        },
    }
    output_variables = {
        "code_sign_validation_passed": {
            "description": "Whether or not the file indicated conforms to the provided code signature configuration."
        },
        "vt_type_description": {"description": "Returned from Virus Total"},
        "vt_creation_date": {"description": "Returned from Virus Total"},
        "vt_reputation": {
            "description": "The reputation of the file according to Virus Total."
        },
        "vt_signature_product": {"description": "Returned from Virus Total"},
        "vt_signature_verified": {"description": "Returned from Virus Total"},
        "vt_signature_description": {"description": "Returned from Virus Total"},
        "vt_signature_date": {"description": "Returned from Virus Total"},
        "vt_signature_status": {"description": "Returned from Virus Total"},
        "vt_signature_valid_usage": {"description": "Returned from Virus Total"},
        "vt_signature_name": {"description": "Returned from Virus Total"},
        "vt_signature_algorithm": {"description": "Returned from Virus Total"},
        "vt_signature_valid_from": {"description": "Returned from Virus Total"},
        "vt_signature_valid_to": {"description": "Returned from Virus Total"},
        "vt_signature_serial_number": {"description": "Returned from Virus Total"},
        "vt_signature_cert_issuer": {"description": "Returned from Virus Total"},
        "vt_signature_thumbprint": {"description": "Returned from Virus Total"},
    }

    __doc__ = description

    def check_expected_authority_names(
        self, authorityNameReference: list, signatureAuthorityNames: list
    ) -> bool:
        self.output("Checking signature authority names.", verbose_level=2)
        if len(authorityNameReference) != len(signatureAuthorityNames):
            self.output(
                "The number of provided authority names does not match the number of authority names detected on the file.",
                verbose_level=3,
            )
            return False

        else:
            namesMatch = True
            nCertIndexes = len(authorityNameReference) - 1
            self.output(
                "Checking each item in the expected authority name list.",
                verbose_level=3,
            )
            currentCertIndex = 0
            while namesMatch and currentCertIndex <= nCertIndexes:
                self.output(
                    "Index: {}\tExpected Authority Name: {}\tActualAuthorityName: {}".format(
                        currentCertIndex,
                        authorityNameReference[currentCertIndex],
                        signatureAuthorityNames[currentCertIndex],
                    ),
                    verbose_level=3,
                )
                if (
                    authorityNameReference[currentCertIndex]
                    != signatureAuthorityNames[currentCertIndex]
                ):
                    namesMatch = False
                currentCertIndex += 1

            self.output(
                "Signature on product matches expected authority names: {}".format(
                    namesMatch
                ),
                verbose_level=2,
            )

            return namesMatch

    def get_pause_interval(self) -> int:
        try:
            s = self.env.get[
                "pause_interval", self.input_variables["pause_interval"]["default"]
            ]
            interval = int(s)
        except:
            interval = DEFAULT_PAUSE_INTERVAL
        finally:
            return interval

    def calculate_sha256(self, filePath: str) -> str:
        if (path.exists(filePath) and path.isfile(filePath)) == False:
            raise ProcessorError("File ({}) does not exist".format(filePath))

        self.output("Calculating the sha256.", verbose_level=3)
        blockSize = int(65536)
        hasher = hashlib.sha256()
        with open(filePath, "rb") as fileBlob:
            buffer = fileBlob.read(blockSize)
            while len(buffer) > 0:
                hasher.update(buffer)
                buffer = fileBlob.read(blockSize)

        sha256 = hasher.hexdigest()
        self.output("Calculated SHA256: {}".format(sha256), verbose_level=3)
        return sha256

    def get_min_scan_date(self, maxReportAge: int = None) -> int:
        if maxReportAge == None:
            sMaxAge = 0

        sMaxAge = maxReportAge * 24 * 60 * 60
        nowEpoch = int(time.mktime(time.gmtime()))
        maxAgeEpoch = nowEpoch - sMaxAge

        return maxAgeEpoch

    def main(self):
        # Set Variables
        apiKey = self.env.get("VIRUSTOTAL_API_KEY")
        pauseInterval = self.get_pause_interval()
        maxRetry = int(
            self.env.get(
                "max_retry_attempts",
                self.input_variables["max_retry_attempts"]["default"],
            )
        )
        maxAgeDays = int(
            self.env.get(
                "max_report_age_days",
                self.input_variables["max_report_age_days"]["default"],
            )
        )
        filePath = self.env.get("file_path", self.env.get("pathname"))
        codeSignConfig = self.env.get(
            "code_sign_verification_config", DEFAULT_CODE_SIGN_VERIFICATION_CONFIG
        )

        sha = self.calculate_sha256(filePath)
        minTimeEpoch = self.get_min_scan_date(maxAgeDays)

        if apiKey > "":
            self.output("API Key retrieved.", verbose_level=3)
        else:
            raise ProcessorError("API Key not found. Cannot continue.")

        try:
            # Search for sha
            searchUrl = VT_API_V3_BASE_URL + "/search?query={}".format(sha)
            curl_cmd = (
                self.curl_binary(),
                "--url",
                searchUrl,
                "-H",
                "X-apikey: {}".format(apiKey),
                "-H",
                "Accept: application/json",
            )
            queryResponse = self.download_with_curl(curl_cmd)
            jsonResponse = json.loads(queryResponse)

            # If not exists or last scan is too old
            self.output(
                "# responses: {}".format(len(jsonResponse["data"])), verbose_level=3
            )
            if len(jsonResponse["data"]) != 0:
                self.output(
                    "MinAge: {}\t\tAnalysisDate: {}".format(
                        minTimeEpoch,
                        jsonResponse["data"][0]["attributes"]["last_analysis_date"],
                    ),
                    verbose_level=3,
                )
                self.output(
                    "Single result?: {}\tTooOld: {}".format(
                        (len(jsonResponse["data"]) == 1),
                        (
                            jsonResponse["data"][0]["attributes"]["last_analysis_date"]
                            < minTimeEpoch
                        ),
                    ),
                    verbose_level=3,
                )

            if len(jsonResponse["data"]) != 1 or (
                (
                    jsonResponse["data"][0]["attributes"]["last_analysis_date"]
                    < minTimeEpoch
                )
            ):
                # Submit File
                self.output(
                    "File does not exist in Virus Total, or there are ambiguous results. Beginning upload process now.",
                    verbose_level=1,
                )
                fileSize = int(path.getsize(filePath))
                submissionUrl = None
                if fileSize < 33554432:
                    self.output(
                        "File size is less than 32MB, using default file submission endpoint",
                        verbose_level=2,
                    )
                    submissionUrl = VT_API_V3_BASE_URL + "/files"
                elif fileSize < 419430400:
                    self.output("Getting file submission url.", verbose_level=3)
                elif fileSize < 524288000:
                    self.output(
                        "Warning: File size is > 400 MB. If this is a compressed "
                        "archive, consider extracting and submitting files individually. ",
                        verbose_level=1,
                    )
                    self.output("Getting file submission url.", verbose_level=3)
                else:
                    raise ProcessorError(
                        "File size is too large for Virus Total. If this is a compressed archive, "
                        "consider submitting enclosed files individually."
                    )

                if submissionUrl == None:
                    curlSubmissionUrl = (
                        self.curl_binary(),
                        "--url",
                        VT_API_V3_BASE_URL + "/files/upload_url",
                        "-H",
                        "X-apikey: {}".format(apiKey),
                        "-H",
                        "Accept: application/json",
                    )
                    time.sleep(pauseInterval)
                    submissionUrlResponse = self.download_with_curl(curlSubmissionUrl)
                    jsUrl = json.loads(submissionUrlResponse)
                    submissionUrl = jsUrl["data"]
                    self.output(
                        "Retrieved a file upload url: {}".format(submissionUrl),
                        verbose_level=3,
                    )

                curlSubmitFile = (
                    self.curl_binary(),
                    "--url",
                    "{}".format(submissionUrl),
                    "-H",
                    "X-apikey: {}".format(apiKey),
                    "-H",
                    "Accept: application/json",
                    "-H",
                    "Content-Type: multipart/form-data",
                    "--form",
                    "file=@{}".format(filePath),
                )
                self.output("Submiting file.", verbose_level=2)
                analysisResponse = self.download_with_curl(curlSubmitFile)
                jsAnalysis = json.loads(analysisResponse)
                analysisId = jsAnalysis["data"]["id"]
                # Wait on file up to the max number of retries, return report.
                attempts = maxRetry
                curlCheckAnalysis = (
                    self.curl_binary(),
                    "--url",
                    (VT_API_V3_BASE_URL + "/analyses/" + analysisId),
                    "-H",
                    "X-apikey: {}".format(apiKey),
                    "-H",
                    "Accept: application/json",
                )
                status = "in progress"

                while (maxRetry == 0) or ((attempts > 0) and (status != "completed")):
                    self.output("Pausing to avoid rate limiting.", verbose_level=3)
                    time.sleep(pauseInterval)
                    self.output(
                        "Checking Virus Total analysis status. Attempt {}.".format(
                            attempts
                        ),
                        verbose_level=3,
                    )
                    analysis = self.download_with_curl(curlCheckAnalysis)
                    jsStatus = json.loads(analysis)
                    del analysis
                    status = jsStatus["data"]["attributes"]["status"]
                    self.output(
                        "Current Analysis Status: {}".format(status), verbose_level=3
                    )
                    attempts -= 1

                # Return results
                detailsUrl = jsStatus["data"]["links"]["item"]

                curlDetails = (
                    self.curl_binary(),
                    "--url",
                    detailsUrl,
                    "-H",
                    "X-apikey: {}".format(apiKey),
                    "-H",
                    "Accept: application/json",
                )
                detailsResponse = self.download_with_curl(curlDetails)
                jsDetails = json.loads(detailsResponse)
                data = jsDetails["data"]

            # Else return results
            else:
                self.output(
                    "Current Report is new enough. Using data.", verbose_level=2
                )
                data = jsonResponse["data"][0]

            if "signature_info" in data["attributes"]:
                self.output(
                    "The submitted file has been signed. Getting signature details.",
                    verbose_level=3,
                )
                signInfo = data["attributes"]["signature_info"]
                signersDetails = signInfo["signers details"]
                immediateSigner = signersDetails[0]
                # certain fields are not always present in the signature info key returned by
                # virus total. Coalesce it here.
                if "product" in signInfo:
                    self.env["vt_signature_product"] = signInfo["product"]

                if "description" in signInfo:
                    self.env["vt_signature_description"] = signInfo["description"]

                self.env["vt_signature_verified"] = signInfo["verified"]
                self.env["vt_signature_date"] = signInfo["signing date"]
                self.env["vt_signature_status"] = immediateSigner["status"]
                self.env["vt_signature_valid_usage"] = immediateSigner["valid usage"]
                self.env["vt_signature_name"] = immediateSigner["name"]
                self.env["vt_signature_algorithm"] = immediateSigner["algorithm"]
                self.env["vt_signature_valid_from"] = immediateSigner["valid from"]
                self.env["vt_signature_valid_to"] = immediateSigner["valid to"]
                self.env["vt_signature_serial_number"] = immediateSigner[
                    "serial number"
                ]
                self.env["vt_signature_cert_issuer"] = immediateSigner["cert issuer"]
                self.env["vt_signature_thumbprint"] = immediateSigner["thumbprint"]
            else:
                self.output("The object has not been signed.", verbose_level=3)

            self.env["vt_type_description"] = data["attributes"]["type_description"]
            self.env["vt_creation_date"] = data["attributes"].get("creation_date") or ""
            self.env["vt_reputation"] = data["attributes"]["reputation"]

            # Code signature verification
            allChecks = {}
            if len(codeSignConfig["code_signing_checks"]) > 0:
                continueOnVerificationFailure: bool = (
                    codeSignConfig.get("continue_on_failure") or False
                )
                self.output(
                    "Validating provided {} provided code signing checks.".format(
                        len(codeSignConfig["code_signing_checks"])
                    ),
                    verbose_level=2,
                )
                self.output(
                    "Code signing checks: {}".format(
                        codeSignConfig["code_signing_checks"]
                    ),
                    verbose_level=3,
                )
                checks = list(codeSignConfig["code_signing_checks"].keys())
                codeSignVerificationFailed = False
                for check in checks:
                    self.output("Evaluating check ({}).".format(check), verbose_level=2)
                    if check == "expected_authority_names":
                        authorityNames = list(map(itemgetter("name"), signersDetails))
                        allChecks[check] = self.check_expected_authority_names(
                            codeSignConfig["code_signing_checks"][
                                "expected_authority_names"
                            ],
                            authorityNames,
                        )
                        if allChecks[check] == False:
                            codeSignVerificationFailed = True

                    elif 1 == 0:  # Additional check types
                        self.output("Place holder for additional check types.")
                    else:
                        raise ProcessorError(
                            "Error: check ({}) not defined.".format(check)
                        )

                if codeSignVerificationFailed and (
                    continueOnVerificationFailure == False
                ):
                    raise ProcessorError("Code signature verification failed.")
            else:
                self.output("No code signing checks configured.")

        except Exception as e:
            raise e

        finally:
            self.output("Process complete.")


if __name__ == "__main__":
    PROCESSOR = VirusTotalAnalyzerV3()
    PROCESSOR.execute_shell()
