#!/usr/bin/python3
# -*- coding: utf-8 -*-
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

import json
import re
from inspect import _void

from autopkglib import Processor, ProcessorError, URLTextSearcher

__all__ = ["CVEScoreGetter"]

NVD_SEARCH_URL_BASE = "https://nvd.nist.gov/vuln/detail/"
CVSS_VERSION_OPTS = ["v3,v2"]
CVSS_VERSION_DEFAULT = "v3"
CVE_NULL_RATING_DEFAULT = ""
PAUSE_INTERVAL = 5



class CVEScoreGetter(URLTextSearcher):
    """
    Search the National Vulnerability Database for provided CVEs, return the maximum score and corresponding rating category.
    Returns blank strings for output variables if There are no CVEs to check.
    """

    description = __doc__

    input_variables = {
        "cves": {
            "required": False,
            "description": (
                "A list of CVEs (delimit with commas) to search nvd.nist.gov for."
            ),
            "default": "",
        },
        "cvss_version": {
            "required": False,
            "description": "CVSS version to use in risk calculation. Options: {}".format(
                CVSS_VERSION_OPTS
            ),
            "default": CVSS_VERSION_DEFAULT,
        },
        "null_cve_rating": {
            "required": False,
            "description": "If no CVEs are evaluated, return this string as the 'maximum_cve_rating'",
            "default": CVE_NULL_RATING_DEFAULT,
        },
    }
    output_variables = {
        "maximum_cve_score": {
            "description": "The maximum score returned for the list of CVEs."
        },
        "maximum_cve_rating": {
            "description": "The rating (critical/medium/etc.) corresponding to the returned maximum_cve_score"
        },
    }

    def split_cves(self, cves: str) -> list:
        trimmed = []
        for s in cves.split(","):
            trimmed.append(s.strip())

        return trimmed

    def get_cve_score(self, cve: str) -> dict:
        scoreDict = {}
        cvssVersion = self.env.get(
            "cvss_version", self.input_variables["cvss_version"]["default"]
        )
        url = NVD_SEARCH_URL_BASE + cve

        self.output(
            "Getting {} score for {}.".format(cvssVersion, cve), verbose_level=3
        )
        html = self.download(url, text=True)

        pattern = '\\"severityDetail\\"[\s\S]*?{}\-calculator[\s\S]*?((?P<risk_score>[\d\.]*)\s+(?P<risk_rating>\w*))\<\/a\>'.format(
            cvssVersion
        )
        rePattern = re.compile(pattern, re.I)
        myMatch = rePattern.search(html)

        if myMatch == None:
            score = "0.0"
            rating = "N/A"
            self.output(
                "CVE Not found within NVD database. Perhaps a NVD record does not exist at this time.",
                verbose_level=2,
            )
        else:
            groupDict = myMatch.groupdict()
            score = groupDict["risk_score"]
            rating = groupDict["risk_rating"].capitalize()

            self.output("Score: {}\tRating: {}".format(score, rating), verbose_level=3)

        scoreDict["risk_score"] = score
        scoreDict["risk_rating"] = rating

        return scoreDict

    def main(self):

        cveString = self.env.get("cves")
        cves = list(set(self.split_cves(cveString)))
        pauseInterval = PAUSE_INTERVAL

        scores = []
        try:
            for cve in cves:
                if cve != "":
                    score = self.get_cve_score(cve)
                    scores.append(score)
                    sleep(pauseInterval)
                    self.output(
                        "Pausing {} seconds to avoid rate limiting.".format(
                            pauseInterval
                        ),
                        verbose_level=3,
                    )

            self.output("Found {} CVE Scores.".format(len(scores)), verbose_level=3)

            scores.sort(key=lambda x: x["risk_score"], reverse=True)

            if len(scores) > 0:
                topCveScore = scores[0]
                self.env["maximum_cve_score"] = topCveScore["risk_score"]
                self.env["maximum_cve_rating"] = topCveScore["risk_rating"]
            else:
                self.output("No CVE Scores returned.")
                self.env["maximum_cve_score"] = ""
                self.env["maximum_cve_rating"] = self.env.get(
                    "null_cve_rating",
                    self.input_variables["null_cve_rating"]["default"],
                )

            self.output(
                "Maximum CVSS Score: {}\tRating: {}".format(
                    self.env["maximum_cve_score"], self.env["maximum_cve_rating"]
                ),
                verbose_level=1,
            )

        except Exception as e:
            raise ProcessorError(e)

        self.output("Completed string manipulations.", verbose_level=2)


if __name__ == "__main__":
    PROCESSOR = CVEScoreGetter()
    PROCESSOR.execute_shell()
