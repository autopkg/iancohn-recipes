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

import json
import re
from fnmatch import fnmatch

from autopkglib import Processor, ProcessorError, URLGetter

DELL_BASE_URL = "https://www.dell.com/support/driver/en-us/ips/api/driverlist/fetchdriversbyproduct?"
DELL_DETAILS_BASE_URL = (
    "https://www.dell.com/support/home/en-us/drivers/driversdetails?driverid="
)
# productcode=optiplex-5000-desktop
# &oscode=WT64A
# X-Requested-With : XMLHttpRequest
# CVE\-\d{4}\-\d{4}
__all__ = ["DellSoftwareUrlProvider"]

# Define Options
FORM_FACTOR_OPT = ["Desktop", "Laptop", "Tower", "AIO", "Small", "Mini", ""]
PRODUCT_FAMILY_OPT = ["Precision", "Optiplex", "Latitude", "XPS"]
CATEGORY_OPT = [
    '"AP"  >> #Application',
    '"AU"  >> #Audio',
    '"BI"  >> #BIOS',
    '"CM"  >> #Modem/Communications',
    '"CS"  >> #Chipset',
    '"DK"  >> #Docks/Stands',
    '"DP"  >> #Dell Data Security',
    '"IN"  >> #Mouse, Keyboard & Input Devices',
    '"NI"  >> #Network, Ethernet & Wireless',
    '"SM"  >> #Systems Management',
    '"ST"  >> #Storage',
    '"SY"  >> #Security',
    '"TDS" >> #Trusted Device Security',
    '"VI"  >> #Video',
]
FILE_TYPE_OPT = [
    '"BEW"  >> #CPG BIOS Executable for Windows/DOS'
    '"CUG"  >> #A zip file or cab file containing the users guide in HTML',
    '"LW64" >> #Update Package for MS Windows 64-Bit.',
    '"LWXP" >> #Update Package for MS Windows 32-Bit',
    '"SAE"  >> #An application',
    '"SEZ"  >> #Extracts files directly to local disk',
]

# Define Defaults
DEFAULT_FF = "Desktop"
DEFAULT_FAM = "Optiplex"
DEFAULT_MODEL = "5000"
DEFAULT_OS = "BIOSA"
DEFAULT_CAT = "BI"
DEFAULT_FILE_TYPE = "BEW"
DEFAULT_RE = ".*"
DEFAULT_RE_FIELD = ""


class DellSoftwareUrlProvider(URLGetter):
    """Use Dell Driver Fetch API to retrieve software product download url"""

    description = (
        "Provides a download url and file metadata for Dell software packages."
    )
    input_variables = {
        "OS_CODE": {
            "required": False,
            "default": DEFAULT_OS,
            "description": "The OS Code to download the package for.",
        },
        "PRODUCT_CODE_OVERRIDE": {
            "required": False,
            "description": (
                "The product code to use, if the product code does not "
                "conform to the standard of [family]-[model]-[form factor]"
            ),
        },
        "FAMILY": {
            "required": False,
            "default": DEFAULT_FAM,
            "description": (
                "The product family to use when searching Dell's downloads."
                "Options: {}".format(PRODUCT_FAMILY_OPT)
            ),
        },
        "MODEL": {
            "required": False,
            "default": DEFAULT_MODEL,
            "description": "The Model number (or name) to used for searching packages.",
        },
        "FORM_FACTOR": {
            "required": False,
            "default": DEFAULT_FF,
            "description": (
                "The Form Factor of the system used for searching packages. "
                "Options: {}".format(FORM_FACTOR_OPT)
            ),
        },
        "CATEGORY": {
            "required": False,
            "default": DEFAULT_CAT,
            "description": (
                "The category code of the software." "Options: {}".format(CATEGORY_OPT)
            ),
        },
        "FILE_TYPE": {
            "required": False,
            "default": DEFAULT_FILE_TYPE,
            "description": (
                "The code for the file type to download."
                "Options: {}".format(FILE_TYPE_OPT)
            ),
        },
        "DRIVER_NAME_RE_PATTERN": {
            "required": False,
            "default": DEFAULT_RE,
            "description": "A RegEx pattern to use to match the Driver Name against.",
        },
        "DRIVER_FILE_NAME_RE_PATTERN": {
            "required": False,
            "default": DEFAULT_RE,
            "description": "A RegEx pattern to use to match the Driver Name against.",
        },
        "POPULATE_CVES": {
            "required": False,
            "default": False,
            "description": (
                "If True, after retrieving driver details, the processor will continue "
                "to search the details page for CVEs addressed by this package"
            ),
        },
    }
    output_variables = {
        "ProductFamily": {"description": "Self described."},
        "ProductModel": {"description": "Self described."},
        "FormFactor": {"description": "The form factor of the product"},
        "ProductCode": {
            "description": "The Dell product code targeted by the software."
        },
        "DriverId": {
            "description": "The unique identifier assigned to the product by Dell."
        },
        "DriverName": {"description": "The friendly name of the driver."},
        "Type": {"description": "The driver type."},
        "TypeName": {"description": "The driver type name"},
        "Importance": {"description": "The importance/severity of the release."},
        "ImportanceId": {
            "description": "The importance/severity of the release expressed as an int."
        },
        "ReleaseDate": {"description": "The release date of the product."},
        "RequiresRestart": {
            "description": "Whether the software requires a restart to complete successfully."
        },
        "DellVersion": {"description": "The version of the product according to Dell."},
        "Version": {"description": "A more standard version of the version."},
        "VersionFriendly": {
            "description": "The version of the product as its friendly version (ex. A10)."
        },
        "DellDescription": {"description": "Dell's description of the product."},
        "url": {"description": "The download url for the product."},
        "CatName": {"description": "The category name of the product."},
        "FileId": {"description": "The numerical id of the download file."},
        "FileName": {"description": "The name of the file."},
        "FileFormatName": {"description": "The format of the file."},
        "FileSize": {"description": "The size of the file in bytes."},
        "ConvertedFileSize": {
            "description": "The size of the file as the largest, easily readable size."
        },
        "CVE": {
            "description": "A comma separated list of CVEs addressed by the retrieved software, as listed by Dell."
        },
        "DetailsUrl": {
            "description": "A url leading to the details page for the retrieved driver."
        },
    }

    __doc__ = description

    def main(self):
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json;charset=utf-8",
        }
        osCode = self.env.get("OS_CODE", self.input_variables["OS_CODE"]["default"])
        family = self.env.get("FAMILY", self.input_variables["FAMILY"]["default"])
        model = self.env.get("MODEL", self.input_variables["MODEL"]["default"])
        formFactor = self.env.get(
            "FORM_FACTOR", self.input_variables["FORM_FACTOR"]["default"]
        )
        if (self.env.get("PRODUCT_CODE_OVERRIDE") or "") > "":
            productCode = self.env.get("PRODUCT_CODE_OVERRIDE")
        else:
            productCode = "{}-{}-{}".format(family, model, formFactor)

        category = self.env.get("CATEGORY", self.input_variables["CATEGORY"]["default"])
        fileType = self.env.get(
            "FILE_TYPE", self.input_variables["FILE_TYPE"]["default"]
        )
        nameRePattern = self.env.get(
            "DRIVER_NAME_RE_PATTERN",
            self.input_variables["DRIVER_NAME_RE_PATTERN"]["default"],
        )
        fileNameRePattern = self.env.get(
            "DRIVER_FILE_NAME_RE_PATTERN",
            self.input_variables["DRIVER_FILE_NAME_RE_PATTERN"]["default"],
        )
        baseUrl = self.env.get("DELL_BASE_URL", DELL_BASE_URL)

        self.output("Constructing URL", verbose_level=3)
        driverSearchUrl = (
            baseUrl
            + "productCode={}".format(str(productCode))
            + "&oscode={}".format(str(osCode))
        )

        self.output(
            "Retrieving software products from Dell URL ({})".format(driverSearchUrl),
            verbose_level=3,
        )

        try:
            blob = self.download(driverSearchUrl, text=True, headers=headers)
            softwares = json.loads(blob)
            self.output(
                "Retrieved {} packages for Dell product with code: {}".format(
                    len(softwares["DriverListData"]), softwares["ProductCode"]
                ),
                verbose_level=3,
            )
            # Select array item by product name
            selected_products = list()
            for product in softwares["DriverListData"]:
                self.output(
                    'Desired Type: "{}"\t\tFound Type:"{}"'.format(
                        fileType, product["FileFrmtInfo"]["FileType"]
                    ),
                    verbose_level=4,
                )

                if str(product["FileFrmtInfo"]["FileType"]).lower() != fileType.lower():
                    self.output("File Type does not match.", verbose_level=4)
                    continue

                if product["Cat"] != category:
                    self.output("Category does not match.", verbose_level=4)
                    continue

                if (osCode.upper() in map(str.upper, product["AppOses"])) != True:
                    self.output("OS does not match.", verbose_level=4)
                    continue

                self.output(
                    "Matching ({}) against pattern ({})".format(
                        product["DriverName"], nameRePattern
                    ),
                    verbose_level=3,
                )
                self.output(
                    str(
                        re.findall(
                            re.compile(nameRePattern), str(product["DriverName"])
                        )
                    ),
                    verbose_level=3,
                )
                if (
                    len(
                        re.findall(
                            re.compile(nameRePattern), str(product["DriverName"])
                        )
                    )
                    == 0
                ):
                    self.output(
                        "Driver Name does not match the supplied RegEx pattern.",
                        verbose_level=4,
                    )
                    continue

                self.output(
                    "Matching ({}) against pattern ({})".format(
                        product["FileFrmtInfo"]["FileName"], fileNameRePattern
                    ),
                    verbose_level=3,
                )
                self.output(
                    str(
                        re.findall(
                            re.compile(fileNameRePattern),
                            str(product["FileFrmtInfo"]["FileName"]),
                        )
                    ),
                    verbose_level=3,
                )
                if (
                    len(
                        re.findall(
                            re.compile(fileNameRePattern),
                            str(product["FileFrmtInfo"]["FileName"]),
                        )
                    )
                    == 0
                ):
                    self.output(
                        "Driver File Name does not match the supplied RegEx pattern.",
                        verbose_level=4,
                    )
                    continue

                self.output(
                    "Found a matching product: {}".format(product["DriverName"]),
                    verbose_level=2,
                )
                selected_products.append(product)

            self.output(
                "{} products found.".format(len(selected_products)), verbose_level=2
            )
            if len(selected_products) == 0:
                ProcessorError("No products found.")
            elif len(selected_products) > 1:
                ProcessorError(
                    "Multiple products found. Could not determine the correct software desired."
                )

            software = selected_products[0]
            self.output("Selected product {}".format(software["DriverName"]))

            dellVersion = software["DellVer"]
            self.output(
                "Parsing Version string as given by Dell: {}".format(dellVersion),
                verbose_level=2,
            )

            if fnmatch(dellVersion, "*,*"):
                self.output("Splitting version", verbose_level=3)
                splitVersion = dellVersion.split(",")
                versionString = splitVersion[0].strip()
                versionFriendly = splitVersion[1].strip()
            else:
                self.output("Version does not requiring splitting.")
                versionString = dellVersion.strip()
                versionFriendly = dellVersion.strip()

            if self.env.get("POPULATE_CVES") == True:
                detailsUrl = DELL_DETAILS_BASE_URL + software["DriverId"]
                self.output(
                    "Attempting to parse the driver details page to retrieve CVE details. ({})".format(
                        detailsUrl
                    ),
                    verbose_level=2,
                )
                detailsBlob = self.download(detailsUrl, text=True)
                cvePattern = r"CVE\-\d{4}\-\d*"
                cveMatches = re.findall(cvePattern, detailsBlob, re.IGNORECASE)

                dsaLinkMatches = re.findall(
                    r"\<a\ href\=\"(?P<url>https:\/\/[\w~_.\/-]+)\"\>",
                    software["BrfDesc"],
                    re.IGNORECASE,
                )
                if len(dsaLinkMatches) > 0:
                    self.output(
                        "This appears to be a Dell Security Advisory. Searching linked url(s) for linked CVEs.",
                        verbose_level=3,
                    )
                    for dsaUrl in dsaLinkMatches:
                        self.output("Searching url: {}".format(dsaUrl), verbose_level=2)
                        dsaBlob = self.download(dsaUrl, text=True)
                        dsaLinkedCves = re.findall(cvePattern, dsaBlob, re.IGNORECASE)
                        self.output(
                            "{} CVEs found on page.".format(len(dsaLinkedCves)),
                            verbose_level=3,
                        )
                        cveMatches += dsaLinkedCves

                cves = ",".join(cveMatches)
                self.output(
                    "{} total linked CVEs found for this package. CVEs: {}".format(
                        len(cveMatches), cves
                    ),
                    verbose_level=3,
                )

            else:
                self.output(
                    "Declining to search for CVEs mitigated by this package.",
                    verbose_level=3,
                )
                cves = None

            # Set output variables
            self.env["DriverId"] = software["DriverId"] or ""
            self.env["DriverName"] = software["DriverName"] or ""
            self.env["Type"] = software["Type"] or ""
            self.env["TypeName"] = software["TypeName"] or ""
            self.env["Importance"] = software["Imp"] or ""
            self.env["ImportanceId"] = software["ImpId"] or ""
            self.env["ReleaseDate"] = software["ReleaseDateValue"] or ""
            self.env["RequiresRestart"] = str(bool(software["IsRestart"])) or "False"
            self.env["DellVersion"] = software["DellVer"] or ""
            self.env["Version"] = versionString or ""
            self.env["VersionFriendly"] = versionFriendly or ""
            self.env["DellDescription"] = software["BrfDesc"] or ""
            self.env["url"] = software["FileFrmtInfo"]["HttpFileLocation"] or ""
            self.env["CatName"] = software["CatName"] or ""
            self.env["FileId"] = software["FileFrmtInfo"]["FileId"] or ""
            self.env["FileName"] = software["FileFrmtInfo"]["FileName"] or ""
            self.env["FileFormatName"] = (
                software["FileFrmtInfo"]["FileFormatName"] or ""
            )
            self.env["FileSize"] = software["FileFrmtInfo"]["FileSize"] or ""
            self.env["ConvertedFileSize"] = (
                software["FileFrmtInfo"]["ConvertedFileSize"] or ""
            )
            self.env["CVE"] = cves or ""
            self.env["DetailsUrl"] = detailsUrl or ""
            self.env["ProductFamily"] = family or ""
            self.env["ProductModel"] = model or ""
            self.env["FormFactor"] = formFactor or ""
            self.env["ProductCode"] = productCode or ""

        except Exception as e:
            self.output("Unexpected JSON encountered.")
            raise e


if __name__ == "__main__":
    PROCESSOR = DellSoftwareUrlProvider()
    PROCESSOR.execute_shell()
