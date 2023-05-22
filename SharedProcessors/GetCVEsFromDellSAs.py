#!/usr/bin/python
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

# Factored for Python 3
from __future__ import absolute_import

import json
import re
from fnmatch import fnmatch
'''
url: https://www.dell.com/support/security/en-us/Security/DdsArticle
body: 
Advisory:false
FromDate:
Information:false
Notices:false
ProprietaryComponent:false
PublishFromDate:
PublishToDate:
SearchString:DSA-2023-167
ThirdpartyComponent:false
ToDate:
UpdateFromDate:
UpdateToDate:
isFirstCall:true
pageNumber:1
recordsPerPage:10
selection:1234
severityList:
response:
{
    "AdvisoriesModelData": [
        {
            "Severity": "Medium",
            "SeverityOrder": 3,
            "RedirectUrl": "<a class=\"dds__link\" name=\"DSA-2023-167: Precision 7920 Rack and 7920 XL Rack Security Update for an Out of Bounds Write Vulnerability\" target=\"_blank\" href=\"https://www.dell.com/support/kbdoc/en-us/000213287/dsa-2023-167-dell-client\">DSA-2023-167: Precision 7920 Rack and 7920 XL Rack Security Update for an Out of Bounds Write Vulnerability</a>",
            "Type": "Advisory",
            "DellProprietaryCode": "Proprietary Code",
            "CombinedProductList": "oth-xlr7920,precision-7920r-workstation",
            "AccessLevel": "10",
            "CVEIdentifier": "CVE-2023-25537",
            "ArticleId": "000213287",
            "Title": "DSA-2023-167: Precision 7920 Rack and 7920 XL Rack Security Update for an Out of Bounds Write Vulnerability",
            "FirstPublished": "2023-05-10T17:13:57",
            "LastPublished": "2023-05-19T16:12:59",
            "UrlName": "dsa-2023-167-dell-client"
        }
    ],
    "SecurityNoticesCount": 0,
    "AdvisoryCount": null,
    "InformationCount": 0,
    "page": {
        "size": 0,
        "totalElements": 1,
        "totalPages": 0,
        "number": 0
    },
    "ToolTipArticleLock": "Some Dell Technologies resources are permission-based and can only be accessed when you’re signed into your account.",
    "productNameFilter": [
        "7920 XL Rack",
        "Precision 7920 Rack"
    ]
}
'''