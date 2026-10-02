#!/usr/local/autopkg/python
# -*- coding: utf-8 -*-
#
# Copyright 2026 Ian Cohn
# https://www.github.com/autopkg/iancohn-recipes
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

import atexit
#import string
#import random
import base64
from copy import deepcopy
from ctypes import c_int32
from datetime import datetime, timezone
from enum import Enum, auto
from io import BytesIO
import json
from os import path, walk, unlink
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import uuid

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

#import dns.resolver
import keyring
import requests
import smbclient
#from requests_gssapi import HTTPKerberosAuth, OPTIONAL
#from lxml import etree


from autopkglib import ( # pylint: disable=import-error
    Processor,
    ProcessorError,
)

class IntuneProcessorBase(Processor):
    """Common functions needed for Intune processors"""
    def initialize_auth(self):
        #self.initialize_ntlm_auth()
        self.output("Checking supplied parameters", 3)
        self.keychain_service_name = self.env.get("keychain_password_service")
        self.keychain_username = self.env.get("keychain_password_username", None) or self.env.get("MCMAPI_USERNAME", '')
        self.fqdn = self.env.get("mcm_site_server_fqdn", '')
        if (self.fqdn == None or self.fqdn == ''):
            raise ValueError("mcm_site_server_fqdn cannot be blank")
        if (self.keychain_service_name == None or self.keychain_service_name == ''):
            raise ValueError("keychain_password_service cannot be blank")
        if (self.keychain_username == None or self.keychain_username == ''):
            raise ValueError("keychain_password_username cannot be blank")
        self.password = keyring.get_password(self.keychain_service_name, self.keychain_username)
        self.initialize_gss_auth()

if __name__ == "__main__":
    PROCESSOR = IntuneProcessorBase()
    PROCESSOR.execute_shell()
