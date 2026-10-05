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

#from copy import deepcopy
#from ctypes import c_int32
#from datetime import datetime, timezone
#from enum import Enum, auto
from io import BytesIO
#import json
#from os import path, walk, unlink
#from pathlib import Path
import platform
import zipfile

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


import requests
import keyring
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

def setup_credential():
    system = platform.system()
    if system == "Darwin":
        try:
            from keyring.backends import macOS
            keyring.set_keyring(macOS.Keyring())
        except ImportError as e:
            raise e
    elif system == "Windows":
        try:
            from keyring.backends import Windows
            keyring.set_keyring(Windows.WinVaultKeyring())
        except ImportError as e:
            raise e


setup_credential()

from autopkglib import ( # pylint: disable=import-error
    Processor,
    ProcessorError,
)

class IntuneProcessorBase(Processor):
    """Common functions needed for Intune processors"""
    def initialize_export_properties(self,input_variable_name: str):
        self.export_properties = self.env.get(input_variable_name)
    
    def strip_namespaces(self,element):
        """Remove all namespaces from an XML element for easier XPath
        query support
        """
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element

    def set_export_properties(self):
        if self.__getattribute__('response_value') is None:
            raise ProcessorError("No response value")
        self.output("Attempting to set export properties", 2)
        for k in list(self.export_properties.keys()):
            k_type = self.export_properties.get(k,{}).get(
                'type','TypeNotFound'
                )
            self.output(
                (f"Getting export property '{k}' from a {k_type} "
                "expression"),
                3
                )
            eval_property = self.export_properties[k]['options']['property']
            if self.export_properties[k]["type"] == 'property':
                if (not self.response_value.__contains__(eval_property)
                    and self.export_properties[k].get(
                        'raise_error', False
                        ) == True
                        ):
                    raise ProcessorError(
                        f"Property {eval_property} does not exist on "
                        "the retrieved object. Valid properties are: "
                        f"{', '.join(list(self.response_value.keys()))}")
                value = self.response_value.get(eval_property, None)
            elif self.export_properties[k]["type"] == 'xpath':
                if not self.response_value.__contains__(
                    eval_property
                    ) and self.export_properties[k].get(
                        'raise_error',False
                        ) == True:
                    raise ProcessorError(
                        f"Property {eval_property} "
                        "does not exist on the retrieved object."
                        )
                elif not self.response_value.__contains__(eval_property):
                    value = None
                else:
                    try:
                        xml_element = etree.XML(
                            self.response_value.get(eval_property,'').replace(
                                (
                                    '<?xml version="1.0" encoding="'
                                    'utf-16"?>'
                                    ),
                                '',
                                1).replace(
                                    (
                                        "<?xml version='1.0' "
                                        "encoding='utf-16'?>"
                                    ),
                                    '',
                                    1
                                    )
                                )
                        if self.export_properties[k]['options'].get(
                            'strip_namespaces',
                            False
                            ) == True:
                            self.output(
                                "Stripping namespaces from XML element "
                                "before evaluating xpath expression",
                                3
                                )
                            xml_element = self.strip_namespaces(
                                xml_element
                                )
                        xml_xpath_expr = self.export_properties[k][
                            'options']['expression']
                        results = xml_element.xpath(xml_xpath_expr)
                        self.output(
                            "Got results from xpath expression",
                            3
                            )
                        if len(results) == 0:
                            if self.export_properties[k].get(
                                    'raise_error', False) == True:
                                self.output(
                                    "XPath expression returned no "
                                    "results, and raise_error was set "
                                    "to True",
                                    3
                                    )
                                raise ProcessorError(
                                    "XPath expression "
                                    f"{xml_xpath_expr} "
                                    f"on property {eval_property} "
                                    "returned no results.")
                            else:
                                self.output(
                                    "XPath expression returned no "
                                    "results, and raise_error was set "
                                    "to False",
                                    3
                                    )
                                value = None
                        else:
                            select_value_index = str(
                                self.export_properties[k]['options'].get(
                                    'select_value_index',
                                    '*'
                                    )
                                    )
                            self.output(
                                f"Selecting item {select_value_index} "
                                f"from ({len(results)}) "
                                "results from xpath expression",
                                3
                                )
                            if str(select_value_index) == '*':
                                value = [str(r) for r in results]
                            else:
                                try:
                                    self.output(
                                        "Selecting item "
                                        f"{select_value_index} from "
                                        "xpath results",
                                        3
                                        )
                                    index = int(select_value_index)
                                    value = str(results[index])
                                except Exception as e:
                                    raise ProcessorError(
                                        "Failed to select index "
                                        f"{select_value_index} from "
                                        "xpath results for expression "
                                        f"{xml_xpath_expr} on property "
                                        f"{eval_property}. "
                                        f"Error: {str(e)}"
                                        )
                    except Exception as e:
                        if self.export_properties[k].get(
                            'raise_error',False) == True:
                            raise ProcessorError(
                                "Failed to evaluate xpath expression "
                                f"{xml_xpath_expr} on property "
                                f"{eval_property}. Error: {str(e)}")
                        else:
                            value = None              
            truncated_value = value if len(str(value)) <= 32 \
                else (str(value)[0:31] + '...') 
            self.output(
                f"Setting '{k}' export property from a(n) "
                f"{self.export_properties[k]['type']} expression which "
                f"evaluated to ({truncated_value}) on the retrieved "
                "application",
                3
                )
            self.env[k] = value
        self.output("Finished setting export properties", 2)
    
    @staticmethod
    def pad_pkcs7(data: bytes, block_size_bits: int = 128) -> bytes:
        """Pads input byte array to match AES block size requirements using PKCS#7."""
        padder = padding.PKCS7(block_size_bits).padder()
        return padder.update(data) + padder.finalize()

    @staticmethod
    def create_source_zip(source_folder: str) -> bytes:
        """
        Zips all non-hidden files within the source directory into an in-memory buffer.
        Ensures ZIP path separators use forward slashes (POSIX) for cross-platform compliance.
        """
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(source_folder):
                for file in files:
                    if file.startswith("."):
                        continue  # Ignore OS hidden files (.DS_Store, etc.)
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, source_folder)
                    posix_path = rel_path.replace("\\", "/")
                    zf.write(abs_path, posix_path)
        return zip_buffer.getvalue()

    @staticmethod
    def encrypt_content(unencrypted_bytes: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypts content using AES-256-CBC mode with PKCS#7 padding."""
        padded_data = IntuneProcessorBase.pad_pkcs7(unencrypted_bytes, 128)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def get_intune_app_by_name(self,application_name : str):
        self.output(f'Searching Intune for application with name [{application_name}]',3)
        url = f"https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps"
        body = {"$filter": f"displayName eq '{application_name}'"}
        app_search_response = requests.request(
            method = 'GET', 
            url = url, 
            headers = self.graph_headers,
            params = body
        )
        if app_search_response.status_code != 200:
            raise ProcessorError(
                f"Status [{str(app_search_response.status_code) or ''}]"
                f"\tReason [{app_search_response.reason or ''}]"
            )
        if len(app_search_response.json()['value']) > 1:
            raise ProcessorError(
                "Multiple application objects were "
                "returned from the initial query"
                )
        if len(app_search_response.json()['value']) == 0:
            self.output("No applications were found.", 2)
            self.response_value = {}
            return

        app_search_value = app_search_response.json()['value'][0]
        self.response_value = app_search_value
        self.output("Found application", 3)
        return
    
    def initialize_graph_auth(self):
        self.output("Authenticating to Microsoft Graph API", 2)
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        body = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        
        token_response = requests.request(
            method = 'POST',
            #headers = {'Content-Type': 'application/json','Accept':'application/json'},
            url = token_url,
            data=body
        )
        self.output(f"HTTP Status: <{token_response.status_code}>", 3)
        if not token_response.ok:
            self.output(f"Error Message: {token_response.text}")
            token_response.raise_for_status()
        self.access_token_type = token_response.json()['token_type']
        self.access_token_expires_in = token_response.json()['expires_in']
        self.access_token = token_response.json()['access_token']
        self.graph_headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }
        self.output("Graph API Authentication completed successfully", 3)

    
    def initialize_auth(self):
        self.output("Checking supplied authentication parameters", 3)
        self.intune_app_keychain_service = self.env.get('intune_app_keychain_service')
        self.intune_app_keychain_username = self.env.get('intune_app_keychain_username')
        if (self.intune_app_keychain_service == None or self.intune_app_keychain_service == ''):
            raise ValueError("intune_app_keychain_service cannot be blank")
        if (self.intune_app_keychain_username == None or self.intune_app_keychain_username == ''):
            raise ValueError("intune_app_keychain_username cannot be blank")
        
        self.tenant_id = self.env.get('intune_tenant_id')
        self.client_id = self.env.get('intune_app_client_id')
        self.client_secret = keyring.get_password(self.intune_app_keychain_service, self.intune_app_keychain_username)
        
        self.initialize_graph_auth()

if __name__ == "__main__":
    PROCESSOR = IntuneProcessorBase()
    PROCESSOR.execute_shell()