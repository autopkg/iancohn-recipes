#!/usr/local/autopkg/python
# -*- coding: utf-8 -*-
#
# Copyright 2025 Ian Cohn
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

import requests
import keyring

from requests_ntlm import HttpNtlmAuth
from autopkglib import Processor, ProcessorError

__all__ = ["McmScopeIdGetter"]

class McmScopeIdGetter(Processor):
    description = """AutoPkg Processor to connect to an MCM Admin Service and retrieve the site's scope id."""
    input_variables = {
        "keychain_password_service": {
            "required": False,
            "description": "The service name used to store the password. Defaults to com.github.autopkg.iancohn-recipes.mcmapi",
            "default": 'com.github.autopkg.iancohn-recipes.mcmapi'
        },
        "keychain_password_username": {
            "required": False,
            "description": "The username of the credential to retrieve. Defaults to %MCMAPI_USERNAME%"
        },
        "mcm_site_server_fqdn": {
            "required": True,
            "description": "The FQDN of the site server. Ex. mcm.domain.com"
        }
    }
    output_variables = {
        "mcm_scope_id": {
            "description": "The scope id returned from the site."
        }
    }
    
    __doc__ = description

    def convert_site_id_to_scope_id(self, site_id: str) -> str:
        """Convert a SiteID string to a scope id"""
        site_id_guid = site_id.replace('{','').replace('}','')
        scopeId = f"ScopeId_{site_id_guid}"
        return scopeId

    def get_mcm_ntlm_auth(
            self, keychain_service_name: str, 
            keychain_username: str) -> HttpNtlmAuth:
        """Get the credential from keychain using the supplied
        parameters and return an HttpNtlmAuth object from the retrieved
        details
        """
        password = keyring.get_password(keychain_service_name,keychain_username)
        return HttpNtlmAuth(keychain_username,password)

    def main(self):
        """McmScopeIdGetter Main Method"""

        try:
            #if (self.env.get("mcm_site_server_fqdn_is_cmg", self.input_variables["mcm_site_server_fqdn_is_cmg"]["default"]) != True):
            #    raise ValueError("CMGs are not currently supported")
            self.output("Generating headers.",3)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            self.output("Checking supplied parameters",3)
            keychain_service_name = self.env.get(
                "keychain_password_service", 
                self.input_variables["keychain_password_service"]["default"]
                )
            keychain_username = self.env.get(
                "keychain_password_username",
                self.env.get("MCMAPI_USERNAME",'')
                )
            fqdn = self.env.get("mcm_site_server_fqdn", '')

            if (fqdn == None or fqdn == ''):
                raise ValueError("mcm_site_server_fqdn cannot be blank")

            if (keychain_service_name == None or keychain_username == ''):
                raise ValueError("keychain_password_service cannot be blank")

            if (keychain_username == None or keychain_username == ''):
                raise ValueError("keychain_password_username cannot be blank")

            self.output(f"Attempting to get SiteInfo from {fqdn}",2)
            url = (
                f"https://{fqdn}/AdminService/wmi/SMS_Identification"
                ".GetSiteID"
            )
            ntlm = self.get_mcm_ntlm_auth(keychain_service_name=keychain_service_name,keychain_username=keychain_username)
            response = requests.request(
                method='GET',
                url=url,
                auth=ntlm,
                headers=headers,
                timeout=10,
                verify=False
            )
            json_response = response.json()
            site_id = json_response.get('SiteID')
            self.output(
                f"Converting {site_id} to scope id and setting it "
                "as mcm_scope_id",
                2)
            self.env["mcm_scope_id"] = self.convert_site_id_to_scope_id(
                site_id = site_id
                )

        except Exception as e:
            self.output("Failed to retrieve the scope id for the MCM site.")
            raise e

if __name__ == "__main__":
    processor = McmScopeIdGetter()
    processor.execute_shell()