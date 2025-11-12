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

__all__ = ["McmAppGetter"]

class McmAppGetter(Processor):
    description = """AutoPkg Processor to connect to an MCM Admin Service and retrieve an application object, if it exists."""
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
        },
        "application_name": {
            "required": True,
            "description": "The name of the application in MCM to search for."
        },
        "export_properties": {
            "required": False,
            "default": {
                "existing_app_ci_id": "CI_ID",
                "existing_app_sdmpackagexml": "SDMPackageXML",
                "existing_app_securityscopes": "SecuredScopeNames"
            },
            "description": "A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output. The key name specified will be used as the AutoPkg variable name; the value is the property name to retrieve from the MCM application."
        }
        #"mcm_site_server_fqdn_is_cmg": {
        #    "required": False,
        #    "description": "If set to True, the fqdn is interpreted as a cloud management gateway.",
        #    "default": False
        #},
        #"mcm_site_code": {
        #    "required": True,
        #    "description": "The Site Code for the mcm site."
        #},
        #"output_var_name": {
        #    "required": False,
        #    "description":
        #        "Output variable name. Defaults to 'mcm_scope_id'"
        #}
    }
    output_variables = {
        "mcm_scope_id": {
            "description": "The scope id returned from the site."
        }
    }
    
    __doc__ = description

    def convert_site_id_to_scope_id(self,siteId:str) -> str:
        siteIdGuid = siteId.replace('{','').replace('}','')
        scopeId = f"ScopeId_{siteIdGuid}"
        return scopeId

    def get_mcm_ntlm_auth(self, keychainServiceName:str, keychainUsername:str) -> HttpNtlmAuth:
        password = keyring.get_password(keychainServiceName,keychainUsername)
        return HttpNtlmAuth(keychainUsername,password)

    def main(self):
        """McmAppGetter Main Method"""

        try:
            self.output("Generating headers.",3)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            self.output("Checking supplied parameters",3)
            keychainServiceName = self.env.get("keychain_password_service", self.input_variables["keychain_password_service"]["default"])
            keychainUsername = self.env.get("keychain_password_username",self.env.get("MCMAPI_USERNAME",''))
            fqdn = self.env.get("mcm_site_server_fqdn", '')

            if (fqdn == None or fqdn == ''):
                raise ProcessorError("mcm_site_server_fqdn cannot be blank")

            if (keychainServiceName == None or keychainUsername == ''):
                raise ProcessorError("keychain_password_service cannot be blank")

            if (keychainUsername == None or keychainUsername == ''):
                raise ProcessorError("keychain_password_username cannot be blank")

            self.output(f"Attempting to get SiteInfo from {fqdn}",2)
            url = f"https://{fqdn}/AdminService/wmi/SMS_Identification.GetSiteID"
            ntlm = self.get_mcm_ntlm_auth(keychainServiceName=keychainServiceName,keychainUsername=keychainUsername)
            response = requests.request(
                method='GET',
                url=url,
                auth=ntlm,
                headers=headers,
                timeout=10,
                verify=False
            )
            siteInfoJsonResponse = response.json()
            siteId = siteInfoJsonResponse.get('SiteID')
            self.output(f"Converting {siteId} to scope id and setting it as mcm_scope_id",2)
            self.env["mcm_scope_id"] = self.convert_site_id_to_scope_id(siteId=siteId)
            application_name = self.env.get("application_name")
            self.output(f"Attempting to get application ({application_name}) from {fqdn}", 2)
            url = f"https://{fqdn}/AdminService/wmi/SMS_Application"
            body = {"$filter": f"LocalizedDisplayName eq '{application_name}' and IsLatest eq true",'$select': "CI_ID"}
            self.output(f"Body: {body}", 3)
            appSearchResponse = requests.request(
                method='GET',
                url=url,
                auth=ntlm,
                headers=headers,
                verify=False,
                params=body
            )
            self.output(f"Done searching for application. {type(appSearchResponse).__name__} type object returned.",3)
            appSearchJson = appSearchResponse.json()
            appSearchValue = appSearchJson.get('value',[])
            self.output(f"Getting app with ci_id: {appSearchValue[0].get('CI_ID')}", 3)
            if len(appSearchValue) == 1:
                appUrl = f"https://{fqdn}/AdminService/wmi/SMS_Application({appSearchValue[0].get('CI_ID')})"
                app = requests.request(
                    method='GET',
                    url=appUrl,
                    auth=ntlm,
                    headers=headers,
                    verify=False
                )
                appValue = app.json()['value'][0]
            if len(appSearchValue) > 1:
                raise ProcessorError('Non-unique application object was returned from MCM.')
            elif len(appSearchValue) == 0:
                self.output("No application was returned. Specified export properties will be populated with null/empty values.")
            export_properties:dict = self.env.get('export_properties',self.input_variables['export_properties']['default'])
            self.output("Setting the value of specified export properties",2)
            for k in list(export_properties.keys()):
                if appValue.__contains__(export_properties[k]) == False:
                    self.output(f"Property {export_properties[k]} does not exist on the retrieved object.", 2)
                    continue
                self.output(f"Setting '{k}' export property from the value of '{export_properties[k]}' property on the retrieved application", 3)
                self.env[k] = appValue.get(export_properties[k],None) if len(appSearchValue) == 1 else None
                self.output(f"{k} is empty: {self.env.get(k) is None}")
                
        except Exception as e:
            self.output("Failed to retrieve the application from the MCM site.")
            raise e

if __name__ == "__main__":
    processor = McmAppGetter()
    processor.execute_shell()