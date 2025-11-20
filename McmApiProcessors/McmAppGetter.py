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
from lxml import etree

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
                "existing_app_ci_id": {"type": "property", "raise_error": False,"options": {"expression": "CI_ID"}},
                "existing_app_sdmpackagexml": {"type": "property", "raise_error": False,"options": {"expression": "SDMPackageXML"}},
                "existing_app_securityscopes": {"type": "property", "raise_error": False,"options": {"expression": "SecuredScopeNames"}}
            },
            "description": 
                "A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output. "
                "Each key name specified will be used as the AutoPkg variable name; each value should be populated by a dictionary "
                "representing how to retrieve the property from the MCM application. Supported retrieval types are 'property' and 'xpath'. "
                "'raise_error' specifies whether to raise an error if the property cannot be found. "
                ""
                "'property' type options require an 'expression' option specifying the property name to retrieve from the MCM application. "
                "'xpath' type options require a 'property' option specifying the property name (generally 'SDMPackageXML') to run the xpath query against, and an 'expression'. "
                "The 'strip_namespaces' option may also be specified to indicate whether to strip namespaces from the XML before evaluating the xpath expression."
                "The 'select_value_index' option may also be specified to indicate which value to select from the xpath result set (default is '*' (return all values as an array list)). "
                "Positive or negative integers may be specified to select a specific index from the result set (0-based). Negative integers count from the end of the result set (-1 is the last item))."
        }
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

    def strip_namespaces(element):
        """Remove all namespaces from an XML element for easier XPath query support"""
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element

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
            if len(appSearchValue) == 0:
                self.output('Application not found.', 2)
                return
            self.output(f"Getting app with ci_id: {appSearchValue[0].get('CI_ID')}", 3)
            if len(appSearchValue) == 1:
                appUrl = f"https://{fqdn}/AdminService/wmi/SMS_Application({appSearchValue[0].get('CI_ID')})"
                app = requests.request(
                    method='GET',
                    url=appUrl,
                    auth=ntlm,
                    headers=headers,
                    verify=False,
                    timeout=(2,5)
                )
            if len(appSearchValue) > 1:
                raise ProcessorError('Non-unique application object was returned from MCM.')
            elif len(appSearchValue) == 0:
                self.output("No application was returned. Specified export properties will be populated with null/empty values.")
            if app.status_code != 200:
                raise ProcessorError(f"An error was encountered whilst retrieving an application with CI_ID: {appSearchValue[0].get('CI_ID')}")
            app_value = app.json()['value'][0]
            export_properties:dict = self.env.get('export_properties',self.input_variables['export_properties']['default'])
            self.output("Setting the value of specified export properties",2)
            for k in list(export_properties.keys()):
                self.output(f"Getting export property '{k}' from a {export_properties.get(k,{}).get('type','TypeNotFound')} expression", 3)
                if export_properties[k]["type"] == 'property':
                    if not app_value.__contains__(export_properties[k]['options']['expression']) and export_properties[k].get('raise_error',False) == True:
                        raise ProcessorError(f"Property {export_properties[k]['options']['expression']} does not exist on the retrieved object. Valid properties are: {', '.join(list(app_value.keys()))}")
                    value = app_value.get(export_properties[k]['options']['expression'],None)
                elif export_properties[k]["type"] == 'xpath':
                    if not app_value.__contains__(export_properties[k]['options']['property']) and export_properties[k].get('raise_error',False) == True:
                        raise ProcessorError(f"Property {export_properties[k]['options']['property']} does not exist on the retrieved object.")
                    elif not app_value.__contains__(export_properties[k]['options']['property']):
                        value = None
                    else:
                        try:
                            xml_element = etree.XML(app_value.get(export_properties[k]['options']['property'],'').replace('<?xml version="1.0" encoding="utf-16"?>','',1).replace("<?xml version='1.0' encoding='utf-16'?>",'',1))
                            if export_properties[k]['options'].get('strip_namespaces',False) == True:
                                self.output("Stripping namespaces from XML element before evaluating xpath expression",3)
                                xml_element = McmAppGetter.strip_namespaces(xml_element)
                            xml_xpath_expr = export_properties[k]['options']['expression']
                            results = xml_element.xpath(xml_xpath_expr)
                            self.output("Got results from xpath expression",3)
                            if len(results) == 0:
                                if export_properties[k].get('raise_error',False) == True:
                                    self.output("XPath expression returned no results, and raise_error was set to True",3)
                                    raise ProcessorError(f"XPath expression {export_properties[k]['options']['expression']} on property {export_properties[k]['options']['property']} returned no results.")
                                else:
                                    self.output("XPath expression returned no results, and raise_error was set to False",3)
                                    value = None
                            else:
                                select_value_index = str(export_properties[k]['options'].get('select_value_index','*'))
                                self.output(f"Selecting item {select_value_index} from ({len(results)}) results from xpath expression",3)
                                if str(select_value_index) == '*':
                                    value = [str(r) for r in results]
                                else:
                                    try:
                                        self.output(f"Selecting item {select_value_index} from xpath results",3)
                                        index = int(select_value_index)
                                        value = str(results[index])
                                    except Exception as e:
                                        raise ProcessorError(f"Failed to select index {select_value_index} from xpath results for expression {export_properties[k]['options']['expression']} on property {export_properties[k]['options']['property']}. Error: {str(e)}")
                        except Exception as e:
                            if export_properties[k].get('raise_error',False) == True:
                                raise ProcessorError(f"Failed to evaluate xpath expression {export_properties[k]['options']['expression']} on property {export_properties[k]['options']['property']}. Error: {str(e)}")
                            else:
                                value = None              
                self.output(f"Setting '{k}' export property from a(n) {export_properties[k]['type']} expression which evaluated to ({value if len(str(value)) <= 32 else (str(value)[0:31] + '...') }) on the retrieved application", 3)
                self.env[k] = value
                
        except Exception as e:
            self.output("Failed to retrieve the application from the MCM site.")
            raise e

if __name__ == "__main__":
    processor = McmAppGetter()
    processor.execute_shell()