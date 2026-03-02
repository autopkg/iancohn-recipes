#!/usr/local/autopkg/python
# pylint: disable=invalid-name
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

import os.path
import sys

# to use a base module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
sys.path.insert(0, os.path.dirname(__file__))

from McmApiLib.McmAppGetterBase import (  # pylint: disable=import-error, wrong-import-position
    McmAppGetterBase,
)

__all__ = ["McmAppGetter"]

class McmAppGetter(McmAppGetterBase):
    description = """AutoPkg Processor to connect to an MCM Admin
    Service and retrieve an application object, if it exists
    """
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
        "mcm_ssl_verification": {
            "required": False,
            "description": 
                "Either a boolean, in which case it controls whether we verify the "
                "server’s TLS certificate, or a string, in which case it must be a "
                "path to a CA bundle to use",
            "default": False
        },
        "krb_config_type": {
            "required": False,
            "description": "How to generate the kerberos configuration.",
            "options": ["auto","query","custom"],
            "default": ["auto"]
        },
        #krb_config_path
        "application_name": {
            "required": True,
            "description": "The name of the application in MCM to search for."
        },
        "mcm_app_getter_export_properties": {
            "required": False,
            "default": {
                "existing_app_ci_id": {"type": "property", "raise_error": False,"options": {"property": "CI_ID"}},
                "existing_app_sdmpackagexml": {"type": "property", "raise_error": False,"options": {"property": "SDMPackageXML"}},
                "existing_app_securityscopes": {"type": "property", "raise_error": False,"options": {"property": "SecuredScopeNames"}}
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
        },
        "mcm_application_found": {
            "description": "Returns True if the application was found in the MCM instance, otherwise, returns false."
        }
    }
    
    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = McmAppGetter()
    PROCESSOR.execute_shell()
