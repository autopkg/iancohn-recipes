#!/usr/local/autopkg/python
# pylint: disable=invalid-name
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

import os.path
import sys

# to use a base module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
sys.path.insert(0, os.path.dirname(__file__))

from IntuneLib.IntuneAppGetterBase import (  # pylint: disable=import-error, wrong-import-position
    IntuneAppGetterBase,
)

__all__ = ["IntuneAppGetter"]

class IntuneAppGetter(IntuneAppGetterBase):
    description = """AutoPkg Processor to connect to an MCM Admin
    Service and retrieve an application object, if it exists
    """
    input_variables = {
        "intune_app_keychain_service": {
            "required": False,
            "description": "The service name used to store the password. Defaults to com.github.autopkg.iancohn-recipes.mcmapi",
            "default": 'com.github.autopkg.iancohn-recipes.intuneprocessors'
        },
        "intune_app_keychain_username": {
            "required": False,
            "description": "The username of the credential to retrieve."
        },
        "intune_app_client_id": {
            "required": True,
            "description": "The client id of the app registration with permissions to Intune"
        },
        "intune_tenant_id": {
            "required": True,
            "description": "The tenant id for the Intune tenant and app registration",
        },
        "application_name": {
            "required": True,
            "description": "The name of the application in MCM to search for."
        },
        "intune_app_getter_export_properties": {
            "required": False,
            "default": {
                "existing_app_id": {"type": "property", "raise_error": False,"options": {"property": "id"}},
                "existing_app_install_cli": {"type": "property", "raise_error": False,"options": {"property": "installCommandLine"}},
                "existing_app_publishing_state": {"type": "property", "raise_error": False,"options": {"property": "publishingState"}},
                "existing_app_content_version": {"type": "property", "raise_error": False,"options": {"property": "committedContentVersion"}},
            },
            "description": 
                "A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output. "
                "Each key name specified will be used as the AutoPkg variable name; each value should be populated by a dictionary "
                "representing how to retrieve the property from the application. For Intune apps, only 'property' is supported. "
                "'raise_error' specifies whether to raise an error if the property cannot be found. "
                ""
                "'property' type options require an 'expression' option specifying the property name to retrieve from the application. "
                "'xpath' type options require a 'property' option specifying the property name (generally 'SDMPackageXML') to run the xpath query against, and an 'expression'. "
        }
    }
    output_variables = {
        "intune_application_found": {
            "description": "Returns True if the application was found in the Intune instance, otherwise, returns false."
        }
    }
    
    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = IntuneAppGetter()
    PROCESSOR.execute_shell()
