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

from McmApiLib.McmSDMPackageXMLGeneratorBase import (  # pylint: disable=import-error, wrong-import-position
    McmSDMPackageXMLGeneratorBase,
)

__all__ = ["McmSDMPackageXmlGenerator"]

class McmSDMPackageXMLGenerator(McmSDMPackageXMLGeneratorBase):
    description = "Generate an SDMPackageXML string which represents an MCM Application object."
    
    __doc__ = description

    input_variables = {
        "mcm_application_configuration": {
            "required": True, 
            "description": (
                "A nested dictionary object representing the configuration for the application."
            ), 
        }, 
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
        "mcm_scope_id": {
            "required": False, 
            "description": "The authoring scope id for objects in the target MCM site."
        }, 
        "existing_app_sdmpackagexml": {
            "required": False, 
            "description": "The SDMPackageXML property of an existing application which should be updated.", 
            "default": None
        }, 
        "existing_app_ci_id": {
            "required": False, 
            "description": "The CI_ID property of the application which should be updated.", 
            "default": None
        }
    }
    output_variables = {
        "SDMPackageXML": {"description": "Serialized XML string representing an application object."}, 
        "mcm_scope_id": {"description": "The authoring scope id for objects in the target MCM site."}, 
        "mcm_application": {"description": "A dictionary representation of the mcm application"}, 
        "mcm_application_ci_id": {"description": "The CI_ID where the application should be posted. 0 indicates a new application."}, 
    }

    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = McmSDMPackageXMLGenerator()
    PROCESSOR.execute_shell()
