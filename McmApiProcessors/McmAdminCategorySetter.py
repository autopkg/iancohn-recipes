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

from McmApiLib.McmAdminCategorySetterBase import (  # pylint: disable=import-error, wrong-import-position
    McmAdminCategorySetterBase,
)

__all__ = ["McmScopeSetter"]

class McmAdminCategorySetter(McmAdminCategorySetterBase):
    description = """Sets the security scope of an MCM object.
    Not to be confused with McmScopeId, which references the
    site-wide scope id
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
        "object_key": {
            "required": False,
            "description": "The object key of the object to set security scopes on. Defaults to the value of app_model_name"
        },
        "action": {
            "required": False,
            "description": 
                "The action to take on the supplied object's category memberships.",
            "default": "replace",
            "options": ['add','remove','replace']
        },
        "admin_category_names": {
            "required": False,
            "description": "A list of category friendly names",
            "default": []
        },
        "current_admin_categories": {
            "required": False,
            "description": "Pre-populate the administrative categories assigned to the object to reduce queries to MCM. Defaults to the value of app_categories",
            "default": []
        },
    }
    output_variables = {}

    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = McmAdminCategorySetter()
    PROCESSOR.execute_shell()
