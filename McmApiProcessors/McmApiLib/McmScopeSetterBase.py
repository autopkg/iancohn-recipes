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

from autopkglib import (  # pylint: disable=import-error
    ProcessorError,
)

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import platform
import sys

sys.path.insert(0,os.path.dirname(__file__))
from McmApiLib.McmApiBase import ( #noqa: E402
    McmApiBase
)

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

import requests

class McmScopeSetterBase(McmApiBase):
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.fqdn = self.env.get('mcm_site_server_fqdn')

        self.action = self.env.get('action',self.input_variables['action']['default']).lower()
        if self.input_variables['action']['options'].__contains__(self.action.lower()) == False:
            raise ProcessorError(f"'action' must be one of {', '.join(self.input_variables['action']['options'])}")
        self.object_key = self.env.get("object_key", self.env.get('app_model_name',''))
        if self.object_key is None or self.object_key == '' or self.object_key == '':
            self.output(f"Supplied object_key: {self.object_key}")
            raise ProcessorError("object_key is required")
        self.current_scope_names = self.env.get("existing_security_scopes",self.env.get('app_securityscopes',[]))
        if self.current_scope_names is None or isinstance(self.current_scope_names, list) == False:
            self.output(f"Current scope names: {self.current_scope_names}", 3)
            raise ProcessorError("existing_security_scopes is required")
        self.action_scope_names = self.env.get('security_scopes',self.env.get('security_scopes',[]))
        if self.action_scope_names is None or isinstance(self.action_scope_names, list) == False or len(self.action_scope_names) == 0:
            raise ProcessorError("security_scopes is required, and must have at least one item.")
        self.object_type_id = self.get_mcm_object_type_id(object_key=self.object_key)
        self.all_scopes = self.get_mcm_security_scopes()

    def get_mcm_security_scopes(self) -> dict:
        """Connect to MCM and retrieve an object to enable mapping
        security scope name by id and id by security scope name
        """
        self.output("Retrieving possible security scopes", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategory"
        sms_secured_categories = requests.request(
            method = 'GET',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
        )
        return {
            "scopes": [{"category_id":c['CategoryID'], "category_name": c['CategoryName']} for c in (sms_secured_categories.json().get('value',[]))],
            "by_category_id": {d['CategoryID']: d['CategoryName'] for d in (sms_secured_categories.json().get('value',[]))},
            "by_category_name_lower": {e['CategoryName'].lower(): e['CategoryID'] for e in (sms_secured_categories.json().get('value',[]))},
        }

    def execute(self):
        self.initialize_all()
        self.final_scope_names = []
        self.remove_scope_names = []
        self.add_scope_names = []
        for s in self.action_scope_names:
            if  self.action == 'remove' and self.current_scope_names.__contains__(s):
                self.output(f"Scope {s} will be removed", 3)
                self.remove_scope_names.append(s)
            elif ['add','replace'].__contains__(self.action) and self.current_scope_names.__contains__(s) == False:
                self.output(f"Scope {s} will be added", 3)
                self.add_scope_names.append(s)
            if ['add','replace'].__contains__(self.action) and self.final_scope_names.__contains__(s) == False:
                self.final_scope_names.append(s)
            
        for s in self.current_scope_names:
            if self.action == 'replace' and self.final_scope_names.__contains__(s) == False:
                self.output(f"Scope {s} will be removed", 3)
                self.remove_scope_names.append(s)
            elif self.action == 'add' and self.final_scope_names.__contains__(s) == False:
                self.output(f"Scope {s} will be kept", 3)
                self.final_scope_names.append(s)
        self.output(f"Final security scopes will be set to: {', '.join(self.final_scope_names)}", 2)
        if self.final_scope_names == self.current_scope_names:
            self.output("Current scopes match desired scopes. Nothing to do.", 1)
            return
        if len(self.add_scope_names) == 0:
            self.output("No scopes to add", 2)
        # Add Scopes
        add_url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership.AddMemberships"
        add_scope_ids = [self.all_scopes['by_category_name_lower'][name.lower()].upper() for name in self.add_scope_names ]
        if len(self.add_scope_names) == 0:
            self.output("No security scopes to add.", 3)
        else:
            self.output("Adding security scopes", 2)
        for add in add_scope_ids:
            add_body = {
                    "ObjectIDs": [self.object_key],
                    "ObjectTypeIDs": [self.object_type_id],
                    "CategoryIDs": [add]
                }
            self.output("Adding a security scope", 3)
            add_response = requests.request(
                method = 'POST',
                url = add_url,
                auth = self.get_mcm_auth(),
                headers = self.headers,
                json = add_body,
                verify = self.get_ssl_verify_param()
            )
            self.output(f"Add security scopes response: {add_response.reason}", 3)
            add_response.raise_for_status()
        self.output("Done adding any security scopes", 3)
        # Remove scopes
        remove_scope_ids = [self.all_scopes['by_category_name_lower'][name.lower()].upper() for name in self.remove_scope_names ]
        if len(self.remove_scope_names) == 0:
            self.output("No security scopes to remove.", 3)
            return
        else:
            self.output("Removing security scopes", 2)
        for remove in remove_scope_ids:
            remove_url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership.RemoveMemberships"
            self.output("Removing scope ids",3)
            remove_json = {
                    "ObjectIDs": [self.object_key],
                    "ObjectTypeIDs": [self.object_type_id],
                    "CategoryIDs": [remove]
                }
            self.output("Removing a security scope", 3)
            remove_response = requests.request(
                method = 'POST',
                url = remove_url,
                headers = self.headers,
                auth = self.get_mcm_auth(),
                json = remove_json,
                verify = self.get_ssl_verify_param()
            )
            self.output(f"Remove security scopes response: {remove_response}", 3)
            remove_response.raise_for_status()
        self.output("Done removing security scopes", 3)


if __name__ == "__main__":
    PROCESSOR = McmScopeSetterBase()
    PROCESSOR.execute_shell()