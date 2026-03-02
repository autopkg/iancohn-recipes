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
import requests

from autopkglib import (  # pylint: disable=import-error
    ProcessorError,
)

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

sys.path.insert(0,os.path.dirname(__file__))
from McmApiLib.McmApiBase import ( #noqa: E402
    McmApiBase
)
class McmAdminCategorySetterBase(McmApiBase):
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
        self.action_admin_category_names = self.env.get('admin_category_names') or []
        if isinstance(self.action_admin_category_names, list) == False:
            raise ProcessorError("category_names must be a list type object, even if it contains no items")
        self.action_admin_categories = [
            self.get_category(
                category_name=n,category_type_name='AppCategories'
                ) for n in self.action_admin_category_names
                ]
        self.action_admin_category_unique_ids = []
        for c in self.action_admin_categories:
            if c is not None:
                self.action_admin_category_unique_ids.append(c['CategoryInstance_UniqueID'])
        self.current_admin_categories = self.env.get('current_admin_categories',self.env.get('app_categories')) or []

    def execute(self):
        self.initialize_all()
        self.output(f"Current Administrative Categories: {', '.join(self.current_admin_categories)}", 2)
        self.output(f"Action: {self.action}", 2)
        self.final_cat_memberships = []
        for c in self.current_admin_categories:
            if  c is not None and self.action == 'remove' and self.action_admin_category_unique_ids.__contains__(c):
                self.output(f"Category {c} will be explicitly removed", 3)
            elif c is not None and self.action.lower() == 'add' and self.final_cat_memberships.__contains__(c) == False:
                self.output(f"Category {c} will be kept", 3)
                self.final_cat_memberships.append(c)
        self.output(f"\n\t{', '.join(self.action_admin_category_names)}\n\t{', '.join(self.action_admin_category_unique_ids)}", 3)
        for s in self.action_admin_category_unique_ids:
            if s is not None and ['add','replace'].__contains__(self.action) and self.final_cat_memberships.__contains__(s) == False:
                self.output(f"Category {s} will be added", 3)
                self.final_cat_memberships.append(s)
        self.output(f"Updated Administrative Cateogires: {', '.join(self.final_cat_memberships)}", 2)
        if self.final_cat_memberships == self.current_admin_categories:
            self.output("Current categories match desired scopes. Nothing to do.", 1)
            return
        # Update categories
        add_url = f"https://{self.fqdn}/AdminService/wmi/SMS_ApplicationLatest"
        category_post_body = {
            "ModelName": self.object_key,
            "CategoryInstance_UniqueIDs": self.final_cat_memberships,
        }
        self.output("Updating the categories on the object", 3)
        add_response = requests.request(
            method = 'POST',
            url = add_url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            json = category_post_body,
            verify = False
        )
        self.output(f"Category update response: {add_response.reason}", 3)
        add_response.raise_for_status()

if __name__ == "__main__":
    PROCESSOR = McmAdminCategorySetterBase()
    PROCESSOR.execute_shell()