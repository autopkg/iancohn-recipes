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
import sys

sys.path.insert(0,os.path.dirname(__file__))
from McmApiLib.McmApiBase import ( #noqa: E402
    McmApiBase
)

class McmCategoryGetterBase(McmApiBase):
    """Return details about a user category with the specified name and type"""
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.initialize_export_properties("mcm_category_getter_export_properties")
        self.fqdn = self.env.get('mcm_site_server_fqdn')

    def execute(self):
        self.initialize_all()
        category_name = self.env.get('category_name')
        category_type_name = self.env.get('category_type') or ''
        self.get_category(category_name=category_name, category_type_name=category_type_name)
        if self.response_value is None or self.response_value == {}:
            create_if_not_exists = self.env.get('create_nonexistant_category')
            self.output(f"Category {self.env.get('category_name')} does not exist", 2)
            if create_if_not_exists == False:
                raise ProcessorError("Category does not exist, and create_if_not_exists was set to False.")
            self.output(f"Creating a new {self.env.get('category_type_name')} category", 3)
            raise ProcessorError("Category creation is not supported at this time.")

        self.output(f"Finished searching for category", 3)
        self.set_export_properties()