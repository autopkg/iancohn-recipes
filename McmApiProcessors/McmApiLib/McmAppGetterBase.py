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

class McmAppGetterBase(McmApiBase):
    """Search MCM for an application and return the specified
    export properties
    """
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.initialize_export_properties("mcm_app_getter_export_properties")
        self.fqdn = self.env.get('mcm_site_server_fqdn')
        self.application_name = self.env.get('application_name')

    def execute(self):
        self.env['mcm_application_found'] = False
        self.initialize_all()
        self.get_application_by_name()
        if self.response_value is not None and self.response_value != {}:
            self.env['mcm_application_found'] = True
            self.set_export_properties()
        else:
            self.output("No application found; no export properties will be set", 3)


if __name__ == "__main__":
    processor = McmAppGetterBase()
    processor.execute_shell()