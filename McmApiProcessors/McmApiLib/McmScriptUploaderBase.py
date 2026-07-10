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
    McmApiBase,
)

import requests

class McmScriptUploaderBase(McmApiBase):
    """Upload a script object"""
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.initialize_export_properties("mcm_script_uploader_export_properties")
        self.fqdn = self.env.get('mcm_site_server_fqdn')
        self.script_name = self.env.get('mcm_script_name')
        self.script_description = self.env.get('mcm_script_description')
        self.script_timeout = self.env.get('mcm_script_timeout')
        self.script_content = self.env.get('mcm_script_content')
        self.script_parameters_list = self.env.get('mcm_script_parameters',[])

        self.new_script_parameter = {
            'String': self.new_script_parameter_string,
            'Integer': self.new_script_parameter_int,
            'List': self.new_script_parameter_list,
            'Boolean': self.new_script_parameter_boolean
        }

    def execute(self):
        self.initialize_all()
        existing_script = self.get_script_by_name()
        mcm_script_params = {}
        if len(self.script_parameters_list) > 0:
            self.output(f"Generating script parameters for {len(self.script_parameters_list)} parameters", 1)
            script_parameters_nodes = []
            for script_parameter in self.script_parameters_list:
                script_parameters_nodes.append(
                    self.new_script_parameter(**script_parameter)
                )
            script_parameters_node = self.new_script_parameters_node(script_parameters_nodes)
            self.output("Converting script parameters to raw XML", 3)
            script_parameters_xml = script_parameters_node.to_xml_string(xml_declaration=True, pretty_print=True)
            self.output("Converting XML script parameters to base64", 3)
            script_parameters_b64 = self.convert_to_b64(script_parameters_xml)
            mcm_script_params['ParamsDefinition'] = script_parameters_b64
            self.output("Done with script parameters", 1)
        
        # Convert Script to b64, 76 chars in each line, unicode encoded, with preamble
        # https://github.com/AdamGrossTX/ConfigMgr.AdminService/blob/main/ConfigMgr.AdminService/Public/Get-CMScript.ps1
        # use wmi/SMS_Scripts.CreateScripts method


        url = f"https://{self.fqdn}/AdminService/wmi/SMS_Application"
        if self.ci_id > 0:
            url = f"{url}({str(self.ci_id)})"
        self.output("Generating post body",3)
        body = {"SDMPackageXML": self.app_sdmpackagexml}
        self.output(f"Posting application to {url}", 2)
        post_response = requests.request(
            method = 'POST',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
            json = body
        )
        self.output(f"Status Code [{post_response.status_code}]")
        if [200,201].__contains__(post_response.status_code) == False:
            raise ProcessorError(post_response.reason)
        post_json = post_response.json()
        self.output("Got Json body from response", 3)
        if post_json.__contains__("error"):
            self.output(
                f"\tError Code: {post_json['error']['code']}"
                "\n\tError Message: "
                f"{post_json['error']['message']}"
                )
        
        self.response_value = post_json
        self.set_export_properties()
        
if __name__ == "__main__":
    PROCESSOR = McmScriptUploaderBase()
    PROCESSOR.execute_shell()