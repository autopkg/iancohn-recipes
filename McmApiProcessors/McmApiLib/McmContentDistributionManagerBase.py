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
import platform
import sys
import time

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402

sys.path.insert(0,os.path.dirname(__file__))
from McmApiLib.McmApiBase import ( #noqa: E402
    McmApiBase,
)

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

import requests

from autopkglib import (  # pylint: disable=import-error
    ProcessorError,
)
TIMEOUT_MAX_VALUE = 86400
POLLING_INTERVAL = 10
class McmContentDistributionManagerBase(McmApiBase):
    """Distribute content to distribution points/groups in MCM"""
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.fqdn = self.env.get('mcm_site_server_fqdn')

        self.content_package_security_key = self.env.get("content_package_security_key", self.env.get('app_model_name',''))
        if self.content_package_security_key == '':
            raise ProcessorError(
                "No content package security key provided. "
                "Please provide a value for content_package_security_key "
                "or app_model_name."
                )
        if len(self.env.get('distribution_point_group_names',[])) == 0 and len(self.distribution_point_names) == 0:
            raise ProcessorError(
                "No distribution points or groups provided. "
                "Please provide a value for distribution_point_group_names "
                "or distribution_point_names."
                )
        self.action = self.env.get("action")
        self.distribution_point_group_names = self.env.get("distribution_point_group_names", [])
        self.distribution_point_names = self.env.get("distribution_point_names", [])
        self.fail_on_dist_failure = self.env.get('fail_on_distribution_failure')
        self.env["content_distributed_successfully"] = False

    def execute(self):
        self.initialize_all()
        # Validate that the content package exists
        self.output(
            (
                "Validating a content package is associated with "
                f"provided security key {self.content_package_security_key} exists."
            ),
            2)
        content_package_search_url = f"https://{self.fqdn}/AdminService/wmi/SMS_ContentPackage?$filter=SecurityKey eq '{self.content_package_security_key}'"
        content_package_search_response = requests.request(
            method = 'GET',
            url = content_package_search_url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
        )
        if content_package_search_response.status_code != 200:
            raise ProcessorError(
                f"Error searching for content package with security key {self.content_package_security_key}: "
                f"{content_package_search_response.reason}"
            )
        if len(content_package_search_response.json()['value']) == 0:
            self.output(
                f"No content package found with security key {self.content_package_security_key}.",
                2
            )
        elif len(content_package_search_response.json()['value']) > 1:
            raise ProcessorError(
                f"Multiple content packages found with security key {self.content_package_security_key}. "
                "Please provide a unique security key."
            )
        content_package = content_package_search_response.json()['value'][0]
        content_package_id = content_package['PackageID']
        self.output(f"Found content package: {content_package_id}", 3)
        # Validate that the distribution points/groups exist
        self.output(
            (
                "Validating that the provided distribution points/groups "
                "exist in MCM."
            ),
            2)
        if len(self.distribution_point_group_names) > 0:
            self.output("Retrieving valid distribution point group targets.", 2)
            dpgs = self.get_distribution_point_groups()
            dpg_ids = [dpg['GroupID'] for dpg in dpgs if dpg['Name'] in self.distribution_point_group_names]
            if len(dpg_ids) > 0:
                self.output(f"Distributing content package {content_package_id} to {', '.join(self.distribution_point_group_names)}", 2)
                if self.action == 'Add':
                    url = f"https://{self.fqdn}/AdminService/wmi/SMS_ContentPackage('{content_package_id}')/AdminService.AddDistributionPointGroup"
                    self.output(f"Post url: {url}", 3)
                    
                    body = {
                        "DistributionPointGroup": dpg_ids,
                    }
                    response = requests.request(
                        method = 'POST',
                        url = url,
                        auth = self.get_mcm_auth(),
                        headers = self.headers,
                        json = body,
                        verify = self.get_ssl_verify_param(),
                    )
                    if False == (response.status_code in [200,201]):
                        raise ProcessorError((
                            f"Error ({response.status_code}) distributing content package {content_package_id} to "
                            "distribution point groups "
                            f"{self.distribution_point_group_names}: "
                            f"{response.reason}"
                        ))
                    self.output(f"Distribution created. {', '.join(dpg_ids) }", 2)
                elif self.action == 'Remove':
                    self.output("WARNING: Removal not supported yet", 1)
                    pass
            if len(self.distribution_point_names) > 0:
                self.output("WARNING: Processor does not support single distribution points.",1)
            
            if False == self.env.get('wait_for_distribution'):
                self.output("Exiting without waiting for distribution to complete.", 2)
                return
            if self.action == 'Remove':
                self.output("Removal action; nothing further to do.", 1)
                return

            self.output("Pausing 30 seconds for distribution jobs to initialize.", 3)
            time.sleep(30.0)
            timeout_seconds = self.env.get('timeout')
            filter_parts = [f"GroupID eq '{x}'" for x in dpg_ids]
            filter_string = f"ObjectID eq '{self.content_package_security_key}' and ({' or '.join(filter_parts)})"
            url = f"https://{self.fqdn}/AdminService/wmi/SMS_DPGroupDistributionStatusDetails?$filter={filter_string}"
            self.output(f"Waiting for up to ({timeout_seconds}) seconds for distribution to complete...", 2)
            self.output(f"Status query url: {url}", 3)
            now = time.time()
            if timeout_seconds == 0:
                self.output(f"Setting timeout to maximum value of {TIMEOUT_MAX_VALUE}", 2)
                timeout_seconds = TIMEOUT_MAX_VALUE
            end = now + timeout_seconds
            warned = False
            while time.time() < end:
                status_codes = []
                r = requests.request(
                    method= 'GET',
                    url = url,
                    auth = self.get_mcm_auth(),
                    headers = self.headers,
                    verify = self.get_ssl_verify_param(),
                )
                if r.status_code != 200:
                    if self.fail_on_dist_failure:
                        raise ProcessorError("Failure while checking distribution status.")
                    else:
                        self.output("WARNING: Non-fatal error while checking distribution status.", 2)
                        break
                status_codes = [rs.get('MessageState').__str__() for rs in r.json().get('value',[])]
                if ('3' in status_codes or '4' in status_codes):
                    if self.fail_on_dist_failure:
                        raise ProcessorError(f"Error distributing content.{', '.join(status_codes)}")
                    elif warned:
                        self.output("WARNING: Error encountered while distributing content.", 1)
                        warned = True
                if False == ('2' in status_codes):
                    self.output("Distribution jobs completed.", 3)
                    break
                self.output((
                    "Distribution in progress. Polling again in "
                    f"{POLLING_INTERVAL} seconds."
                    )
                )   
                time.sleep(10)
            if status_codes.__contains__('3') or status_codes.__contains__('4') and (self.fail_on_dist_failure):
                raise ProcessorError("An error occurred whilst distributing content to one or more targets.")
            elif status_codes.__contains__('2'):
                self.output("WARNING: the timeout has been reached, but content is still distributing.", 1)
            self.env["content_distributed_successfully"] = True
            self.output("Completed", 1)

if __name__ == "__main__":
    PROCESSOR = McmContentDistributionManagerBase()
    PROCESSOR.execute_shell()