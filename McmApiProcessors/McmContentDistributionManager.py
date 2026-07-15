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

from McmApiLib.McmContentDistributionManagerBase import (  # pylint: disable=import-error, wrong-import-position
    McmContentDistributionManagerBase,
)

__all__ = ["McmContentDistributionManager"]
#irm -credential $cred -Method POST -Uri 
# "https://f1fad-epcmps.ad.psu.edu/AdminService/wmi/SMS_ContentPackage/
# PD2000E7/AdminService.AddDistributionPointGroup" -Body 
# (@{DistributionPointGroup=@('{2B9A5DF7-E586-4231-8F8E-7E3073FA8FE3}')} 
# | ConvertTo-Json -Compress) -Verbose -ContentType 'application/json'
class McmContentDistributionManager(McmContentDistributionManagerBase):
    description = """Distribute content to distribution points/groups in MCM"""

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
        "content_package_security_key": {
            "required": False,
            "description": "The security key of the content package to distribute."
        },
        "action": {
            "required": False,
            "description": "The action to perform. Valid values are 'Add' or 'Remove'.",
            "default": "Add"
        },
        "distribution_point_group_names": {
            "required": False,
            "description": 
                "A list of distribution point group names to add or remove "
                "the content package from. Either distribution_point_group_names "
                "or distribution_point_names must contain at least 1 item.",
            "default": []
        },
        "wait_for_distribution": {
            "required": False,
            "description":
                "If True, wait for the distribution to complete before returning. "
                "If False, return immediately after initiating the distribution.",
            "default": False
        },
        "timeout": {
            "required": False,
            "description":
                "The maximum time to wait for the distribution to complete, in seconds. "
                "Only applicable if wait_for_distribution is True. "
                "Defaults to 3600 seconds (1 hour).",
            "default": 3600
        },
        "fail_on_distribution_failure": {
            "required": False,
            "description":
                "If True, raise an error if the distribution fails. "
                "If False, return a warning if the distribution fails.",
            "default": True
        },
        #"distribution_point_names": {
        #    "required": False,
        #    "description": 
        #        "A list of distribution point names to add or remove "
        #        "the content package from. Either distribution_point_group_names "
        #        "or distribution_point_names must contain at least 1 item.",
        #    "default": []
        #},
    }
    output_variables = {
        "content_distributed_successfully": {
            "description": (
                "True if content distributions were successfully created and "
                "(if 'fail_on_distribution_failure is set to True) no errors "
                "occurred while monitoring the distribution status."
            )
        },
        "content_removed_successfully": {
            "description": (
                "True if all content removals completed successfully"
            )
        }
    }

    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = McmContentDistributionManager()
    PROCESSOR.execute_shell()
