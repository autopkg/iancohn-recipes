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

from McmApiLib.McmAppDeployerBase import (  # pylint: disable=import-error, wrong-import-position
    McmAppDeployerBase,
)

__all__ = ["McmAppDeployer"]

class McmAppDeployer(McmAppDeployerBase):
    description = """AutoPkg Processor to connect to an MCM Admin
    Service and deploy an application object to a collection, if it exists
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
            "default": "auto"
        },
        "application_model_name": {
            "required": True,
            "description": "The model name of the application to deploy. Defaults to app_model_name",
        },
        "assignment_action": {
            "required": False,
            "description": "Whether to DETECT or APPLY the application",
            "default": 'APPLY',
        },
        "collection_name": {
            "required": True,
            "description": "The collection name to target in the assignment",
            "default": "",
        },
        "delete_existing": {
            "required": False,
            "description": "Whether to delete an existing assignment.",
            "default": False
        },
        "assignment_description": {
            "required": False,
            "description": "A comment/description for the deployment",
            "default": "",
        },
        "deployment_enabled": {
            "required": False,
            "description": (
                "Can be set to False if the deployment should be created in a disabled state."
            ),
            "default": True,
        },
        "enforcement_deadline": {
            "required": False,
            "description": (
                "The date and time (ex. '07/15/2026 19:27:25') "
                "when the application assignment will be enforced. "
                "If not specified, enforcement will begin immediately"
            ),
            "default": None,
        },
        "start_time": {
            "required": False,
            "description": (
                "The date and time when the deployment should begin. "
                "If not specified, the deployment begins immediately."
            ),
            "default": None,
        },
        #"expiration_time": {
        #    "required": False,
        #    "description": (
        #        "The date and time when the deployment should end. "
        #        "If not specified, the deployment will not expire."
        #    ),
        #    "default": None,
        #},
        "use_utc_times": {
            "required": False,
            "description": "Whether start time and enforcement deadline times are in UTC",
            "default": False,
        },
        "soft_deadline_enabled": {
            "required": False,
            "description": (
                "Delay enforcement of this deployment according to user preferences, "
                "up to the grace period defined in client settings"
            ),
            "default": False,
        },
        "wol_enabled": {
            "required": False,
            "description": "Whether or not to notify clients of the assignment via a WoL packet.",
            "default": False,
        },
        "offer_type": {
            "required": False,
            "description": "Assign the application as 'REQUIRED' or 'AVALIABLE'",
            "options": ["REQUIRED","AVAILABLE"],
            "default": "REQUIRED",
        },
        "notify_user": {
            "required": False,
            "description": "Whether to notify users of the offer availability",
            "default": False,
        },
        "display_user_ui": {
            "required": False,
            "description": "Whether to display the user UI",
            "default": False,
        },
        "install_outside_maintenance_window": {
            "required": False,
            "description": "Whether to override any configured maintenance windows for the deployment.",
            "default": False,
        },
        "reboot_outside_maintenance_window": {
            "required": False,
            "description": (
                "Whether clients executing the deployment may reboot outside of "
                "any maintenance windows configured for the type of deployment."
            ),
            "default": False
        },
        "offer_flags": {
            "required": False,
            "description": (
                "Offer flags for the assignment. Use HIGHIMPACTDEPLOYMENT "
                "when 'Show dialog instead of toast' is desired."
            ),
            "options": [
                "PREDEPLOY","ONDEMAND","ENABLEPROCESSTERMINATION",
                "ALLOWUSERSTOREPAIRAPP","RELATIVESCHEDULE","HIGHIMPACTDEPLOYMENT",
                "REMOVEONCOLLECTIONDROP"
            ],
            "default": []
        },
        "assignment_name": {
            "required": False,
            "description": (
                "Use a custom value for the assignment name. "
                "If not specified, one will be generated from "
                "details of the deployment",
            ),
        },
        "assignment_type": {
            "required": False,
            "description": (
                "The assignment type. Non-defualt values have not been tested."
            ),
            "options": [
                "CIA_TYPE_DCM_BASELINE", "CIA_TYPE_UPDATES",
                "CIA_TYPE_APPLICATION", "CIA_TYPE_UPDATE_GROUP",
                "CIA_TYPE_POLICY",
            ],
            "default": "CIA_TYPE_APPLICATION",
        },
        "desired_config_type": {
            "required": False,
            "description": "The desired configuration type",
            "options": ["REQUIRED", "NOT_ALLOWED"],
            "default": "REQUIRED",
        },
        "disable_mom_alerts": {
            "required": False,
            "description": (
                "True if the client is configured to raise MOM alerts when a "
                "configuration item is applied. "
                "Non-default values have not been tested."
            ),
            "default": False
        },
        "dp_locality_flags": {
            "required": False,
            "description": (
                "An array of flags to determine how the client obtains distribution "
                "points, according to distribution point locality."
                # documented incorrectly on MS' site
                # https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/compliance/sms_ciassignmentbaseclass-server-wmi-class
            ),
            "options": [
                "DP_DOWNLOAD_FROM_LOCAL","DP_DOWNLOAD_FROM_REMOTE",
                "DP_NO_FALLBACK_UNPROTECTED","DP_ALLOW_WUMU",
                "DP_ALLOW_METERED_NETWORK"
                ],
            "default": ["DP_DOWNLOAD_FROM_REMOTE","DP_DOWNLOAD_FROM_LOCAL",],
        },
        "assignment_priority": {
            "required": False,
            "description": (
                "The priority for installation of the application. "
                "Non-default values have not been tested."

            ),
            "options": ["LOW","MEDIUM","HIGH"],
            "default": "MEDIUM"
        },
        "state_message_priority": {
            "required": False,
            "description": (
                "Priority of state message to be reported from client. "
                "Non-default values have not been tested."
            ),
            "options": ["URGENT","HIGHT","NORMAL","LOW"],
            "default": "NORMAL",
        },
        "log_compliance_to_win_event": {
            "required": False,
            "description": "Whether to log compliance to the Windows Event Log",
            "default": False,
        },
        "suppress_reboot_on_client_types": {
            "required": False,
            "description": "A list of client types on which reboots should be suppressed",
            "options": ["WORKSTATIONS", "SERVERS"],
            "default": [
                "WORKSTATIONS",
                "SERVERS"
            ],
        },
        "locale_id": {
            "required": False,
            "description": "The ID for the locale of the assignment name and description",
            "default": 1033,
        },
        "mcm_app_deployer_export_properties": {
            "required": False,
            "default": {
                "deployment_object_class": {"type": "property", "raise_error": True,"options": {"property": "__CLASS"}},
                "deployment_assignment_id": {"type": "property", "raise_error": True,"options": {"property": "AssignmentID"}},
                "deployment_assignment_name": {"type":"property", "raise_error": True, "options": {"property": "AssignmentName"}},
                "deployment_collection_name": {"type": "property", "raise_error": True, "options": {"property": "CollectionName"}},
                "deployment_collection_id": {"type": "property", "raise_error": True,"options": {"property": "TargetCollectionID"}},
            },
            "description": 
                "A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output. "
                "Each key name specified will be used as the AutoPkg variable name; each value should be populated by a dictionary "
                "representing how to retrieve the property from the MCM application. Supported retrieval types are 'property' and 'xpath'. "
                "'raise_error' specifies whether to raise an error if the property cannot be found. "
                ""
                "'property' type options require an 'expression' option specifying the property name to retrieve from the MCM application. "
                "'xpath' type options require a 'property' option specifying the property name (generally 'SDMPackageXML') to run the xpath query against, and an 'expression'. "
                "The 'strip_namespaces' option may also be specified to indicate whether to strip namespaces from the XML before evaluating the xpath expression."
                "The 'select_value_index' option may also be specified to indicate which value to select from the xpath result set (default is '*' (return all values as an array list)). "
                "Positive or negative integers may be specified to select a specific index from the result set (0-based). Negative integers count from the end of the result set (-1 is the last item))."
        }
    }
    output_variables = {}
    
    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = McmAppDeployer()
    PROCESSOR.execute_shell()
