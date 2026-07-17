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

#import json
from datetime import datetime,timezone

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
    McmApiBase,OfferFlag,OfferType,InstallPriority,
    AssignmentAction,AssignmentType,DesiredConfigType,
    DesiredConfigTypeToShortAction,DPLocalityFlag,StateMessagePriority,
    SuppressRebootClientType,XmlNodeAsDict,
)

import requests

time_format = '''%Y-%m-%dT%H:%M:%SZ'''

class McmAppDeployerBase(McmApiBase):
    """Upload an application object"""
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.initialize_export_properties("mcm_app_deployer_export_properties")
        self.fqdn = self.env.get('mcm_site_server_fqdn')
        
        self.app_model_name = self.env.get('application_model_name',self.env.get('app_model_name',''))
        if self.app_model_name == '':
            raise ProcessorError("Must specify an application model name.")
        
        self.assignment_action = AssignmentAction[self.env.get('assignment_action')].value
        
        self.collection_name = self.env.get('collection_name')
        if self.collection_name == '':
            raise ProcessorError("collection_name must be populated with the name of a valid collection in MCM.")
        
        self.assignment_description = self.env.get('assignment_description')
        
        self.deployment_enabled:bool = self.env.get('deployment_enabled')
        
        self.use_utc_times:bool = self.env.get('use_utc_times')
        
        now = datetime.now()

        if self.env.get('start_time') is None:
            start_time = now.astimezone()
        elif self.test_time_format(str(self.env.get('start_time',''))):
            start_time = datetime.fromisoformat(self.env.get('start_time'))
            if start_time.tzinfo is None:
                self.output("Attaching local time to start_time", 3)
                start_time = start_time.replace(tzinfo=datetime.now().astimezone().tzinfo)
        else:
            raise ProcessorError("start_time must be a valid ISO formatted time, ")        

        if self.env.get('enforcement_deadline') is None:
            enforcement_deadline = start_time
        elif self.test_time_format(str(self.env.get('enforcement_deadline',''))):
            enforcement_deadline = datetime.fromisoformat(self.env.get('enforcement_deadline'))
            if enforcement_deadline.tzinfo is None:
                self.output("Attaching local time to enforcement_deadline", 3)
                enforcement_deadline = enforcement_deadline.replace(tzinfo=datetime.now().astimezone().tzinfo)
        else:
            raise ProcessorError("enforcement_deadline must be a valid ISO formatted time, ")
        
        self.start_time = start_time.strftime(time_format)
        self.enforcement_deadline = enforcement_deadline.strftime(time_format)
        
        #if self.env.get('expiration_time') is None:
        #    self.expiration_time = None
        #elif self.test_time_format(self.env.get('expiration_time'), time_formats):
        #    self.expiration_time = self.env.get('expiration_time')
        #else:
        #    raise ProcessorError(
        #        (
        #        "expiration_time must be a valid time, "
        #        f"formatted as '{' or '.join(time_formats)}'"
        #        )
        #    )
        
        self.wol_enabled:bool = self.env.get('wol_enabled')
        self.offer_type = OfferType[self.env.get('offer_type')].value
        self.notify_user:bool = self.env.get('notify_user')
        self.display_user_ui:bool = self.env.get('display_user_ui')
        self.install_outside_maintenance_window:bool = self.env.get('install_outside_maintenance_window')
        self.reboot_outside_maintenance_window:bool = self.env.get('reboot_outside_maintenance_window')
        
        offer_flags_type = type(self.env.get('offer_flags')).__name__
        if offer_flags_type == 'str':
            offer_flags = [self.env.get('offer_flags')]
        elif offer_flags_type == 'list':
            offer_flags = self.env.get('offer_flags')
        else:
            raise ProcessorError("Invalid parameter type (offer_flags)")
        self.offer_flags = sum([OfferFlag[of].value for of in offer_flags])
        
        self.additional_properties = self.new_app_assignment_additional_properties(
            uninstall_enabled = self.env.get('offer_flags',[]).__contains__('REMOVEONCOLLECTIONDROP')
        )

        self.assignment_type = AssignmentType[self.env.get('assignment_type')].value

        self.desired_config_type = DesiredConfigType[self.env.get('desired_config_type')].value
        self.disable_mom_alerts:bool = self.env.get('disable_mom_alerts')

        dp_flags_type = type(self.env.get('dp_locality_flags')).__name__
        if dp_flags_type == 'str':
            dp_flags = [self.env.get('dp_locality_flags')]
        elif dp_flags_type == 'list':
            dp_flags = self.env.get('dp_locality_flags')
        else:
            raise ProcessorError("Invalid parameter type (dp_locality_flags)")
        self.dp_locality_flags = sum([DPLocalityFlag[df].value for df in dp_flags])

        self.assignment_priority = InstallPriority[self.env.get('assignment_priority')].value
        self.state_message_priority = StateMessagePriority[self.env.get('state_message_priority')].value
        self.winlog:bool = self.env.get('log_compliance_to_win_event')
        
        r_s_clients_type = type(self.env.get('suppress_reboot_on_client_types')).__name__
        if r_s_clients_type == 'str':
            r_s_clients = [self.env.get('suppress_reboot_on_client_types')]
        elif r_s_clients_type == 'list':
            r_s_clients = self.env.get('suppress_reboot_on_client_types')
        else:
            raise ProcessorError("Invalid parameter type (suppress_reboot_on_client_types)")
        self.reboot_suppress_clients = sum([SuppressRebootClientType[rs].value for rs in r_s_clients])
        self.soft_deadline_enabled = self.env.get('soft_deadline_enabled')
        self.locale_id:int = self.env.get('locale_id')

    @staticmethod
    def new_app_assignment_additional_properties(
        randomization: int = 0,
        deadline: int = 0,
        uninstall_enabled: bool = False
        ) -> str:
        node = XmlNodeAsDict(
            NodeName="Properties",
            ChildNodes=[
                XmlNodeAsDict(
                    NodeName="ActivationRandomizationMinutes",
                    NodeInnerText=f'{randomization.__str__()}',
                ),
                XmlNodeAsDict(
                    NodeName="RelativeDeadlineMinutes",
                    NodeInnerText=f'{deadline.__str__()}',
                ),
                XmlNodeAsDict(
                    NodeName="ImplicitUninstallEnabled",
                    NodeInnerText=f'{uninstall_enabled.__str__().lower()}',
                ),
            ]
        )
        return node.to_xml_string(xml_declaration=True)
    
    def execute(self):
        self.initialize_all()
        
        app = self.get_application_by_model_name(self.app_model_name)
        if {} == app:
            raise ProcessorError("No application found. Nothing to deploy!")
        app_name = app['LocalizedDisplayName']

        collection = self.get_collection_by_name(collection_name=self.collection_name)
        if {} == collection:
            raise ProcessorError("No collection found. Nothing to deploy to.")
        
        existing_assignment = self.get_app_assignment(
            app_model_id=app['ModelID'],
            collection_id=collection['CollectionID']
        )

        if {} != existing_assignment:
            if self.env.get('delete_existing', False):
                result = self.delete_app_assignment(assignment_id=existing_assignment.get('AssignmentID',0))
                if False == result:
                    raise ProcessorError("Error encountered while deleting app assignment.")
                else:
                    self.output("Successfully deleted app assignment.", 3)
            else:
                raise ProcessorError((
                    "An existing assignment for this application/collection was found. "
                    "It must be removed to create an assignment."
                ))
        else:
            self.output("No existing assignment found. Continuing...", 3)

        if self.env.get('assignment_name', "") != "":
            self.assignment_name = self.env.get('assignment_name')
        else:
            self.assignment_name = (
                f"{app_name}_{self.collection_name}_"
                f"{DesiredConfigTypeToShortAction[self.env.get('desired_config_type')].value}"
            )
            self.output(f"Generated assignment name: {self.assignment_name}", 3)
        
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_ApplicationAssignment"
        self.output("Generating post body",3)
        body = {
            "AdditionalProperties": self.additional_properties,
            "ApplicationName": app_name,
            "ApplyToSubTargets": False, # always false, deprecated
            "AppModelID": app['ModelID'],
            "AssignedCIs": [app['CI_ID']],
            "AssignmentAction": self.assignment_action,
            "AssignmentDescription": f"{self.assignment_description}",
            "AssignmentType": self.assignment_type,
            "DesiredConfigType": self.desired_config_type,
            "DisableMomAlerts": self.disable_mom_alerts,
            "Enabled": self.deployment_enabled,
            "LogComplianceToWinEvent": self.winlog,
            "NotifyUser": self.notify_user,
            "OverrideServiceWindows": self.install_outside_maintenance_window,
            "AssignmentName": self.assignment_name,
            "TargetCollectionID": collection['CollectionID'],
            "EnforcementDeadline": self.enforcement_deadline,
            "StartTime": self.start_time,
            "UseGMTTimes": self.use_utc_times,
            "SuppressReboot": self.reboot_suppress_clients,
            "AssignmentUniqueID": self.new_guid_str().upper(),
            "WoLEnabled": self.wol_enabled,
            "DPLocality": self.dp_locality_flags,
            "OfferFlags": self.offer_flags,
            "OfferTypeID": self.offer_type,
            #"Priority": self.assignment_priority,
            #"StateMessagePriority": self.state_message_priority,
            "UserUIExperience": self.display_user_ui,
            "SoftDeadlineEnabled": self.soft_deadline_enabled
        }
        #if self.env.get(expiration_time,None) is not None and self.env.get(expiration_time,'') != "":
        #    pass # no expiration time on app deployments
        #    #body['ExpirationTime'] = self.expiration_time
        #self.output(json.dumps(body), 3)
        self.output(f"Craeting application assignment at {url}", 2)
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
    PROCESSOR = McmAppDeployerBase()
    PROCESSOR.execute_shell()