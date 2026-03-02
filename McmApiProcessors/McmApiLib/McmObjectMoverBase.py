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
import platform
import sys

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

class McmObjectMoverBase(McmApiBase):
    """Move an object between folders in MCM"""
    def initialize_all(self):
        self.initialize_headers()
        self.initialize_auth()
        self.initialize_ssl_verification()
        self.initialize_export_properties("mcm_app_uploader_export_properties")
        self.fqdn = self.env.get('mcm_site_server_fqdn')

        self.object_class = self.env.get('object_class')
        self.object_key = self.env.get("object_key", self.env.get('app_model_name',''))
        self.folder_map = self.get_mcm_folder_map()

    def get_mcm_object_type_maps() -> dict:
        """Return a dict of mcm object names"""

    def get_mcm_object_type_id(self, object_key) -> int:
        """Return the unique id that MCM assigns to an object id for
        use in security scope assignment by querying the
        SMS_SecuredCategoryMembership for the object
        """
        self.output(f"Getting ObjectTypeID for {object_key}")
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership?$filter=startsWith(ObjectKey,'{self.object_key}') eq true"
        sms_secured_category_membership = requests.request(
            method = 'GET',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
        )
        if len(sms_secured_category_membership.json()['value']) >= 1:
            return sms_secured_category_membership.json()['value'][0]['ObjectTypeID']
        else:
            raise ProcessorError('Could not locate the ObjectTypeID for the given ObjectKey')

    def get_mcm_folder_map(self) -> dict:
        """Connect to MCM and return a map of object folders"""
        def get_path(node_id:int,nodes_by_id:dict) -> str:
            """Helper function to return the path of a folder object"""
            node = nodes_by_id[node_id]
            path = f"/{node['Name']}"
            if node['ParentContainerNodeID'] != 0:
                path = get_path(node_id=node['ParentContainerNodeID'],nodes_by_id=nodes_by_id) + path
            return path
        self.output("Retrieving container nodes", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_ObjectContainerNode"
        sms_container_nodes_response = requests.request(
            method = 'GET',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = False,
        )
        all_nodes = sms_container_nodes_response.json()['value']
        nodes_by_id = {n['ContainerNodeID']: n for n in all_nodes}
        nodes_by_lower_type_and_path = {
            f"{n['ObjectTypeName'].lower()}:{get_path(node_id=n['ContainerNodeID'],nodes_by_id=nodes_by_id).lower()}":n for n in all_nodes
        }

        return {
            "by_id": nodes_by_id,
            "by_lower_type_and_path": nodes_by_lower_type_and_path
        }

    def execute(self):
        self.initialize_all()
        if (current_object_path_string := str(self.env.get('current_object_path'))) != 'None':
            container_node_class = self.object_class
            current_object_path_string = f"{container_node_class}:{current_object_path_string}".lower()
        elif self.uses_revisions(self.object_class):
            self.output(f"{self.object_class} objects use revisions.", 3)
            container_node_class = f"{self.object_class}Latest"
            self.output(f"Querying /{container_node_class} endpoint for the latest node.",2)
            revision_url = f"https://{self.fqdn}/AdminService/wmi/{container_node_class}?$filter=startsWith(CI_UniqueID,'{self.object_key}')"
            self.output(f"URL: {revision_url}", 3)
            revision_response = requests.request(
                method = 'GET',
                url = revision_url,
                auth = self.get_mcm_auth(),
                headers = self.headers,
                verify = False,
            )
            if revision_response.status_code != 200:
                raise ProcessorError(revision_response.reason)
            elif len(revision_response.json()['value']) > 1:
                raise ProcessorError("Error locating a unique revision for this object.")
            revision_response_value = revision_response.json()['value'][0]
            current_object_path_string = f"{container_node_class}:{revision_response_value['ObjectPath']}".lower()
        else:
            raise ProcessorError("Unhandled exception while resolving object path.")
        target_object_path_string = f"{container_node_class}:{self.env.get('target_object_path')}".lower()
        if current_object_path_string.endswith(":/") == False and \
                list(self.folder_map['by_lower_type_and_path'].keys())\
                    .__contains__(current_object_path_string) == False:
            self.output(f"Current object path: {current_object_path_string}", 3)
            raise ProcessorError("Could not resolve current object path.")
        if target_object_path_string.endswith(":/") == False and\
                list(self.folder_map['by_lower_type_and_path'].keys())\
                    .__contains__(target_object_path_string) == False:
            self.output(f"Target object path: {target_object_path_string}", 3)
            raise ProcessorError("Could not resolve target object path.")
        if current_object_path_string.endswith(":/"):
            current_container_node_id = 0
        else:
            current_container_node_id = self.folder_map['by_lower_type_and_path']\
                [current_object_path_string]['ContainerNodeID']
        if target_object_path_string.endswith(":/"):
            target_container_node_id = 0
        else:
            target_container_node_id = self.folder_map['by_lower_type_and_path']\
                [target_object_path_string]['ContainerNodeID']
        if target_container_node_id == current_container_node_id:
            self.output("Object is already a member of the target folder. Nothing to do.", 2)
            return
        self.output(
            "The object is not a member of the target folder. "
            "Constructing request parameters",
            3
            )
        url = (
            f"https://{self.fqdn}/AdminService/wmi/"
            "SMS_ObjectContainerItem.MoveMembers"
        )
        body = {
            "InstanceKeys": [self.object_key],
            "ContainerNodeID": current_container_node_id,
            "TargetContainerNodeID": target_container_node_id,
            "ObjectType": self.folder_map['by_lower_type_and_path']\
                .get(target_object_path_string,{})\
                .get(
                    'ObjectType',
                    self.folder_map['by_lower_type_and_path']\
                        .get(current_object_path_string,{})\
                        .get('ObjectType')
                    )
        }
        self.output(f"Request parameters: {print(body)}",4)
        move_response = requests.request(
            method = 'POST',
            auth = self.get_mcm_auth(),
            url = url,
            headers = self.headers,
            json = body,
            verify = False
        )
        self.output(f"Status Code [{move_response.status_code}]", 3)
        if [200, 201].__contains__(move_response.status_code) == False:
            raise ProcessorError(move_response.reason)

if __name__ == "__main__":
    PROCESSOR = McmObjectMoverBase()
    PROCESSOR.execute_shell()