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
import requests
import keyring
import json
from requests_ntlm import HttpNtlmAuth
from autopkglib import Processor,ProcessorError

__all__ = ["McmObjectMover"]

class McmObjectMover(Processor):
    description = """Move an object to a specified folder"""

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
        "object_class": {
            "required": False,
            "description": "The class of the object to move."
        },
        "object_key": {
            "required": False,
            "description": "The object key of the object to set security scopes on. Defaults to the value of app_model_name"
        },
        "current_object_path": {
            "required": False,
            "description": "Pre-populate the current folder path of the object to reduce queries to MCM."
        },
        "target_object_path": {
            "required": True,
            "description": "The target location for the object.",
        }
    }
    output_variables = {
        "mcm_package_scope_set": {
            "description": "Indicates whether the package scope was successfully set.",
        },
    }

    __doc__ = description
    def get_mcm_ntlm_auth(self, keychainServiceName:str, keychainUsername:str) -> HttpNtlmAuth:
        password = keyring.get_password(keychainServiceName,keychainUsername)
        return HttpNtlmAuth(keychainUsername,password)
    
    def get_mcm_object_type_maps() -> dict:
        """Return a dict of mcm object names"""

    def get_mcm_object_type_id(self,) -> int:
        """Return the unique id that MCM assigns to an object id for use in security scope assignment by querying the SMS_SecuredCategoryMembership for the object."""
        self.output(f"Getting ObjectTypeID for {object_key}")
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership?$filter=startsWith(ObjectKey,'{self.object_key}') eq true"
        sms_secured_category_membership = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False
        )
        if len(sms_secured_category_membership.json()['value']) >= 1:
            return sms_secured_category_membership.json()['value'][0]['ObjectTypeID']
        else:
            raise ProcessorError('Could not locate the ObjectTypeID for the given ObjectKey')

    def get_mcm_folder_map(self) -> dict:
        def get_path(node_id:int,nodes_by_id:dict) -> str:
            node = nodes_by_id[node_id]
            path = f"/{node['Name']}"
            if node['ParentContainerNodeID'] != 0:
                path = get_path(node_id=node['ParentContainerNodeID'],nodes_by_id=nodes_by_id) + path
            return path
        self.output("Retrieving container nodes", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_ObjectContainerNode"
        sms_container_nodes_response = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False,
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

    def uses_revisions(self,object_class:str,dynamic:bool=False) -> bool:
        if dynamic == True:
            raise ProcessorError("Dynamic revision determination not supported at this time.")
        else:
            result = ['sms_application','sms_configurationitem'].__contains__(object_class.lower())
        return result

    def main(self):
        self.output("Generating headers.",3)
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        self.output("Checking supplied parameters",3)
        keychainServiceName = self.env.get("keychain_password_service", self.input_variables["keychain_password_service"]["default"])
        keychainUsername = self.env.get("keychain_password_username",self.env.get("MCMAPI_USERNAME",''))
        self.fqdn = self.env.get("mcm_site_server_fqdn", '')
        if (self.fqdn == None or self.fqdn == ''):
            raise ProcessorError("mcm_site_server_fqdn cannot be blank")
        if (keychainServiceName == None or keychainUsername == ''):
            raise ProcessorError("keychain_password_service cannot be blank")
        if (keychainUsername == None or keychainUsername == ''):
            raise ProcessorError("keychain_password_username cannot be blank")
        self.output("Generating NTLM Auth object.",3)
        self.ntlm = self.get_mcm_ntlm_auth(
            keychainServiceName=keychainServiceName,
            keychainUsername=keychainUsername
        )

        try:
            object_class = self.env.get('object_class')
            object_key = self.env.get("object_key", self.env.get('app_model_name',''))
            folder_map = self.get_mcm_folder_map()
            if (current_object_path_string := str(self.env.get('current_object_path'))) != 'None':
                container_node_class = object_class
                current_object_path_string = f"{container_node_class}:{current_object_path_string}".lower()
                pass
            elif self.uses_revisions(object_class):
                self.output(f"{object_class} objects use revisions.", 3)
                container_node_class = f"{object_class}Latest"
                self.output(f"Querying /{container_node_class} endpoint for the latest node.",2)
                revision_url = f"https://{self.fqdn}/AdminService/wmi/{container_node_class}?$filter=startsWith(CI_UniqueID,'{object_key}')"
                self.output(f"URL: {revision_url}", 3)
                revision_response = requests.request(
                    method='GET',
                    url=revision_url,
                    auth=self.ntlm,
                    headers=self.headers,
                    verify=False,
                )
                revision_response_value = revision_response.json()['value']
                if len(revision_response_value) != 1:
                    raise ProcessorError("Error locating a unique revision for this object.")

                current_object_path_string = f"{container_node_class}:{revision_response_value[0]['ObjectPath']}".lower()
            else:
                raise ProcessorError("Unhandled exception while resolving object path.")
            target_object_path_string = f"{container_node_class}:{self.env.get('target_object_path')}".lower()
            if list(folder_map['by_lower_type_and_path'].keys()).__contains__(current_object_path_string) == False:
                self.output(f"Current object path: {current_object_path_string}\nFolder Map: {json.dumps(folder_map)}", 3)
                raise ProcessorError("Could not resolve current object path.")
            if list(folder_map['by_lower_type_and_path'].keys()).__contains__(target_object_path_string) == False:
                self.output(f"Target object path: {target_object_path_string}\nFolder Map: {json.dumps(folder_map)}", 3)
                raise ProcessorError("Could not resolve target object path.")
            if folder_map['by_lower_type_and_path'][target_object_path_string]['ContainerNodeID'] == folder_map['by_lower_type_and_path'][current_object_path_string]['ContainerNodeID']:
                self.output("Object is already a member of the target folder. Nothing to do.", 2)
                return
            self.output("The object is not a member of the target folder. Constructing request parameters", 3)
            url = f"https://{self.fqdn}/AdminService/wmi/SMS_ObjectContainerItem.MoveMembers"
            body = {
                "InstanceKeys": [object_key],
                "ContainerNodeID": folder_map['by_lower_type_and_path'][current_object_path_string]['ContainerNodeID'],
                "TargetContainerNodeID": folder_map['by_lower_type_and_path'][target_object_path_string]['ContainerNodeID'],
                "ObjectType": folder_map['by_lower_type_and_path'][target_object_path_string]['ObjectType']
            }
            self.output(f"Request parameters: {json.dumps(body)}",3)
            move_response = requests.request(
                method='POST',
                auth=self.ntlm,
                url=url,
                headers=self.headers,
                json=body,
                verify=False
            )
            self.output(f"Result: {move_response}", 3)
            
            # Identify Current ContainerNodeID
                # Determine if object type uses revisions
                # Get actual target ci_id (TypeLatest or just Type)
                # Get the current folder string ObjectPath
            # If target.lower() != current.lower():
                # Identify Target ContainerNodeID
                    # Get map (id) by path.lower()
                # Call SMS_ObjectContainerNode.MoveFolders(ContainerNodeIDs, TargetContainerNodeID)
                
            pass
    
        except Exception as e:
            raise e

if __name__ == "__main__":
    PROCESSOR = McmObjectMover()
    PROCESSOR.execute_shell()