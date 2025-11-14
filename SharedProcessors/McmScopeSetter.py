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
from lxml import etree
from requests_ntlm import HttpNtlmAuth
from autopkglib import Processor,ProcessorError

__all__ = ["McmScopeSetter"]

class McmScopeSetter(Processor):
    description = """Sets the security scope of an MCM object"""

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
        "object_key": {
            "required": False,
            "description": "The object key of the object to set security scopes on. Defaults to the value of app_model_name"
        },
        "security_scopes": {
            "required": False,
            "description": "A list of security scopes to set on the object. Must contain at least one item.",
        },
        "action": {
            "required": False,
            "description": 
                "The action to take on the supplied object's security scopes. ",
            "default": "replace",
            "options": ['add','remove','replace']
        },
        "existing_security_scopes": {
            "required": False,
            "description": "The existing security scopes attached to the item. Defaults to the value of app_securityscopes",
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

    def get_mcm_security_scopes(self) -> dict:
        self.output("Retrieving possible security scopes", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategory"
        sms_secured_categories = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False,
        )
        return {
            "scopes": [{"category_id":c['CategoryID'], "category_name": c['CategoryName']} for c in (sms_secured_categories.json().get('value',[]))],
            "by_category_id": {d['CategoryID']: d['CategoryName'] for d in (sms_secured_categories.json().get('value',[]))},
            "by_category_name_lower": {e['CategoryName'].lower(): e['CategoryID'] for e in (sms_secured_categories.json().get('value',[]))},
        }

    def get_mcm_object_type_id(self,object_key:str) -> int:
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
        self.action = self.env.get('action',self.input_variables['action']['default']).lower()
        if self.input_variables['action']['options'].__contains__(self.action.lower()) == False:
            raise ProcessorError(f"'action' must be one of {', '.join(self.input_variables['action']['options'])}")
        self.object_key = self.env.get("object_key", self.env.get('app_model_name',''))
        if self.object_key is None or self.object_key == '' or self.object_key == '':
            self.output(f"Supplied object_key: {self.object_key}")
            raise ProcessorError("object_key is required")
        self.current_scope_names = self.env.get("existing_security_scopes",self.env.get('app_securityscopes',[]))
        if self.current_scope_names is None or isinstance(self.current_scope_names, list) == False:
            self.output(f"Current scope names: {self.current_scope_names}", 3)
            raise ProcessorError("existing_security_scopes is required")
        self.action_scope_names = self.env.get('security_scopes',self.env.get('security_scopes',[]))
        if self.action_scope_names is None or isinstance(self.action_scope_names, list) == False or len(self.action_scope_names) == 0:
            raise ProcessorError("security_scopes is required, and must have at least one item.")
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
            self.object_type_id = self.get_mcm_object_type_id(object_key=self.object_key)
            self.output(f"Retrieved ObjectTypeID: {self.object_type_id}", 3)
            self.all_scopes = self.get_mcm_security_scopes()
            self.final_scope_names = []
            self.remove_scope_names = []
            self.add_scope_names = []
            for s in self.action_scope_names:
                if  self.action == 'remove' and self.current_scope_names.__contains__(s):
                    self.output(f"Scope {s} will be removed", 3)
                    self.remove_scope_names.append(s)
                elif ['add','replace'].__contains__(self.action) and self.current_scope_names.__contains__(s) == False:
                    self.output(f"Scope {s} will be added", 3)
                    self.add_scope_names.append(s)
                if ['add','replace'].__contains__(self.action) and self.final_scope_names.__contains__(s) == False:
                    self.final_scope_names.append(s)
                
            for s in self.current_scope_names:
                if self.action == 'replace' and self.final_scope_names.__contains__(s) == False:
                    self.output(f"Scope {s} will be removed", 3)
                    self.remove_scope_names.append(s)
                elif self.action == 'add' and self.final_scope_names__contains__(s) == False:
                    self.output(f"Scope {s} will be kept", 3)
                    self.final_scope_names.append(s)
            self.output(f"Final security scopes will be set to: {', '.join(self.final_scope_names)}", 2)
            if self.final_scope_names == self.current_scope_names:
                self.output("Current scopes match desired scopes. Nothing to do.", 1)
                return
            if len(self.add_scope_names) == 0:
                self.output("No scopes to add", 2)
            # Add Scopes
            add_url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership.AddMemberships"
            add_scope_ids = [self.all_scopes['by_category_name_lower'][name.lower()].upper() for name in self.add_scope_names ]
            for add in add_scope_ids:
                add_params = {
                    "method":'POST',
                    "url":add_url,
                    "auth": self.ntlm,
                    "headers":self.headers,
                    "json":{
                        "ObjectIDs": [self.object_key],
                        "ObjectTypeIDs": [self.object_type_id],
                        "CategoryIDs": [add]
                    },
                    "verify":False
                }
                add_response = requests.request(**add_params)
                self.output(f"Add security scopes response: {add_response}", 3)
            # Remove scopes
            remove_scope_ids = [self.all_scopes['by_category_name_lower'][name.lower()].upper() for name in self.remove_scope_names ]
            if len(self.remove_scope_names) == 0:
                self.output("No security scopes to remove.", 3)
            for remove in remove_scope_ids:
                remove_url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership.RemoveMemberships"
                self.output("Removing scope ids",3)
                remove_response = requests.request(
                    method='POST',
                    url=remove_url,
                    headers=self.headers,
                    auth=self.ntlm,
                    json={
                        "ObjectIDs": [self.object_key],
                        "ObjectTypeIDs": [self.object_type_id],
                        "CategoryIDs": [remove]
                    },
                    verify=False
                )
                self.output(f"Remove security scopes response: {remove_response}", 3)            
        except Exception as e:
            raise e

if __name__ == "__main__":
    PROCESSOR = McmScopeSetter()
    PROCESSOR.execute_shell()