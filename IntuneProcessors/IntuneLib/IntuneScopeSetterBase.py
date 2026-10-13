#!/usr/local/autopkg/python
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

import json

from autopkglib import (  # pylint: disable=import-error
    ProcessorError,
)

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

sys.path.insert(0,os.path.dirname(__file__))
from IntuneLib.IntuneProcessorBase import ( #noqa: E402
    IntuneProcessorBase
)

import requests

class IntuneScopeSetterBase(IntuneProcessorBase):
    """Search Intune for an application and return the specified
    export properties
    """
    @staticmethod
    def combine_lists(original_list:list,new_list:list,algorithm_action:str) -> list:
        _action = algorithm_action.lower().strip()
        if False == ['add','remove','replace'].__contains__(_action):
            raise ProcessorError("Algorithm action not supported")

        if _action == 'replace':
            return new_list

        _resulting_list = list(original_list)
        for nli in new_list:
            if _action == 'add' and nli.lower() not in [lm.lower() for lm in _resulting_list]:
                _resulting_list.append(nli)
            elif _action == 'remove' and nli.lower() in [lm.lower() for lm in _resulting_list]:
                _resulting_list.remove(nli)

        return _resulting_list
    
    def initialize_all(self):
        self.initialize_auth()

    def execute(self):
        self.output("Getting scope tags", 3)
        self.initialize_all()
        
        all_scopes = self.get_scope_tags()
        
        scope_names = self.env.get('scope_names')
        if len(scope_names) == 0:
            raise ProcessorError("Must specify at least one scope name to use this processor")
        object_url = self.env.get('object_url',self.env.get('intune_application_url', None))
        if object_url is None or object_url == '':
            raise ProcessorError("object_url is required.")
        beta_version_forced = False
        api_version = self.get_api_version_from_url(object_url)
        self.output(f"Provided url uses the /{api_version} graph api endpoint", 3)
        self.output(f"Checking if the provided url contains roleScopeTagIds property", 2)
        field_search_response = requests.get(
            url=object_url,
            headers=self.graph_headers(),
            data={'$select':'@odata.context,roleScopeTagIds'}
        )
        if api_version.lower() == 'beta':
            use_beta = True
        else:
            use_beta = False
        field_search_response.raise_for_status()
        if True != field_search_response.json().__contains__('roleScopeTagIds') and not use_beta:
            self.output(f"Object does not appear to expose assigned scopes via {api_version} api version. Checking beta version.", 3)
            object_url = str(object_url).replace(api_version,'beta',1)
            use_beta = True
            beta_version_forced = True
            field_search_response = requests.get(
                url = object_url,
                headers = self.graph_headers()
            )
        elif api_version.lower() == 'beta' and True != field_search_response.json().__contains__('roleScopeTagIds'):
            raise ProcessorError("Object does not appear to expose assigned security scopes. Nothing to do")

        current_object = field_search_response.json()
        object_has_scopes = current_object.__contains__('roleScopeTagIds')
        if True != object_has_scopes:
            raise ProcessorError("Could not locate")
        if beta_version_forced:
            self.output(
                "The object's provided url did not provide assigned scope tags, " \
                "however the beta api version appears to. The beta version of the "
                "url will be used going forward.", 4
                )

        # map scope tags by id and by name
        scopes_by_id = {}
        scopes_by_name_lower = {}
        for scope in all_scopes:
            scopes_by_id[str(scope.get('id'))] = scope
            scopes_by_name_lower[str(scope.get('displayName').lower())] = scope

        action = self.env.get('action')
        current_scope_ids = list(current_object['roleScopeTagIds'])
        current_scope_ids.sort()
        current_scope_names = [scopes_by_id[str(id)]['displayName'] for id in current_object['roleScopeTagIds']]
        self.output(f"The object currently is assigned scope tags [{', '.join(current_scope_names)}]",2)
        self.output(f"Action: {action}", 3)
        new_scope_list = self.combine_lists(original_list=current_scope_names,new_list=scope_names,algorithm_action=action)
        self.output(f"Resulting desired scope tag list: {', '.join(new_scope_list)}", 2)
        new_scope_ids = []
        for nsi in new_scope_list:
            if True != scopes_by_name_lower.__contains__(nsi.lower()):
                raise ProcessorError(f"Could not process scope name [{nsi}]")
                
            new_scope_ids.append(str(scopes_by_name_lower[nsi.lower()]['id']))

        new_scope_ids.sort()
        self.output(f"Resulting desired scope tag ids: {', '.join(new_scope_ids)}", 3)
        if new_scope_ids == current_scope_ids:
            self.output("No changes detected. Nothing to do", 3)
            self.env['success'] = True
            return
        
        patch_body = {
            '@odata.type': current_object['@odata.type'],
            "roleScopeTagIds": new_scope_ids
        }
        patch_response = requests.patch(
            url = object_url,
            headers = self.graph_headers(),
            json = patch_body
        )
        patch_response.raise_for_status()
        self.output(f"Patch result: <{patch_response.status_code}>", 3)
        self.env['success'] = True
        return
    
if __name__ == "__main__":
    processor = IntuneScopeSetterBase()
    processor.execute_shell()