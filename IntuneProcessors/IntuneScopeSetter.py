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

from IntuneLib.IntuneScopeSetterBase import (  # pylint: disable=import-error, wrong-import-position
    IntuneScopeSetterBase,
)

__all__ = ["IntuneScopeSetter"]

class IntuneScopeSetter(IntuneScopeSetterBase):
    description = """AutoPkg Processor to connect to an MCM Admin
    Service and retrieve an application object, if it exists
    """
    input_variables = {
        "intune_app_keychain_service": {
            "required": False,
            "description": "The service name used to store the password. Defaults to com.github.autopkg.iancohn-recipes.mcmapi",
            "default": 'com.github.autopkg.iancohn-recipes.intuneprocessors'
        },
        "intune_app_keychain_username": {
            "required": False,
            "description": "The username of the credential to retrieve.",
        },
        "intune_app_client_id": {
            "required": True,
            "description": "The client id of the app registration with permissions to Intune",
        },
        "intune_tenant_id": {
            "required": True,
            "description": "The tenant id for the Intune tenant and app registration",
        },
        "object_type": {
            "required": False,
            "description": "The type of object to upload",
            "default": "Win32LobApp",
            "options": [
                "Win32LobApp",
            ]
        },
        "object_url": {
            "required": False,
            "description": "The graph url to the object. Defaults to the value of intune_application_url",
        },
        "action": {
            "required": False,
            "description": "Whether to add, remove, or replace the existing set of scope tags on the object",
            "default": "add",
            "options": [
                "add",
                "remove",
                "replace"
            ]
        },
        "scope_names": {
            "required": False,
            "description": "An array of scope names to pass to the processor",
            "default": ['Default'],
        },
    }
    output_variables = {
        "success": {
            "description": "Returns True if the operation succeeded."
        }
    }

    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = IntuneScopeSetter()
    PROCESSOR.execute_shell()
