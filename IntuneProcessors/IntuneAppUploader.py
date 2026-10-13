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

from IntuneLib.IntuneAppUploaderBase import (  # pylint: disable=import-error, wrong-import-position
    IntuneAppUploaderBase,
)

__all__ = ["IntuneAppUploader"]

class IntuneAppUploader(IntuneAppUploaderBase):
    description = """AutoPkg Processor to connect to Intune
    and upload a new application object.
    """
    input_variables = {
        "intune_app_keychain_service": {
            "required": False,
            "description": "The service name used to store the password. Defaults to com.github.autopkg.iancohn-recipes.mcmapi",
            "default": 'com.github.autopkg.iancohn-recipes.intuneprocessors'
        },
        "intune_app_keychain_username": {
            "required": False,
            "description": "The username of the credential to retrieve."
        },
        "intune_app_client_id": {
            "required": True,
            "description": "The client id of the app registration with permissions to Intune"
        },
        "intune_tenant_id": {
            "required": True,
            "description": "The tenant id for the Intune tenant and app registration",
        },
        "application_type": {
            "required": False,
            "description": "The type of app to upload.",
            "default": "Win32LobApp",
            "options": [
                "Win32LobApp"
            ]
        },
        "application_name": {
            "required": True,
            "description": "The name of the application in MCM to search for."
        },
        "application_description": {
            "required": False,
            "description": "A description for the application.",
            "default": ""
        },
        "application_publisher": {
            "required": True,
            "description": "The publisher of the application"
        },
        "application_icon_unix_path": {
            "required": False,
            "description": "A local unix path to a local icon file to use for the application."
        },
        "application_install_commandline": {
            "required": True,
            "description": "The full command line needed to execute the installation",
        },
        "application_uninstall_commandline": {
            "required": False,
            "description": "The full command line needed to execute uninstallation",
            "default": "cmd /c"
        },
        "max_run_time": {
            "required": False,
            "description": "The time (in minutes) needed to install the application",
            "default": '60',
        },
        "allow_uninstall": {
            "required": False,
            "description": "Whether to allow users to uninstall the application using Company Portal",
            "default": False,
        },
        "restart_behavior": {
            "required": False,
            "description": "The restart behavior following installation",
            "default": "baseOnReturnCode",
            "options": ["basedOnReturnCode","suppress","allow","force"]
        },
        "installation_runas": {
            "required": False,
            "description": "Whether the install should run as 'system' or the loggd in user",
            "default": "system",
            "options": ['system','user']
        },
        #"application_setup_filename": {
        #    "required": False,
        #    "description": "The file name of the setup file. Defaults to intunewin_setup_filename",
        #},
        "minimum_supported_os": {
            "required": False,
            "description": "The minimum OS this application can install to.",
            "default": "1607",
        },
        "applicable_architectures": {
            "required": False,
            "description": "The os architectures to which this application can install",
            "default": 'x64,arm64,x86',
        },
        "application_display_version": {
            "required": False,
            "description": "The version to display for the application in Company Portal",
            "default": ''
        },
        "detection_rules": {
            "required": False,
            "description": "An array of detection rules to apply to the application"
        },
        "update_existing_application": {
            "required": False,
            "description": "Whether to overwrite an existing app of the same name",
            "default": False,
        },
        "intune_filepath": {
            "required": False,
            "description": "The full path of the file to upload. Defaults to intunewin_filepath"
        },
        "intune_setup_filepath": {
            "required": False,
            "description": "The path to the setup file within the archive. Defaults to intunewin_setup_file"
        },
        "unencrypted_filesize": {
            "required": False,
            "description": "The filesize of the unencrypted file. Defaults to intunewin_unencrypted_filesize"
        },
        "encrypted_filesize": {
            "required": False,
            "description": "The filesize of the encrypted file. Defaults to intunewin_encrypted_filesize"
        },
        "encryption_key": {
            "required": False,
            "description": "The encryption key. If uploading a .intunewin file, defaults to intunewin_encryption_key"
        },
        "mac_key": {
            "required": False,
            "description": "The mac key. If uploading a .intunewin file, defaults to intunewin_mac_key"
        },
        "mac": {
            "required": False,
            "description": "The mac. If uploading a .intunewin file, defaults to intunewin_mac"
        },
        "initialization_vector": {
            "required": False,
            "description": "The initialization vector for the file. If uploading a .intunewin file, defaults to intunewin_initialization_vector"
        },
        "file_digest": {
            "required": False,
            "description": "The file digest for the file. If uploading a .intunewin file, defaults to intunewin_file_digest"
        },
        "file_digest_algorithm": {
            "required": False,
            "description": "The file digest algorithm for the file. If uploading .intunewin file, defaults to intunewin_file_digest_algorithm"
        },
        "profile_identifier": {
            "required": False,
            "description": "The profile_identifier for the file. If uploading a .intunewin file, defaults to intunewin_profile_identifier"
        },
        "intune_app_uploader_export_properties": {
            "required": False,
            "default": {
                "new_app_id": {"type": "property", "raise_error": False,"options": {"property": "id"}},
                "new_app_install_cli": {"type": "property", "raise_error": False,"options": {"property": "installCommandLine"}},
                "new_app_publishing_state": {"type": "property", "raise_error": False,"options": {"property": "publishingState"}},
                "new_app_content_version": {"type": "property", "raise_error": False,"options": {"property": "committedContentVersion"}},
            },
            "description": 
                "A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output. "
                "Each key name specified will be used as the AutoPkg variable name; each value should be populated by a dictionary "
                "representing how to retrieve the property from the application. For Intune apps, only 'property' is supported. "
                "'raise_error' specifies whether to raise an error if the property cannot be found. "
                ""
                "'property' type options require an 'expression' option specifying the property name to retrieve from the application. "
                "'xpath' type options require a 'property' option specifying the property name (generally 'SDMPackageXML') to run the xpath query against, and an 'expression'. "
        }
    }
    output_variables = {
        "intune_application_created": {
            "description": "Returns True if the application was created successfully in the Intune instance, otherwise, returns false."
        },
        "intune_application_url": {
            "description": "The url of the resulting intune object"
        }
    }
    
    __doc__ = description
    
    def main(self):
        """Run the execute function"""
        self.execute()
    
if __name__ == "__main__":
    PROCESSOR = IntuneAppUploader()
    PROCESSOR.execute_shell()
