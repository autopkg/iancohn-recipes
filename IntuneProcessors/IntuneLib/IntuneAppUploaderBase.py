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

from autopkglib import (  # pylint: disable=import-error
    ProcessorError,
)

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys
import json

sys.path.insert(0,os.path.dirname(__file__))
from IntuneLib.IntuneProcessorBase import ( #noqa: E402
    IntuneProcessorBase,
    IntuneOdataType,
    validate_enum
)

class IntuneAppUploaderBase(IntuneProcessorBase):
    """Search Intune for an application and return the specified
    export properties
    """
    def initialize_all(self):
        self.initialize_auth()
        self.initialize_export_properties("intune_app_uploader_export_properties")
        self.application_name = self.env.get('application_name')

    def execute(self):
        self.initialize_all()

        existing_app = self.get_intune_app_by_name(self.application_name)
        if existing_app != {} and False == self.env.get('update_existing_application', False):
            self.output(f"Application [{self.application_name}] already exists.", 3)
            raise ProcessorError("Cannot continue. If updating is desired, set update_existing_application to True")
        
        self.output("Examining filepath", 2)
        filepath = self.env.get('intune_filepath', self.env.get('intunewin_filepath',''))
        filename = os.path.basename(filepath)
        if filepath.strip() == '':
            raise ProcessorError("intune_filepath cannot be blank")
        elif not os.path.exists(filepath):
            raise ProcessorError(f"File [{filepath}] does not exist")
        
        if os.path.splitext(filepath)[1].lower() == '.intunewin':
            is_intunewin = True
        else:
            is_intunewin = False

        if not is_intunewin:
            raise ProcessorError("Unsupported file type. Only .intunewin is currently supported")

        self.output("Getting encryption information from arguments", 2)
        _unencrypted_filesize = self.env.get(
            'unencrypted_filesize',
            self.env.get('intunewin_unencrypted_filesize')
            )
        unencrypted_filesize = self.try_cast(type_name = int,value = _unencrypted_filesize)

        encryption_key = self.env.get(
            'encryption_key',
            self.env.get('intunewin_encryption_key','')
            ).strip()
        mac_key = self.env.get('mac_key',self.env.get('intunewin_mac_key','')).strip()
        mac = self.env.get('mac',self.env.get('intunewin_mac','')).strip()
        initialization_vector = self.env.get(
            'initialization_vector',
            self.env.get('intunewin_initialization_vector','')
            ).strip()
        file_digest = self.env.get('file_digest',self.env.get('intunewin_file_digest','')).strip()
        file_digest_algorithm = self.env.get(
            'file_digest_algorithm',
            self.env.get('intunewin_file_digest_algorithm','')
            ).strip()
        profile_identifier = self.env.get(
            'profile_identifier',
            self.env.get('intunewin_profile_identifier','')
            ).strip()

        if is_intunewin and (
            encryption_key == '' or mac_key == '' or mac == '' or initialization_vector == '' or
            file_digest == '' or file_digest_algorithm == '' or profile_identifier == ''
            ):
            raise ProcessorError("Encryption info parameters must be defined when using .intunewin files")

        
        minimum_supported_os = self.env.get('minimum_supported_os', '1607')
        app_type = validate_enum(IntuneOdataType,self.env.get('application_type')).value

        all_rules = []

        detection_rules = []
        # Included rule is just for testing.
        #configured_detection_rules = #self.env.get('detection_rules',
        configured_detection_rules = [{
            'rule_short_odata_type': 'Win32LobAppFileSystemRule',
            'options': {
                'path': 'C:\\path\\to\\folder',
                'operation_type': 'exists',
                'operator': 'notConfigured',
                'filesystem_object_name': 'File.txt',
                'check_x32_on_x64': False
            }
        }]
        #)
        self.output(f"Iterating over {len(configured_detection_rules)} detection rules", 2)
        for detection_rule in configured_detection_rules:
            self.output("Begin inspecting detection rule", 3)
            _detection_config = detection_rule['options']
            _short_odata_type = detection_rule['rule_short_odata_type']
            self.output(f"rule_short_odata_type: {_short_odata_type}")
            rule = self.rule_creator[_short_odata_type](
                _short_odata_type,
                'detection',
                **_detection_config
                )
            all_rules.append(rule)
            detection_rules.append(rule.get_detection_rule())
            self.output("Done with rule")

        self.output("Finished with detection rules", 2)

        requirement_rules = []
        configured_requirement_rules = self.env.get('requirement_rules',[])
        self.output(f"Iterating over {len(configured_requirement_rules)} requirement rules", 2)
        for requirement_rule in configured_requirement_rules:
            self.output("Begin inspecting requirement rule", 3)
            _requirement_config = requirement_rule['options']
            _short_odata_type = requirement_rule['rule_short_odata_type']
            rule = self.rule_creator[_short_odata_type](
                _short_odata_type,
                'requirement',
                **_requirement_config
                )
            all_rules.append(rule)
            requirement_rules.append(rule.get_requirement_rule())
            self.output("Done with rule")

        self.output("Finished with requirement rules", 2)         
        icon_path = self.env.get('application_icon_unix_path')

        if icon_path is not None and icon_path != '':
            self.output("Getting icon data", 2)
            icon, mime_type = self.encode_icon(local_path = icon_path)
            icon_data = {
                '@odata.type': '#microsoft.graph.mimeContent',
                'type': mime_type,
                'value': icon
            }
        else:
            icon_data = {}

        self.output("Collecting app payload", 2)
        app_payload = {
            '@odata.type': app_type,
            'displayName': self.env.get('application_name'),
            'description': self.env.get('application_description'),
            'publisher': self.env.get('application_publisher'),
            'setupFilePath': self.env.get('intune_setup_filepath', self.env.get('intunewin_setup_file', 'setup.exe')),
            'fileName': filename,
            'installCommandLine': self.env.get('application_install_commandline'),
            'uninstallCommandLine': self.env.get('application_uninstall_commandline'),
            'applicableArchitectures': self.env.get('applicable_architectures'),
            'minimumSupportedWindowsRelease': minimum_supported_os,
            'displayVersion': self.env.get('application_display_version'),
            'installExperience': {
                'runAsAccount': self.env.get('installation_runas'),
                'deviceRestartBehavior': self.env.get('restart_behavior'),
            },
            'detectionRules': detection_rules,
            'largeIcon': icon_data,
        }
        if len(requirement_rules) > 0:
            app_payload['requirementRules'] = requirement_rules,
        app_payload['rules'] = all_rules

        if False:
            raise ProcessorError("Updating not supported yet.")

        new_app = self.new_intune_app(app_payload=app_payload)
        app_id = new_app['id']

        content_version = self.new_intune_app_content_version(application_id=app_id,odata_type_str=new_app['@odata.type'])
        
        sas_uri = self.new_azure_blob_sas_uri(
            file_path=filepath,
            application_id=app_id,
            odata_type_str=new_app['@odata.type'],
            content_version_id=content_version,
            unencrypted_size=unencrypted_filesize,
            wait=True
            )
        file_id = sas_uri.get('id','')
        _ = self.upload_intune_content(
            file_path = filepath,
            sas_uri = sas_uri['azureStorageUri'],
            application_id = app_id,
            file_id = file_id,
            odata_type_str = new_app['@odata.type'],
            content_version_id = content_version,
            encryption_key = encryption_key,
            mac_key = mac_key,
            initialization_vector = initialization_vector,
            mac = mac,
            file_digest = file_digest,
            file_digest_algorithm = file_digest_algorithm,
            profile_identifier = profile_identifier
        )

        self.response_value = self.get_intune_app_by_name(application_name=self.application_name)
        
        if self.response_value is not None and self.response_value != {}:
            self.env['intune_application_created'] = True
            self.set_export_properties()
        else:
            self.output("No application found; no export properties will be set", 3)


if __name__ == "__main__":
    processor = IntuneAppUploaderBase()
    processor.execute_shell()