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

        existing_app_response = self.get_intune_app_by_name(self.application_name)
        if existing_app_response is not None and len(existing_app_response) == 2:
            existing_app = existing_app_response[1]
        if existing_app != {} and False == self.env.get('update_existing_application', False):
            self.output(f"Application [{self.application_name}] already exists.", 3)
            raise ProcessorError("Cannot continue. If updating is desired, set update_existing_application to True")
        
        self.output("Examining filepath", 2)
        filepath = self.env.get('intune_filepath', self.env.get('intunewin_filepath',''))
        if filepath == '':
            raise ProcessorError("filepath must not be empty.")
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
        _encrypted_filesize = self.env.get(
            'encrypted_filesize',
            self.env.get('intunewin_encrypted_filesize')
            )
        encrypted_filesize = self.try_cast(type_name = int,value = _encrypted_filesize)
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
        configured_detection_rules = self.env.get('detection_rules')

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
        
        install_experience = {
            'runAsAccount': self.env.get('installation_runas'),
            #'maxRunTimeInMinutes': max_run_time, # not supported on v1.0 endpoint
            'deviceRestartBehavior': self.env.get('restart_behavior'),
            #'inUseBehavior': None # not supported on v1.0 endpoint
        }

        # Return Codes
        default_return_codes = {
            0: "success",
            1707: "success",
            3010: "softReboot",
            1641: "hardReboot",
            1618: "retry"
        }
        if self.env.get('keep_default_return_codes'):
            return_codes = dict(default_return_codes)
        else:
            return_codes = {}
        
        for rc in self.env.get('return_codes',[]):
            return_codes[rc.get('return_code')] = rc['type']

        return_codes_list = []
        for crc in return_codes.items():
            return_codes_list.append({'returnCode':crc[0],'type':crc[1]})
        
        self.output("Collecting app payload", 2)
        app_payload = {
            '@odata.type': app_type,
            'displayName': self.env.get('application_name'),
            'description': self.env.get('application_description'),
            'publisher': self.env.get('application_publisher'),
            'isFeatured': self.env.get('is_featured'),
            'setupFilePath': self.env.get('intune_setup_filepath', self.env.get('intunewin_setup_file', 'setup.exe')),
            'fileName': filename,
            'installCommandLine': self.env.get('application_install_commandline'),
            'uninstallCommandLine': self.env.get('application_uninstall_commandline'),
            'applicableArchitectures': self.env.get('applicable_architectures'),
            'minimumSupportedWindowsRelease': minimum_supported_os,
            'displayVersion': str(self.env.get('application_display_version','')),
            'installExperience': install_experience,
            'detectionRules': detection_rules,
            'largeIcon': icon_data,
            'returnCodes': return_codes_list,
        }
        empty_str_null = ['',None]
        if False == empty_str_null.__contains__(self.env.get('privacy_url')):
            app_payload['privacyInformationUrl'] = str(self.env.get('privacy_url'))
        if False == empty_str_null.__contains__(self.env.get('information_url')):
            app_payload['informationUrl'] = str(self.env.get('information_url'))
        if False == empty_str_null.__contains__(self.env.get('owner')):
            app_payload['owner'] = str(self.env.get('owner'))
        if False == empty_str_null.__contains__(self.env.get('developer')):
            app_payload['developer'] = str(self.env.get('developer'))
        if False == empty_str_null.__contains__(self.env.get('notes')):
            app_payload['notes'] = str(self.env.get('notes'))
        if False == empty_str_null.__contains__(self.env.get('allowed_architectures')):
            app_payload['allowedArchitectures'] = str(self.env.get('allowed_architectures'))
        if False == empty_str_null.__contains__(self.env.get('minimum_diskspace_mb')):
            app_payload['minimumFreeDiskSpaceInMB'] = int(self.env.get('minimum_diskspace_mb'))
        if False == empty_str_null.__contains__(self.env.get('minimum_memory_mb')):
            app_payload['minimumMemoryInMB'] = int(self.env.get('minimum_memory_mb'))
        if False == empty_str_null.__contains__(self.env.get('minimum_processors')):
            app_payload['minimumNumberOfProcessors'] = int(self.env.get('minimum_processors'))
        if False == empty_str_null.__contains__(self.env.get('minimum_cpuspeed_mhz')):
            app_payload['minimumCpuSpeedInMHz'] = int(self.env.get('minimum_cpuspeed_mhz'))

        if len(requirement_rules) > 0:
            app_payload['requirementRules'] = requirement_rules,
        app_payload['rules'] = all_rules

        new_app = self.new_intune_app(app_payload=app_payload)
        app_id = new_app['id']
        
        content_version = self.new_intune_app_content_version(application_id=app_id,odata_type_str=new_app['@odata.type'])
        
        sas_uri = self.new_azure_blob_sas_uri(
            file_path=filepath,
            application_id=app_id,
            odata_type_str=new_app['@odata.type'],
            content_version_id=content_version,
            encrypted_size=encrypted_filesize,
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

        # /beta items
        # 
        beta_payload = {
            '@odata.type': app_type,
        }
        has_beta = False
        # Max Run Time
        default_max_run_time = self.input_variables['max_run_time']['default']
        max_run_time = self.try_cast(type_name=int,value=self.env.get('max_run_time'),default=default_max_run_time)
        if default_max_run_time != max_run_time:
            self.output("Non-default maximum runtime has been set. ", 3)
            has_beta = True
            install_experience['maxRunTimeInMinutes'] = max_run_time
            install_experience['inUseBehavior'] = None
            beta_payload['installExperience'] = install_experience

        # Display Version
        display_version = self.env.get('application_display_version','')
        if display_version.strip() != '':
            self.output("Display Version has been set.", 3)
            has_beta = True
            beta_payload['displayVersion'] = display_version.strip()

        if has_beta:
            self.update_intune_app_beta(
                app_payload=beta_payload,
                app_id=app_id,
                raise_error=True
                )

        
        new_app = self.get_intune_app_by_name(application_name=self.application_name,use_beta_url=False)
        self.output(f"Intune app url: {new_app[0]}")
        if new_app is not None and len(new_app) == 2 and new_app[1] != {}:
            self.env['intune_application_created'] = True
            self.response_value = new_app[1]
            self.env['intune_application_url'] = new_app[0]
            self.set_export_properties()
        else:
            self.output("No application found; no export properties will be set", 3)


if __name__ == "__main__":
    processor = IntuneAppUploaderBase()
    processor.execute_shell()