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

import os.path
import sys

# to use a base module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
sys.path.insert(0, os.path.dirname(__file__))

from SmbCopierLib.SmbCopierBase import (  # pylint: disable=import-error, wrong-import-position
    SmbCopierBase,
)

__all__ = ["SmbCheckPath"]


class SmbCheckPath(SmbCopierBase):
    """This processor copies a file or folder to or from an SMB share using a credential stored in Keychain"""
   
    description = __doc__
    input_variables = {
        "smbcopier_keychain_servicename": {
            "required": True,
            "description": "The service name used to store the password.",
        },
        "smbcopier_keychain_username": {
            "required": True,
            "description": "The username of the credential to retrieve."
        },
        "smb_path": {
            "required": True,
            "description": "Path to a file or directory"
        }
    }
    output_variables = {
        "smb_path_exists": {
            "description": "Returns True if the path exists, returns None if error encountered",
        },
        "smb_path_is_dir": {
            "description": "Returns True if the path exists and is a container/directory, returns None if item does not exist",
        },
        "smb_path_is_file": {
            "description": "Returns True if the path exists and is a file, returns None if item does not exist",
        },
    }
    
    def main(self):
        self.initialize_all()
        self.check_smb_path(self.env.get('smb_path'))
        self.env['smb_path_exists'] = self.smb_path_exists
        self.env['smb_path_is_dir'] = self.smb_path_is_dir
        self.env['smb_path_is_file'] = self.smb_path_is_file

if __name__ == "__main__":
    PROCESSOR = SmbCheckPath()
    PROCESSOR.execute_shell()