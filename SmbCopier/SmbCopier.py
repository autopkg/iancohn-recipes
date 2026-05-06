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

import platform
import shutil

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os
import sys

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"lib","vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

import keyring
import smbclient

from autopkglib import ( # pylint: disable=import-error
    Processor,
    ProcessorError,
)

def setup_credential():
    system = platform.system()
    if system == "Darwin":
        try:
            from keyring.backends import macOS
            keyring.set_keyring(macOS.Keyring())
        except ImportError as e:
            raise e
    elif system == "Windows":
        try:
            from keyring.backends import Windows
            keyring.set_keyring(Windows.WinVaultKeyring())
        except ImportError as e:
            raise e

setup_credential()

__all__ = ["SmbCopier"]


class SmbCopier(Processor):
    """This processor copies a file or folder to or from an SMB share using a credential stored in Keychain"""
    
    # Global version
    __version__ = "2026.05.06.0"
    
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
        "source_path": {
            "required": True,
            "description": "Path to a file or directory to copy."
        },
        "destination_path": {
            "required": True,
            "description": "SMB\\UNC formatted path to the destination."
        },
        "overwrite": {
            "required": False,
            "description": "Whether or not to overwrite the destination path if it already exists.",
            "default": False,
        },
    }
    output_variables = {}
    
    def initialize_auth(self):
        #self.initialize_ntlm_auth()
        self.output("Checking supplied parameters", 3)
        self.keychain_servicename = self.env.get("smbcopier_keychain_servicename", None)
        self.keychain_username = self.env.get("smbcopier_keychain_username", None)
        if (self.keychain_servicename == None or self.keychain_servicename == ''):
            raise ValueError("smbcopier_keychain_servicename cannot be blank")
        if (self.keychain_username == None or self.keychain_username == ''):
            raise ValueError("smbcopier_keychain_username cannot be blank")
        self.smb_password = keyring.get_password(self.keychain_servicename, self.keychain_username)
        self.output("Initializing SMB Client config with credential.", 3)
        smbclient.ClientConfig(username=self.keychain_username,password=self.smb_password)


    @staticmethod
    def is_smb(path : str) -> bool:
        _is_smb = False
        if path.startswith('\\\\'):
            _is_smb = True
        return _is_smb
    @staticmethod
    def smb_to_local(path : str) -> str:
        return path.replace('\\','/').replace('//','/')
    @staticmethod
    def local_to_smb(path : str, unc_prefix : bool=False,) -> str:
        _path = path.replace('/','\\')
        if unc_prefix:
            _path = _path.replace('\\','\\\\', 1)
        return _path
    def convert_path(self,path,in_type : str, out_type):
        if in_type == out_type:
            return path
        elif in_type == 'smb' and out_type == 'local':
            return self.smb_to_local(path)
        elif in_type == 'local' and out_type == 'smb':
            return self.local_to_smb(path)
        else:
            raise ProcessorError(f"Cannot convert {in_type} to {out_type}")
    @staticmethod
    def smb_should_nest(path : str) -> bool:
        return path.endswith('\\')
    @staticmethod
    def local_should_nest(path : str) -> bool:
        return path.endswith('/')
    
    def smb_parent(self, path : str) -> str:
        local_path = self.smb_to_local(path)
        local_parent = os.path.dirname(local_path)
        smb_parent = self.local_to_smb(local_parent,unc_prefix=True)
        return smb_parent
    
    def smb_split(self, path : str) -> list[str]:
        local_path = self.smb_to_local(path)
        local_split_path = os.path.split(local_path)
        smb_split_path = [
            self.local_to_smb(local_split_path[0],unc_prefix=True),
            self.local_to_smb(local_split_path[1],unc_prefix=True),
        ]
        return smb_split_path
    
    def smb_join(self,a, *p) -> str:
        local_path = self.smb_to_local(a)
        local_joined_path = os.path.join(local_path, *p)
        smb_joined_path = self.local_to_smb(local_joined_path)
        return smb_joined_path
    
    def smb_relpath(self,path : str, start : str = None,) -> str:
        relpath_params = {
            "path": self.smb_to_local(path),
            "start": None if start is None else self.smb_to_local(start),
        }
        local_relpath = os.path.relpath(**relpath_params)
        smb_relpath = self.local_to_smb(local_relpath)
        return smb_relpath

    def try_smbcopy(
            self,
            source_path : str,
            destination_path : str,
            create_path : bool = True,
            overwrite : bool = False) -> bool:
        """Attempt to mount an smb path and copy the indicated file"""
        filesystem = {
            'smb': {
                'opener': smbclient.open_file,
                'exists': smbclient.path.exists,
                'isfile': smbclient.path.isfile,
                'isdir': smbclient.path.isdir,
                'makedirs': smbclient.makedirs,
                'remove': smbclient.remove,
                'rmdir': smbclient.rmdir,
                'should_nest': self.smb_should_nest,
                'parent': self.smb_parent,
                'split': self.smb_split,
                'join': self.smb_join,
                'walk': smbclient.walk,
                'relpath': self.smb_relpath
            },
            'local': {
                'opener': open,
                'exists': os.path.exists,
                'isfile': os.path.isfile,
                'isdir': os.path.isdir,
                'makedirs': os.makedirs,
                'remove': os.remove,
                'rmdir': os.rmdir,
                'should_nest': self.local_should_nest,
                'parent': os.path.dirname,
                'split': os.path.split,
                'join': os.path.join,
                'walk': os.walk,
                'relpath': os.path.relpath,
            },
        }

        try:
            src_loc = 'smb' if self.is_smb(source_path) else 'local'
            self.output(f"Source path type: {src_loc}", 2)
            if not filesystem[src_loc]['exists'](source_path):
                self.output(f"Source does not exist: {source_path}")
                raise ProcessorError('Source does not exist.')
            
            src_type = 'file' if filesystem[src_loc]['isfile'](source_path) else \
                'directory' if filesystem[src_loc]['isdir'](source_path) else \
                    None
            
            if src_type is None:
                raise ProcessorError('Could not determine source object type')

            self.output(f"Source object type is a {src_type}", 3)

            dst_loc = 'smb' if self.is_smb(destination_path) else 'local'
            self.output(f"Destination location type: {dst_loc}", 2)
            
            if filesystem[dst_loc]['should_nest'](destination_path):
                self.output(f"Source {src_type} will be nested into destination path.", 3)
                _destination_path = filesystem[dst_loc]['join'](
                    destination_path,
                    self.convert_path(
                        path=filesystem[src_loc]['split'](source_path)[-1],
                        in_type=src_loc,
                        out_type=dst_loc
                        )
                    )
                self.output(f"New destination path: {_destination_path}", 3)
            else:
                _destination_path = destination_path

            if filesystem[dst_loc]['exists'](_destination_path):
                self.output(f"{src_type.capitalize()} already exists", 3)
                if not overwrite:
                    raise ProcessorError("Destination path already exists")
                else:
                    self.output(f"Overwrite: {overwrite}, the current {src_type} object will be removed.", 3)
                    if src_type == 'file':
                        filesystem[dst_loc]['remove'](_destination_path)
                    else:
                        for root,dirs,files in filesystem[dst_loc]['walk'](_destination_path,topdown=False):
                            for file in files:
                                self.output(f"Deleting File: {filesystem[dst_loc]['join'](root,file)}", 3)
                                filesystem[dst_loc]['remove'](filesystem[dst_loc]['join'](root,file))
                            for dir in dirs:
                                self.output(f"Deleting Directory: {filesystem[dst_loc]['join'](root,dir)}", 3)
                                filesystem[dst_loc]['rmdir'](filesystem[dst_loc]['join'](root,dir))
                        self.output(f"Deleting Directory: {root}", 3)
                        filesystem[dst_loc]['rmdir'](root)
                        self.output("Finished deleting current occupants.", 3)

            dirname = filesystem[dst_loc]['parent'](_destination_path)
            if not filesystem[dst_loc]['exists'](dirname):
                if create_path:
                    self.output(f"Creating parent directory, if it does not exist: {dirname}", 3)
                    _ = filesystem[dst_loc]['makedirs'](dirname, exist_ok=True)
                else:
                    raise ProcessorError(f"{dirname} does not exist and create_path was not set to True")

            if (src_type == 'directory'):
                src_root = None
                dst_root = _destination_path
                for root, dirs, files in filesystem[src_loc]['walk'](source_path):
                    if src_root is None:
                        src_root = root
                    for dir in dirs:
                        src_dir_relpath = filesystem[src_loc]['relpath'](filesystem[src_loc]['join'](root,dir),src_root)
                        dst_dir_abspath = filesystem[dst_loc]['join'](dst_root,src_dir_relpath)
                        filesystem[dst_loc]['makedirs'](dst_dir_abspath,exist_ok=True)
                    for file in files:
                        src_file_relpath = filesystem[src_loc]['relpath'](filesystem[src_loc]['join'](root,file),src_root)
                        dst_file_relpath = self.convert_path(src_file_relpath,in_type=src_loc,out_type=dst_loc)
                        src_file_abspath = filesystem[src_loc]['join'](source_path,src_file_relpath)
                        dst_file_abspath = filesystem[dst_loc]['join'](dst_root,dst_file_relpath)
                        self.output(f"Copying file {src_file_relpath} to {dst_file_abspath}")
                        with filesystem[src_loc]['opener'](src_file_abspath,mode='rb') as src, \
                            filesystem[dst_loc]['opener'](dst_file_abspath,mode='wb') as dst:
                            shutil.copyfileobj(src,dst)
                    
            else:
                with filesystem[src_loc]['opener'](source_path,mode='rb') as src, \
                    filesystem[dst_loc]['opener'](_destination_path,mode='wb') as dst:
                    shutil.copyfileobj(src,dst)
            return True
        
        except Exception as e:
            self.output(e, 2)
            return False

    def main(self):
        self.initialize_auth()
        self.try_smbcopy(
            self.env.get('source_path'),
            self.env.get('destination_path'),
            create_path=True,
            overwrite=self.env.get('overwrite',False)
            )
        pass


if __name__ == "__main__":
    PROCESSOR = SmbCopier()
    PROCESSOR.execute_shell()