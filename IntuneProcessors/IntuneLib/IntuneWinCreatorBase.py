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
import os
import sys
import platform

sys.path.insert(0,os.path.dirname(__file__))
from IntuneLib.IntuneProcessorBase import ( #noqa: E402
    IntuneProcessorBase
)

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

import base64
import hashlib
import hmac
import zipfile
from io import BytesIO

TOOL_VERSION = "1.8.7.0"

class IntuneWinCreatorBase(IntuneProcessorBase):
    """Create an IntuneWin compressed file from a directory
    """
    @staticmethod
    def generate_detection_xml(
        setup_file: str,
        unencrypted_size: int,
        key_b64: str,
        mac_key_b64: str,
        iv_b64: str,
        mac_b64: str,
        file_digest_b64: str,
        tool_version: str = TOOL_VERSION,
    ) -> str:
        """
        Generates Detection.xml matching the exact XML schema produced by Microsoft's Intune Content Prep Tool.
        Uses CRLF (\r\n) line endings and exact element structure expected by .NET XmlSerializer.
        """
        xml_content = (
            f'<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="{tool_version}">\r\n'
            f'<Name>{setup_file}</Name>\r\n'
            f'<UnencryptedContentSize>{unencrypted_size}</UnencryptedContentSize>\r\n'
            f'<FileName>IntunePackage.intunewin</FileName>\r\n'
            f'<SetupFile>{setup_file}</SetupFile>\r\n'
            f'<EncryptionInfo>\r\n'
            f'<EncryptionKey>{key_b64}</EncryptionKey>\r\n'
            f'<MacKey>{mac_key_b64}</MacKey>\r\n'
            f'<InitializationVector>{iv_b64}</InitializationVector>\r\n'
            f'<Mac>{mac_b64}</Mac>\r\n'
            f'<ProfileIdentifier>ProfileVersion1</ProfileIdentifier>\r\n'
            f'<FileDigest>{file_digest_b64}</FileDigest>\r\n'
            f'<FileDigestAlgorithm>SHA256</FileDigestAlgorithm>\r\n'
            f'</EncryptionInfo>\r\n'
            f'</ApplicationInfo>'
        )
        return xml_content

    def package_intunewin(
            self,
            source_folder : str,
            setup_file : str,
            output_folder : str, 
            output_filename : str
            ):
        os.makedirs(output_folder, exist_ok=True)
        self.output("Creating .intunewin file", 1)
        self.output("Compressing source directory into inner ZIP archive", 3)
        unencrypted_zip = self.create_source_zip(source_folder)
        
        # IntuneWinAppUtil sets UnencryptedContentSize to the byte length of the unencrypted inner ZIP payload
        self.env['intunewin_unencrypted_size'] = len(unencrypted_zip)

        self.output("Computing unencrypted inner ZIP SHA-256 digest",3)
        digest = hashlib.sha256(unencrypted_zip).digest()
        file_digest_b64 = base64.b64encode(digest).decode("utf-8")

        self.output("Generating random cryptographic keys (AES-256 & HMAC-SHA256)", 3)
        encryption_key = os.urandom(32)  # 256 bits
        mac_key = os.urandom(32)         # 256 bits
        iv = os.urandom(16)              # 128 bits

        self.output("Encrypting archive (AES-256-CBC) and generating HMAC", 3)
        encrypted_bytes = self.encrypt_content(unencrypted_zip, encryption_key, iv)
        
        # Official IntuneWinAppUtil calculates HMAC-SHA256 over (IV + AES Ciphertext):
        mac = hmac.new(mac_key, iv + encrypted_bytes, hashlib.sha256).digest()

        key_b64 = base64.b64encode(encryption_key).decode("utf-8")
        mac_key_b64 = base64.b64encode(mac_key).decode("utf-8")
        iv_b64 = base64.b64encode(iv).decode("utf-8")
        mac_b64 = base64.b64encode(mac).decode("utf-8")

        # IntuneWinAppUtil 48-byte binary header layout:
        # Bytes 0..31: HMAC-SHA256 signature (32 bytes)
        # Bytes 32..47: AES Initialization Vector (16 bytes)
        header_48_bytes = mac + iv
        packaged_content = header_48_bytes + encrypted_bytes

        detection_xml = self.generate_detection_xml(
            setup_file=setup_file,
            unencrypted_size=self.env['intunewin_unencrypted_size'],
            key_b64=key_b64,
            mac_key_b64=mac_key_b64,
            iv_b64=iv_b64,
            mac_b64=mac_b64,
            file_digest_b64=file_digest_b64,
            tool_version=TOOL_VERSION,
        )

        output_path = os.path.join(output_folder, output_filename)
        self.output(f"Writing outer .intunewin package to {output_path}", 3)

        # Outer archive layout matching Microsoft Intune Content Prep Tool ZIP structure:
        # 1. Store mode (ZIP_STORED / Method 0) without secondary compression
        # 2. No explicit directory entries
        # 3. UTF-8 BOM (\xef\xbb\xbf) prefix for Detection.xml matching .NET StreamWriter
        detection_bytes = b"\xef\xbb\xbf" + detection_xml.encode("utf-8")

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_STORED) as outer_zip:
            outer_zip.writestr("IntuneWinPackage/Contents/IntunePackage.intunewin", packaged_content)
            outer_zip.writestr("IntuneWinPackage/Metadata/Detection.xml", detection_bytes)

        self.output("successfully created .intunewin file", 1)

    def initialize_all(self):
        pass
    def execute(self):
        self.initialize_all()
        source_folder = self.env.get('intunewin_source_folder')
        setup_file = self.env.get('intunewin_setup_file')
        output_folder = self.env.get('intunewin_output_folder',self.env['RECIPE_CACHE_DIR'])
        output_filename = self.env.get('intunewin_output_filename',os.path.splitext(setup_file)[0]) + '.intunewin'
        destination_filepath = os.path.join(output_folder,output_filename)
        try:
            if os.path.exists(destination_filepath):
                self.output(f"File [{destination_filepath}] already exists", 3)
                if self.env.get('intunewin_overwrite'):
                    self.output("Removing existing file", 2)
                    os.unlink(destination_filepath)
                else:
                    raise ProcessorError(f'File [{destination_filepath}] already exists and intunewin_overwrite was not set to True')

            self.package_intunewin(
                source_folder=source_folder,
                setup_file=setup_file,
                output_folder=output_folder,
                output_filename=output_filename
            )
            self.env['intunewin_filepath'] = destination_filepath
        except Exception as e:
            raise ProcessorError(f"Failed to create IntuneWin file: {e}")


if __name__ == "__main__":
    processor = IntuneWinCreatorBase()
    processor.execute_shell()