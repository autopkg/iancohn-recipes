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

import atexit
#import string
#import random
import base64
from copy import deepcopy
from ctypes import c_int32
from datetime import datetime, timezone
from enum import Enum, auto
from io import BytesIO
import json
from os import path, walk, unlink
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import uuid
import zipfile

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from autopkglib import ( # pylint: disable=import-error
    Processor,
    ProcessorError,
)

class IntuneProcessorBase(Processor):
    """Common functions needed for Intune processors"""
    @staticmethod
    def pad_pkcs7(data: bytes, block_size_bits: int = 128) -> bytes:
        """Pads input byte array to match AES block size requirements using PKCS#7."""
        padder = padding.PKCS7(block_size_bits).padder()
        return padder.update(data) + padder.finalize()

    @staticmethod
    def create_source_zip(source_folder: str) -> bytes:
        """
        Zips all non-hidden files within the source directory into an in-memory buffer.
        Ensures ZIP path separators use forward slashes (POSIX) for cross-platform compliance.
        """
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(source_folder):
                for file in files:
                    if file.startswith("."):
                        continue  # Ignore OS hidden files (.DS_Store, etc.)
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, source_folder)
                    posix_path = rel_path.replace("\\", "/")
                    zf.write(abs_path, posix_path)
        return zip_buffer.getvalue()

    @staticmethod
    def encrypt_content(unencrypted_bytes: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypts content using AES-256-CBC mode with PKCS#7 padding."""
        padded_data = IntuneProcessorBase.pad_pkcs7(unencrypted_bytes, 128)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def initialize_auth(self):
        self.output("Checking supplied parameters", 3)

if __name__ == "__main__":
    PROCESSOR = IntuneProcessorBase()
    PROCESSOR.execute_shell()