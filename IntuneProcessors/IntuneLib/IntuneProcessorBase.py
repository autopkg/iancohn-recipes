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

from io import BytesIO
from enum import Enum, auto
from enum import Enum
from typing import Any, Type, TypeVar
import platform
import zipfile
import time
import base64
import mimetypes
import json

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


import requests
import keyring
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from lxml import etree

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

# TypeVar ensures IDEs know the return type matches the specific Enum passed in
E = TypeVar("E", bound=Enum)

from autopkglib import ( # pylint: disable=import-error
    Processor,
    ProcessorError,
)

GRAPH_BASE_URL = 'https://graph.microsoft.com'
INTUNE_MAX_ICON_SIZE = 750 * 1024 # 750 KB
# Helper functions
def validate_enum(enum_cls: Type[E], value: Any) -> E:
    """Validates and converts any value against any Enum class.
    Args:
        enum_cls: The Enum class to validate against (e.g., AppType, Intent).
        value: The incoming parameter value (string, int, or Enum instance).
    Returns:
        The validated Enum member instance.
    Raises:
        ValueError: If value is not a valid member or value of enum_cls.
    """
    # 1. If it's already an instance of the target Enum class
    if isinstance(value, enum_cls):
        return value
    # 2. Try looking up by value (only for hashable types like str, int)
    if isinstance(value, (str, int)):
        try:
            return enum_cls[value]
        except ValueError:
            pass  # Fall through to clean error message
    # 3. Clean error reporting across all types
    valid_options = [e.name for e in enum_cls]
    raise ValueError(
        f"Invalid value '{value}' (type: {type(value).__name__}) for {enum_cls.__name__}. "
        f"Must be one of: {valid_options}"
    )

# Detection/Requirement classes
class IntuneOdataType(Enum):
    #
    Win32LobApp = '#microsoft.graph.win32LobApp'
    #
    Win32LobAppRegistryRule = '#microsoft.graph.win32LobAppRegistryRule'
    Win32LobAppPowerShellScriptRule = '#microsoft.graph.win32LobAppPowerShellScriptRule'
    Win32LobAppFileSystemRule = '#microsoft.graph.win32LobAppFileSystemRule'
    Win32LobAppProductCodeRule =  '#microsoft.graph.win32LobAppProductCodeRule'
    #
    Win32LobAppRegistryDetection = '#microsoft.graph.win32LobAppRegistryDetection'
    Win32LobAppPowerShellScriptDetection = '#microsoft.graph.win32LobAppPowerShellScriptDetection'
    Win32LobAppFileSystemDetection = '#microsoft.graph.win32LobAppFileSystemDetection'
    Win32LobAppProductCodeDetection = '#microsoft.graph.win32LobAppProductCodeDetection'
    #
    Win32LobAppRegistryRequirement = '#microsoft.graph.win32LobAppRegistryRequirement'
    Win32LobAppPowerShellScriptRequirement = '#microsoft.graph.win32LobAppPowerShellScriptRequirement'
    Win32LobAppFileSystemRequirement = '#microsoft.graph.win32LobAppFileSystemRequirement'
    #
    MacOSIncludedApp = '#microsoft.graph.macOSIncludedApp'
    MacOSDmgApp = '#microsoft.graph.macOSDmgApp'
    MacOSPkgApp = '#microsoft.graph.macOSPkgApp'
    MacOSLobChildApp = '#microsoft.graph.macOSLobChildApp'

class IntuneRuleType(Enum):
    detection = 'detection'
    requirement = 'requirement'

class IntuneRuleShortOdataType(Enum):
    Win32LobAppRegistryRule = 'Win32LobAppRegistryRule'
    Win32LobAppPowerShellScriptRule = 'Win32LobAppPowerShellScriptRule'
    Win32LobAppFileSystemRule = 'Win32LobAppFileSystemRule'
    Win32LobAppProductCodeRule = 'Win32LobAppProductCodeRule'

short_type_to_odata_type = {
    'Win32LobAppRegistryRule': '#microsoft.graph.win32LobAppRegistryRule',
    'Win32LobAppPowerShellScriptRule': '#microsoft.graph.win32LobAppPowerShellScriptRule',
    'Win32LobAppFileSystemRule': '#microsoft.graph.win32LobAppFileSystemRule',
    'Win32LobAppProductCodeRule': '#microsoft.graph.win32LobAppProductCodeRule',
}
rule_short_type_to_requirement_odata_type = {
    'Win32LobAppRegistryRule': '#microsoft.graph.win32LobAppRegistryRequirement',
    'Win32LobAppPowerShellScriptRule': '#microsoft.graph.win32LobAppPowerShellScriptRequirement',
    'Win32LobAppFileSystemRule': '#microsoft.graph.win32LobAppFileSystemRequirement',
}
rule_short_type_to_detection_odata_type = {
    'Win32LobAppRegistryRule': '#microsoft.graph.win32LobAppRegistryDetection',
    'Win32LobAppPowerShellScriptRule': '#microsoft.graph.win32LobAppPowerShellScriptDetection',
    'Win32LobAppFileSystemRule': '#microsoft.graph.win32LobAppFileSystemDetection',
    'Win32LobAppProductCodeRule': '#microsoft.graph.win32LobAppProductCodeDetection',
}
rule_odata_type_to_detection_odata_type = {
    '#microsoft.graph.win32LobAppRegistryRule': '#microsoft.graph.win32LobAppRegistryDetection',
    '#microsoft.graph.win32LobAppPowerShellScriptRule': '#microsoft.graph.win32LobAppPowerShellScriptDetection',
    '#microsoft.graph.win32LobAppFileSystemRule': '#microsoft.graph.win32LobAppFileSystemDetection',
    '#microsoft.graph.win32LobAppProductCodeRule': '#microsoft.graph.win32LobAppProductCodeDetection',
}
rule_odata_type_to_requirement_odata_type = {
    '#microsoft.graph.win32LobAppRegistryRule': '#microsoft.graph.win32LobAppRegistryRequirement',
    '#microsoft.graph.win32LobAppPowerShellScriptRule': '#microsoft.graph.win32LobAppPowerShellScriptRequirement',
    '#microsoft.graph.win32LobAppFileSystemRule': '#microsoft.graph.win32LobAppFileSystemRequirement',
}
odata_rule_type_helper = {
    'detection': rule_odata_type_to_detection_odata_type,
    'requirement': rule_odata_type_to_requirement_odata_type,
}

class IntunePowerShellScriptRunAsAccountOption(Enum):
    system = 'system'
    user = 'user'

class IntuneComparisonType(Enum):
    exists = 'exists'
    doesNotExist = 'doesNotExist'
    integer = 'integer'
    version = 'version'
    string = 'string'
    float = 'float'
    sizeInMB = 'sizeInMB'
    createdDate = 'createdDate'
    modifiedDate = 'modifiedDate'
    boolean = 'boolean'

class IntuneComparisonOperator(Enum):
    notConfigured = 'notConfigured'
    equal = 'equal'
    notEqual = 'notEqual'
    greaterThan = 'greaterThan'
    greaterThanOrEqual = 'greaterThanOrEqual'
    lessThan = 'lessThan'
    lessThanOrEqual = 'lessThanOrEqual'

supported_operators = {
    'exists': ['notConfigured'],
    'doesNotExist': ['notConfigured'],
    'integer': ['equal', 'notEqual','greaterThan','greatherThanOrEqual','lessThan','lessThanOrEqual'],
    'version': ['equal', 'notEqual','greaterThan','greatherThanOrEqual','lessThan','lessThanOrEqual'],
    'string': ['equal', 'notEqual'],
    'float': ['equal', 'notEqual','greaterThan','greatherThanOrEqual','lessThan','lessThanOrEqual'],
    'sizeInMB': ['equal', 'notEqual','greaterThan','greatherThanOrEqual','lessThan','lessThanOrEqual'],
    'createdDate': ['equal', 'notEqual','greaterThan','greatherThanOrEqual','lessThan','lessThanOrEqual'],
    'modifiedDate': ['equal', 'notEqual','greaterThan','greatherThanOrEqual','lessThan','lessThanOrEqual'],
    'boolean': ['equal', 'notEqual'],
}
# Sample enum validation > returns the actual enum if successful
# my_rule_type = validate_enum(IntuneRuleType, 'detection')

class IntuneObject(dict):
    """Super class for all Intune objects"""
    def __init__(self,short_odata_type : str):
        _odata_type = validate_enum(IntuneOdataType,short_odata_type)
        super().__init__({'@odata.type': _odata_type.value})

class IntuneRule(IntuneObject):
    """Super class for detection and requirement rules"""
    def __init__(self,rule_short_odata_type : str, rule_type : str):
        self['@odata.type'] = validate_enum(IntuneOdataType,rule_short_odata_type).value

        _rule_type = validate_enum(IntuneRuleType,rule_type)
        self['ruleType'] = _rule_type.value
    def get_rule(self,**kwargs) -> dict:
        rule_odata_type = odata_rule_type_helper[self['ruleType']][self['@odata.type']]
        output = {
            '@odata.type': rule_odata_type,
            **kwargs
        }
        return output

class IntuneRegistryRule(IntuneRule):
    def __init__(
        self,
        rule_short_odata_type : str,
        rule_type : str,
        key_path : str,
        operation_type : str,
        operator : str,
        comparison_value : str = '',
        value_name : str = None,
        check_x32_on_x64 : bool = False,
        ):
        _operation_type = validate_enum(IntuneComparisonType,operation_type)
        _operator = validate_enum(IntuneComparisonOperator,operator)
        if (_operator.value not in supported_operators[_operation_type.value]):
            raise ProcessorError(f'Operator [{operator}] is does not support [{operation_type}] comparisons.')
        super().__init__(
            rule_short_odata_type=rule_short_odata_type,
            rule_type = rule_type
            )
        self['check32BitOn64System'] = check_x32_on_x64
        self['keyPath'] = key_path
        self['valueName'] = value_name
        self['operationType'] = _operation_type.value
        self['operator'] = _operator.value
        if comparison_value == '':
            self['comparisonValue'] = None
        else:
            self['comparisonValue'] = comparison_value

    def get_detection_rule(self) -> dict:
        return self.get_rule(
            check32BitOn64System = self['check32BitOn64System'],
            keyPath = self['keyPath'],
            valueName = self['valueName'],
            detectionType = self['operationType'],
            operator = self['operator'],
            detectionValue = self['comparisonValue']
        )

    def get_requirement_rule(self) -> dict:
        return self.get_rule(
            operator = self['operator'],
            detectionValue = self['comparisonValue'],
            check32BitOn64System = self['check32BitOn64System'],
            keyPath = self['keyPath'],
            valueName = self['valueName'],
            detectionType = self['operationType']
        )

class IntuneProductCodeRule(IntuneRule):
    def __init__(
        self,
        rule_short_odata_type : str,
        rule_type : str,
        product_code : str,
        operation_type : str,
        operator : str,
        comparison_value : str = ''
        ):
        _operation_type = validate_enum(IntuneComparisonType,operation_type)
        if (_operation_type.value not in ['exists','version']):
            raise ProcessorError(f'Operation type [{operation_type}] not supported for MSI rules.')
        _operator = validate_enum(IntuneComparisonOperator,operator)
        if (_operator.value not in supported_operators[_operation_type.value]):
            raise ProcessorError(f'Operator [{operator}] is does not support [{operation_type}] comparisons.')
        super().__init__(
            rule_short_odata_type=rule_short_odata_type,
            rule_type = rule_type
            )
        self['productCode'] = product_code
        self['productVersionOperator'] = 'notConfigured' if operation_type == 'exists' else _operator.value
        self['productVersion'] = None if comparison_value == '' else comparison_value

    def get_detection_rule(self) -> dict:
        return self.get_rule(
            productCode = self['productCode'],
            productVersionOperator = self['productVersionOperator'],
            productVersion = self['productVersion']
        )

class IntuneFileSystemRule(IntuneRule):
    def __init__(
        self,
        rule_short_odata_type : str,
        rule_type : str,
        path : str,
        operation_type : str,
        operator : str,
        comparison_value : str = '',
        filesystem_object_name : str = None,
        check_x32_on_x64 : bool = False,
        ):
        _operation_type = validate_enum(IntuneComparisonType,operation_type)
        _operator = validate_enum(IntuneComparisonOperator,operator)
        if (_operator.value not in supported_operators[_operation_type.value]):
            raise ProcessorError(f'Operator [{operator}] is does not support [{operation_type}] comparisons.')
        super().__init__(
            rule_short_odata_type = rule_short_odata_type,
            rule_type = rule_type
            )
        self['path'] = path
        self['fileOrFolderName'] = filesystem_object_name
        self['check32BitOn64System'] = check_x32_on_x64
        self['operationType'] = _operation_type.value
        self['operator'] = _operator.value
        if comparison_value == '':
            self['comparisonValue'] = None
        else:
            self['comparisonValue'] = comparison_value

    def get_detection_rule(self) -> dict:
        return self.get_rule(
            path = self['path'],
            fileOrFolderName = self['fileOrFolderName'],
            check32BitOn64System = self['check32BitOn64System'],
            detectionType = self['operationType'],
            operator = self['operator'],
            detectionValue = self['comparisonValue']
        )

    def get_requirement_rule(self) -> dict:
        return self.get_rule(
            operator = self['operator'],
            detectionValue = self['comparisonValue'],
            path = self['path'],
            fileOrFolderName = self['fileOrFolderName'],
            check32BitOn64System = self['check32BitOn64System'],
            detectionType = self['operationType']
        )

class IntunePowerShellScriptRule(IntuneRule):
    def __init__(
        self,
        rule_short_odata_type : str,
        rule_type : str,
        display_name : str, # script file name
        operation_type : str,
        operator : str,
        script_content_b64 : str,
        comparison_value : str = '',
        enforce_signature_check : bool = False,
        run_as_x32 : bool = False,
        run_as_account : str = 'system' # system, user
        ):
        _run_as_account = validate_enum(IntunePowerShellScriptRunAsAccountOption,run_as_account)
        _operation_type = validate_enum(IntuneComparisonType,operation_type)
        _operator = validate_enum(IntuneComparisonOperator,operator)
        if (_operator.value not in supported_operators[_operation_type.value]):
            raise ProcessorError(f'Operator [{operator}] is does not support [{operation_type}] comparisons.')
        if comparison_value == '':
            _comparison_value = None
        else:
            _comparison_value = comparison_value
        super().__init__(
            rule_short_odata_type=rule_short_odata_type,
            rule_type = rule_type
            )
        self['displayName'] = None if rule_type == 'detection' else display_name
        self['enforceSignatureCheck'] = enforce_signature_check
        self['runAs32Bit'] = run_as_x32
        self['runAsAccount'] = None if rule_type == 'detection' else _run_as_account.value
        self['scriptContent'] = script_content_b64
        self['operationType'] = 'notConfigured' if rule_type == 'detection' else _operation_type.value
        if rule_type != 'detection':
            self['operator'] = _operator.value
        self['comparisonValue'] = None if rule_type == 'detection' else _comparison_value

    def get_detection_rule(self) -> dict:
        # Script 'detect' must follow standards
        # Write out a string and exit 0 if application is detected, otherwise do not return any output
        return self.get_rule(
            enforceSignatureCheck = self['enforceSignatureCheck'],
            runAs32Bit = self['runAs32Bit'],
            scriptContent = self['scriptContent']
        )

    def get_requirement_rule(self) -> dict:
        return self.get_rule(
            operator = self['operator'],
            detectionValue = self['comparisonValue'],
            displayName = self['displayName'],
            enforceSignatureCheck = self['enforceSignatureCheck'],
            runAs32Bit = self['runAs32Bit'],
            runAsAccount = self['runAsAccount'],
            scriptContent = self['scriptContent'],
            detectionType = self['operationType']
        )

# IntuneApp
class IntuneApp(dict):
    """ A generic class from which Win32 (IntuneWin), pkg, apk, etc. 
    can inherit
    """
    def __init__(self,odata_short_type):
        super().__init__({'@odata.type': 4})

class IntuneAppRestartBehavior(Enum):
    """Valid IntuneAppRestartBehavior values"""
    suppress = 'suppress' # No specific action
    basedOnReturnCode = 'basedOnReturnCode'
    allow = 'allow' # The app may initiate a reboot
    force = 'force' # Intune will force a mandatory reboot

class IntuneAppShortOdataType(Enum):
    """Valid IntuneAppShortOdataType values"""
    Win32LobApp = "Win32LobApp"

class IntuneProcessorBase(Processor):
    """Common functions needed for Intune processors"""
    
    # Global version
    __version__ = "2026.10.10.0"

    # Helpers
    rule_creator = {
        'Win32LobAppRegistryRule': IntuneRegistryRule,
        'Win32LobAppPowerShellScriptRule': IntunePowerShellScriptRule,
        'Win32LobAppFileSystemRule': IntuneFileSystemRule,
        'Win32LobAppProductCodeRule': IntuneProductCodeRule,
    }
    @staticmethod
    def can_cast(type_name, value) -> bool:
        """Return True if the supplied value can cast as the supplied
        type name
        """
        return __class__.try_cast(type_name, value) is not None
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
                    #if file.startswith("."):
                    #    continue  # Ignore OS hidden files (.DS_Store, etc.)
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
    @staticmethod
    def get_api_version_from_url(url: str) -> str:
        return url.lstrip(f"{GRAPH_BASE_URL}/").split('/',1)[0]
    @staticmethod
    def new_file_encryption_info(
        encryption_key: str,
        mac_key: str,
        initialization_vector: str,
        mac: str,
        file_digest: str,
        file_digest_algorithm: str = 'SHA256',
        odata_type: str = '#microsoft.graph.fileEncryptionInfo',
        profile_identifier: str = 'ProfileVersion1'
        ) -> dict:
        return {
            '@odata.type': odata_type,
            'encryptionKey': encryption_key,
            'macKey': mac_key,
            'initializationVector': initialization_vector,
            'mac': mac,
            'fileDigest': file_digest,
            'fileDigestAlgorithm': file_digest_algorithm,
            'profileIdentifier': profile_identifier,
        }
    @staticmethod
    def pad_pkcs7(data: bytes, block_size_bits: int = 128) -> bytes:
        """Pads input byte array to match AES block size requirements using PKCS#7."""
        padder = padding.PKCS7(block_size_bits).padder()
        return padder.update(data) + padder.finalize()
    @staticmethod
    def try_cast(type_name, value, default = None):
        """Cast the supplied value as the indicated type. If it cannot
        cast, return a default value
        """
        try:
            return type_name(value)
        except:
            return default
        
    def encode_icon(
            self,
            local_path: str,
            b64_encoding: str = 'utf-8',
            optimize: bool = True,
            skip_size_check : bool = False
            ) -> tuple:
        """Inspect an icon .png file, encode the binary data, and return
        the resulting Base64 string
        """
        self.output("Encoding icon data", 3)
        if not local_path.lower().endswith('.png'):
            raise ProcessorError("Only PNG files are supported for icons.")
        mime_type, _ = mimetypes.guess_type(local_path)
        if not mime_type:
            mime_type = 'image/png'

        with open(local_path, 'rb') as f:
            icon_bytes = f.read()
        encoded = base64.b64encode(icon_bytes).decode(b64_encoding)
        if skip_size_check == True:
            self.output("Checking resulting image size", 3)
            size = self.get_base64_string_size(encoded)
            if size > INTUNE_MAX_ICON_SIZE:
                raise ProcessorError(f"Image  size [{(str(size / 1024).__floor__())} KB]is too large for use in Intune")
            self.output("Image size is ok.", 3)
        else:
            self.output("Skipping size check on icon string", 3)
        return encoded, mime_type
    @staticmethod
    def get_base64_string_size(b64_string : str) -> int:
        clean_string = b64_string.split(',')[-1].strip()
        string_len = len(clean_string)
        padding = clean_string.count('=')
        filesize = int((string_len * 3) / 4) - padding
        return filesize

    def get_intune_app_by_name(self,application_name : str, use_beta_url : bool = False) -> tuple:
        self.output(f'Searching Intune for application with name [{application_name}]',3)
        if use_beta_url:
            api_version = 'beta'
        else:
            api_version = 'v1.0'
        url = f"{GRAPH_BASE_URL}/{api_version}/deviceAppManagement/mobileApps"
        body = {"$filter": f"displayName eq '{application_name}'"}
        app_search_response = requests.request(
            method = 'GET', 
            url = url, 
            headers = self.graph_headers(),
            params = body
        )
        if app_search_response.status_code != 200:
            raise ProcessorError(
                f"Status [{str(app_search_response.status_code) or ''}]"
                f"\tReason [{app_search_response.reason or ''}]"
            )
        if len(app_search_response.json()['value']) > 1:
            raise ProcessorError(
                "Multiple application objects were "
                "returned from the initial query"
                )
        if len(app_search_response.json()['value']) == 0:
            self.output("No applications were found.", 2)
            return None,{}

        app_search_value = app_search_response.json()['value'][0]
        detail_url = f"{url}/{app_search_value['id']}"
        self.output("Getting object details", 3)
        detail_response = requests.request(
            method = 'GET', 
            url = detail_url, 
            headers = self.graph_headers(),
        )

        self.output("Found application", 3)
        return detail_url,detail_response.json()
    
    def get_scope_tags(self,name : str = None) -> list:
        url = f"{GRAPH_BASE_URL}/beta/deviceManagement/roleScopeTags"
        if name is not None:
            params = {
                "$filter": f"displayName eq '{name}'"
            }
        else:
            params = {}
        response = requests.get(
            url = url,
            headers = self.graph_headers(),
            params = params,
        )
        if not response.ok:
            raise ProcessorError(f"Scope tags could not be retrieved. <{response.status_code}> {response.text}")
        return response.json()['value']

    def initialize_export_properties(self,input_variable_name: str):
        self.export_properties = self.env.get(input_variable_name)
    
    def initialize_graph_auth(self):
        """Retrieve an access token from Microsoft Graph"""

        self.output("Authenticating to Microsoft Graph API", 2)
        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        body = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        token_time = time.monotonic()
        token_response = requests.request(
            method = 'POST',
            #headers = {'Content-Type': 'application/json','Accept':'application/json'},
            url = token_url,
            data=body
        )
        self.output(f"HTTP Status: <{token_response.status_code}>", 3)
        if not token_response.ok:
            self.output(f"Error Message: {token_response.text}")
            token_response.raise_for_status()
        self.access_token_type = token_response.json()['token_type']
        self.access_token_expires_in = token_response.json()['expires_in']
        self.access_token_expires_at = token_time + token_response.json()['expires_in']
        self.access_token = token_response.json()['access_token']
        self.output("Graph API Authentication completed successfully", 3)

    def graph_headers(self):
        """Checks if the current access token is expired. If needed,
        call initialize_graph_auth() again get a new token. Returns
        a dict of headers including the authorization token.
        """
        
        grace_period = 10

        if self.__getattribute__('access_token') is None:
            self.initialize_graph_auth()
        
        if self.__getattribute__('access_token_expires_at') < (time.monotonic() - grace_period):
            self.output("Access token appears to be stale. Refreshing it.", 3)
            self.initialize_graph_auth()
            self.graph_headers()
            return
        
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": 'application/json',
        }
    
    def initialize_auth(self):
        self.output("Checking supplied authentication parameters", 3)
        self.intune_app_keychain_service = self.env.get('intune_app_keychain_service')
        self.intune_app_keychain_username = self.env.get('intune_app_keychain_username')
        if (self.intune_app_keychain_service == None or self.intune_app_keychain_service == ''):
            raise ValueError("intune_app_keychain_service cannot be blank")
        if (self.intune_app_keychain_username == None or self.intune_app_keychain_username == ''):
            raise ValueError("intune_app_keychain_username cannot be blank")
        
        self.tenant_id = self.env.get('intune_tenant_id')
        self.client_id = self.env.get('intune_app_client_id')
        self.client_secret = keyring.get_password(self.intune_app_keychain_service, self.intune_app_keychain_username)
        
        self.initialize_graph_auth()

    def new_intune_app(self,app_payload : dict) -> dict:
        new_app_url = f"{GRAPH_BASE_URL}/v1.0/deviceAppManagement/mobileApps"
        self.output("Posting app payload to Intune", 2)
        self.output(f"\r\n{json.dumps(app_payload,indent=2)}",4)
        new_app_response = requests.post(
            url = new_app_url,
            headers = self.graph_headers(),
            json = app_payload
        )
        new_app_response.raise_for_status()
        time.sleep(3.0)
        return new_app_response.json()

    def update_intune_app_beta(self, app_payload, app_id, raise_error : bool = False) -> dict:
        "Send a PATCH request to the Intune app via the /beta endpoint"
        app_url = f"{GRAPH_BASE_URL}/beta/deviceAppManagement/mobileApps/{app_id}"
        self.output("Sending PATCH request for application.", 2)
        self.output(f"{json.dumps(app_payload)}", 4)
        patch_response = requests.patch(
            url = app_url,
            headers = self.graph_headers(),
            json = app_payload,
        )
        if True != patch_response.ok and raise_error:
            self.output(f"<{patch_response.status_code}> {patch_response.text}")
            patch_response.raise_for_status()
        
        self.output(f"PATCH Succeeded: {patch_response.ok}", 3)
        
        return

    def new_intune_app_content_version(self,application_id, odata_type_str : str) -> int:
        _odata_type_str = odata_type_str.lstrip('#')
        url = f"{GRAPH_BASE_URL}/v1.0/deviceAppManagement/mobileApps/{application_id}/{_odata_type_str}/contentVersions"
        self.output('Requesting new content version url', 3)
        response = requests.request(
            method = 'POST',
            url = url,
            headers = self.graph_headers(),
            json = {},
        )
        if not response.ok:
            self.output(f"<{response.status_code}> {response.text}", 3)
            response.raise_for_status()

        return int(response.json()['id'])

    def set_export_properties(self):
        """Examine self.export_properties and set their values given
        the configuration options
        """
        if self.__getattribute__('response_value') is None:
            raise ProcessorError("No response value")
        self.output("Attempting to set export properties", 2)
        for k in list(self.export_properties.keys()):
            k_type = self.export_properties.get(k,{}).get(
                'type','TypeNotFound'
                )
            self.output(
                (f"Getting export property '{k}' from a {k_type} "
                "expression"),
                3
                )
            eval_property = self.export_properties[k]['options']['property']
            if self.export_properties[k]["type"] == 'property':
                if (not self.response_value.__contains__(eval_property)
                    and self.export_properties[k].get(
                        'raise_error', False
                        ) == True
                        ):
                    raise ProcessorError(
                        f"Property {eval_property} does not exist on "
                        "the retrieved object. Valid properties are: "
                        f"{', '.join(list(self.response_value.keys()))}")
                value = self.response_value.get(eval_property, None)
            elif self.export_properties[k]["type"] == 'xpath':
                if not self.response_value.__contains__(
                    eval_property
                    ) and self.export_properties[k].get(
                        'raise_error',False
                        ) == True:
                    raise ProcessorError(
                        f"Property {eval_property} "
                        "does not exist on the retrieved object."
                        )
                elif not self.response_value.__contains__(eval_property):
                    value = None
                else:
                    try:
                        xml_element = etree.XML(
                            self.response_value.get(eval_property,'').replace(
                                (
                                    '<?xml version="1.0" encoding="'
                                    'utf-16"?>'
                                    ),
                                '',
                                1).replace(
                                    (
                                        "<?xml version='1.0' "
                                        "encoding='utf-16'?>"
                                    ),
                                    '',
                                    1
                                    )
                                )
                        if self.export_properties[k]['options'].get(
                            'strip_namespaces',
                            False
                            ) == True:
                            self.output(
                                "Stripping namespaces from XML element "
                                "before evaluating xpath expression",
                                3
                                )
                            xml_element = self.strip_namespaces(
                                xml_element
                                )
                        xml_xpath_expr = self.export_properties[k][
                            'options']['expression']
                        results = xml_element.xpath(xml_xpath_expr)
                        self.output(
                            "Got results from xpath expression",
                            3
                            )
                        if len(results) == 0:
                            if self.export_properties[k].get(
                                    'raise_error', False) == True:
                                self.output(
                                    "XPath expression returned no "
                                    "results, and raise_error was set "
                                    "to True",
                                    3
                                    )
                                raise ProcessorError(
                                    "XPath expression "
                                    f"{xml_xpath_expr} "
                                    f"on property {eval_property} "
                                    "returned no results.")
                            else:
                                self.output(
                                    "XPath expression returned no "
                                    "results, and raise_error was set "
                                    "to False",
                                    3
                                    )
                                value = None
                        else:
                            select_value_index = str(
                                self.export_properties[k]['options'].get(
                                    'select_value_index',
                                    '*'
                                    )
                                    )
                            self.output(
                                f"Selecting item {select_value_index} "
                                f"from ({len(results)}) "
                                "results from xpath expression",
                                3
                                )
                            if str(select_value_index) == '*':
                                value = [str(r) for r in results]
                            else:
                                try:
                                    self.output(
                                        "Selecting item "
                                        f"{select_value_index} from "
                                        "xpath results",
                                        3
                                        )
                                    index = int(select_value_index)
                                    value = str(results[index])
                                except Exception as e:
                                    raise ProcessorError(
                                        "Failed to select index "
                                        f"{select_value_index} from "
                                        "xpath results for expression "
                                        f"{xml_xpath_expr} on property "
                                        f"{eval_property}. "
                                        f"Error: {str(e)}"
                                        )
                    except Exception as e:
                        if self.export_properties[k].get(
                            'raise_error',False) == True:
                            raise ProcessorError(
                                "Failed to evaluate xpath expression "
                                f"{xml_xpath_expr} on property "
                                f"{eval_property}. Error: {str(e)}")
                        else:
                            value = None              
            truncated_value = value if len(str(value)) <= 32 \
                else (str(value)[0:31] + '...') 
            self.output(
                f"Setting '{k}' export property from a(n) "
                f"{self.export_properties[k]['type']} expression which "
                f"evaluated to ({truncated_value}) on the retrieved "
                "application",
                3
                )
            self.env[k] = value
        self.output("Finished setting export properties", 2)

    def strip_namespaces(self,element):
        """Remove all namespaces from an XML element for easier XPath
        query support
        """
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element

    def new_azure_blob_sas_uri(
            self,
            file_path : str,
            application_id : str,
            odata_type_str : str,
            content_version_id : int,
            encrypted_size : int,
            unencrypted_size : int,
            wait: bool = True
            ) -> dict:
        file_name = os.path.basename(file_path)
        #file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(file_path)[1]
        if not file_ext.lower() == '.intunewin':
            raise ProcessorError(f'Only IntuneWin files are supported. Not [{file_ext}]')
        file_payload = {
            '@odata.type': '#microsoft.graph.mobileAppContentFile',
            'name': file_name,
            'size': unencrypted_size,
            'sizeEncrypted': encrypted_size #IntuneWin files are pre-encrypted
        }
        url = f"{GRAPH_BASE_URL}/v1.0/deviceAppManagement/mobileApps/{application_id}/{odata_type_str.lstrip('#')}/contentVersions/{str(content_version_id)}/files"
        self.output(f"Posting file metadata", 3)
        response = requests.request(
            method = 'POST',
            url = url,
            headers = self.graph_headers(),
            json = file_payload,
        )
        self.output(f"Status: <{response.status_code}> {response.text}", 4)
        if not response.ok:
            response.raise_for_status()
        if False == wait:
            self.output("Declining to wait for SAS URI to finish provisioning", 3)
            return response.json()
        sasUriState = response.json().get('uploadState', '')
        failures = 0
        while sasUriState.lower() != 'azureStorageUriRequestSuccess':
            sasUriResponse = requests.request(
                url = f"{url}/{response.json()['id']}",
                method='GET',
                headers=self.graph_headers()
            )
            if not sasUriResponse.ok:
                failures += 1
                if failures > 5:
                    self.output(f"Encountered more than {str(failures)} failures while waiting for SAS URI to be provisioned", 1)
                    self.output(f"Last status: <{sasUriState.status_code}> {sasUriState.text}", 1)
                    sasUriState.raise_for_status()
            sasUriState = sasUriResponse.json().get('uploadState','')
            if sasUriState == 'azureStorageUriRequestSuccess':
                self.output("SAS Storage URI is ready", 3)
                return sasUriResponse.json()
            else:
                self.output("Waiting for Azure storage container to initialize...", 3)
                time.sleep(5)

    def upload_intune_content(
            self,
            file_path : str,
            sas_uri : str,
            application_id : str,
            file_id : str,
            odata_type_str : str,
            content_version_id : str,
            encryption_key : str,
            mac_key : str,
            initialization_vector : str,
            mac : str,
            file_digest : str,
            file_digest_algorithm : str,
            profile_identifier : str
            ) -> dict:
        chunk_size = 6 * 1024 * 1024
        block_ids = []
        block_index = 0
        self.output("Uploading data...", 2)
        with open(file_path,'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                self.output("Spewing chunk into Azure SAS URI", 4)
                block_identifier = base64.b64encode(f"block-{block_index:04}".encode()).decode()
                block_ids.append(block_identifier)
                block_uri = f"{sas_uri}&comp=block&blockid={block_identifier}"
                put_block = requests.put(
                    url = block_uri,
                    headers = {'x-ms-blob-type': 'BlockBlob'},
                    data = chunk
                )
                put_block.raise_for_status()
                block_index += 1
        self.output("Finished uploading data", 2)

        self.output("Uploading block list to Azure Storage, signal upload is finished", 3)
        block_list_xml = (
            "<BlockList>"
            + "".join([f"<Latest>{block_id}</Latest>" for block_id in block_ids])
            + "</BlockList>"
        )
        block_list_url = f"{sas_uri}&comp=blocklist"
        put_block_list = requests.put(
            url = block_list_url,
            headers = {'Content-Type': 'application/xml',},
            data = block_list_xml,
        )
        put_block_list.raise_for_status()
        self.output(f"Initiating 'commit' operation on content version [{str(content_version_id)}]", 3)
        status_url = f"{GRAPH_BASE_URL}/v1.0/deviceAppManagement/mobileApps/{application_id}/{odata_type_str.lstrip('#')}/contentVersions/{content_version_id}/files/{file_id}"
        commit_url = f"{status_url}/commit"
        file_encryption_info = {
                '@odata.type': '#microsoft.graph.fileEncryptionInfo',
                'encryptionKey': encryption_key,
                'macKey': mac_key,
                'initializationVector': initialization_vector,
                'mac': mac,
                'fileDigest': file_digest,
                'fileDigestAlgorithm': file_digest_algorithm,
                'profileIdentifier': profile_identifier,
            }
        commit_payload = {
            'fileEncryptionInfo': file_encryption_info
        }
        commit_post = requests.post(
            url = commit_url,
            headers = self.graph_headers(),
            json = commit_payload,
        )
        self.output(f"<{commit_post.status_code}> {commit_post.text}", 3)
        commit_post.raise_for_status()
        time.sleep(3.0)
        self.output("Waiting for commit success", 3)
        failures = 0
        while True:
            self.output("Attempting to get commit result", 3)
            status_query = requests.get(
                url = status_url,
                headers=self.graph_headers()
            )
            if False == status_query.ok:
                failures += 1
                self.output(f"Content commit status query has failed {str(failures)} times", 2)
                if failures > 5:
                    raise ProcessorError("Error query content commit")
            else:
                state = status_query.json().get("uploadState",'')
                self.output(f"Current state: {state}", 3)
                if state == "commitFileSuccess":
                    break
                elif state == "commitFileFailed":
                    raise ProcessorError("Failed to commit file to Intune!")
            time.sleep(5)

        self.output("Binding content to app object", 2)
        app_commit_url = f"{GRAPH_BASE_URL}/v1.0/deviceAppManagement/mobileApps/{application_id}"
        patch_payload = {
            '@odata.type': odata_type_str,
            'committedContentVersion': str(content_version_id),
        }
        app_commit_patch = requests.patch(
            url = app_commit_url,
            headers = self.graph_headers(),
            json = patch_payload
        )

        app_commit_patch.raise_for_status()
        failures = 0
        self.output("Waiting on publishing state...", 3)
        while True:
            app_query = requests.get(
                url = app_commit_url,
                headers = self.graph_headers())
            if False == app_query.ok:
                failures += 1
                self.output(f"App commit status query has failed {str(failures)} times", 2)
                if failures > 5:
                    raise ProcessorError("Error query app commit")
            pub_state = app_query.json().get("publishingState")
            if pub_state == "published":
                break
            time.sleep(10)
        self.output("Finished uploading application")
        return app_query.json()
    
if __name__ == "__main__":
    PROCESSOR = IntuneProcessorBase()
    PROCESSOR.execute_shell()