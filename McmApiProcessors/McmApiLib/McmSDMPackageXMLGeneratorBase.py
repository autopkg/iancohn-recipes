#!/usr/local/autopkg/python
# pylint: disable=invalid-name, too-many-lines
# -*- coding: utf-8 -*-
#
# Copyright 2025 Ian Cohn
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
import uuid
import json
import string
import random
import base64
#from ctypes import c_int32
from datetime import datetime
#from enum import Enum, auto
from os import path, walk
from io import BytesIO
#from lxml import etree
from copy import deepcopy
from pathlib import Path

# to use a base/external module in AutoPkg we need to add this path to the sys.path.
# this violates flake8 E402 (PEP8 imports) but is unavoidable, so the following
# imports require noqa comments for E402
import os.path
import sys

from autopkglib import Processor, ProcessorError

sys.path.insert(0,path.dirname(__file__))
from McmApiLib.McmApiBase import ( #noqa: E402
    McmApiBase,
    McmIdentifier,
    XmlAttributeAsDict,
    XmlNodeAsDict,
    ProgramVisibility,
    RebootBehavior,
    RequirementRuleDataType,
    ArgumentType,
    RuleEvaluationMethod,
    DeploymentTechnology,
    ExecutionContext,
    ActionProvider,
    Operator,
    SettingSourceType,
    SettingPropertyPath,
    ContentHandlingMode,
    ActionType,
    DetectionType,
    PROPERTY_PATH_DATA_TYPE,
    BEHAVIOR_TYPE_TO_CONTEXT,
)

platform_name = platform.system().lower()
arch = platform.machine().lower()
vendor_path = os.path.join(os.path.dirname(__file__),"vendor",platform_name,arch)
if vendor_path not in sys.path:
    sys.path.insert(0, vendor_path)
from PIL import Image

class McmSDMPackageXMLGeneratorBase(McmApiBase):
    """Class for functions used to create an SDMPackageXML string"""
    def initialize_all(self):
        self.fqdn = self.env.get('mcm_site_server_fqdn')
        self.get_requirements_rule_config = {
            'XmlString': self.new_requirements_rule_from_string, 
            'Dict': self.new_requirements_rule
        }
        self.get_setting_reference = {
            'File': self.get_file_setting_reference_nodes, 
            'Folder': self.get_folder_setting_reference_nodes, 
            'RegistryKey': self.get_registrykey_setting_reference_nodes, 
            'RegistryKeyValue': self.get_registryvalue_setting_reference_nodes, 
            'MSI': self.get_msi_setting_reference_nodes, 
            'SimpleSetting': self.get_registryvalue_setting_reference_nodes
        }
        self.initialize_headers()
        self.initialize_ntlm_auth()
        self.initialize_ssl_verification()

    # User nodes
    @staticmethod
    def new_user(user_id: str) -> XmlNodeAsDict:
        """Create a user XmlNodeAsDict instance"""
        attributes = [
            XmlAttributeAsDict(Name = 'Qualifier', Value = 'LogonName'), 
            XmlAttributeAsDict(Name = 'Id', Value = user_id)
        ]
        user = XmlNodeAsDict(NodeName = 'User', Attributes = attributes)
        return user

    @staticmethod
    def new_owners_node(user_ids: list = []) -> XmlNodeAsDict:
        """Create an owner XmlNodeAsDict instance"""
        user_nodes = []
        for u in user_ids:
            user_nodes.append(McmSDMPackageXMLGeneratorBase.new_user(u))
        owners_node = XmlNodeAsDict(NodeName = 'Owners', ChildNodes = user_nodes)
        return owners_node

    @staticmethod
    def new_contacts_node(user_ids: list = []) -> XmlNodeAsDict:
        """Create a contacts XmlNodeAsDict instance from a list of user
        nodes
        """
        user_nodes = []
        for u in user_ids:
            user_nodes.append(McmSDMPackageXMLGeneratorBase.new_user(u))
        contacts_node = XmlNodeAsDict(NodeName = 'Contacts', ChildNodes = user_nodes)
        return contacts_node

    # Content
    def new_content_file(self, pathname: str, unix_root: str) -> XmlNodeAsDict:
        """Return an XmlNodeAsDict object for the supplied file path"""
        relative_windows_path = self.get_relative_windows_path(pathname, unix_root)
        if pathname.endswith("/"):
            size = 0
        else:        
            size = path.getsize(pathname)
        return XmlNodeAsDict(NodeName = "File", Attributes = [XmlAttributeAsDict(Name = 'Name', Value = relative_windows_path), 
                                                        XmlAttributeAsDict(Name = 'Size', Value = size)])

    def new_content_importer(
            self, content_location: str, content_location_local: str,
            content_id: str = None, enable_peer_cache: bool = True,
            fast_network_action: ContentHandlingMode =
            ContentHandlingMode['Download'], 
            slow_network_action: ContentHandlingMode =
            ContentHandlingMode['DoNothing']
            ) -> XmlNodeAsDict:
        """Create a new Content node as an XmlNodeAsDict object"""
        if content_id is None or content_id == '':
                content_id = f'Content_{uuid.uuid4().__str__()}'
        importer = XmlNodeAsDict(
            NodeName = 'Content',
            Attributes = [XmlAttributeAsDict('ContentId', (content_id)), XmlAttributeAsDict(Name = 'Version', Value = '1')], external_reference_id = id(content_location_local))
        content_files = []
        if content_location_local[-1] !=  '/':
            content_location_local = f"{content_location_local}/"
        files = []
        empty_dirs = []
        for dirpath, dirnames, filenames in walk(content_location_local):
            if filenames:
                for filename in filenames:
                    files.append(path.join(dirpath, str(filename)))
            else:
                empty_dirs.append(path.join(dirpath, ''))
        files.sort(key = lambda p: (Path(p).parent, Path(p).name))
        empty_dirs.sort()
        content_items = files + empty_dirs
        for c in content_items:
            content_files.append(self.new_content_file(pathname = c, unix_root = content_location_local))
        importer.append_child_node(content_files)
        location = XmlNodeAsDict(NodeName = 'Location')
        if content_location is not None and len(content_location) > 0 and content_location[-1] !=  "\\":
            content_location = f"{content_location}\\"
            location.set_node_inner_text(content_location)
            importer.append_child_node([location])
            peer_cache = XmlNodeAsDict(NodeName = 'PeerCache')
            peer_cache.set_node_inner_text(f"{enable_peer_cache}".lower())
            importer.append_child_node([peer_cache])
            on_fast_network = XmlNodeAsDict(NodeName = 'OnFastNetwork')
            on_fast_network.set_node_inner_text(f"{fast_network_action.name}")
            importer.append_child_node([on_fast_network])
            on_slow_network = XmlNodeAsDict(NodeName = 'OnSlowNetwork')
            on_slow_network.set_node_inner_text(f"{slow_network_action.name}")
            importer.append_child_node([on_slow_network])
        return importer
    
    @staticmethod
    def get_content_reference(
            content_importer: XmlNodeAsDict) -> XmlNodeAsDict:
        """Create an XmlNodeAsDict inistance that references the supplied
        content importer node
        """
        attributes = [
            XmlAttributeAsDict(
                Name = 'ContentId', 
                Value = content_importer.get_attribute_value(
                    attribute_name = 'ContentId')
                    ), 
            XmlAttributeAsDict(
                Name = 'Version', 
                Value = content_importer.get_attribute_value(
                    attribute_name = 'Version'
                    )
                )
        ]
        reference = XmlNodeAsDict(
            NodeName = 'Contents', 
            ChildNodes = [
                XmlNodeAsDict(NodeName = 'Content', Attributes = attributes)
            ]
        )
        return reference
    
    @staticmethod
    def new_icon_resource(
            local_path: str, id_length: int = 41, 
            b64_encoding: str = 'utf-8', 
            optimize: bool = True
            ) -> XmlNodeAsDict:
        """Inspect an icon .png file, encode the binary data, and return
        the the information as an XmlNodeAsDict instance
        """
        if not local_path.lower().endswith('.png'):
            raise ProcessorError("Only PNG files are supported for icons.")
        with Image.open(local_path) as old:
            reduced = Image.new("RGB", old.size)
            reduced.paste(old)
            buffer = BytesIO()
            reduced.save(buffer, format = "PNG", optimize = optimize)
            _ = buffer.seek(0)
            encoded = base64.b64encode(buffer.read())\
                .decode(encoding = b64_encoding)
        icon_id_string_choices = random.choices(
            string.ascii_letters + string.digits, k = id_length
            )
        icon_id = f"Icon_p-{''.join(icon_id_string_choices)}"
        attributes = [XmlAttributeAsDict(Name = 'Id', Value = icon_id)]
        data_node = XmlNodeAsDict(NodeName = 'Data', NodeInnerText = encoded)
        icon_resource = XmlNodeAsDict(
            NodeName = 'Icon', 
            Attributes = attributes, 
            ChildNodes = [data_node])
        return icon_resource
    
    @staticmethod
    def get_icon_reference(icon_resource: XmlNodeAsDict) -> XmlNodeAsDict:
        """Create a XmlNodeAsDict instance which references the supplied
        icon node
        """
        icon_id = icon_resource.get_attribute_value(attribute_name = 'Id')
        icon_reference = XmlNodeAsDict(
            NodeName = 'Icon', 
            Attributes = [XmlAttributeAsDict(Name = 'Id', Value = icon_id)]
            )
        return icon_reference

    # Requirements & Detection
    @staticmethod
    def new_operator(operator: str) -> XmlNodeAsDict:
        """Create an operator XmlNodeAsDict object"""
        try:
            _operator = Operator(operator)
        except:
            valid = ', '.join(f.value for f in Operator)
            raise ValueError(f"Invalid operator: '{operator}'. Valid: {valid}")
        node = XmlNodeAsDict(NodeName = 'Operator', NodeInnerText = _operator.name)
        return node

    def new_annotation(
            self, display_name: str = '', description: str = '',
            include_xmlns: bool = False) -> XmlNodeAsDict:
        """Create an annotation XmlNodeAsDict object"""
        display_name_node = XmlNodeAsDict(
            NodeName = 'DisplayName', 
            Attributes = [XmlAttributeAsDict(Name = 'Text', Value = display_name)]
            )
        description_node = XmlNodeAsDict(
            NodeName = 'Description', 
            Attributes = [XmlAttributeAsDict(Name = 'Text', Value = description)]
            )
        annotation = XmlNodeAsDict(
            NodeName = 'Annotation', 
            ChildNodes = [display_name_node, description_node])
        if include_xmlns:
            annotation['Attributes'] = [
                XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap('Rule')['ns'])
                ]
        return annotation
    @staticmethod
    def new_constant_value(value: any, data_type: str) -> XmlNodeAsDict:
        """Create a constant value XmlNodeAsDict object"""
        try:
            if list(f.value for f in RequirementRuleDataType).__contains__(data_type):
                requirement_rule_data_type = RequirementRuleDataType(data_type)
            else:
                requirement_rule_data_type = RequirementRuleDataType(PROPERTY_PATH_DATA_TYPE[data_type])
        except:
            valid = ', '.join(f.value for f in RequirementRuleDataType)
            raise ValueError(f"Invalid data type: '{data_type}'. Valid: {valid}")
        attributes = [
            XmlAttributeAsDict(Name = 'Value', Value = value), 
            XmlAttributeAsDict(Name = 'DataType', Value = requirement_rule_data_type.name)
        ]
        constant_value = XmlNodeAsDict(NodeName = 'ConstantValue', Attributes = attributes)
        return constant_value
    
    @staticmethod
    def new_constant_value_list(constant_values: list) -> XmlNodeAsDict:
        """Create a constant value list XmlNodeAsDict object"""
        if len(constant_values or []) < 2:
            raise ValueError('At least 2 ConstantValue objects are required.')
        unique_data_types = []
        for v in constant_values:
            if v is None:
                raise ValueError("constant value cannot be 'NoneType'")
            udt = v.get_attribute_value('DataType')
            if udt is not None and udt !=  '' and not unique_data_types.__contains__(udt):
                unique_data_types.append(udt)
        if len(unique_data_types) !=  1:
            raise ValueError('ConstantValue objects must all be of the same DataType')
        constant_values.sort(key = lambda x: x.get_attribute_value('Value'))
        array_data_type = f"{unique_data_types[0]}Array"
        attributes = [
            XmlAttributeAsDict(Name = 'DataType', Value = array_data_type)
        ]
        return XmlNodeAsDict(NodeName = 'ConstantValueList', Attributes = attributes, ChildNodes = constant_values)

    def new_file_setting(
            self, path: str, filter: str, Is64Bit: bool = True, 
            logical_name = McmIdentifier()\
                .get_logical_name(object_type_name = 'File'), 
            external_reference_id: int = None, 
            group_ids: list[int] = None
            ) -> XmlNodeAsDict:
        """Create a new file based detection setting"""
        child_nodes = [
            self.new_annotation(include_xmlns = True), 
            XmlNodeAsDict(NodeName = 'Path', NodeInnerText = path), 
            XmlNodeAsDict(NodeName = 'Filter', NodeInnerText = filter)
        ]
        attributes = [
            XmlAttributeAsDict(
                Name = 'Is64Bit', 
                Value = f"{Is64Bit.__str__().lower()}"
                ), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = logical_name), 
            XmlAttributeAsDict(
                Name = 'xmlns', 
                Value = self.get_nsmap(namespace_name = 'DesiredConfiguration')['ns']
            )
        ]
        file_setting = XmlNodeAsDict(
            NodeName = 'File', Attributes = attributes, 
            ChildNodes = child_nodes, 
            external_reference_id = external_reference_id, 
            group_ids = group_ids
            )
        return file_setting

    def get_file_setting_reference_nodes(
            self, setting: XmlNodeAsDict, authoring_scope_id : str, 
            application_id: str, setting_options: dict, version: int = 1
            ) -> list[XmlNodeAsDict]:
        """Create a reference XmlNodeAsDict object from the supplied
        file setting XmlNodeAsDict and authoring scope string
        """
        nodes = []
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = application_id), 
            XmlAttributeAsDict(Name = 'Version', Value = version), 
        ]
        if setting_options.get('Property') is None:
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = 'Int64'))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Count')
        elif PROPERTY_PATH_DATA_TYPE.__contains__(setting_options.get('Property', '')) == False:
            self.output(f"Property must be null or one of the following: {', '.join(list(PROPERTY_PATH_DATA_TYPE.keys()))}`t Actual value: {setting_options.get('Property')}", 3)
            raise ValueError('Invalid Property value.')
        else:
            data_type = PROPERTY_PATH_DATA_TYPE.get(setting_options.get('Property'))
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = data_type))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Value')
        attributes.append(XmlAttributeAsDict(Name = 'SettingLogicalName', Value = setting.get_attribute_value('LogicalName')))
        attributes.append(XmlAttributeAsDict(Name = 'SettingSourceType', Value = 'File'))
        attributes.append(method_attribute)
        if method_attribute.get('Value', '') == 'Value':
            attributes.append(XmlAttributeAsDict(Name = 'PropertyPath', Value = setting_options['Property']))
        attributes.append(XmlAttributeAsDict(Name = 'Changeable', Value = 'false'))
        setting_reference = XmlNodeAsDict(NodeName = 'SettingReference', Attributes = attributes)
        nodes.append(setting_reference)
        if ['Between', 'OneOf', 'NoneOf'].__contains__(setting_options.get('Operator')):
            comparisons = []
            for c in setting_options.get('Value', []):
                item = self.new_constant_value(value = c, data_type = setting_options.get('DataType', setting_options.get('Property')))
                comparisons.append(item)

            comparison = self.new_constant_value_list(constant_values = comparisons)
        elif method_attribute.get('Value') == 'Count':
            comparison = self.new_constant_value(value = '0', data_type = 'Int64')
        else:
            comparison = self.new_constant_value(value = setting_options['Value'], data_type = setting_reference.get_attribute_value('DataType'))
        nodes.append(comparison)
        return nodes

    def new_folder_setting(
            self, path, filter, Is64Bit = True, 
            logical_name = McmIdentifier()\
                .get_logical_name(object_type_name = 'Folder'), 
            external_reference_id: int = None, 
            group_ids: list[int] = None
            ) -> XmlNodeAsDict:
        """Create a new folder based detection setting"""
        child_nodes = [
            self.new_annotation(include_xmlns = True), 
            XmlNodeAsDict(NodeName = 'Path', NodeInnerText = path), 
            XmlNodeAsDict(NodeName = 'Filter', NodeInnerText = filter)
        ]
        attributes = [
            XmlAttributeAsDict(Name = 'Is64Bit', Value = f"{Is64Bit.__str__().lower()}"), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = logical_name), 
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap(namespace_name = 'DesiredConfiguration')['ns'])
        ]
        folder_setting = XmlNodeAsDict(NodeName = 'Folder', ChildNodes = child_nodes, Attributes = attributes, external_reference_id = external_reference_id, group_ids = group_ids)
        return folder_setting

    def get_folder_setting_reference_nodes(
            self, setting: XmlNodeAsDict, authoring_scope_id: str,
            application_id: str, setting_options:dict, version:int = 1
            ) -> list[XmlNodeAsDict]:
        """Create a reference XmlNodeAsDict object from the supplied
        folder setting XmlNodeAsDict and authoring scope string
        """
        nodes = []
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = application_id), 
            XmlAttributeAsDict(Name = 'Version', Value = version), 
        ]
        if setting_options.get('Property') is not None:
            data_type = PROPERTY_PATH_DATA_TYPE.get(setting_options.get('Property'))
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = data_type))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Value')
        else:
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = 'Int64'))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Count')
        attributes.append(XmlAttributeAsDict(Name = 'SettingLogicalName', Value = setting.get_attribute_value('LogicalName')))
        attributes.append(XmlAttributeAsDict(Name = 'SettingSourceType', Value = 'Folder'))
        attributes.append(method_attribute)
        if method_attribute.get('Value', '') == 'Value':
            attributes.append(XmlAttributeAsDict(Name = 'PropertyPath', Value = setting_options['Property']))
        attributes.append(XmlAttributeAsDict(Name = 'Changeable', Value = 'false'))
        nodes.append(XmlNodeAsDict(NodeName = 'SettingReference', Attributes = attributes))
        if ['Between', 'OneOf', 'NoneOf'].__contains__(setting_options.get('Operator')):
            comparisons = []
            for c in setting_options.get('Value', []):
                comparisons.append(self.new_constant_value(value = c, data_type = PROPERTY_PATH_DATA_TYPE.get(setting_options.get('Property'))))
            comparison = self.new_constant_value_list(constant_values = comparisons)
        elif method_attribute.get('Value') == 'Count':
            comparison = self.new_constant_value(value = '0', data_type = 'Int64')
        else:
            comparison = self.new_constant_value(value = setting_options['Value'], data_type = data_type)
        nodes.append(comparison)
        return nodes

    def new_msi_setting(
            self, product_code, IsPerUser = False,
            logical_name = McmIdentifier().get_logical_name(
                object_type_name = 'MSI'
                ),
            external_reference_id:int = None,
            group_ids: list[int] = None) -> XmlNodeAsDict:
        """Create a new msi detection setting"""
        child_nodes = [
            self.new_annotation(include_xmlns = True), 
            XmlNodeAsDict(NodeName = 'ProductCode', NodeInnerText = product_code)
        ]
        attributes = [
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap(namespace_name = 'DesiredConfiguration')['ns']), 
            XmlAttributeAsDict(Name = 'IsPerUser', Value = f"{IsPerUser.__str__().lower()}"), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = logical_name)
        ]
        msi_setting = XmlNodeAsDict(NodeName = 'MSI', ChildNodes = child_nodes, Attributes = attributes, external_reference_id = external_reference_id, group_ids = group_ids)
        return msi_setting

    def get_msi_setting_reference_nodes(
            self, setting: XmlNodeAsDict, authoring_scope_id: str,
            application_id: str, setting_options:dict,
            version:int = 1) -> list[XmlNodeAsDict]:
        """Create a reference XmlNodeAsDict object from the supplied
        msi setting XmlNodeAsDict and authoring scope string
        """
        nodes = []
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = application_id), 
            XmlAttributeAsDict(Name = 'Version', Value = version), 
        ]
        if setting_options.get('Operator') is not None:
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = 'Version'))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Value')
        else:
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = 'Int64'))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Count')
        attributes.append(XmlAttributeAsDict(Name = 'SettingLogicalName', Value = setting.get_attribute_value('LogicalName')))
        attributes.append(XmlAttributeAsDict(Name = 'SettingSourceType', Value = 'MSI'))
        attributes.append(method_attribute)
        if method_attribute.get('Value') == 'Value':
            property_path = 'ProductVersion'
            attributes.append(XmlAttributeAsDict(Name = "PropertyPath", Value = property_path))
        attributes.append(XmlAttributeAsDict(Name = 'Changeable', Value = 'false'))
        nodes.append(XmlNodeAsDict(NodeName = 'SettingReference', Attributes = attributes))
        if method_attribute.get('Value') == 'Count':
            comparison = self.new_constant_value(value = '0', data_type = 'Int64')
        else:
            comparison = self.new_constant_value(value = setting_options['Value'], data_type = 'Version')
        nodes.append(comparison)
        return nodes

    def new_registrykey_setting(
            self, hive: str, key, Is64Bit = True,
            logical_name = McmIdentifier().get_logical_name(
                object_type_name = 'RegKey'
                ),
            external_reference_id:int = None,
            group_ids: list[int] = None) -> XmlNodeAsDict:
        """Create a new registry key based detection setting"""
        child_nodes = [
            self.new_annotation(include_xmlns = True), 
            XmlNodeAsDict(NodeName = 'Key', NodeInnerText = key)
        ]
        attributes = [
            XmlAttributeAsDict(Name = 'Hive', Value = hive), 
            XmlAttributeAsDict(Name = 'Is64Bit', Value = f"{Is64Bit.__str__().lower()}"), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = logical_name), 
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap(namespace_name = 'DesiredConfiguration')['ns'])
        ]
        regkey_setting = XmlNodeAsDict(NodeName = 'RegistryKey', ChildNodes = child_nodes, Attributes = attributes, external_reference_id = external_reference_id, group_ids = group_ids)
        return regkey_setting

    def get_registrykey_setting_reference_nodes(
            self, setting: XmlNodeAsDict, authoring_scope_id: str,
            application_id: str, setting_options:dict = None,
            version:int = 1) -> list[XmlNodeAsDict]:
        """Create a reference XmlNodeAsDict object from the supplied
        registry key setting XmlNodeAsDict and authoring scope string
        """
        nodes = []
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = application_id), 
            XmlAttributeAsDict(Name = 'Version', Value = version), 
        ]
        attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = 'Boolean'))
        method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Value')
        attributes.append(XmlAttributeAsDict(Name = 'SettingLogicalName', Value = setting.get_attribute_value('LogicalName')))
        attributes.append(XmlAttributeAsDict(Name = 'SettingSourceType', Value = 'RegistryKey'))
        attributes.append(method_attribute)
        attributes.append(XmlAttributeAsDict(Name = 'PropertyPath', Value = 'RegistryKeyExists'))
        attributes.append(XmlAttributeAsDict(Name = 'Changeable', Value = 'false'))
        nodes.append(XmlNodeAsDict(NodeName = 'SettingReference', Attributes = attributes))
        comparison = self.new_constant_value(value = 'true', data_type = 'Boolean')
        nodes.append(comparison)
        return nodes

    def new_registryvalue_setting(
            self, hive, key, value_name, data_type: str,
            Is64Bit = True,
            logical_name = McmIdentifier().get_logical_name(
                object_type_name = 'RegSetting'), 
            create_missing_path:bool = True, depth: str = "Base",
            external_reference_id:int = None,
            group_ids: list[int] = None) -> XmlNodeAsDict:
        """Create a new registry value detection setting"""    
        registry_discovery_node_attributes = [
            XmlAttributeAsDict(Name = 'Hive', Value = hive), 
            XmlAttributeAsDict(Name = 'Depth', Value = depth), 
            XmlAttributeAsDict(Name = 'Is64Bit', Value = f"{Is64Bit.__str__().lower()}"), 
            XmlAttributeAsDict(Name = 'CreateMissingPath', Value = f"{create_missing_path.__str__().lower()}")
        ]
        registry_discovery_node_children = [
            XmlNodeAsDict(NodeName = 'Key', NodeInnerText = key), 
            XmlNodeAsDict(NodeName = 'ValueName', NodeInnerText = value_name)
        ]
        child_nodes = [
            self.new_annotation(include_xmlns = True), 
            XmlNodeAsDict(NodeName = 'RegistryDiscoverySource', Attributes = registry_discovery_node_attributes, ChildNodes = registry_discovery_node_children)
        ]
        attributes = [
            XmlAttributeAsDict(Name = 'LogicalName', Value = logical_name), 
            XmlAttributeAsDict(Name = 'DataType', Value = data_type), 
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap(namespace_name = 'DesiredConfiguration')['ns'])
        ]
        regvalue_setting = XmlNodeAsDict(NodeName = 'SimpleSetting', ChildNodes = child_nodes, Attributes = attributes, external_reference_id = external_reference_id, group_ids = group_ids)
        return regvalue_setting

    def get_registryvalue_setting_reference_nodes(
            self, setting: XmlNodeAsDict, authoring_scope_id: str,
            application_id: str, setting_options:dict,
            version:int = 1) -> list[XmlNodeAsDict]:
        """Create a reference XmlNodeAsDict object from the supplied
        registry value setting XmlNodeAsDict and authoring scope string
        """
        nodes = []
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = application_id), 
            XmlAttributeAsDict(Name = 'Version', Value = version), 
        ]
        if setting_options.get('DataType') is not None:
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = setting_options['DataType']))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Value')
        else:
            attributes.append(XmlAttributeAsDict(Name = 'DataType', Value = 'Int64'))
            method_attribute = XmlAttributeAsDict(Name = 'Method', Value = 'Count')
        attributes.append(XmlAttributeAsDict(Name = 'SettingLogicalName', Value = setting.get_attribute_value('LogicalName')))
        attributes.append(XmlAttributeAsDict(Name = 'SettingSourceType', Value = 'Registry'))
        attributes.append(method_attribute)
        attributes.append(XmlAttributeAsDict(Name = 'Changeable', Value = 'false'))
        nodes.append(XmlNodeAsDict(NodeName = 'SettingReference', Attributes = attributes))
        if ['Between', 'OneOf', 'NoneOf'].__contains__(setting_options.get('Operator')):
            comparisons = []
            for c in setting_options.get('ValueData', []):
                item = self.new_constant_value(value = c, data_type = setting_options['DataType'])
                comparisons.append(item)
            comparison = self.new_constant_value_list(constant_values = comparisons)
        elif method_attribute.get('Value') == 'Count':
            comparison = self.new_constant_value(value = '0', data_type = 'Int64')
        else:
            comparison = self.new_constant_value(value = setting_options['ValueData'], data_type = setting_options['DataType'])
        nodes.append(comparison)
        return nodes

    def new_detection_rule_expression(
            self, authoring_scope_id: str, application_id: str,
            deployment_type_id: str, detection_item:dict,
            is_root:bool = False) -> XmlNodeAsDict:
        """Create a new detection rule expression"""
        attributes = []
        if detection_item['Type'] == 'Group' and is_root == False:
            attributes.append(
                XmlAttributeAsDict(Name = 'IsGroup', Value = 'true')
            )
        detection_options = detection_item.get('Options', {})
        if (detection_options.get('Operator', '') !=  ''):
            item_operator = detection_options.get('Operator', '')
        elif detection_item.get('Type', '') == 'RegistryKey':
            item_operator = 'Equals'
        else:
            raise ValueError(f"Invalid detection rule configuration.::{detection_options.get('Operator', '')}/{item_operator}\ttype:{detection_options.get('Type')}")
        operands_child_nodes = []
        if detection_item['Type'] == 'Group':
            for item in detection_item['Options']['Items']:
                operands_child_nodes.append(self.new_detection_rule_expression(detection_item = item, authoring_scope_id = authoring_scope_id, application_id = application_id, deployment_type_id = deployment_type_id))
        else:
            options_id = id(detection_item['Options'])
            setting = XmlNodeAsDict.instance_map_by_external_id.get(f"{options_id}")
            reference_getter = self.get_setting_reference[setting.get('NodeName')]
            if reference_getter:
                setting_reference_nodes = reference_getter(setting = setting, authoring_scope_id = authoring_scope_id, application_id = application_id, 
                        setting_options = detection_options)
                operands_child_nodes.extend(setting_reference_nodes)
            else:
                raise ValueError("Unknown Type.")
        detection_rule_expression = XmlNodeAsDict(NodeName = 'Expression', Attributes = attributes, 
                ChildNodes = [self.new_operator(item_operator), XmlNodeAsDict(NodeName = 'Operands', ChildNodes = operands_child_nodes)], 
                external_reference_id = id(detection_options))
        return detection_rule_expression

    def new_setting(
            self, detection_type: str, options:dict) -> XmlNodeAsDict:
        """Create a new detection setting"""
        try:
            setting_detection_type = DetectionType(detection_type)
        except:
            valid = ', '.join(f.value for f in DetectionType)
            raise ProcessorError(f"Invalid detection type: '{detection_type}'. Valid: {valid}")
        if ['CustomScript', 'Group'].__contains__(setting_detection_type.name):
            raise ProcessorError('Must provide a valid detection type to use new_setting.')
        if setting_detection_type.name == 'File':
            return self.new_file_setting(path = options['Path'], filter = options['Filter'], Is64Bit = options.get('Is64Bit', True), external_reference_id = id(options))
        elif setting_detection_type.name == 'Folder':
            return self.new_folder_setting(path = options['Path'], filter = options['Filter'], Is64Bit = options.get('Is64Bit', True), external_reference_id = id(options))
        elif setting_detection_type.name == 'RegistryKey':
            return self.new_registrykey_setting(hive = options['Hive'], key = options['Key'], Is64Bit = options.get('Is64Bit', True), external_reference_id = id(options))
        elif setting_detection_type.name == 'RegistryKeyValue':
            return self.new_registryvalue_setting(hive = options['Hive'], key = options['Key'], value_name = options['ValueName'], data_type = options['DataType'], Is64Bit = options.get('Is64Bit', True), external_reference_id = id(options))
        elif setting_detection_type.name == 'MSI':
            return self.new_msi_setting(product_code = options['ProductCode'], IsPerUser = options.get('IsPerUser', False), external_reference_id = id(options))

    def get_nested_settings(
            self, detection_config:dict) -> list[XmlNodeAsDict]:
        """Create detection settings objects for 'end' setting entities
        (non-group objects)
        """
        results = []
        if detection_config['Type'] == 'Group':
            for item in detection_config['Options']['Items']:
                results.extend(self.get_nested_settings(detection_config = item))
        else:
            results.append(self.new_setting(detection_type = detection_config['Type'], options = detection_config['Options']))
        return results

    def new_detection_rule_node(
            self, authoring_scope_id: str, application_id,
            deployment_type_id: str, detection:dict, severity: str = "None",
            noncompliance_on_nonexistance:bool = False) -> XmlNodeAsDict:
        """Create a new detection rule XmlNodeAsDict node"""
        expression = self.new_detection_rule_expression(
            authoring_scope_id = authoring_scope_id,
            application_id = application_id,
            deployment_type_id = deployment_type_id,
            detection_item = detection, is_root = True)
        dt_model_name = f"{authoring_scope_id}/{deployment_type_id}"
        child_nodes = [
                self.new_annotation(), 
                expression
        ]
        attributes = [
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap(namespace_name = 'Rule')['ns']), 
            XmlAttributeAsDict(Name = 'id', Value = dt_model_name), 
            XmlAttributeAsDict(Name = 'Severity', Value = severity), 
            XmlAttributeAsDict(Name = 'NonCompliantWhenSettingIsNotFound', Value = noncompliance_on_nonexistance.__str__().lower())
        ]
        rule_node = XmlNodeAsDict(NodeName = 'Rule', Attributes = attributes, ChildNodes = child_nodes, external_reference_id = id(detection))
        return rule_node

    def new_enhanced_detection_method_node(
            self, authoring_scope_id: str, application_id: str,
            deployment_type_id: str, detection_config:dict,
            severity: str = 'Informational',
            noncompliance_on_nonexistance:bool = False) -> XmlNodeAsDict:
        """Create a new enhanced detection XmlNodeAsAttribute object"""
        setting_nodes = self.get_nested_settings(detection_config = detection_config)
        settings_node = XmlNodeAsDict(NodeName = 'Settings', ChildNodes = setting_nodes, Attributes = [XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap('AppMgmtDigest')['ns'])])
        rule_node = self.new_detection_rule_node(authoring_scope_id = authoring_scope_id, application_id = application_id, deployment_type_id = deployment_type_id, 
                detection = detection_config, severity = severity, noncompliance_on_nonexistance = noncompliance_on_nonexistance)
        enhanced_detection_method = XmlNodeAsDict(NodeName = 'EnhancedDetectionMethod', Attributes = [XmlAttributeAsDict(Name = "xmlns", Value = self.get_nsmap('AppMgmtDigest')['ns'])], xml_declaration = True)
        enhanced_detection_method.append_child_node([settings_node])
        enhanced_detection_method.append_child_node([rule_node])
        return enhanced_detection_method

    # Dependency
    def new_dependency(self, authoring_scope_id: str, application_logical_name: str, dt_logical_name: str, auto_install:bool = False) -> XmlNodeAsDict:
        """Create a new dependency"""
        dt_appref_attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = application_logical_name)
        ]
        dt_application_reference = XmlNodeAsDict(NodeName = 'DeploymentTypeApplicationReference', Attributes = dt_appref_attributes)

        dtref_attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = dt_logical_name), 
            XmlAttributeAsDict(Name = 'Changeable', Value = auto_install.__str__().lower())
            # Changeable = true = autoinstall(yes)
        ]
        dt_reference = XmlNodeAsDict(NodeName = 'DeploymentTypeReference', Attributes = dtref_attributes)
        child_nodes = [
            dt_application_reference, 
            dt_reference
        ]
        expression_attributes = [
            XmlAttributeAsDict(Name = 'DesiredState', Value = 'Required')
        ]
        dependency = XmlNodeAsDict(NodeName = 'DeploymentTypeIntentExpression', Attributes = expression_attributes, ChildNodes = child_nodes)
        return dependency

    def new_dependency_group(self, rule_name: str, dependencies: list[XmlNodeAsDict], id: str = None) -> XmlNodeAsDict:
        """Create a new dependency group"""
        if id is None:
            id = McmIdentifier().get_logical_name(object_type_name = 'DTRule')
        attributes = [
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap('Rule')['ns']), 
            XmlAttributeAsDict(Name = 'id', Value = id), 
            XmlAttributeAsDict(Name = 'Severity', Value = 'Critical')
        ]
        annotation = self.new_annotation(display_name = rule_name)
        dt_exp_child_nodes = [
            self.new_operator('Or'), 
            XmlNodeAsDict(NodeName = 'Operands', ChildNodes = dependencies)
        ]
        dt_expression = XmlNodeAsDict(NodeName = 'DeploymentTypeExpression', ChildNodes = dt_exp_child_nodes)
        child_nodes = [
            annotation, 
            dt_expression
        ]
        return XmlNodeAsDict(NodeName = 'DeploymentTypeRule', Attributes = attributes, ChildNodes = child_nodes)

    def new_dependencies_node(self, dependency_groups: list[XmlNodeAsDict]) -> XmlNodeAsDict:
        """Create a new dependencies XmlNodeAsDict object from the supplied
        dependency groups
        """
        dependencies_node = XmlNodeAsDict(NodeName = 'Dependencies', ChildNodes = dependency_groups)
        return dependencies_node

    # Requirements
    def new_requirements_rule(
            self, rule:dict, rule_id: str, severity = 'None',
            noncompliance_on_nonexistance:bool = False) -> XmlNodeAsDict:
        """Create a new requirements rule"""
        raise Exception("Not supported yet.")
        pass

    def new_requirements_rule_from_string(
            self, rule: str, rule_id: str, severity = 'None', noncompliance_on_nonexistance:bool = False) -> XmlNodeAsDict:
        """Convert a raw XML string to a requirements rule XmlNodeAsDict
        object
        """
        attributes = [
            XmlAttributeAsDict(Name = 'xmlns', Value = self.get_nsmap('Rule')['ns']), 
            XmlAttributeAsDict(Name = 'id', Value = rule_id), 
            XmlAttributeAsDict(Name = 'Severity', Value = f"{severity}"), 
            XmlAttributeAsDict(Name = 'NonCompliantWhenSettingIsNotFound', Value = f"{noncompliance_on_nonexistance.__str__().lower()}")
        ]
        requirements_rule = XmlNodeAsDict(NodeName = 'Rule', Attributes = attributes)
        instance = XmlNodeAsDict.from_xml_string_with_tracking(xml_string = rule)
        requirements_rule['ChildNodes'] = instance['ChildNodes']
        return requirements_rule
    
    # Installer
    def new_process_information(self, process_name: str, process_display_name: str) -> XmlNodeAsDict:
        """Create a new process detection object"""
        process_information = XmlNodeAsDict(
            NodeName = 'ProcessInformation', Attributes = [
                XmlAttributeAsDict(Name = 'Name', Value = process_name)
            ], 
            ChildNodes = [
                XmlNodeAsDict(
                    NodeName = 'DisplayInfo', Attributes = [
                        XmlAttributeAsDict(Name = 'DefaultLanguage', Value = '')
                    ], 
                    ChildNodes = [
                        XmlNodeAsDict(
                            NodeName = 'Info', 
                            Attributes = [
                                XmlAttributeAsDict(Name = 'Language', Value = ''), 
                                XmlAttributeAsDict(Name = 'DisplayName', Value = process_display_name)
                            ]
                        )
                    ]
                )
            ]
        )
        return process_information

    def new_install_process_detection(self, process_information: list[XmlNodeAsDict]) -> XmlNodeAsDict:
        """Create an install process detection XmlNodeAsDict object from
        the list of process information objects
        """
        install_process_detection = XmlNodeAsDict(
            NodeName = 'InstallProcessDetection', 
            ChildNodes = [
                XmlNodeAsDict(
                    NodeName = 'ProcessList', 
                    ChildNodes = process_information
                )
            ]
        )
        return install_process_detection

    def new_arg(self, arg_name: str, arg_type: str, arg_value:any = None) -> XmlNodeAsDict:
        """Create an arg XmlNodeAsDict object"""
        try:
            cls_arg_type = ArgumentType[arg_type]
        except:
            valid = ', '.join(f.value for f in ArgumentType)
            raise ValueError(f"Invalid operator: '{arg_type}'. Valid: {valid}")
        params = {
            "NodeName": "Arg", 
            "Attributes": [
                XmlAttributeAsDict(Name = 'Name', Value = arg_name), 
                XmlAttributeAsDict(Name = 'Type', Value = cls_arg_type.value)
            ]
        }
        if arg_value is None:
            pass
        elif (cls_arg_type.value.endswith('[]')) == False:
            params['NodeInnerText'] = arg_value
        else:
            params["ChildNodes"] = []
            if isinstance(arg_value, str):
                params["ChildNodes"].append(XmlNodeAsDict(NodeName = 'Item', NodeInnerText = arg_value))
            elif isinstance(arg_value, list):
                for i in arg_value:
                    params["ChildNodes"].append(XmlNodeAsDict(NodeName = 'Item', NodeInnerText = i.__str__()))
            else:
                raise ValueError("Invalid value supplied for arg_value.")
        arg_node = XmlNodeAsDict(**params)
        return arg_node

    def new_dt_action(self, action_type: str, provider: str, args: list[XmlNodeAsDict], content_reference: XmlNodeAsDict = None) -> XmlNodeAsDict:
        """Create a new deployment type action"""
        try:
            item_action_type = ActionType(action_type)
        except:
            valid = ', '.join(f.value for f in ActionType)
            raise ValueError(f"Invalid action type: '{action_type}'. Valid: {valid}")
        try:
            item_provider = ActionProvider(provider)
        except:
            valid = ', '.join(f.value for f in ActionProvider)
            raise ValueError(f"Invalid action provider type: '{provider}'. Valid: {valid}")
        
        action = XmlNodeAsDict(
            NodeName = item_action_type.name, 
            ChildNodes = [
                XmlNodeAsDict(NodeName = 'Provider', NodeInnerText = item_provider.name), 
                XmlNodeAsDict(NodeName = 'Args', ChildNodes = args)
            ]
        )
        if content_reference is not None:
            action.append_child_node([content_reference])
        return action

    def new_detection_nodes(self, authoring_scope_id: str, application_id: str, deployment_type_id: str, detection_item:dict, execution_context: str = 'System') -> list:
        """Output a list of exactly 2 items where item 0 is the
        DetectAction XmlNodeAsDict object and item 1 is itself a list of
        the detection nodes needed for the CustomData node
        """
        try:
            detection_type = DetectionType(detection_item.get('Type'))
        except:
            valid = ', '.join(f.value for f in DetectionType)
            raise ProcessorError(f"Invalid detection type: '{detection_item.get('Type')}'. Valid: {valid}")
        try:
            _ = ExecutionContext(execution_context)
        except:
            valid = ', '.join(f.value for f in ExecutionContext)
            raise ProcessorError(f"Invalid execution context: '{execution_context}'. Valid: {valid}")
        custom_data_nodes = []
        detect_action_params = {
            "action_type": "DetectAction", 
            "args": []
        }
        if detection_type.name == 'CustomScript':
            detect_action_params['provider'] = 'Script'
            detect_action_params['args'].append(self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context))
            detect_action_params['args'].append(self.new_arg(arg_name = 'ScriptType', arg_type = 'Int32', arg_value = '0'))
            detect_action_params['args'].append(self.new_arg(arg_name = 'ScriptBody', arg_type = 'String', arg_value = detection_item.get('Options', {}).get('ScriptContent', '')))
            detect_action_params['args'].append(self.new_arg(arg_name = 'RunAs32Bit', arg_type = 'Boolean', arg_value = bool(detection_item.get('Options', {}).get('RunAs32Bit') or False)).__str__().lower())
            custom_data_nodes.append(XmlNodeAsDict(NodeName = 'DetectionMethod', NodeInnerText = 'Script'))
            custom_data_nodes.append(XmlNodeAsDict(
                NodeName = 'DetectionScript', 
                Attributes = [XmlAttributeAsDict(Name = 'Language', Value = 'PowerShell')], 
                NodeInnerText = detection_item.get('Options', {}).get('ScriptContent', ''))
            )
        else:
            enhanced_detection = self.new_enhanced_detection_method_node(authoring_scope_id = authoring_scope_id, application_id = application_id, 
                    deployment_type_id = deployment_type_id, detection_config = detection_item)
            xml_string = enhanced_detection.to_xml_string()
            detect_action_params['provider'] = 'Local'
            detect_action_params['args'].append(self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context))
            detect_action_params['args'].append(self.new_arg(arg_name = 'MethodBody', arg_type = 'String', arg_value = xml_string))
            custom_data_nodes.append(XmlNodeAsDict(NodeName = 'DetectionMethod', NodeInnerText = 'Enhanced'))
            enhanced_detection['Attributes'].clear()
            custom_data_nodes.append(enhanced_detection)
        detect_action = self.new_dt_action(**detect_action_params)
        return [detect_action, custom_data_nodes]

    # Application
    def new_tags_node(self, tags: list[str] = []) -> XmlNodeAsDict:
        """Create a tags XmlNodeAsDict object from a list of tag strings"""
        tag_list = []
        for t in tags:
            tag_list.append(XmlNodeAsDict(NodeName = 'Tag', NodeInnerText = t))
        tags_node = XmlNodeAsDict(NodeName = 'Tags', ChildNodes = tag_list)
        return tags_node

    def new_display_info(self, title: str, language: str = 'en-US', publisher: str = None, software_version: str = None, release_date: str = datetime.now().strftime("%m/%d/%Y"), 
                description: str = None, info_url: str = None, info_url_text: str = None, privacy_url: str = None, user_categories_node: XmlNodeAsDict = None, 
                tags: list = None, icon_reference: XmlNodeAsDict = None):
        """Create a new display info node"""
        attributes = [
            XmlAttributeAsDict(Name = 'Language', Value = language)
        ]
        child_nodes = [
            XmlNodeAsDict(NodeName = 'Title', NodeInnerText = title), 
        ]
        info = XmlNodeAsDict(NodeName = 'Info', Attributes = attributes, ChildNodes = child_nodes)
        if description is not None and description !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'Description', NodeInnerText = description)
            ])
        if publisher is not None and publisher !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'Publisher', NodeInnerText = publisher)
            ])

        if software_version is not None and software_version !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'Version', NodeInnerText = software_version)
            ])
        if release_date is not None and release_date !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'ReleaseDate', NodeInnerText = release_date)
            ])
        if icon_reference is not None:
            info.append_child_node([
                icon_reference
            ])
        if info_url is not None and info_url !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'InfoUrl', NodeInnerText = info_url)
            ])
        if info_url_text is not None and info_url_text !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'InfoUrlText', NodeInnerText = info_url_text)
            ])
        if privacy_url is not None and privacy_url !=  '':
            info.append_child_node([
                XmlNodeAsDict(NodeName = 'PrivacyUrl', NodeInnerText = privacy_url)
            ])
        if user_categories_node is not None:
            info.append_child_node([user_categories_node])
        if len(tags or []) > 0:
            info.append_child_node([self.new_tags_node(tags = tags)])
        return info

    def new_display_info_node(self, display_infos: list, default_language: str = 'en-US') -> XmlNodeAsDict:
        """Create a new display info XmlNodeAsDict object from the supplied
        list of display infos
        """
        display_info_node = XmlNodeAsDict(
            NodeName = 'DisplayInfo', 
            Attributes = [
                XmlAttributeAsDict(Name = 'DefaultLanguage', Value = default_language)
            ], 
            ChildNodes = display_infos
        )
        return display_info_node

    def new_user_categories_node(self, user_category_unique_ids: list[str]) -> XmlNodeAsDict:
        """Create a user categories XmlNodeAsDict object from the supplied
        list of user category unique identifiers
        """
        params = {'NodeName':'UserCategories'}
        if len(user_category_unique_ids) > 0:
            child_nodes = []
            for c in user_category_unique_ids:
                child_nodes.append(
                    XmlNodeAsDict(NodeName = 'Tag', NodeInnerText = c)
                )
            params['ChildNodes'] = child_nodes
        user_categories_node = XmlNodeAsDict(**params)
        return user_categories_node
    
    # Deployment Type
    def new_languages_node(self, languages: list[str]) -> XmlNodeAsDict:
        """Create a languages XmlNodeAsDict object"""
        item_languages = []
        for l in languages:
            if l is not None:
                item_languages.append(XmlNodeAsDict(NodeName = 'Lang', NodeInnerText = l))
        languages_node = XmlNodeAsDict(NodeName = 'Languages', ChildNodes = item_languages)
        return languages_node

    def get_deployment_type_reference(self, deployment_type: XmlNodeAsDict) -> XmlNodeAsDict:
        """Create a reference XmlNodeAsDict object from the supplied
        deployment type XmlNodeAsDict
        """
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = deployment_type.get_attribute_value('AuthoringScopeId')), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = deployment_type.get_attribute_value('LogicalName')), 
            XmlAttributeAsDict(Name = 'Version', Value = deployment_type.get_attribute_value('Version'))
        ]
        reference = XmlNodeAsDict(NodeName = 'DeploymentType', Attributes = attributes)
        return reference

    def merge_deployment_types(self, authoring_scope_id: str, dicts: list[dict] = [],
                               existing_deployment_types: list[XmlNodeAsDict] = [],
                               persist_unhandled_deployment_types:bool = False) -> list:
        """Match configured deployment types to existing deployment
        types and return an ordered list of deployment types to add to
        an application
        """
        self.output("Attempting to merge configured deployment types with those from an existing application", 2)
        lookup_existing_by_name = {d.find_children_by_name(node_name = 'Title')[0].get('NodeInnerText'): d for d in existing_deployment_types}
        used_names = set()
        count_all = len(dicts or []) + len(existing_deployment_types or [])
        self.output(f"{count_all} deployment type objects", 3)
        priorities_range = list(range(1, (count_all + 1)))
        self.output(f"Priorities {priorities_range[0]} through {priorities_range[-1]} may be used", 3)
        used_priorities = []
        merged = {}
        dicts.reverse()
        for item in dicts:
            dt_name = item.get('Options', {}).get('DeploymentTypeName', '')
            self.output(f"Processing {dt_name}", 3)
            if used_names.__contains__(dt_name):
                raise ProcessorError("Each Deployment Type Name can only be used once")
            self.output(f"Matching deployment type configuration to any existing one.", 3)
            existing_dt = lookup_existing_by_name.get(dt_name)
            dt_logical_name = existing_dt.get_attribute_value(attribute_name = 'LogicalName') if existing_dt is not None else McmIdentifier().get_logical_name(object_type_name = 'DeploymentType')
            dt_revision = (int(existing_dt.get_attribute_value(attribute_name = 'Version'))) if existing_dt is not None else 0
            dt_next_revision = dt_revision + 1
            if existing_dt is not None:
                self.output(f"Got details from existing deployment type", 3)
                behavior_if_exists = item.get('Options',{}).get('BehaviorIfExists', 'Exit')
                if behavior_if_exists == 'Exit':
                    self.output(f"An existing deployment type with this name was found and BehaviorIfExists was set to 'Exit'", 3)
                    exit()
                elif behavior_if_exists == 'Skip':
                    continue
                elif behavior_if_exists == 'Update':
                    preferred_priority = item.get('Priority') or (existing_deployment_types.index(existing_dt) + 1)
                    self.output(f"The existing deployment type will be updated with new information", 3)
                elif behavior_if_exists == 'AppendIndex':
                    self.output(f"Appending an index to the deployment type name", 3)
                    index = 1
                    done_with_name = False
                    while done_with_name == False and index < 20:
                        search_name = f"{item.get('DeploymentTypeName')} ({index.__str__()})"
                        result = lookup_existing_by_name.get(search_name)
                        if result is None:
                            self.output(f"Appending an index ({index.__str__()}) to the deployment type name.", 3)
                            dt_name = search_name
                            done_with_name = True
                        index +=  1
                        if index == 20:
                            self.output("Wow... There are 20 similarly named deployment types. You should probably look at this.", 3)
                            break
                        else:
                            continue
                    if done_with_name == False:
                        raise ProcessorError("Could not find a name that was not already taken.")
                    preferred_priority = item.get('Priority') or priorities_range[-1]
                elif behavior_if_exists == 'AppendVersion':
                    self.output(f"Appending the version to deployment type", 3)
                    search_name = f"{item.get('DeploymentTypeName')} {self.software_version}"
                    self.output(f"Checking to see if an app with the version appended exists ({search_name}).", 3)
                    result = lookup_existing_by_name(search_name)
                    if result is None:
                        self.output("Appending the version to the application name.", 3)
                        dt_name = search_name
                    else:
                        raise ProcessorError(f"An application already exists which already includes the version in the title. ({search_name})")
                    preferred_priority = item.get('Priority') or priorities_range[-1]
            else:
                self.output("This appears to be a new deployment type.", 3)
                preferred_priority = item.get('Priority') or priorities_range[-1]
            self.output(f"Deployment Type with this name has not yet been configured", 3)
            used_priorities.append(preferred_priority)
            priorities_range.remove(preferred_priority)
            used_names.add(dt_name)
            item["DeploymentTypeName"] = dt_name
            self.output(f"Setting priority {preferred_priority}", 3)
            merged[str(preferred_priority)] = {
                "Type": "dict",
                "Object": item,
                "LogicalName": dt_logical_name,
                "Version": dt_next_revision
            }
            self.output(f"Done with {dt_name}", 3)
        if persist_unhandled_deployment_types:
            self.output("Unhandled deployment types will be persisted", 3)
            for e in existing_deployment_types:
                dt_name = e.find_children_by_name(node_name = 'Title')[0]['NodeInnerText']
                self.output(f"Checking if deployment type name '{dt_name}' has been used", 3)
                if used_names.__contains__(dt_name) == False:
                    dt_revision = int(e.get_attribute_value("Version"))
                    dt_logical_name = e.get_attribute_value('LogicalName')
                    preferred_priority = priorities_range[0]
                    priorities_range.remove(preferred_priority)
                    used_priorities.append(preferred_priority)
                    used_names.add(dt_name)
                    self.output(f"Setting priority {preferred_priority}", 3)
                    merged[str(preferred_priority)] = {
                        "Type": "XmlNodeAsDict",
                        "Object": e,
                        "LogicalName": dt_logical_name,
                        "Version": dt_revision
                    }
        self.output(f"Sorting {len(merged)} deployment type configurations", 3)
        sorted_merged = []
        for p in sorted(merged):
            sorted_merged.append(merged[p])
        return sorted_merged

    def add_install_action(self, installer_root: XmlNodeAsDict, deployment_type_configuration:dict) -> None:
        """Parse the details of the deployment type dict and
        add a new install action node to the installer root node
        commensurate with the configuration
        """
        try:
            visibility = ProgramVisibility(deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility', 'Hidden'))
        except:
            valid = ', '.join(f.value for f in ProgramVisibility)
            raise ProcessorError(f"Invalid installation program visibility: '{deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility')}'. Valid: {valid}")
        try:
            reboot_behavior = RebootBehavior(deployment_type_configuration.get('Options', {}).get('RebootBehavior', 'BasedOnExitCode'))
        except:
            valid = ', '.join(f.value for f in RebootBehavior)
            raise ProcessorError(f"Invalid reboot behavior: '{deployment_type_configuration.get('Options', {}).get('RebootBehavior')}'. Valid: {valid}")
        install_action_params = {
            "action_type": "InstallAction", 
            "provider": deployment_type_configuration.get('Technology', 'Script')
        }
        execution_context = BEHAVIOR_TYPE_TO_CONTEXT[deployment_type_configuration.get('Options', {}).get('InstallationBehaviorType', 'InstallForSystem')]
        if ['MSI', 'Script'].__contains__(install_action_params['provider']):
            install_action_params["args"] = [
                self.new_arg(arg_name = 'InstallCommandLine', arg_type = 'String', arg_value = deployment_type_configuration.get('Options', {}).get('InstallationProgram')), 
                self.new_arg(arg_name = 'WorkingDirectory', arg_type = 'String', arg_value = deployment_type_configuration.get('Options', {}).get('InstallationStartIn')), 
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context)
            ]
            #Logon Requirement
            if deployment_type_configuration.get('Options', {}).get('LogonRequirementType') == 'OnlyWhenUserLoggedOn':
                install_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'Boolean', arg_value = 'True'))
            elif deployment_type_configuration.get('Options', {}).get('LogonRequirementType') == 'OnlyWhenNoUserLoggedOn':
                install_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'Boolean', arg_value = 'False'))
            else:
                install_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'String'))
            # Install settings
            install_action_params['args'].append(self.new_arg(arg_name = 'RequiresElevatedRights', arg_type = 'Boolean', arg_value = 'false'))
            requires_user_interaction = (deployment_type_configuration.get('Options', {}).get('RequiresUserInteraction') or '').__str__().lower()
            if requires_user_interaction == '':
                install_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'String'))
            else:
                install_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'Boolean', arg_value = requires_user_interaction))
            install_action_params['args'].append(self.new_arg(arg_name = 'RequiresReboot', arg_type = 'Boolean', arg_value = (reboot_behavior == 'ForceReboot').__str__().lower()))
            install_action_params['args'].append(self.new_arg(arg_name = 'UserInteractionMode', arg_type = 'String', arg_value = visibility.name))
            install_action_params['args'].append(self.new_arg(arg_name = 'PostInstallBehavior', arg_type = 'String', arg_value = reboot_behavior.name))
            estimated_execute_time = deployment_type_configuration.get('Options', {}).get('EstimatedInstallationTimeMins') or 0
            if (0 <=  estimated_execute_time <=  1440) == False:
                raise ProcessorError("EstimatedInstallationTime must be an integer between 0 and 1440")
            install_action_params['args'].append(self.new_arg(arg_name = 'ExecuteTime', arg_type = 'Int32', arg_value = f"{estimated_execute_time}"))
            max_execute_time = deployment_type_configuration.get('Options', {}).get('MaximumAllowedRuntimeMins') or  120
            if (15 <=  max_execute_time <=  1440) == False:
                raise ProcessorError("MaximumAllowedRuntimeMins must be an integer between 15 and 1440")
            install_action_params['args'].append(self.new_arg(arg_name = 'MaxExecuteTime', arg_type = 'Int32', arg_value = f"{max_execute_time}"))
            install_action_params['args'].append(self.new_arg(arg_name = 'RunAs32Bit', arg_type = 'Boolean', arg_value = f"{deployment_type_configuration.get('Options', {}).get('Force32BitInstaller', False).__str__().lower()}"))
            # Return Codes
            if deployment_type_configuration.get('Options', {}).get('KeepDefaultReturnCodes', True):
                success_exit_codes = [0, 1707]
                reboot_exit_codes = [3010]
                hardreboot_exit_codes = [1641]
                fastretry_exit_codes = [1618]
                failure_exit_codes = []
            else:
                success_exit_codes = []
                reboot_exit_codes = []
                hardreboot_exit_codes = []
                fastretry_exit_codes = []
                failure_exit_codes = []
            rc_hash = {
                "Success": success_exit_codes, 
                "Failure": failure_exit_codes, 
                "HardReboot": hardreboot_exit_codes, 
                "Reboot": reboot_exit_codes, 
                "FastRetry": fastretry_exit_codes
            }
            for rc in (deployment_type_configuration.get('Options', {}).get('CustomReturnCodes') or []):
                rc_hash[rc['CodeType']].append(rc['ReturnCode'])
            for rc_type in rc_hash.keys():
                if len(rc_hash[rc_type]) > 0:
                    self.output(f"Adding Exit Code arg for {rc_type}", 3)
                    install_action_params['args'].append(self.new_arg(arg_name = f"{rc_type}ExitCodes", arg_type = 'Int32Array', arg_value = rc_hash[rc_type]))
            self.output("Done with return codes.", 3)
            # Content Reference
            self.output("Parsing any content references", 1)
            if deployment_type_configuration.get('Options', {}).get('ContentLocation', '') !=  '':
                local_content_path_id = id(deployment_type_configuration.get('Options', {}).get('ContentLocation_Local'))
                self.output(f"Getting content importer with id: {local_content_path_id}", 2)
                content_importer = XmlNodeAsDict.instance_map_by_external_id[f"{local_content_path_id}"]
                self.output("Getting content reference.", 3)
                content_reference = self.get_content_reference(content_importer)
                self.output("Got content reference.", 3)
                install_action_params['content_reference'] = content_reference
        elif install_action_params['provider'] == 'TaskSequence':
            raise ProcessorError("TaskSequence deployment types are not yet supported")
            install_action_params["args"] = [
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context), 
                self.new_arg(arg_name = 'MethodBody', arg_type = 'String', arg_value = xml_string)
            ]
        elif install_action_params['provider'] == 'Windows8App':
            raise ProcessorError("Windows8App deployment types are not yet supported")
            install_action_params["args"] = [
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context), 
                self.new_arg(arg_name = 'MethodBody', arg_type = 'String', arg_value = xml_string)
            ]
        else:
            raise ProcessorError("Not supported.")
        install_action = self.new_dt_action(**install_action_params)
        installer_root.append_child_node([install_action])

    def add_uninstall_action(self, installer_root: XmlNodeAsDict, deployment_type_configuration:dict) -> None:
        """Parse the details of the deployment type dict and
        add a new uninstall action node to the installer root node
        commensurate with the configuration
        """
        try:
            visibility = ProgramVisibility(deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility', 'Hidden'))
        except:
            valid = ', '.join(f.value for f in ProgramVisibility)
            raise ProcessorError(f"Invalid installation program visibility: '{deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility')}'. Valid: {valid}")
        try:
            reboot_behavior = RebootBehavior(deployment_type_configuration.get('Options', {}).get('RebootBehavior', 'BasedOnExitCode'))
        except:
            valid = ', '.join(f.value for f in RebootBehavior)
            raise ProcessorError(f"Invalid reboot behavior: '{deployment_type_configuration.get('Options', {}).get('RebootBehavior')}'. Valid: {valid}")
        uninstall_action_params = {
            "action_type": "UninstallAction", 
            "provider": deployment_type_configuration.get('Technology', 'Script')
        }
        execution_context = BEHAVIOR_TYPE_TO_CONTEXT[deployment_type_configuration.get('Options', {}).get('InstallationBehaviorType', 'InstallForSystem')]
        if ['MSI', 'Script'].__contains__(uninstall_action_params['provider']):
            uninstall_action_params["args"] = [
                self.new_arg(arg_name = 'InstallCommandLine', arg_type = 'String', arg_value = deployment_type_configuration.get('Options', {}).get('UninstallProgram')), 
                self.new_arg(arg_name = 'WorkingDirectory', arg_type = 'String', arg_value = deployment_type_configuration.get('Options', {}).get('UninstallStartIn')), 
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context)
            ]
            #Logon Requirement
            if deployment_type_configuration.get('Options', {}).get('LogonRequirementType') == 'OnlyWhenUserLoggedOn':
                uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'Boolean', arg_value = 'True'))
            elif deployment_type_configuration.get('Options', {}).get('LogonRequirementType') == 'OnlyWhenNoUserLoggedOn':
                uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'Boolean', arg_value = 'False'))
            else:
                uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'String'))
            # Uninstall settings
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresElevatedRights', arg_type = 'Boolean', arg_value = 'false'))
            requires_user_interaction = (deployment_type_configuration.get('Options', {}).get('RequiresUserInteraction') or '').__str__().lower()
            if requires_user_interaction == '':
                uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'String'))
            else:
                uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'Boolean', arg_value = requires_user_interaction))
            #uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'Boolean', arg_value = deployment_type_configuration.get('Options', {}).get('RequiresUserInteraction', False).__str__().lower()))
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'RequiresReboot', arg_type = 'Boolean', arg_value = (reboot_behavior == 'ForceReboot').__str__().lower()))
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'UserInteractionMode', arg_type = 'String', arg_value = visibility.name))
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'PostInstallBehavior', arg_type = 'String', arg_value = reboot_behavior.name))
            estimated_execute_time = deployment_type_configuration.get('Options', {}).get('EstimatedInstallationTimeMins', 0)
            if (0 <=  estimated_execute_time <=  1440) == False:
                raise ProcessorError("EstimatedInstallationTimeMins must be an integer between 0 and 1440")
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'ExecuteTime', arg_type = 'Int32', arg_value = f"{estimated_execute_time}"))
            max_execute_time = deployment_type_configuration.get('Options', {}).get('MaximumAllowedRuntimeMins', 120)
            if (15 <=  max_execute_time <=  1440) == False:
                raise ProcessorError("MaximumAllowedRuntimeMins must be an integer between 15 and 1440")
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'MaxExecuteTime', arg_type = 'Int32', arg_value = f"{max_execute_time}"))
            uninstall_action_params['args'].append(self.new_arg(arg_name = 'RunAs32Bit', arg_type = 'Boolean', arg_value = deployment_type_configuration.get('Options', {}).get('Force32BitInstaller', False).__str__().lower()))
            # Return Codes
            if deployment_type_configuration.get('Options', {}).get('KeepDefaultReturnCodes', True):
                success_exit_codes = [0, 1707]
                reboot_exit_codes = [3010]
                hardreboot_exit_codes = [1641]
                fastretry_exit_codes = [1618]
                failure_exit_codes = []
            else:
                success_exit_codes = []
                reboot_exit_codes = []
                hardreboot_exit_codes = []
                fastretry_exit_codes = []
                failure_exit_codes = []
            rc_hash = {
                "Success": success_exit_codes, 
                "Failure": failure_exit_codes, 
                "HardReboot": hardreboot_exit_codes, 
                "SoftReboot": reboot_exit_codes, 
                "FastRetry": fastretry_exit_codes
            }
            for rc in (deployment_type_configuration.get('Options', {}).get('CustomReturnCodes') or []):
                rc_hash[rc['CodeType']].append(rc['ReturnCode'])
            for rc_type in rc_hash.keys():
                if len(rc_hash[rc_type]) > 0:
                    uninstall_action_params['args'].append(self.new_arg(arg_name = f"{rc_type.replace('Soft', '', 1)}ExitCodes", arg_type = 'Int32Array', arg_value = rc_hash[rc_type]))
            # Content Reference
            uninstall_setting = deployment_type_configuration.get('Options', {}).get('UninstallSetting') or 'NoneRequired'
            if uninstall_setting == 'Different' and (deployment_type_configuration.get('Options', {}).get('UninstallContentLocation') or '') !=  '':
                content_reference = self.get_content_reference(content_importer = XmlNodeAsDict.instance_map_by_external_id[f"{id(deployment_type_configuration.get('Options', {}).get('UninstallContentLocation_Local'))}"])
                uninstall_action_params['content_reference'] = content_reference
            elif uninstall_setting == 'SameAsInstall':
                content_reference = self.get_content_reference(content_importer = XmlNodeAsDict.instance_map_by_external_id[f"{id(deployment_type_configuration.get('Options', {}).get('ContentLocation_Local'))}"])
                uninstall_action_params['content_reference'] = content_reference
            elif uninstall_setting == 'Different' and deployment_type_configuration.get('Options', {}).get('UninstallContentLocation', '').strip() == '':
                raise ProcessorError("ContentLocation must be specified when UninstallSetting = 'Different'")
        elif uninstall_action_params['provider'] == 'TaskSequence':
            raise ProcessorError("TaskSequence deployment types are not yet supported")
            uninstall_action_params["args"] = [
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context), 
                self.new_arg(arg_name = 'MethodBody', arg_type = 'String', arg_value = xml_string)
            ]
        elif uninstall_action_params['provider'] == 'Windows8App':
            raise ProcessorError("Windows8App deployment types are not yet supported")
            uninstall_action_params["args"] = [
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context), 
                self.new_arg(arg_name = 'MethodBody', arg_type = 'String', arg_value = xml_string)
            ]
        else:
            raise ProcessorError("Not supported.")
        
        uninstall_action = self.new_dt_action(**uninstall_action_params)
        installer_root.append_child_node([uninstall_action])

    def add_repair_action(self, installer_root: XmlNodeAsDict, deployment_type_configuration:dict) -> None:
        """Parse the details of the deployment type dict and
        add a new repair action node to the installer root node
        commensurate with the configuration
        """
        try:
            visibility = ProgramVisibility(deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility', 'Hidden'))
        except:
            valid = ', '.join(f.value for f in ProgramVisibility)
            raise ProcessorError(f"Invalid installation program visibility: '{deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility')}'. Valid: {valid}")
        try:
            reboot_behavior = RebootBehavior(deployment_type_configuration.get('Options', {}).get('RebootBehavior', 'BasedOnExitCode'))
        except:
            valid = ', '.join(f.value for f in RebootBehavior)
            raise ProcessorError(f"Invalid reboot behavior: '{deployment_type_configuration.get('Options', {}).get('RebootBehavior')}'. Valid: {valid}")
        repair_action_params = {
            "action_type": "RepairAction", 
            "provider": deployment_type_configuration.get('Technology', 'Script')
        }
        execution_context = BEHAVIOR_TYPE_TO_CONTEXT[deployment_type_configuration.get('Options', {}).get('InstallationBehaviorType', 'InstallForSystem')]
        if ['MSI', 'Script'].__contains__(repair_action_params['provider']):
            repair_action_params["args"] = [
                self.new_arg(arg_name = 'InstallCommandLine', arg_type = 'String', arg_value = deployment_type_configuration.get('Options', {}).get('RepairProgram')), 
                self.new_arg(arg_name = 'WorkingDirectory', arg_type = 'String', arg_value = deployment_type_configuration.get('Options', {}).get('RepairStartIn')), 
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context)
            ]
            #Logon Requirement
            if deployment_type_configuration.get('Options', {}).get('LogonRequirementType') == 'OnlyWhenUserLoggedOn':
                repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'Boolean', arg_value = 'True'))
            elif deployment_type_configuration.get('Options', {}).get('LogonRequirementType') == 'OnlyWhenNoUserLoggedOn':
                repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'Boolean', arg_value = 'False'))
            else:
                repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresLogOn', arg_type = 'String'))
            # Repair settings
            repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresElevatedRights', arg_type = 'Boolean', arg_value = 'false'))
            requires_user_interaction = (deployment_type_configuration.get('Options', {}).get('RequiresUserInteraction') or '').__str__().lower()
            if requires_user_interaction == '':
                repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'String'))
            else:
                repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'Boolean', arg_value = requires_user_interaction))
            #repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresUserInteraction', arg_type = 'Boolean', arg_value = deployment_type_configuration.get('Options', {}).get('RequiresUserInteraction', False).__str__().lower()))
            repair_action_params['args'].append(self.new_arg(arg_name = 'RequiresReboot', arg_type = 'Boolean', arg_value = (reboot_behavior == 'ForceReboot').__str__().lower()))
            repair_action_params['args'].append(self.new_arg(arg_name = 'UserInteractionMode', arg_type = 'String', arg_value = visibility.name))
            repair_action_params['args'].append(self.new_arg(arg_name = 'PostInstallBehavior', arg_type = 'String', arg_value = reboot_behavior.name))
            estimated_execute_time = deployment_type_configuration.get('Options', {}).get('EstimatedInstallationTimeMins', 0)
            if (0 <=  estimated_execute_time <=  1440) == False:
                raise ProcessorError("EstimatedInstallationTime must be an integer between 0 and 1440")
            repair_action_params['args'].append(self.new_arg(arg_name = 'ExecuteTime', arg_type = 'Int32', arg_value = f"{estimated_execute_time}"))
            max_execute_time = deployment_type_configuration.get('Options', {}).get('MaximumAllowedRuntimeMins', 120)
            if (15 <=  max_execute_time <=  1440) == False:
                raise ProcessorError("MaximumAllowedRuntimeMins must be an integer between 15 and 1440")
            repair_action_params['args'].append(self.new_arg(arg_name = 'MaxExecuteTime', arg_type = 'Int32', arg_value = f"{max_execute_time}"))
            repair_action_params['args'].append(self.new_arg(arg_name = 'RunAs32Bit', arg_type = 'Boolean', arg_value = deployment_type_configuration.get('Options', {}).get('Force32BitInstaller', False).__str__().lower()))
            # Return Codes
            if deployment_type_configuration.get('Options', {}).get('KeepDefaultReturnCodes', True):
                success_exit_codes = [0, 1707]
                reboot_exit_codes = [3010]
                hardreboot_exit_codes = [1641]
                fastretry_exit_codes = [1618]
                failure_exit_codes = []
            else:
                success_exit_codes = []
                reboot_exit_codes = []
                hardreboot_exit_codes = []
                fastretry_exit_codes = []
                failure_exit_codes = []
            rc_hash = {
                "Success": success_exit_codes, 
                "Failure": failure_exit_codes, 
                "HardReboot": hardreboot_exit_codes, 
                "SoftReboot": reboot_exit_codes, 
                "FastRetry": fastretry_exit_codes
            }
            for rc in (deployment_type_configuration.get('Options', {}).get('CustomReturnCodes') or []):
                rc_hash[rc['CodeType']].append(rc['ReturnCode'])
            for rc_type in rc_hash.keys():
                if len(rc_hash[rc_type]) > 0:
                    repair_action_params['args'].append(self.new_arg(arg_name = f"{rc_type.replace('Soft', '')}ExitCodes", arg_type = 'Int32Array', arg_value = rc_hash[rc_type]))
        elif repair_action_params['provider'] == 'TaskSequence':
            raise ProcessorError("TaskSequence deployment types are not yet supported")
        elif repair_action_params['provider'] == 'Windows8App':
            raise ProcessorError("Windows8App deployment types are not yet supported")
            repair_action_params["args"] = [
                self.new_arg(arg_name = 'ExecutionContext', arg_type = 'String', arg_value = execution_context), 
                self.new_arg(arg_name = 'MethodBody', arg_type = 'String', arg_value = xml_string)
            ]
        else:
            raise ProcessorError("Not supported.")
        
        repair_action = self.new_dt_action(**repair_action_params)
        installer_root.append_child_node([repair_action])

    def add_technology_specific_custom_data(self, installer_root: XmlNodeAsDict, deployment_type_configuration:dict, detection_nodes: list) -> None:
        """Parse the details of the deployment type dict and
        add a custom data node to the installer root node
        commensurate with the configuration
        """
        custom_data_nodes = detection_nodes
        deployment_technology = deployment_type_configuration.get('Technology')
        if ['MSI', 'Script'].__contains__(deployment_technology):
            custom_data_nodes.append(XmlNodeAsDict(NodeName = 'InstallCommandLine', NodeInnerText = deployment_type_configuration.get('Options', {}).get('InstallationProgram')))
        elif deployment_technology == 'TaskSequence':
            custom_data_nodes.append(XmlNodeAsDict(NodeName = 'InstallCommandLine', NodeInnerText = 'Task Sequence'))
        if deployment_type_configuration.get('Options', {}).get('Force32BitInstaller', False).__str__().lower() == 'true':
            custom_data_nodes.append(XmlNodeAsDict(NodeName = 'RedirectCommandLine', NodeInnerText = 'true'))
        install_content_local = deployment_type_configuration.get('Options', {}).get('ContentLocation_Local', '')
        if ['MSI', 'Script'].__contains__(deployment_technology):
            if install_content_local !=  '':
                install_content = XmlNodeAsDict.instance_map_by_external_id[f"{id(install_content_local)}"]
                install_content_id = install_content.get_attribute_value(attribute_name = 'ContentId')
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'InstallContent', Attributes = [XmlAttributeAsDict(Name = 'ContentId', Value = install_content_id), XmlAttributeAsDict(Name = 'Version', Value = '1')]))
            uninstall_setting = deployment_type_configuration.get('Options', {}).get('UninstallSetting') or 'SameAsInstall'
            uninstall_content_local = deployment_type_configuration.get('Options', {}).get('UninstallContentLocation_Local', '')
            if uninstall_setting == 'SameAsInstall' and install_content_local !=  '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'UninstallContent', Attributes = [XmlAttributeAsDict(Name = 'ContentId', Value = install_content_id), XmlAttributeAsDict(Name = 'Version', Value = '1')]))
            elif uninstall_setting == 'Different' and uninstall_content_local !=  '':
                uninstall_content = XmlNodeAsDict.instance_map_by_external_id[f"{id(uninstall_content_local)}"]
                uninstall_content_id = uninstall_content.get_attribute_value(attribute_name = 'ContentId')
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'UninstallContent', Attributes = [XmlAttributeAsDict(Name = 'ContentId', Value = uninstall_content_id), XmlAttributeAsDict(Name = 'Version', Value = '1')]))
            uninstall_command_line = deployment_type_configuration.get('Options', {}).get('UninstallProgram', '')
            uninstall_start_in = deployment_type_configuration.get('Options', {}).get('UninstallStartIn') or ''
            if uninstall_command_line !=  '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'UninstallCommandLine', NodeInnerText = uninstall_command_line))
            if uninstall_start_in.strip() !=  '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'UninstallFolder', NodeInnerText = uninstall_start_in))
            custom_data_nodes.append(XmlNodeAsDict(NodeName = 'UninstallSetting', NodeInnerText = uninstall_setting))
            repair_command_line = deployment_type_configuration.get('Options', {}).get('RepairProgram', '')
            repair_start_in = deployment_type_configuration.get('Options', {}).get('RepairStartIn', '')
            if repair_command_line !=  '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'RepairCommandLine', NodeInnerText = repair_command_line))
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'RepairFolder', NodeInnerText = repair_start_in))
            self.output("Adding MaxExecute node.", 3)
            custom_data_nodes.append(XmlNodeAsDict(NodeName = "MaxExecuteTime", NodeInnerText = str(deployment_type_configuration.get('Options', {}).get('MaximumAllowedRuntimeMins') or 120)))
            self.output("Adding ExecuteTime node.", 3)
            custom_data_nodes.append(XmlNodeAsDict(NodeName = "ExecuteTime", NodeInnerText = str(deployment_type_configuration.get('Options', {}).get('EstimatedInstallationTimeMins') or 0)))
            self.output("Added execution time nodes.", 3)
            if deployment_type_configuration.get('Options', {}).get('KeepDefaultReturnCodes', True):
                return_code_nodes = [
                    XmlNodeAsDict(NodeName = "ExitCode", Attributes = [XmlAttributeAsDict(Name = "Code", Value = "0"), XmlAttributeAsDict(Name = "Class", Value = "Success")]), 
                    XmlNodeAsDict(NodeName = "ExitCode", Attributes = [XmlAttributeAsDict(Name = "Code", Value = "1707"), XmlAttributeAsDict(Name = "Class", Value = "Success")]), 
                    XmlNodeAsDict(NodeName = "ExitCode", Attributes = [XmlAttributeAsDict(Name = "Code", Value = "3010"), XmlAttributeAsDict(Name = "Class", Value = "SoftReboot")]), 
                    XmlNodeAsDict(NodeName = "ExitCode", Attributes = [XmlAttributeAsDict(Name = "Code", Value = "1641"), XmlAttributeAsDict(Name = "Class", Value = "HardReboot")]), 
                    XmlNodeAsDict(NodeName = "ExitCode", Attributes = [XmlAttributeAsDict(Name = "Code", Value = "1618"), XmlAttributeAsDict(Name = "Class", Value = "FastRetry")]), 
                ]
            else:
                return_code_nodes = []
            rc_type_hash = {
                "Success": "Success", 
                "Failure": "Failure", 
                "HardReboot": "HardReboot", 
                "Reboot": "SoftReboot", 
                "FastRetry": "FastRetry"
            }
            for rc in (deployment_type_configuration.get('Options', {}).get('CustomReturnCodes') or []):
                node_params = {
                    "NodeName": "ExitCode", 
                    "Attributes": [
                        XmlAttributeAsDict(Name = "Code", Value = str(rc.get('ReturnCode'))), 
                        XmlAttributeAsDict(Name = "Class", Value = rc_type_hash[rc.get('CodeType')])
                    ]
                }
                if (code_name :=  rc.get('Name', '')) !=  '':
                    node_params['Attributes'].append(XmlAttributeAsDict(Name = "Name", Value = code_name))
                if (code_description :=  rc.get('Description', '')) !=  '':
                    node_params['NodeInnerText'] = code_description
                return_code_nodes.append(XmlNodeAsDict(**node_params))
            if len(return_code_nodes) > 0:
                custom_data_nodes.append(XmlNodeAsDict(NodeName = "ExitCodes", ChildNodes = return_code_nodes))
            self.output("Add Installation Program Visibility node.", 3)
            custom_data_nodes.append(XmlNodeAsDict(NodeName = "UserInteractionMode", NodeInnerText = (deployment_type_configuration.get('Options', {}).get('InstallationProgramVisibility') or 'Hidden')))
        if ['MSI', 'Script'].__contains__(deployment_technology):
            allow_uninstall = deployment_type_configuration.get('Options', {}).get('AllowUninstall', True)
            if allow_uninstall:
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'AllowUninstall', NodeInnerText = allow_uninstall.__str__().lower()))
            source_product_code = deployment_type_configuration.get('Options', {}).get('SourceUpdateProductCode', '')
            if source_product_code !=  '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName = 'SourceUpdateProductCode', NodeInnerText = source_product_code))
        else: # TaskSequence or Windows8App specific nodes.
            pass
        detect_processes = deployment_type_configuration.get('Options', {}).get('InstallProcessDetection', [])
        if len(detect_processes) > 0:
            processes = []
            for ipd in detect_processes:
                processes.append(self.new_process_information(process_name = ipd['ProcessName'], process_display_name = ipd['DisplayName']))
            custom_data_nodes.append(self.new_install_process_detection(process_information = processes))
        installer_root.append_child_node([XmlNodeAsDict(NodeName = 'CustomData', ChildNodes = custom_data_nodes)])

    def new_installer_node(self, authoring_scope_id: str, application_id: str, logical_name: str, version:int, deployment_type_configuration:dict) -> XmlNodeAsDict:
        """Create a new installer XmlNodeAsDict object"""
        installer_root = XmlNodeAsDict(NodeName = 'Installer', Attributes = [XmlAttributeAsDict(Name = 'Technology', Value = deployment_type_configuration.get('Technology'))])
        installer_root.append_child_node([
            XmlNodeAsDict(NodeName = 'ExecutionContext', NodeInnerText = deployment_type_configuration.get('ExecutionContext', 'System'))
        ])
        if deployment_type_configuration.get('ExecutionContext', 'System') !=  'System' or deployment_type_configuration.get('LogonRequirementType', '') == 'OnlyWhenUserLoggedOn':
            installer_root.append_child_node([XmlNodeAsDict(NodeName = 'RequiresLogOn', NodeInnerText = 'true')])
        elif deployment_type_configuration.get('LogonRequirementType', '') == 'OnlyWhenNoUserLoggedOn':
            installer_root.append_child_node([XmlNodeAsDict(NodeName = 'RequiresLogOn', NodeInnerText = 'false')])
        self.output("Examining content", 3)
        content_path = deployment_type_configuration.get('Options', {}).get('ContentLocation')
        local_content_path = deployment_type_configuration.get('Options', {}).get('ContentLocation_Local')
        content_nodes = []
        if [content_path, local_content_path].__contains__(None) == False:
            self.output("Adding install content", 2)
            content_params = {
                "content_location": content_path, 
                "content_location_local": local_content_path, 
                "enable_peer_cache": deployment_type_configuration.get('Options', {}).get('EnablePeerCache', True), 
                "fast_network_action": ContentHandlingMode(deployment_type_configuration.get('Options', {}).get('OnFastNetwork', 'Download')), 
                "slow_network_action": ContentHandlingMode(deployment_type_configuration.get('Options', {}).get('OnSlowNetwork', 'Download'))
            }
            content_nodes.append(self.new_content_importer(**content_params))
        else:
            self.output("No install content", 2)
        
        uninstall_setting = deployment_type_configuration.get('Options', {}).get('UninstallSetting') or 'NoneRequired'
        self.output("Examining any uninstall content", 3)
        if uninstall_setting == 'Different':
            content_params = {
                "content_location": deployment_type_configuration.get('Options', {}).get('UninstallContentLocation', None), 
                "content_location_local": deployment_type_configuration.get('Options', {}).get('UninstallContentLocation_Local', None), 
                "enable_peer_cache": deployment_type_configuration.get('Options', {}).get('EnablePeerCache', True), 
                "fast_network_action": ContentHandlingMode(deployment_type_configuration.get('Options', {}).get('OnFastNetwork', 'Download')), 
                "slow_network_action": ContentHandlingMode(deployment_type_configuration.get('Options', {}).get('OnSlowNetwork', 'Download'))
            }
            self.output('Adding uninstall content', 2)
            content_nodes.append(self.new_content_importer(**content_params))
        else:
            self.output("No specific uninstall content", 2)
        self.output('Appending collected content nodes', 3)
        installer_root.append_child_node([XmlNodeAsDict(NodeName = 'Contents', ChildNodes = content_nodes)])
        self.output('Creating detection nodes', 3)
        detection_nodes = self.new_detection_nodes(authoring_scope_id = authoring_scope_id, application_id = application_id, 
                deployment_type_id = logical_name, detection_item = deployment_type_configuration.get('Options', {}).get('Detection'))
        self.output('Adding detection node(s) to installer node', 3)
        installer_root.append_child_node([detection_nodes[0]])
        # Install action
        self.output("Adding install action node", 2)
        self.add_install_action(installer_root = installer_root, deployment_type_configuration = deployment_type_configuration)
        # UninstallAction
        if (deployment_type_configuration.get('Options', {}).get('UninstallProgram') or '').strip() !=  '':
            self.output("Adding uninstall action node", 2)
            self.add_uninstall_action(installer_root = installer_root, deployment_type_configuration = deployment_type_configuration)
        # RepairAction
        if (deployment_type_configuration.get('Options', {}).get('RepairProgram') or '').strip() !=  '':
            self.output("Adding repair action node", 2)
            self.add_repair_action(installer_root = installer_root, deployment_type_configuration = deployment_type_configuration)
        # CustomData
        self.output(f"Adding custom data specific to {deployment_type_configuration.get('Technology')} deployment technology.", 3)
        self.add_technology_specific_custom_data(installer_root = installer_root, deployment_type_configuration = deployment_type_configuration, detection_nodes = detection_nodes[1])
        self.output("Finished adding custom data.", 3)
        return installer_root

    def new_deployment_type(
            self, authoring_scope_id: str, application_id: str,
            logical_name: str, version:int,
            deployment_type_configuration:dict) -> XmlNodeAsDict:
        """Create a new deployment type XmlNodeAsDict object"""
        self.output("Generating a deployment type node.", 3)
        attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = authoring_scope_id), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = logical_name), 
            XmlAttributeAsDict(Name = 'Version', Value = str(version))
        ]
        try:
            self.output("Getting technology type.", 3)
            technology = DeploymentTechnology(deployment_type_configuration.get('Technology'))
        except:
            valid = ', '.join(f.value for f in DeploymentTechnology)
            raise ProcessorError(f"Invalid deployment technology: '{deployment_type_configuration.get('Technology')}'. Valid: {valid}")
        title = deployment_type_configuration.get('Options', {}).get('DeploymentTypeName', 'Install')
        self.output(f"Title: {title}", 3)
        node = XmlNodeAsDict(NodeName = 'DeploymentType', Attributes = attributes)
        child_nodes = [XmlNodeAsDict(NodeName = 'Title', NodeInnerText = title, Attributes = [self.new_resource_id_attribute()])]
        # Append administrator comments
        administrator_comment = deployment_type_configuration.get('Options', {}).get('AdministratorComment', '')
        if administrator_comment !=  '':
            child_nodes.append(XmlNodeAsDict(NodeName = "Description", Attributes = [self.new_resource_id_attribute()], NodeInnerText = administrator_comment))
        else:
            child_nodes.append(XmlNodeAsDict(NodeName = "Description", Attributes = [self.new_resource_id_attribute()]))
        # Append languages
        languages = deployment_type_configuration.get('Options', {}).get('Languages', [])
        if languages == None:
            languages_list = []
        elif isinstance(languages, str):
            languages_list = [languages]
        elif isinstance(languages, list):
            languages_list = languages
        if len(languages_list) > 0:
            child_nodes.append(self.new_languages_node(languages_list))
        # Append requirements
        requirements_rules = []
        requirements = deployment_type_configuration.get('Options', {}).get('Requirements') or []
        self.output(f"Assembling {len(requirements)} requirements", 2)
        for r in requirements:
            rule_config_type = r['Type']
            rule_getter = self.get_requirements_rule_config[rule_config_type]
            rule_id = McmIdentifier().get_logical_name(object_type_name = 'Rule')
            self.output(f"Configuring requirement rule '{rule_id}' from {rule_config_type}", 3)
            requirements_rules.append(rule_getter(rule = r['Rule'], rule_id = rule_id))
        if len(requirements_rules) > 0:
            self.output("Adding requirements node", 2)
            child_nodes.append(XmlNodeAsDict(NodeName = 'Requirements', ChildNodes = requirements_rules))
        
        # Append dependencies
        self.output("Examining dependencies", 3)
        dependency_groups = deployment_type_configuration.get('Options', {}).get('DependencyGroups') or []
        if (len(dependency_groups) > 0):
            self.output("Creating dependency groups", 3)
            dependency_group_nodes = []
            for dg in dependency_groups:
                dependency_nodes = []
                for n in dg.get('Dependencies', []):
                    dependency_nodes.append(self.new_dependency(authoring_scope_id = authoring_scope_id, 
                            application_logical_name = n.get('ApplicationLogicalName'),
                            dt_logical_name = n.get('DeploymentTypeLogicalName'),
                            auto_install = n.get('AutoInstall', False)))
                self.output(f"Finished with the dependency group {dg['DependencyGroupName']}", 3)
                dependency_group_nodes.append(self.new_dependency_group(rule_name = dg["DependencyGroupName"], dependencies = dependency_nodes))
            self.output("Finished constructing dependency groups.", 3)
            dependencies_node = self.new_dependencies_node(dependency_groups = dependency_group_nodes)
            child_nodes.append(dependencies_node)
        self.output("Adding common nodes to deployment type", 3)
        child_nodes.append(XmlNodeAsDict(NodeName = 'DeploymentTechnology', NodeInnerText = f"GLOBAL/{technology.name}DeploymentTechnology"))
        child_nodes.append(XmlNodeAsDict(NodeName = 'Technology', NodeInnerText = technology.name))
        child_nodes.append(XmlNodeAsDict(NodeName = 'Hosting', NodeInnerText = deployment_type_configuration.get('Hosting', 'Native')))
        # Append installer
        self.output("Adding installer node", 3)
        installer_node = self.new_installer_node(authoring_scope_id = authoring_scope_id, application_id = application_id, 
                logical_name = logical_name, version = version, deployment_type_configuration = deployment_type_configuration)
        self.output("Created installer node.", 3)
        child_nodes.append(installer_node)
        node.append_child_node(child_nodes)
        return node

    def execute(self):
        self.initialize_all()
        # Define namespaces
        appNs = self.get_nsmap('AppMgmtDigest')
        self.nsmap = appNs['nsmap']
        self.authoring_scope = self.get_mcm_scope_id()

        # Search for existing app
        app = self.env.get('mcm_application_configuration')
        version = app.get('SoftwareVersion')
        self.software_version = version
        behavior_if_app_exists = app.get('BehaviorIfExists', 'Exit')
        existing_app_ci_id = self.env.get('existing_app_ci_id') or 0
        self.output(f"Existing CI_ID: {existing_app_ci_id}", 3)
        existing_app_sdmpackagexml = self.env.get('existing_app_sdmpackagexml') or ''
        self.output(f"Existing SDMPackageXML Length: {len(existing_app_sdmpackagexml)}", 3)
        if existing_app_sdmpackagexml !=  '' and existing_app_ci_id > 0:
            self.output("An existing application with this name was located.", 2)
            existing_app = XmlNodeAsDict.from_xml_string_with_tracking(
                xml_string = existing_app_sdmpackagexml\
                    .replace('<?xml version="1.0" encoding="utf-16"?>', '', 1)\
                        .replace("<?xml version='1.0' encoding='utf-16'?>", '', 1)
                )
        else:
            self.output(f"Existing app does not exist.", 3)
            existing_app = None
        is_new_app = True
        app_name = app.get('Name')
        if existing_app is not None and behavior_if_app_exists == 'Exit':
            self.output(f"The application already exists and BehaviorIfExists was set to 'Exit'. Nothing to do.", 1)
            return
        if existing_app is None:
            self.output("A new application object will be created.", 3)
            pass
        elif behavior_if_app_exists == 'Update':
            is_new_app = False
            self.output('Using the existing Logical Name and CI_ID for the application and incrementing the revision/version.', 1)
            app_name = app.get('Name')
            app_nodes = existing_app.find_children_by_name('Application')
            self.output(f"{app_name} contains {len(app_nodes)} application nodes.", 3)
            app_logical_name = app_nodes[0].get_attribute_value('LogicalName')
            app_version = int(existing_app.find_children_by_name('Application')[0].get_attribute_value('Version')) + 1
            self.env['mcm_application_ci_id'] = existing_app_ci_id
        elif behavior_if_app_exists == 'AppendIndex':
            self.output(f"An index will be appended.", 3)
            done = False
            index = 1
            while done == False and index < 20:
                search_name = f"{app.get('Name')} ({index.__str__()})"
                result = McmApiBase.find_application_by_name(search_name)
                if result is None:
                    self.output(f"Appending an index ({index.__str__()}) to the application name.", 3)
                    app_name = search_name
                    done = True
                index +=  1
                if index == 20:
                    self.output("Wow... There are 20 versions of this application. You should probably look at this.", 3)
                    break
                else:
                    continue
            if done == False:
                raise ProcessorError("Could not find a name that was not already taken.")
            self.env['mcm_application_ci_id'] = 0
        elif behavior_if_app_exists == 'AppendVersion':
            search_name = f"{app.get('Name')} {app.get('SoftwareVersion')}"
            self.output(f"Checking to see if an app with the version appended exists ({search_name}).", 3)
            result = McmApiBase.find_application_by_name(search_name)
            if result is None:
                self.output("Appending the version to the application name.", 3)
                app_name = search_name
            else:
                raise ProcessorError(f"An application already exists which already includes the version in the title. ({search_name})")
        else:
            raise ProcessorError("Invalid setting for BehaviorIfExists.")
        if is_new_app == True:
            app_version = 1
            app_logical_name = McmIdentifier().get_logical_name('Application')
            self.env['mcm_application_ci_id'] = 0            
        self.output(f"\n\tName: {app_name}\n\tLogicalName: {app_logical_name}\n\tRevision: {app_version}\n\tCI_ID: {existing_app_ci_id}", 3)
        self.output("Examining deployment types.", 1)
        if self.env.get('mcm_application_ci_id', 0) > 0:
            existingDts = existing_app.find_children_by_name(node_name = 'DeploymentType')
            self.output(f"Comparing configured deployment types to {len(app.get('DeploymentTypes', []))} deployment types in the existing application.", 3)
            merged = self.merge_deployment_types(authoring_scope_id = self.authoring_scope, dicts = app.get('DeploymentTypes', []), existing_deployment_types = existingDts, persist_unhandled_deployment_types = app.get('PersistUnhandledDeploymentTypes', False))
        else:
            self.output("Deployment types from the supplied configuration will be used.", 3)
            merged = self.merge_deployment_types(authoring_scope_id = self.authoring_scope, dicts = app.get('DeploymentTypes', []), existing_deployment_types = [])
        self.output('Done examining deployment types.', 3)
        dt_list = []
        for dt in merged:
            self.output("Processing deployment type.", 3)
            self.output(f"TYPE: {type(dt).__name__}",4)
            if type(dt).__name__ == 'str':
                self.output(f"{dt}", 4)
            self.output(f"DT KEYS: {', '.join(list(dt.keys()))}", 4)
            if dt["Type"] == 'element':
                dt_list.append(XmlNodeAsDict.convert_element_to_dict(dt['Object'], namespace_mode = 'PersistAsAttribute', parent_namespace = existing_app.nsmap, is_root = False))
            elif dt["Type"] == "XmlNodeAsDict":
                self.output("Appending the existing deployment type", 3)
                dt_list.append(dt['Object'])
            else:
                self.output("Creating a new deployment type.", 3)
                dt_list.append(self.new_deployment_type(authoring_scope_id = self.authoring_scope, application_id = app_logical_name, 
                        logical_name = dt['LogicalName'], version = dt['Version'], deployment_type_configuration = dt['Object']))
        self.output("Creating application object.", 1)
        app_attributes = [
            XmlAttributeAsDict(Name = 'AuthoringScopeId', Value = self.authoring_scope), 
            XmlAttributeAsDict(Name = 'LogicalName', Value = app_logical_name), 
            XmlAttributeAsDict(Name = 'Version', Value = str(app_version))
        ]
        application = XmlNodeAsDict(NodeName = 'Application', Attributes = app_attributes)
        # Append display info
        self.output("Creating DisplayInfo", 2)
        configured_display_info = app.get('DisplayInfo') or {}
        configured_infos = configured_display_info.get('Infos') or []
        self.output("Getting details for any configured icons.", 3)
        icon_file_unix_paths = []
        if app.get('IconFileUnixPath', '') !=  '':
            icon_file_unix_paths.append(app.get('IconFileUnixPath'))
        for v in [x.get('IconFileUnixPath') for x in configured_infos if x.get("IconFileUnixPath", "") !=  ""]:
            if not (icon_file_unix_paths.__contains__(v)):
                icon_file_unix_paths.append(v)
        icon_resources = []
        icon_resources_hash = {}
        icon_references_hash = {}
        all_resources = []
        self.output("Getting icon resource hashes.", 3)
        for i in icon_file_unix_paths:
            self.output(f"Supplied icon path: {i}", 3 )
            resolved_icon_path = str(Path(i).resolve())
            self.output(f"Resolved icon path: {resolved_icon_path}", 3)
            icon_resources_hash[i] = self.new_icon_resource(local_path=resolved_icon_path)
            icon_references_hash[i] = self.get_icon_reference(icon_resource = icon_resources_hash[i])
            all_resources.append(icon_resources_hash[i])
            icon_resources.append(icon_resources_hash[i])
        self.output(f"Collected {len(list(icon_resources_hash.keys()))} icon resource details.", 3)
        # Get UserCategory info
        self.output("Getting UserCategory details.", 3)
        user_category_names = []
        for c in (app.get('UserCategories') or []):
            user_category_names.append(c)
        for namegroup in [y.get('UserCategories') for y in configured_infos if len(y.get('UserCategories', [])) > 0]:
            for n in namegroup:
                if not (user_category_names.__contains__(n)):
                    user_category_names.append(n)
        user_categories = dict.fromkeys(user_category_names)
        for cn in list(user_categories.keys()):
            user_categories[cn] = self.get_user_category_id(cn)
        self.output(f"Collected {len(list(user_categories.keys()))} UserCategory detail objects.", 3)
        # Default DisplayInfo
        self.output("Defining parameters for the default DisplayInfo.", 3)
        default_info_params = {}
        default_language = app.get('DefaultLanguage', 'en-US')
        default_info_params["language"] = default_language
        default_localized_display_name = app.get('LocalizedDisplayName', app.get('Name', self.env.get('NAME', '')))
        if default_localized_display_name == '':
            raise ProcessorError('Applications must have a name.')
        default_info_params["title"] = default_localized_display_name
        default_localized_description = app.get('LocalizedDescription', app.get('Description'))
        default_info_params["description"] = default_localized_description
        if default_localized_description !=  '':
            default_info_params["description"] = default_localized_description
        default_icon_file_unix_path = app.get('IconFileUnixPath', None)
        if default_icon_file_unix_path is not None:
            default_info_params["icon_reference"] = icon_references_hash[default_icon_file_unix_path]
        default_keywords = app.get('Keyword', [])
        default_link_text = app.get('InfoUrlText', None)
        default_privacy_url = app.get('PrivacyUrl', None)
        default_user_documentation = app.get('UserDocumentation', None)
        publisher = app.get('Publisher')
        default_info_params['publisher'] = publisher
        default_info_params['software_version'] = version
        release_date = app.get('ReleaseDate', None)
        if release_date is not None:
            self.output("Adding release date.", 3)
            default_info_params["release_date"] = release_date
        self.output("Defining parameters for any additional DisplayInfo objects.", 3)
        display_infos = []
        default_display_info_configured = False
        configured_languages = []
        for i in configured_infos:
            item_info_language = i.get('Language', '')
            if item_info_language == '':
                raise ProcessorError('Each display info must have Language specified.')
            self.output(f"Processing DisplayInfo for {item_info_language}")
            if configured_languages.__contains__(item_info_language):
                raise ProcessorError('DisplayInfo properties for any language can only be configured once.')
            configured_languages.append(item_info_language)
            if item_info_language == default_language:
                self.output(f"Configuring display properties for the default language ({default_language}).", 2)
                default_display_info_configured = True
            item_info_params = {"language":item_info_language}
            item_info_params['publisher'] = publisher
            item_info_params['software_version'] = version
            if release_date is not None:
                item_info_params["release_date"] = release_date
            if i.get('LocalizedDisplayName', '') == '':
                item_info_params['title'] = default_localized_display_name
            else:
                item_info_params["title"] = i.get('LocalizedDisplayName')
            if i.__contains__('LocalizedDescription'):
                item_info_params["description"] = i.get('LocalizedDescription')
            else:
                item_info_params["description"] = default_localized_description
            if i.__contains__('IconFileUnixPath') and i.get('IconFileUnixPath', '') !=  '':
                item_info_params["icon_reference"] = icon_references_hash[i.get('IconFileUnixPath')]
            elif default_icon_file_unix_path is not None and default_icon_file_unix_path !=  '':
                item_info_params["icon_reference"] = icon_references_hash[default_icon_file_unix_path]
            if i.__contains__('UserDocumentation'):
                item_info_params["info_url"] = i.get('UserDocumentation')
            else:
                item_info_params["info_url"] = default_user_documentation
            if i.__contains__('LinkText'):
                item_info_params["info_url_text"] = i.get('LinkText')
            else:
                item_info_params["info_url_text"] = default_link_text
            if i.__contains__('PrivacyUrl'):
                item_info_params["privacy_url"] = i.get('PrivacyUrl')
            else:
                item_info_params["privacy_url"] = default_privacy_url
            if i.__contains__('UserCategories'):
                infoUserCategories =  i.get('UserCategories', [])
            else:
                infoUserCategories = app.get('UserCategories', [])
            item_user_categories = []
            for c in infoUserCategories:
                item_user_categories.append(user_categories[c])
            if len(item_user_categories) > 0:
                item_info_params["user_categories_node"] = self.new_user_categories_node(user_category_unique_ids = user_categories)
            if i.__contains__('Keyword'):
                item_info_params["tags"] = i.get('Keyword')
            else:
                item_info_params["tags"] = default_keywords
            self.output(f"Done gathering display info parameters. Generating node.", 3)
            display_infos.append(self.new_display_info(**item_info_params))
        if default_display_info_configured == False:
            self.output("Default DisplayInfo was not defined. Creating it now.", 2)
            display_infos.append(self.new_display_info(**default_info_params))
        display_info_node = self.new_display_info_node(display_infos = display_infos, default_language = default_language)
        application.append_child_node([display_info_node])
        # Append deployment type references
        self.output("Adding deployment type references", 2)
        deployment_type_references = []
        for deployment_type in dt_list:
            self.output('Getting reference', 3)
            deployment_type_references.append(self.get_deployment_type_reference(deployment_type = deployment_type))
        deployment_types_node = XmlNodeAsDict(NodeName = 'DeploymentTypes', ChildNodes = deployment_type_references)                
        application.append_child_node([deployment_types_node])
        self.output("Adding title", 2)
        application.append_child_node([XmlNodeAsDict(NodeName = "Title", Attributes = [self.new_resource_id_attribute()], NodeInnerText = app_name)])
        app_description = app.get('Description', '')
        if len(app_description or []) > 0:
            self.output("Adding description", 2)
            application.append_child_node([XmlNodeAsDict(NodeName = "Description", Attributes = [self.new_resource_id_attribute()], NodeInnerText = default_localized_description)])
        if len(publisher or []) > 0:
            self.output("Adding publisher", 2)
            application.append_child_node([XmlNodeAsDict(NodeName = 'Publisher', Attributes = [self.new_resource_id_attribute()], NodeInnerText = publisher)])
        if len(app.get("SoftwareVersion") or []) > 0:
            self.output(f"Adding software version {app.get('SoftwareVersion')}", 2)
            application.append_child_node([XmlNodeAsDict(NodeName = 'SoftwareVersion', Attributes = [self.new_resource_id_attribute()], NodeInnerText = app.get("SoftwareVersion"))])
        if len(release_date or []) > 0:
            self.output("Adding release date", 2)
            application.append_child_node([XmlNodeAsDict(NodeName = 'ReleaseDate', Attributes = [self.new_resource_id_attribute()], NodeInnerText = release_date)])
        optional_reference = app.get('OptionalReference') or ''
        if len(optional_reference.strip()) > 0:
            self.output(f"Adding optional reference", 2)
            application.append_child_node([XmlNodeAsDict(NodeName = 'CustomId', Attributes = [self.new_resource_id_attribute()], NodeInnerText = str(app['OptionalReference']).strip())])
        self.output("Adding AutoInstall setting", 2)
        application.append_child_node([XmlNodeAsDict(NodeName = 'AutoInstall', NodeInnerText = str(app.get('AutoInstall', False)).lower())])
        if len(app.get('Owners', [])) > 0:
            self.output("Adding owners", 2)
            application.append_child_node([self.new_owners_node(user_ids = app['Owners'])])
        if len(app.get('SupportContacts', [])) > 0:
            self.output("Adding contacts", 2)
            application.append_child_node([self.new_contacts_node(user_ids = app['SupportContacts'])])
        if bool(app.get('SendToProtectedDP', False)):
            self.output("Allowing send to protected dp", 3)
            application.append_child_node([XmlNodeAsDict(NodeName = 'SendToProtectedDP', NodeInnerText = 'true')])
        self.output("Creating AppMgmtDigest.", 2)
        app_mgmt_digest_root = XmlNodeAsDict(
            NodeName = 'AppMgmtDigest', 
            Attributes = [
                XmlAttributeAsDict(
                    Name = 'xmlns',
                    Value = self.get_nsmap('AppMgmtDigest')['ns']
                    )], 
            nsmap = self.get_nsmap("Default", include_xsi = True)['nsmap']
            )
        self.output("Adding application node", 3)
        app_mgmt_digest_root.append_child_node([application])
        if len(dt_list) > 0:
            self.output('Adding deployment types.', 3)
            app_mgmt_digest_root.append_child_node(dt_list)
        if len(all_resources) > 0:
            self.output('Adding resources node.', 3)
            resources_node = XmlNodeAsDict(NodeName = 'Resources', ChildNodes = all_resources)
            app_mgmt_digest_root.append_child_node([resources_node])
        self.output("Setting mcm_application variable", 3)
        sdm_package_xml_string = app_mgmt_digest_root.to_xml_string(xml_declaration = True, encoding = 'utf-16', pretty_print = True)
        self.output('Setting SDMPackageXML variable', 2)
        self.env["SDMPackageXML"] = sdm_package_xml_string

if __name__ == "__main__":
    PROCESSOR = McmSDMPackageXMLGeneratorBase()
    PROCESSOR.execute_shell()