#!/usr/local/autopkg/python
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

import atexit
#import string
#import random
#import base64
from copy import deepcopy
from ctypes import c_int32
from datetime import datetime
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

import dns.resolver
import keyring
import requests
import smbclient
from requests_gssapi import HTTPKerberosAuth, OPTIONAL
from lxml import etree


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

def is_empty(object: any) -> bool:
    if object is None:
        return True
    elif isinstance(object,bool):
        return ([False,True].__contains__(object) == False)
    elif isinstance(object,str):
        return (object == '')
    elif isinstance(object,dict):
        return (object == {})
    else:
        raise TypeError(f"Type ({type(object).__name__}) unhandled by is_empty")

__all__ = ["McmApiBase"]
# Enums
class ProgramVisibility(Enum):
    """Valid ProgramVisibility values"""
    Normal    = "Normal"
    Minimized = "Minimized"
    Maximized = "Maximized"
    Hidden    = "Hidden"

class RebootBehavior(Enum):
    """Valid RebootBehavior values"""
    BasedOnExitCode = "BasedOnExitCode"
    NoAction = "NoAction"
    ProgramReboot = "ProgramReboot"
    ForceReboot = "ForceReboot"

class RequirementRuleDataType(Enum):
    """Valid RequirementRuleDataType values"""
    Base64 = "Base64"
    Boolean = "Boolean"
    BooleanArray = "BooleanArray"
    CIMDateTime = "CIMDateTime"
    CIMDateTimeArray = "CIMDateTimeArray"
    Complex = "Complex"
    DateTime = "DateTime"
    DateTimeArray = "DateTimeArray"
    Double = "Double"
    DoubleArray  = "DoubleArray"
    FileSystemAccessControl = "FileSystemAccessControl"
    FileSystemAccessControlArray = "FileSystemAccessControlArray"
    FileSystemAttribute = "FileSystemAttribute"
    FileSystemAttributeArray = "FileSystemAttributeArray"
    Int64 = "Int64"
    Int64Array = "Int64Array"
    Other = "Other"
    RegistryAccessControl = "RegistryAccessControl"
    RegistryAccessControlArray  = "RegistryAccessControlArray"
    String = "String"
    StringArray = "StringArray"
    Version = "Version"
    VersionArray = "VersionArray"
    Xml = "Xml"

class ArgumentType(Enum):
    """Valid ArgumentType values"""
    String = 'String'
    Boolean = 'Boolean'
    Int32 = 'Int32'
    Int32Array = 'Int32[]'

class RuleEvaluationMethod(Enum):
    """Valid Method values for Rule objects"""
    Count = "Count"
    Value = "Value"

class DeploymentTechnology(Enum):
    """Valid DeploymentTechnology values"""
    MSI = "MSI"
    Windows8App = "Windows8App"
    #Deeplink = 2
    Script = "Script"
    #AppV = 4
    #AppV5X = 5
    #WinPhone8 = 6
    #WinPhone8Deeplink = 7
    #WM = 8
    #iOS = 9
    #iOSDeepLink = 10
    #Android = 11
    #AndroidDeepLink = 12
    #Mac = 13
    #WebApp = 14
    #MobileMsi = 15
    #TaskSequence = "TaskSequence"

class ExecutionContext(Enum):
    """Valid ExecutionContext values"""
    Any = "Any"
    User = "User"
    System = "System"

class ActionProvider(Enum):
    """Valid ActionProvider values"""
    Local = "Local"
    Script = "Script"
    TaskSequence = "TaskSequence"

class Operator(Enum):
    """Valid Operator values. Not all operators below are valid in all
    configuration contexts
    """
    Equals = "Equals"
    NotEquals = "NotEquals"
    GreaterThan = "GreaterThan"
    LessThan = "LessThan"
    Between = "Between"
    GreaterEquals = "GreaterEquals"
    LessEquals = "LessEquals"
    BeginsWith = "BeginsWith"
    NotBeginsWith = "NotBeginsWith"
    EndsWith = "EndsWith"
    NotEndsWith = "NotEndsWith"
    Contains = "Contains"
    NotContains = "NotContains"
    AllOf = "AllOf"
    OneOf = "OneOf"
    NoneOf = "NoneOf"
    SetEquals = "SetEquals"
    ###### CUSTOM ######
    Existential = "Existential"
    NotExistential = "NotExistential"
    ##### Grouping #####
    And = "And"
    Or = "Or"

class SettingSourceType(Enum):
    """Valid SettingSourceType values"""
    File = "File"
    Folder = "Folder"
    Registry = "Registry"
    RegistryKey = "RegistryKey"
    MSI = "MSI"

class SettingPropertyPath(Enum):
    """Valid SettingPropertyPath values"""
    RegistryKeyExists = "RegistryKeyExists"
    Size = "Size"
    ProductVersion = "ProductVersion"
    DateCreated = "DateCreated"
    DateModified = "DateModified"

class ContentHandlingMode(Enum):
    """Valid ContentHandlingMode values"""
    DoNothing = "DoNothing"
    Download = "Download"
    DownloadContentForStreaming = "DownloadContentForStreaming"

class DeploymentTypeFilterType(Enum):
    """Valid DeploymentTypeFilterType values"""
    Equals = "Equal"
    StartsWith = "StartsWith"
    Contains = "Contains"

class ActionType(Enum):
    """Valid ActionType values"""
    DetectAction = "DetectAction"
    InstallAction = "InstallAction"
    UninstallAction = "UninstallAction"
    RepairAction = "RepairAction"

class DetectionType(Enum):
    """Valid DetectionType values"""
    File = "File"
    Folder = "Folder"
    RegistryKey = "RegistryKey"
    RegistryKeyValue = "RegistryKeyValue"
    MSI = "MSI"
    Group = "Group"
    CustomScript = "CustomScript"

PROPERTY_PATH_DATA_TYPE = {
    """Map PropertyPaths to valid DataType values"""
    "DateCreated": "DateTime", 
    "DateModified": "DateTime", 
    "ProductVersion": "Version", 
    "Size": "Int64", 
    "Version": "Version"
}
BEHAVIOR_TYPE_TO_CONTEXT = {
    "InstallForSystem":"System", 
    "InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser": "Any", 
    "InstallForUser": "User"
}

# Root
class McmIdentifier(dict):
    """A class used to create valid identifiers for use in MCM"""
    def __init__(self, guid: str = None, resource_id:int = None):
        if guid is None:
            guid = uuid.uuid4()
        else:
            guid = uuid.UUID(guid)
        self.guid = guid.__str__()
        if resource_id is None:
            self.resource_id = McmApiBase.get_int32_from_uuid(guid)
        else:
            self.resource_id = resource_id
    def get_logical_name(self, object_type_name: str = None, object:any = None):
        """Return a logical name identifier given an object type"""
        if (object_type_name is None or object_type_name == ''):
            if object is None:
                raise ProcessorError('object_type_name or object must be supplied')
            object_type = type(object)
            object_type_name = object_type.__name__
        else:
            object_type_name = object_type_name
        return f"{object_type_name}_{self.guid}"
     
    def get_resource_id(self):
        """Return the deterministic resource id of the object"""
        return f"Res_{self.ResourceId.__str__()}"

class XmlAttributeAsDict(dict):
    """Allow XML attributes to be represented as dict objects"""
    def __init__(self, Name: str, Value:any):
        super().__init__({
            'Name': Name, 
            'Value':  McmApiBase.try_cast(type_name = str, value = Value,default = '')
        })

class XmlNodeAsDict(dict):
    """Stub class to allow XmlNodeAsDict to nest inside of itself"""
    pass

class XmlNodeAsDict(dict):
    """Represent an etree.Element object as a dict"""
    instance_map = {}
    instance_map_by_external_id = {}
    def __init__(self, NodeName: str, Attributes: list[XmlAttributeAsDict] = [], ChildNodes: list[XmlNodeAsDict] = None, 
                 NodeInnerText: str = None, nsmap:dict = None, xml_declaration:bool = False, external_reference_id:int = None, group_ids: list[int] = []):
        super().__init__({})
        self['NodeName'] = NodeName
        if Attributes is not None and len(Attributes) > 0:
            self['Attributes'] = Attributes
        if ChildNodes is not None and len(ChildNodes) > 0:
            self['ChildNodes'] = ChildNodes
        else:
            self['ChildNodes'] = []
        
        if is_empty(NodeInnerText) == False:
            self['NodeInnerText'] = NodeInnerText
        self["xml_declaration"] = xml_declaration
        self["nsmap"] = nsmap if nsmap is not None else {}
        XmlNodeAsDict.instance_map[f"{id(self)}"] = self
        if external_reference_id is not None:
            XmlNodeAsDict.instance_map_by_external_id[f"{external_reference_id}"] = self
    @classmethod
    def convert_element_to_dict(cls, element:etree.Element, namespace_mode: str = 'PersistAsAttribute', parent_namespace:dict = None, is_root:bool = True) -> XmlNodeAsDict:
        """Convert an etree.Element object to XmlNodeAsDict class. Used
        to import existing XML objects
        """
        class NamespaceMode(Enum):
            Maintain = "Maintain"
            StripRecursive = "StripRecursive"
            PersistAsAttribute = "PersistAsAttribute"
        params = {
            "NodeName": etree.QName(element).localname, 
            "Attributes": []
        }
        if namespace_mode == 'Maintain':
            params['nsmap'] = element.nsmap
        if is_root:
            parent_namespace = element.nsmap
            params['nsmap'] = element.nsmap
        if namespace_mode == 'PersistAsAttribute' and parent_namespace is not None and element.nsmap !=  parent_namespace:
            params['Attributes'].append(XmlAttributeAsDict(Name = 'xmlns', Value = element.nsmap[None]))
        else:
            pass
        if element.text is not None and element.text !=  '':
            params["NodeInnerText"] = element.text
        for a in element.attrib.keys():
            params["Attributes"].append(XmlAttributeAsDict(Name = a, Value = element.attrib[a]))
        newXmlNodeAsDict = cls(**params)
        for c in element.getchildren():
            newXmlNodeAsDict.append_child_node([XmlNodeAsDict.convert_element_to_dict(c, namespace_mode = namespace_mode, parent_namespace = element.nsmap, is_root = False)])
        return newXmlNodeAsDict
    @classmethod
    def from_xml_string(cls, xml_string: str, namespace_mode: str) -> XmlNodeAsDict:
        """Convert an XML string into an XmlNodeAsDict instance"""
        xml = etree.XML(xml_string)
        return XmlNodeAsDict.convert_element_to_dict(element = xml, namespace_mode = namespace_mode)
    @classmethod
    def from_dict(cls, data):
        """Convert an existing dict to an XmlNodeAsDict instance.
        Useful if importing a dict which has been saved to a file as
        json
        """
        instance = cls(data)
        if 'ChildNodes' in instance and isinstance(instance('ChildNodes', list)):
            instance['ChildNodes'] = [
                cls.from_dict(child) if isinstance(child, dict) else child for child in instance['ChildNodes']
            ]
        return instance
    @classmethod
    def from_json(cls, json_string):
        """Convert an XmlNodeAsDict object which has been stored as
        JSON back to an XmlNodeAsDict instance
        """
        data = json.loads(json_string)
        return cls.from_dict(data)
    def append_child_node(self, ChildNodes: list[XmlNodeAsDict]):
        """Append a list of XmlNodeAsDict instances to the ChildNodes
        of the instance on which this method is called
        """
        for n in ChildNodes:
            self['ChildNodes'].append(n)
    def set_node_inner_text(self, NodeInnerText: str):
        """Overwrite the existing NodeInnerText with the supplied
        string
        """
        self['NodeInnerText'] = NodeInnerText
    def has_children(self):
        """Return True if the XmlNodeAsDict instance's ChildNodes
        contains one or more XmlNodeAsDict instances
        """
        if len(self.get('ChildNodes', [])) == 0:
            return False
        else:
            return True
    def convert_to_xml(self) -> etree.Element:
        """Convert the current instance to an etree.Element object"""
        params = {}
        if isinstance(self.get('nsmap', None), dict):
            default_ns = self['nsmap'].get(None) if self['nsmap'] else None
            prefixed_ns = {k: v for k, v in self['nsmap'].items() if k is not None} if self['nsmap'] else {}
            params['nsmap'] = prefixed_ns if prefixed_ns else None
        for a in self.get('Attributes', []):
            params[a['Name']] = a['Value']
        tag = f"{{{default_ns}}}{self['NodeName']}" if default_ns else self['NodeName']
        params["_tag"] = tag
        node = etree.Element(**params)
        if self.get('NodeInnerText', '') > '':
            node.text = self.get('NodeInnerText')
        for c in self.get('ChildNodes', []):
            if (c is None or isinstance(c, str)):
                print(f"This will probably break. c: {c}")
                print(f"#####################")
                print(f"JSON:\n\t{json.dumps(self)}")
                print(f"#####################")
                pass
            child = c.convert_to_xml()
            node.append(child)
        return node
    def to_xml_string(self, xml_declaration:bool = None, encoding: str = 'utf-16', pretty_print:bool = True) -> str:
        """Convert the current instance to a raw xml string"""
        xml = self.convert_to_xml()
        include_xml_declaration = xml_declaration if xml_declaration is not None else self.get('xml_declaration', False)
        xml_string = etree.tostring(xml, pretty_print = pretty_print, xml_declaration = include_xml_declaration, encoding = encoding).decode(encoding)
        return xml_string
    def get_attribute_value(self, attribute_name: str) -> str:
        """Return the Value property for the XmlAttributeAsDict
        instance attached to this instance for the given attribute
        name
        """
        if (attribute_name, '') == '':
            raise ValueError("Must specify an attribute name to retrieve.")
        result = next((x.get('Value', None) for x in self.get('Attributes', []) if x.get('Name', '') == attribute_name), None)
        return result
    @property
    def LogicalName(self):
        """Return the LogicalName attribute value for this instance"""
        return self.get_attribute_value(attribute_name = 'LogicalName')
    @property
    def ResourceId(self):
        """Return the ResourceId attribute value for this instance"""
        return self.get_attribute_value(attribute_name = 'ResourceId')
    @classmethod
    def from_xml_string_with_tracking(cls, xml_string: str):
        """Parse XML and track explicit namespace declarations"""
        explicit_ns_map = {}
        element_stack = []
        context = etree.iterparse(
            BytesIO(xml_string.encode('UTF-8')), 
            events = ('start', 'start-ns', 'end'), 
            remove_blank_text = False
        )
        pending_ns = {}
        for event, data in context:
            if event == 'start-ns':
                prefix, uri = data
                pending_ns[prefix] = uri
            elif event == 'start':
                element = data
                if pending_ns:
                    explicit_ns_map[id(element)] = dict(pending_ns)
                    pending_ns.clear()
                element_stack.append(element)
        root = context.root
        return cls._convert_element_with_tracking(root, explicit_ns_map)
    @classmethod
    def _convert_element_with_tracking(cls, element:etree.Element, explicit_ns_map:dict):
        """Convert element, preserving explicit namespace
        declarations
        """
        element_id = id(element)
        params = {
            "NodeName": etree.QName(element).localname, 
            "Attributes": []
        }
        if element_id in explicit_ns_map:
            params["Attributes"].append(
                XmlAttributeAsDict(Name = 'xmlns', Value = explicit_ns_map[element_id][''])
                )
        else:
            pass
        if element.text and element.text.strip():
            params["NodeInnerText"] = element.text
        for attr_name in list(element.attrib.keys()):
            if attr_name.startswith('{http://www.w3.org/2000/xmlns/}'):
                continue
            attr_value = element.attrib[attr_name]
            params["Attributes"].append(XmlAttributeAsDict(
                    Name = etree.QName(attr_name).localname,
                    Value = attr_value
                )
            )
        new_node = cls(**params)
        for child in element:
            child_node = cls._convert_element_with_tracking(child, explicit_ns_map)
            new_node.append_child_node([child_node])
        return new_node
    def find_children_by_name(self, node_name: str) -> list:
        """Return direct children of this XmlNodeAsDict instance where
        the tag/node name matches the given string
        """
        return [child for child in self.get('ChildNodes', []) if child.get('NodeName') == node_name]

class McmApiBase(Processor):
    """Common functions used by multiple McmApi processors.
    McmApiProcessors was modeled on grahampugh's JamfUploaderProcessors
    library (https://github.com/autopkg/grahampugh-recipes/)
    """

    # Global version
    __version__ = "2025.12.04.0"

    def get_int32_from_uuid(uuid:uuid.UUID):
        """Deterministically create an int from a given uuid"""
        uuid_hash = hash(uuid)
        uuid_int = abs(c_int32(uuid_hash).value)
        return uuid_int

    def get_mcm_scope_id(self) -> str:
        """Retrieve the MCM scope ID from the site server."""
        if self.env.get("mcm_scope_id", None) is not None:
            self.output("Using existing or already retrieved scope id.", 2)
            return self.env.get("mcm_scope_id")
        
        try:
            self.output(f"Getting scope id from {self.fqdn}", 2)
            url = f"https://{self.fqdn}/AdminService/wmi/SMS_Identification.GetSiteID"
            response = requests.request(
                method = 'GET', 
                url = url, 
                auth = self.get_mcm_auth(),
                headers = self.headers, 
                timeout = (2, 5), 
                verify = self.get_ssl_verify_param()
            )
            response.raise_for_status()
            json_response = response.json()
            site_id = json_response.get('SiteID')
            if not site_id:
                raise ProcessorError("No SiteID returned from MCM server")
            self.output(f"Received response {site_id}", 3)
            scope_id = self.convert_site_id_to_scope_id(site_id)
            self.output(f"Retrieved scope ID: {scope_id}", 2)
            self.env["mcm_scope_id"] = scope_id
            return scope_id
            
        except requests.exceptions.HTTPError as e:
            raise ProcessorError(f"Failed to connect to MCM server: {e}")
        except Exception as e:
            raise ProcessorError(f"Failed to retrieve scope ID: {e}")

    def find_application_by_name(self, application_name: str) -> dict:
        """Connect to MCM, search for an SMS_Application with a
        given name, and return its details
        """
        self.output(f"Attempting to get application ({application_name}) from {self.fqdn}", 2)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_Application"
        body = {"$filter": f"LocalizedDisplayName eq '{application_name}' and IsLatest eq true", '$select':"CI_ID"}
        appSearchResponse = requests.request(
            method = 'GET', 
            url = url, 
            auth = self.get_mcm_auth(), 
            headers = self.headers, 
            verify = self.get_ssl_verify_param(), 
            params = body
        )
        self.output(f"Done searching for application. {type(appSearchResponse).__name__} type object returned.", 3)
        searchValue = appSearchResponse.json()["value"]
        self.output(f"{searchValue.__len__()} Application objects returned from {self.fqdn}", 3)
        if searchValue.__len__() > 1:
            raise ProcessorError("Application_name must be unique and return one or less results")
        elif searchValue.__len__() == 0:
            self.output(f"{application_name} not found in {self.fqdn}", 2)
            return None
        self.output(f"Getting SDMPackageXML for {application_name} from {self.fqdn}", 3)
        appUrl = f"https://{self.fqdn}/AdminService/wmi/SMS_Application({searchValue[0].get('CI_ID')})"
        app = requests.request(
            method = 'GET', 
            url = appUrl, 
            auth = self.get_mcm_auth(), 
            headers = self.headers, 
            verify = self.get_ssl_verify_param()
        )
        self.output("Done getting SDMPackageXML", 3)
        appJson = app.json()
        appValue = appJson['value'] or []
        if len(appValue) == 1 and (sdm_package_xml :=  appValue[0].get('SDMPackageXML', '')) !=  '':
            self.output(f"SDMPackageXML length: {len(sdm_package_xml)}")
            return_object = {
                "SDMPackageXML": sdm_package_xml.replace('<?xml version="1.0" encoding="utf-16"?>', '', 1), 
                "ci_id": appValue[0].get("CI_ID")
            }
        else:
            return_object = None
        return return_object

    def get_application_by_name(self):
        self.output(
            f"Attempting to get application ({self.application_name}) "
            f"from {self.fqdn}",
            2
            )
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_Application"
        body = {
            "$filter": (
                f"LocalizedDisplayName eq '{self.application_name}' "
                "and IsLatest eq true"
                ),
            '$select': "CI_ID"}
        self.output(f"Body: {body}", 3)
        app_search_response = requests.request(
            method = 'GET',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
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
            self.response_value = {}
            return

        app_search_value = app_search_response.json()['value'][0]
        app_ci_id = app_search_value.get('CI_ID')
        self.output(f"Getting details for application with CI_ID {app_ci_id}", 3)
        app_detail_url = (
                f"https://{self.fqdn}/AdminService/wmi/"
                f"SMS_Application({app_ci_id})"
            )
        response = requests.request(
            method = 'GET',
            url = app_detail_url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
            timeout = (2,5)
        )
        if response.status_code == 200 and len(app_search_response.json()['value']) == 1:
            self.response_value = response.json()['value'][0]
        else:
            self.output(f"Status code [{response.status_code}]\tReason ({response.reason})")
            raise ProcessorError(response.reason)

    def find_task_sequence_by_name(self, task_sequence_name: str) -> dict:
        """Connect to MCM, search for task sequence with a given
        name, and return its details"""
        self.output(f"Attempting to get task sequence ({task_sequence_name}) from {self.fqdn}", 2)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_TaskSequencePackage"
        body = {"$filter": f"Name eq '{task_sequence_name}'", '$select':"Name, PackageId"}
        searchResponse = requests.request(
            method = 'GET', 
            url = url, 
            auth = self.get_mcm_auth(), 
            headers = self.headers, 
            verify = self.get_ssl_verify_param(), 
            params = body
        )
        self.output(f"Done searching for task sequence. {type(searchResponse).__name__} type object returned.", 3)
        searchValue = searchResponse.json()["value"]
        self.output(f"{searchValue.__len__()} Application objects returned from {self.fqdn}", 3)
        if searchValue.__len__() > 1:
            raise IndexError("task_sequence_name must be unique and return one or less results")
        elif searchValue.__len__() == 0:
            self.output(f"{task_sequence_name} not found in {self.fqdn}")
            return None
        return searchResponse.json()["value"][0]

    def new_resource_id_attribute(self) -> XmlAttributeAsDict:
        """Utility function for quicker creation of a ResourceId
        XmlAttributeAsDict object
        """
        attr = XmlAttributeAsDict(Name = "ResourceId", Value = f"Res_{McmIdentifier().resource_id}")
        return attr
    
    def get_category(self,category_name: str, category_type_name: str=''):
        filter_clauses = [f"LocalizedCategoryInstanceName eq '{category_name}'"]
        if category_type_name != '':
            filter_clauses.append(f"CategoryTypeName eq '{category_type_name}'")
        search_filter = f"$filter = {' and '.join(filter_clauses)}"
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_CategoryInstance?{search_filter}"
        self.output(f"Getting categories: {url}", 3)
        response = requests.request(
            method = 'GET', 
            url = url, 
            auth = self.get_mcm_auth(),
            headers = self.headers, 
            verify = self.get_ssl_verify_param()
        )
        if response.status_code == 200 and len(response.json()['value']) == 1:
            self.response_value = response.json()["value"][0]
        elif response.status_code == 200 and len(response.json()['value']) > 1:
            raise ProcessorError("Retrieved more than one category")
        elif response.status_code != 200:
            raise ProcessorError(response.reason)
        else:
            self.response_value = {}
        return self.response_value
    
    def get_mcm_category_memberships(self,object_key : str) -> list:
        """Connect to MCM and retrieve the current category memberships
        for a given object
        """
        self.output("Retrieving possible security scopes", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_CategoryInstanceMembership?$filter=ObjectKey eq '{object_key}'"
        sms_category_instances = requests.request(
            method='GET',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param(),
        )
        sms_category_instances.raise_for_status()

        memberships = [{
            "CategoryInstanceID": instance['CategoryInstanceID'],
            "ObjectKey": instance['ObjectKey'],
            "ObjectTypeID": instance['ObjectTypeID'],
            "UniqueID": instance['@odata.etag'],
        } for instance in sms_category_instances.json()['value']]
        
        return memberships

    def get_mcm_object_type_id(self,object_key:str) -> int:
        """Return the unique id that MCM assigns to an object id by
        querying the SMS_SecuredCategoryMembership for the object
        """
        self.output(f"Getting ObjectTypeID for {object_key}")
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_SecuredCategoryMembership?$filter=startsWith(ObjectKey,'{self.object_key}') eq true"
        sms_secured_category_membership = requests.request(
            method = 'GET',
            url = url,
            auth = self.get_mcm_auth(),
            headers = self.headers,
            verify = self.get_ssl_verify_param()
        )
        if len(sms_secured_category_membership.json()['value']) >= 1:
            return sms_secured_category_membership.json()['value'][0]['ObjectTypeID']
        else:
            raise ProcessorError('Could not locate the ObjectTypeID for the given ObjectKey')
    @staticmethod
    def get_nsmap(namespace_name: str, include_xsi:bool = False) -> dict:
        """Create a namespace map object for use in etree.Element
        objects
        """
        class McmXmlNamespace(Enum):
            AppMgmtDigest = 1
            Rule = 2
            Setting = 3
            DesiredConfiguration = 4
            Default = 5
        namespace = McmXmlNamespace[namespace_name].name
        if namespace == 'AppMgmtDigest':
            ns = "http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"
            nsmap = {"AppMgmtDigest": ns}
        elif namespace == 'Rule':
            ns = "http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/06/14/Rules"
            nsmap = {None: ns}
        elif namespace == 'Setting':
            ns = "http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/07/10/DesiredConfiguration"
            nsmap = {None: ns}
        elif namespace == 'DesiredConfiguration':
            ns = "http://schemas.microsoft.com/SystemsCenterConfigurationManager/2009/07/10/DesiredConfiguration"
            nsmap = {None: ns}
        elif namespace == 'Default':
            ns = None
            nsmap = {}
        elif namespace == 'Other':
            ns = 'http://other.name.space'
            nsmap = {None: ns}
        else:
            raise ProcessorError('Unhandled Namespace.')
        output:dict = {
            'ns': ns, 
            'nsmap': nsmap
        }
        if include_xsi == True:
            output['nsmap']['xsi'] = 'http://www.w3.org/2001/XMLSchema-instance'
        return output
    @staticmethod
    def uses_revisions(object_class: str, dynamic: bool = False) -> bool:
        """Return True if the object uses revisions. This determines
        if the object type should be suffixed with 'Latest'
        """
        if dynamic == True:
            raise ProcessorError("Dynamic revision determination not supported at this time.")
        else:
            result = ['sms_application','sms_configurationitem'].__contains__(object_class.lower())
        return result
    @staticmethod
    def try_cast(type_name, value, default = None):
        """Cast the supplied value as the indicated type. If it cannot
        cast, return a default value
        """
        try:
            return type_name(value)
        except:
            return default
    @staticmethod
    def can_cast(type_name, value) -> bool:
        """Return True if the supplied value can cast as the supplied
        type name
        """
        return McmApiBase.try_cast(type_name, value) is not None

    def get_identifier_from_string(self, string: str):
        """Return the simple uuid/guid string from an MCM identifier
        in '[Object Type]_[Guid] format'
        """
        return string.split('_', 1)[1]

    def get_relative_windows_path(self, pathname: str, unix_root: str):
        """Convert a unix path to a relative path compliant with
        Windows operating systems. Calculate the path relative to the
        supplied root unix path
        """
        return pathname.replace(unix_root, '', 1).replace('/', '\\')

    def convert_site_id_to_scope_id(self, site_id: str) -> str:
        """Convert a SiteID string to a scope id"""
        site_id_clean = site_id.replace('{', '').replace('}', '')
        return f"ScopeId_{site_id_clean}"
    
    def _teardown_kerberos_env(self,ccname : str):

        if self._krb5_config_backup != '':
            self.output(f'Reverting KRB5_CONFIG', 2)
            self.output(f'KRB5_CONFIG: {self._krb5_config_backup}', 3)
            os.environ['KRB5_CONFIG'] = self._krb5_config_backup
        else:
            self.output('Unsetting KRB5_CONFIG environment variable', 3)
            krb5_config_unset = subprocess.run(['unset','KRB5_CONFIG'], shell=True, capture_output=True,text=True,check=True)
            self.output(f'KRB5_CONFIG unset return code: {krb5_config_unset.returncode}', 3)
        
        if self._krb5ccname_backup != '':
            self.output(f'Reverting KRB5CCNAME', 2)
            self.output(f'KRB5CCNAME: {self._krb5ccname_backup}', 3)
            os.environ['KRB5CCNAME'] = self._krb5ccname_backup
        else:
            self.output('Unsetting KRB5CCNAME environment variable', 3)
            krb5ccname_unset = subprocess.run(['unset','KRB5CCNAME'], shell=True, capture_output=True,text=True,check=True)
            self.output(f'KRB5CCNAME unset return code: {krb5ccname_unset.returncode}', 3)
        
        if True == self.env.get('keep_env', False):
            self.output('--keep-env was used')
            self.output(f'Temp KRB5_CONFIG: {self._krb5_config}')
            self.output(f'Temp KRB5CCNAME: {self._krb5ccache}')
            return

        self.output('--keep-env was not used. Destroying temporary files', 3)
        self.output(f"Calling kdestroy", 2)
        self.output(f"KRB5CCNAME: {ccname}", 3)
        teardown_result = subprocess.run(['kdestroy','-c',f'{ccname}'],capture_output=True,check=True,text=True)
        self.output(f"kdestroy return code: {teardown_result.returncode}", 2)
        
        if os.path.exists(self._krb5_config):
            self.output("Deleting temporary KRB5_CONFIG", 3)
            _ = os.unlink(self._krb5_config)

        if os.path.exists(self._krb5ccache):
            self.output('Deleting temporary credential cache', 3)
            _ = os.unlink(self._krb5ccache)
    def _build_krb_config(self,realm: str, domain: str, auto_resolve: bool, kdcs: list[str], admin_servers: list[str]) -> str:
        lines = []
        lines.append('[libdefaults]')
        lines.append(f'\tdefault_realm = {realm}')
        lines.append('\tforwardable = true')
        lines.append('\trdns = false')
        if auto_resolve:
            lines.append('\tdns_lookup_kdc = true')
            lines.append('\tdns_lookup_realm = true')
        lines.append('')
        if not auto_resolve:
            lines.append('[realms]')
            lines.append(f'\t{realm}' + ' = {')
            for kdc in kdcs:
                lines.append(f'\t\tkdc = {kdc}')
            if admin_servers:
                for host in admin_servers:
                    lines.append(f'\t\tadmin_server = {host}')
            elif kdcs:
                lines.append(f'\t\tadmin_server = {kdcs[0].split(":")[0]}')
            lines.append('\t}')
            lines.append('')
        lines.append('[domain_realm]')
        lines.append(f'\t.{domain.lower()} = {realm}')
        lines.append(f'\t{domain.lower()} = {realm}')
        lines.append('')
        return '\n'.join(lines)

    def _resolve_kpasswd_hosts(self,realm: str) -> list[str]:
        """SRV lookup for _kpasswd._tcp.<realm>."""
        try:
            answers = dns.resolver.resolve(f'_kpasswd._tcp.{realm.lower()}', 'SRV')
            sorted_records = sorted(answers, key=lambda r: (r.priority, r.weight))
            return [r.target.to_text().rstrip('.') for r in sorted_records]
        except dns.exception.DNSException:
            return []
    
    def _resolve_kdc_hosts(self,realm: str) -> list[str]:
        """SRV lookup for _kerberos._tcp.<realm>, returns list of 'host:port' sorted by priority."""
        try:
            answers = dns.resolver.resolve(f'_kerberos._tcp.{realm.lower()}', 'SRV')
            sorted_records = sorted(answers, key=lambda r: (r.priority, r.weight))
            return [f'{r.target.to_text().rstrip(".")}:{r.port}' for r in sorted_records]
        except dns.exception.DNSException:
            return []

    def _resolve_realm(self,domain: str) -> str:
        """Attempt DNS TXT lookup for _kerberos.<domain>, fall back to uppercased domain."""
        try:
            answers = dns.resolver.resolve(f'_kerberos.{domain}', 'TXT')
            for rdata in answers:
                for txt in rdata.strings:
                    return txt.decode()
        except Exception as e:
            pass
        return domain.upper()

    def _normalize_username(self,username : str, realm : str) -> str:
        """Normalize the realm in the provided user name."""
        if not username.__contains__('@') and not username.__contains__('\\'):
            self.output("Username contains neither @ nor \\. No logical place to infer a realm", 3)
            return username
        if len(username.split('@')) == 2:
            self.output("Username in user@domain format.", 3)
            user_name = username.split('@')[0].strip()
            user_domain = username.split('@')[-1].strip()
        elif len(username.split('\\')) == 2:
            self.output("Username in user@domain format.", 3)
            user_name = username.split('\\')[0].strip()
            user_domain = username.split('\\')[-1].strip()
        else:
            raise ValueError("Unhandled username format.")
        
        if user_domain.upper() != realm.upper():
            self.output(f"user_domain: {user_domain}\trealm: {realm}", 3)
            raise ValueError("User domain and Realm do not match.")
        
        normalized = f"{user_name}@{realm}"
        return normalized

    def _initialize_temp_kerberos_env(self):

        pwd_file = tempfile.NamedTemporaryFile(mode='w',suffix='.pwd',delete=False)
        pwd_file.write(self.password)
        pwd_file.close()
        self.pwd_file = pwd_file.name
        atexit.register(os.unlink,pwd_file.name)

        ccache = tempfile.mkstemp(suffix='.ccache')
        ccname = f'FILE:{ccache[1]}'
        self._krb5ccache = ccache[1]

        self._krb5_config_backup = os.environ.get('KRB5_CONFIG','')
        self._krb5ccname_backup = os.environ.get('KRB5CCNAME', '')

        self.output("Generating kerberos config.", 3)
        server_fqdn = self.env.get('mcm_site_server_fqdn')
        krb_config_type = self.env.get('krb_config_type')
        
        parts = server_fqdn.lower().split('.')
        domain = '.'.join(parts[1:]) if len(parts) > 2 else server_fqdn.lower()
        realm = self._resolve_realm(domain)

        krb_config_params = {
            'realm': realm,
            'domain': domain,
        }
        if krb_config_type == 'query':
            self.output('Realm information will be determined using dns queries')
            krb_config_params['auto_resolve'] = False
            krb_config_params['kdcs'] = self._resolve_kdc_hosts(realm)
            krb_config_params['admin_servers'] = self._resolve_kpasswd_hosts(realm)
        else:
            self.output('Realm information will be auto resolved', 3)
            krb_config_params['auto_resolve'] = True
            krb_config_params['kdcs'] = []
            krb_config_params['admin_servers'] = []
        
        if not krb_config_params['auto_resolve'] and not krb_config_params['kdcs']:
            raise RuntimeError(f"SRV lookup for _kerberos._tcp.{realm.lower()} returned no results and auto_resolve is False.")
        krb5_config = self._build_krb_config(**krb_config_params)
        self.output('Writing out KRB5 config', 3)
        conf = tempfile.NamedTemporaryFile(mode='w',suffix='.krb5.config',delete=False)
        conf.write(krb5_config)
        conf.close()
        self.output("Setting os environment variables", 3)
        self._krb5_config = conf.name
        os.environ['KRB5CCNAME'] = ccname
        os.environ['KRB5_CONFIG'] = self._krb5_config
        
        atexit.register(self._teardown_kerberos_env,ccname)

        self.output(f'KRB5_CONFIG: {self._krb5_config}', 3)
        self.mcm_user = self._normalize_username(username=self.env.get('mcm_user',self.keychain_username), realm=realm)
        self.output(f'Username: {self.mcm_user}', 3)
        self.output(f'Calling kinit', 2)
        kinit_result = subprocess.run(['kinit',f'--password-file={self.pwd_file}', '-c',ccname, self.mcm_user], capture_output=True,text=True,check=True)
        self.output(f'kinit return code: [{kinit_result.returncode}] {kinit_result.stderr}')
    
    def initialize_auth(self):
        #self.initialize_ntlm_auth()
        self.output("Checking supplied parameters", 3)
        self.keychain_service_name = self.env.get("keychain_password_service")
        self.keychain_username = self.env.get("keychain_password_username", None) or self.env.get("MCMAPI_USERNAME", '')
        self.fqdn = self.env.get("mcm_site_server_fqdn", '')
        if (self.fqdn == None or self.fqdn == ''):
            raise ValueError("mcm_site_server_fqdn cannot be blank")
        if (self.keychain_service_name == None or self.keychain_service_name == ''):
            raise ValueError("keychain_password_service cannot be blank")
        if (self.keychain_username == None or self.keychain_username == ''):
            raise ValueError("keychain_password_username cannot be blank")
        self.password = keyring.get_password(self.keychain_service_name, self.keychain_username)
        self.initialize_gss_auth()
    
    def get_mcm_auth(self):
        #self.get_mcm_ntlm_auth()
        return self.get_mcm_gss_auth()
    
    def initialize_gss_auth(self):
        if (self.fqdn == None or self.fqdn == ''):
            raise ValueError("mcmserver cannot be blank")
        self.auth = None
        _ = self._initialize_temp_kerberos_env()
        _ = self.get_mcm_gss_auth()
    
    def get_mcm_gss_auth(self):
        """Construct a HTTPKerberosAuth auth object from the retrieved
        details
        """
        
        if self.__getattribute__('auth') is not None and \
            isinstance(self.auth, HTTPKerberosAuth):
            return self.auth
        self.output("GSSAPI Auth object does not currently exist. It will be created", 2)
        try:
            self.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
            return self.auth
        except Exception as e:
            raise LookupError(f"Failed to retrieve credentials: {e}")
    
    def cleanup_gssapi(self):
        if hasattr(self, 'auth'):
            del self.auth
        import gc
        gc.collect()
    
    def cleanup(self):
        self.cleanup_gssapi()
    
    def initialize_headers(self):
        self.output("Generating headers.", 3)
        self.headers = {
            "Accept": "application/json", 
            "Content-Type": "application/json"
        }
    
    def try_copy_smb_file_to_local(
            self,
            smb_source_path : str,
            local_destination_path : str) -> bool:
        """Attempt to mount an smb path and copy the indicated file"""
        try:
            _ = os.makedirs(os.path.dirname(local_destination_path), exist_ok=True)
            self.output(f"Path ({os.path.dirname(local_destination_path)}) exists: {os.path.exists(os.path.dirname(local_destination_path))}", 3)
            smbclient.ClientConfig(username=self.mcm_user,password=self.password)
            src = smb_source_path.replace("/",r'\\')
            self.output(f"Source file smb path: {src}", 3)
            self.output(f"Local destination path: {local_destination_path}", 3)
            with smbclient.open_file(src,mode="rb") as remote, open(local_destination_path, mode="wb") as local:
                shutil.copyfileobj(remote,local)
            return True
        except Exception as e:
            self.output(e, 2)
            return False
    def initialize_ssl_verification(self):
        _ssl_verify = self.env.get('mcm_ssl_verification')
        if isinstance(_ssl_verify, bool) or ['false','true'].__contains__(str(_ssl_verify).lower()):
            self.ssl_verify = str(_ssl_verify).lower == 'true'
        elif isinstance(_ssl_verify, str):
            if _ssl_verify.startswith('\\\\'):
                _ssl_verify = tempfile.mkstemp(suffix='.pem',prefix='ssl_')[1]
                _ssl_verify = os.path.join(os.path.dirname(__file__),"ssl.pem")
                atexit.register(unlink,_ssl_verify)
                self.output(f"Copying remote cert .pem file to {_ssl_verify}", 4)
                ssl_copy_success = self.try_copy_smb_file_to_local(smb_source_path=self.env.get('mcm_ssl_verification'),local_destination_path=_ssl_verify)
                self.output(f"SSL Copy succeeded: {ssl_copy_success}", 4)
            else:
                self.output("SSL path appears to be local")
            self.ssl_verify = str(Path(_ssl_verify).resolve())
        self.output(f"SSL Verify: {type(self.ssl_verify).__name__}({self.ssl_verify})", 4)
    def get_ssl_verify_param(self):
        """Get the value of the 'verify' parameter for http requests
        """
        if self.__getattribute__('ssl_verify') is not None and (
            isinstance(self.ssl_verify, bool) or isinstance(self.ssl_verify, str)
            ):
            self.output("ssl_verify object exists. Returning it", 3)
            return self.ssl_verify
        self.output("NTLM Auth object does not currently exist. It will be created", 3)
        try:
            self.initialize_ssl_verification()
            return self.ssl_verify
        except Exception as e:
            raise ProcessorError(f"Failed to retrieve ssl verification: {e}")

    def initialize_export_properties(self,input_variable_name: str):
        self.export_properties = self.env.get(input_variable_name)

    def strip_namespaces(self,element):
        """Remove all namespaces from an XML element for easier XPath
        query support
        """
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element

    def set_export_properties(self):
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

if __name__ == "__main__":
    PROCESSOR = McmApiBase()
    PROCESSOR.execute_shell()
