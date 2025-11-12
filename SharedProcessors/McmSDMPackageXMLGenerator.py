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
import keyring
import requests
import uuid
import json
import string
import random
import base64

from ctypes import c_int32
from datetime import datetime
from enum import Enum,auto
from os import path,walk
from requests_ntlm import HttpNtlmAuth
from PIL import Image
from io import BytesIO
from lxml import etree
from copy import deepcopy
from autopkglib import Processor, ProcessorError, get_autopkg_version

# Helper functions
def try_cast(type_name,value,default=None):
    try:
        return type_name(value)
    except:
        return default

def can_cast(type_name,value) -> bool:
    return try_cast(type_name,value) is not None

def get_int32_from_uuid(uuid:uuid.UUID):
    uuid_hash = hash(uuid)
    uuid_int = abs(c_int32(uuid_hash).value)
    return uuid_int

def get_identifier_from_string(string:str):
    return string.split('_',1)[1]

def get_relative_windows_path(pathname:str,unix_root:str):
    return pathname.replace(unix_root,'',1).replace('/','\\')

def convert_site_id_to_scope_id(site_id: str) -> str:
    site_id_clean = site_id.replace('{', '').replace('}', '')
    return f"ScopeId_{site_id_clean}"

def get_nsmap(namespace_name:str,include_xsi:bool=False)->dict:
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

# Enums
class ProgramVisibility(Enum):
    Normal    = "Normal"
    Minimized = "Minimized"
    Maximized = "Maximized"
    Hidden    = "Hidden"

class RebootBehavior(Enum):
    BasedOnExitCode = "BasedOnExitCode"
    NoAction        = "NoAction"
    ProgramReboot   = "ProgramReboot"
    ForceReboot     = "ForceReboot"

class RequirementRuleDataType(Enum):
    Base64                       = "Base64"
    Boolean                      = "Boolean"
    BooleanArray                 = "BooleanArray"
    CIMDateTime                  = "CIMDateTime"
    CIMDateTimeArray             = "CIMDateTimeArray"
    Complex                      = "Complex"
    DateTime                     = "DateTime"
    DateTimeArray                = "DateTimeArray"
    Double                       = "Double"
    DoubleArray                  = "DoubleArray"
    FileSystemAccessControl      = "FileSystemAccessControl"
    FileSystemAccessControlArray = "FileSystemAccessControlArray"
    FileSystemAttribute          = "FileSystemAttribute"
    FileSystemAttributeArray     = "FileSystemAttributeArray"
    Int64                        = "Int64"
    Int64Array                   = "Int64Array"
    Other                        = "Other"
    RegistryAccessControl        = "RegistryAccessControl"
    RegistryAccessControlArray   = "RegistryAccessControlArray"
    String                       = "String"
    StringArray                  = "StringArray"
    Version                      = "Version"
    VersionArray                 = "VersionArray"
    Xml                          = "Xml"

class ArgumentType(Enum):
    String = 'String'
    Boolean = 'Boolean'
    Int32 = 'Int32'
    Int32Array = 'Int32[]'

class RuleEvaluationMethod(Enum):
    Count = "Count"
    Value = "Value"

class DeploymentTechnology(Enum):
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
    Any = "Any"
    User = "User"
    System = "System"
BehaviorTypeToContext = {
    "InstallForSystem":"System",
    "InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser": "Any",
    "InstallForUser": "User"
}
class ActionProvider(Enum):
    Local = "Local"
    Script = "Script"
    TaskSequence = "TaskSequence"

class Operator(Enum):
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
    File = "File"
    Folder = "Folder"
    Registry = "Registry"
    RegistryKey = "RegistryKey"
    MSI = "MSI"

class SettingPropertyPath(Enum):
    RegistryKeyExists = "RegistryKeyExists"
    Size = "Size"
    ProductVersion = "ProductVersion"
    DateCreated = "DateCreated"
    DateModified = "DateModified"

class ContentHandlingMode(Enum):
    DoNothing = "DoNothing"
    Download = "Download"
    DownloadContentForStreaming = "DownloadContentForStreaming"

class DeploymentTypeFilterType(Enum):
    Equals = "Equal"
    StartsWith = "StartsWith"
    Contains = "Contains"

class ActionType(Enum):
    DetectAction = "DetectAction"
    InstallAction = "InstallAction"
    UninstallAction = "UninstallAction"
    RepairAction = "RepairAction"

class DetectionType(Enum):
    File                = "File"
    Folder              = "Folder"
    RegistryKey         = "RegistryKey"
    RegistryKeyValue    = "RegistryKeyValue"
    MSI                 = "MSI"
    Group               = "Group"
    CustomScript        = "CustomScript"

PropertyPathDataType = {
    "DateCreated": "DateTime",
    "DateModified": "DateTime",
    "ProductVersion": "Version",
    "Size": "Int64",
    "Version": "Version"
}

# Root
class McmIdentifier(dict):
    def __init__(self,guid:str=None,resource_id:int=None):
        if guid is None:
            guid = uuid.uuid4()
        else:
            guid = uuid.UUID(guid)
        self.guid = guid.__str__()
        if resource_id is None:
            self.resource_id = get_int32_from_uuid(guid)
        else:
            self.resource_id = resource_id
    def get_logical_name(self,object_type_name:str=None,object:any=None):
        if (object_type_name is None or object_type_name == ''):
            if object is None:
                raise ProcessorError('object_type_name or object must be supplied')
            object_type = type(object)
            object_type_name = object_type.__name__
        else:
            object_type_name = object_type_name
        return f"{object_type_name}_{self.guid}"
     
    def get_resource_id(self):
        return f"Res_{self.ResourceId.__str__()}"

class XmlAttributeAsDict(dict):
    def __init__(self,Name:str,Value:any):
        super().__init__({
            'Name': Name,
            'Value':  try_cast(str,Value,'')
        })

class XmlNodeAsDict(dict):
    pass

class XmlNodeAsDict(dict):
    instance_map = {}
    instance_map_by_external_id = {}
    def __init__(self,NodeName:str,Attributes:list[XmlAttributeAsDict]=[],ChildNodes:list[XmlNodeAsDict]=None,
                 NodeInnerText:str=None,nsmap:dict=None,xml_declaration:bool=False,external_reference_id:int=None,group_ids:list[int]=[]):
        super().__init__({})
        if (external_reference_id or 0) > 0:
            pass
        if NodeName == 'RegistryKey':
            pass
        self['NodeName'] = NodeName
        if Attributes is not None and len(Attributes) > 0:
            self['Attributes'] = Attributes
        if ChildNodes is not None and len(ChildNodes) > 0:
            self['ChildNodes'] = ChildNodes
        else:
            self['ChildNodes'] = []
        if NodeInnerText is not None and NodeInnerText > '':
            self['NodeInnerText'] = NodeInnerText
        self["xml_declaration"] = xml_declaration
        self["nsmap"] = nsmap if nsmap is not None else {}
        XmlNodeAsDict.instance_map[f"{id(self)}"] = self
        if external_reference_id is not None:
            XmlNodeAsDict.instance_map_by_external_id[f"{external_reference_id}"] = self
    @classmethod
    def convert_element_to_dict(cls,element:etree.Element,namespace_mode:str='PersistAsAttribute',parent_namespace:dict=None,is_root:bool=True)->XmlNodeAsDict:
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
        if namespace_mode == 'PersistAsAttribute' and parent_namespace is not None and element.nsmap != parent_namespace:
            params['Attributes'].append(XmlAttributeAsDict(Name='xmlns',Value=element.nsmap[None]))
        else:
            pass
        if element.text is not None and element.text != '':
            params["NodeInnerText"] = element.text
        for a in element.attrib.keys():
            params["Attributes"].append(XmlAttributeAsDict(Name=a,Value=element.attrib[a]))
        newXmlNodeAsDict = cls(**params)
        for c in element.getchildren():
            newXmlNodeAsDict.append_child_node([XmlNodeAsDict.convert_element_to_dict(c,namespace_mode=namespace_mode,parent_namespace=element.nsmap,is_root=False)])
        return newXmlNodeAsDict
    @classmethod
    def from_xml_string(cls,xml_string:str,namespace_mode:str)->XmlNodeAsDict:
        xml = etree.XML(xml_string)
        return XmlNodeAsDict.convert_element_to_dict(element=xml,namespace_mode=namespace_mode)
    @classmethod
    def from_dict(cls, data):
        instance = cls(data)
        if 'ChildNodes' in instance and isinstance(instance('ChildNodes',list)):
            instance['ChildNodes'] = [
                cls.from_dict(child) if isinstance(child, dict) else child for child in instance['ChildNodes']
            ]
        return instance
    @classmethod
    def from_json(cls, json_string):
        data = json.loads(json_string)
        return cls.from_dict(data)
    def append_child_node(self,ChildNodes:list[XmlNodeAsDict]):
        for n in ChildNodes:
            self['ChildNodes'].append(n)
    def set_node_inner_text(self,NodeInnerText:str):
        self['NodeInnerText'] = NodeInnerText
    def has_children(self):
        if len(self.get('ChildNodes',[])) == 0:
            return False
        else:
            return True
    def convert_to_xml(self)->etree.Element:
        params = {}
        if isinstance(self.get('nsmap',None), dict):
            default_ns = self['nsmap'].get(None) if self['nsmap'] else None
            prefixed_ns = {k: v for k, v in self['nsmap'].items() if k is not None} if self['nsmap'] else {}
            params['nsmap'] = prefixed_ns if prefixed_ns else None
        for a in self.get('Attributes',[]):
            params[a['Name']] = a['Value']
        tag = f"{{{default_ns}}}{self['NodeName']}" if default_ns else self['NodeName']
        params["_tag"] = tag
        node = etree.Element(**params)
        if self.get('NodeInnerText','') > '':
            node.text = self.get('NodeInnerText')
        for c in self.get('ChildNodes',[]):
            if (c is None or isinstance(c,str)):
                print(f"This will probably break. c: {c}")
                print(f"#####################")
                print(f"JSON:\n\t{json.dumps(self)}")
                print(f"#####################")
                pass
            child = c.convert_to_xml()
            node.append(child)
        return node
    def to_xml_string(self,xml_declaration:bool=None,encoding:str='utf-16',pretty_print:bool=True)->str:
        xml = self.convert_to_xml()
        include_xml_declaration = xml_declaration if xml_declaration is not None else self.get('xml_declaration',False)
        xml_string = etree.tostring(xml,pretty_print=pretty_print,xml_declaration=include_xml_declaration,encoding=encoding).decode(encoding)
        return xml_string
    def get_attribute_value(self,attribute_name:str)->str:
        if (attribute_name,'') == '':
            raise ValueError("Must specify an attribute name to retrieve.")
        result = next((x.get('Value',None) for x in self.get('Attributes',[]) if x.get('Name','') == attribute_name), None)
        return result
    @property
    def LogicalName(self):
        return self.get_attribute_value(attribute_name='LogicalName')
    @property
    def ResourceId(self):
        return self.get_attribute_value(attribute_name='ResourceId')
    @classmethod
    def from_xml_string_with_tracking(cls,xml_string:str):
        """Parse XML and track explicit namespace declarations"""
        explicit_ns_map = {}
        element_stack = []
        context = etree.iterparse(
            BytesIO(xml_string.encode('UTF-8')),
            events=('start', 'start-ns', 'end'),
            remove_blank_text=False
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
    def _convert_element_with_tracking(cls,element:etree.Element,explicit_ns_map:dict):
        """Convert element, preserving explicit namespace declarations"""
        element_id = id(element)
        params = {
            "NodeName": etree.QName(element).localname,
            "Attributes": []
        }
        if element_id in explicit_ns_map:
            params["Attributes"].append(XmlAttributeAsDict(Name='xmlns',Value=explicit_ns_map[element_id]['']))
        else:
            pass
        if element.text and element.text.strip():
            params["NodeInnerText"] = element.text
        for attr_name in element.attrib.keys():
            if attr_name.startswith('{http://www.w3.org/2000/xmlns/}'):
                continue
            params["Attributes"].append(XmlAttributeAsDict(
                    Name=etree.QName(attr_name).localname,
                    Value=element.attrib[attr_name]
                )
            )
        new_node = cls(**params)
        for child in element:
            child_node = cls._convert_element_with_tracking(child,explicit_ns_map)
            new_node.append_child_node([child_node])
        return new_node
    def find_children_by_name(self,node_name:str) -> list:
        return [child for child in self.get('ChildNodes',[]) if child.get('NodeName') == node_name]

def new_resource_id_attribute() -> XmlAttributeAsDict:
    attr = XmlAttributeAsDict(Name="ResourceId",Value=f"Res_{McmIdentifier().resource_id}")
    return attr

# Content
def new_content_file(pathname:str,unix_root:str) -> XmlNodeAsDict:
    relative_windows_path = get_relative_windows_path(pathname,unix_root)
    size = path.getsize(pathname)
    return XmlNodeAsDict(NodeName="File",Attributes=[XmlAttributeAsDict(Name='Name',Value=relative_windows_path),
                                                      XmlAttributeAsDict(Name='Size',Value=size)])

def new_content_importer(content_location:str,content_location_local:str,content_id:str=None,enable_peer_cache:bool=True,
        fast_network_action:ContentHandlingMode=ContentHandlingMode['Download'],
        slow_network_action:ContentHandlingMode=ContentHandlingMode['DoNothing']) -> XmlNodeAsDict:
    if content_id is None or content_id == '':
            content_id = f'Content_{uuid.uuid4().__str__()}'
    importer = XmlNodeAsDict(NodeName='Content',Attributes=[XmlAttributeAsDict('ContentId',(content_id)),XmlAttributeAsDict(Name='Version',Value='1')],external_reference_id=id(content_location_local))
    content_files = []
    if content_location_local[-1] != '/':
        content_location_local = f"{content_location_local}/"
    for root, dirs, files in walk(content_location_local):
        for filename in files:
            fullName = path.join(root, filename)
            content_files.append(new_content_file(pathname=fullName,unix_root=content_location_local))
    importer.append_child_node(content_files)
    location = XmlNodeAsDict(NodeName='Location')
    if content_location is not None and len(content_location) > 0 and content_location[-1] != "\\":
        content_location = f"{content_location}\\"
        location.set_node_inner_text(content_location)
        importer.append_child_node([location])
        peer_cache = XmlNodeAsDict(NodeName='PeerCache')
        peer_cache.set_node_inner_text(f"{enable_peer_cache}".lower())
        importer.append_child_node([peer_cache])
        on_fast_network = XmlNodeAsDict(NodeName='OnFastNetwork')
        on_fast_network.set_node_inner_text(f"{fast_network_action.name}")
        importer.append_child_node([on_fast_network])
        on_slow_network = XmlNodeAsDict(NodeName='OnSlowNetwork')
        on_slow_network.set_node_inner_text(f"{slow_network_action.name}")
        importer.append_child_node([on_slow_network])
    return importer

def get_content_reference(content_importer:XmlNodeAsDict) -> XmlNodeAsDict:
    attributes = [
        XmlAttributeAsDict(Name='ContentId',Value=content_importer.get_attribute_value(attribute_name='ContentId')),
        XmlAttributeAsDict(Name='Version',Value=content_importer.get_attribute_value(attribute_name='Version'))
    ]
    reference = XmlNodeAsDict(
        NodeName='Contents',ChildNodes=[
            XmlNodeAsDict(NodeName='Content',Attributes=attributes)
        ]
    )
    return reference

def new_icon_resource(local_path:str,id_length:int=41,b64_encoding:str='utf-8',optimize:bool=True) -> XmlNodeAsDict:
    if not local_path.lower().endswith('.png'):
        raise ProcessorError("Only PNG files are supported for icons.")
    with Image.open(local_path) as old:
        reduced = Image.new("RGB",old.size)
        reduced.paste(old)
        buffer = BytesIO()
        reduced.save(buffer,format="PNG",optimize=optimize)
        _ = buffer.seek(0)
        encoded = base64.b64encode(buffer.read()).decode(encoding=b64_encoding)
    icon_id = f"Icon_p-{''.join(random.choices(string.ascii_letters + string.digits,k=id_length))}"
    attributes = [XmlAttributeAsDict(Name='Id',Value=icon_id)]
    data = XmlNodeAsDict(NodeName='Data',NodeInnerText=encoded)
    icon_resource = XmlNodeAsDict(NodeName='Icon',Attributes=attributes,ChildNodes=[data])    
    return icon_resource

def get_icon_reference(icon_resource:XmlNodeAsDict) -> XmlNodeAsDict:
    icon_id = icon_resource.get_attribute_value(attribute_name='Id')
    icon_reference = XmlNodeAsDict(NodeName='Icon',Attributes=[XmlAttributeAsDict(Name='Id',Value=icon_id)])
    return icon_reference

# User nodes
def new_user(user_id:str) -> XmlNodeAsDict:
    attributes = [
        XmlAttributeAsDict(Name='Qualifier',Value='LogonName'),
        XmlAttributeAsDict(Name='Id',Value=user_id)
    ]
    user = XmlNodeAsDict(NodeName='User',Attributes=attributes)
    return user

def new_owners_node(user_ids:list=[]) -> XmlNodeAsDict:
    user_nodes = []
    for u in user_ids:
        user_nodes.append(new_user(u))
    owners_node = XmlNodeAsDict(NodeName='Owners',ChildNodes=user_nodes)
    return owners_node

def new_contacts_node(user_ids:list=[]) -> XmlNodeAsDict:
    user_nodes = []
    for u in user_ids:
        user_nodes.append(new_user(u))
    contacts_node = XmlNodeAsDict(NodeName='Contacts',ChildNodes=user_nodes)
    return contacts_node
# Requirements & Detection
def new_operator(operator:str) -> XmlNodeAsDict:
    try:
        oprtr = Operator(operator)
    except:
        valid = ', '.join(f.value for f in Operator)
        raise ValueError(f"Invalid operator: '{operator}'. Valid: {valid}")
    node = XmlNodeAsDict(NodeName='Operator',NodeInnerText=oprtr.name)
    return node

def new_annotation(display_name:str='',description='',include_xmlns:bool=False) -> XmlNodeAsDict:
    display_name_node = XmlNodeAsDict(NodeName='DisplayName',Attributes=[XmlAttributeAsDict(Name='Text',Value=display_name)])
    description_node = XmlNodeAsDict(NodeName='Description',Attributes=[XmlAttributeAsDict(Name='Text',Value=description)])
    annotation = XmlNodeAsDict(NodeName='Annotation',ChildNodes=[display_name_node,description_node])
    if include_xmlns:
        annotation['Attributes'] = [XmlAttributeAsDict(Name='xmlns',Value=get_nsmap('Rule')['ns'])]
    return annotation

def new_constant_value(value:any,data_type:str):
    try:
        if list(f.value for f in RequirementRuleDataType).__contains__(data_type):
            requirement_rule_data_type = RequirementRuleDataType(data_type)
        else:
            requirement_rule_data_type = RequirementRuleDataType(PropertyPathDataType[data_type])
    except:
        valid = ', '.join(f.value for f in RequirementRuleDataType)
        raise ValueError(f"Invalid data type: '{data_type}'. Valid: {valid}")
    attributes = [
        XmlAttributeAsDict(Name='Value',Value=value),
        XmlAttributeAsDict(Name='DataType',Value=requirement_rule_data_type.name)
    ]
    constant_value = XmlNodeAsDict(NodeName='ConstantValue',Attributes=attributes)
    return constant_value

def new_constant_value_list(constant_values:list) -> XmlNodeAsDict:
    if len(constant_values or []) < 2:
        raise ValueError('At least 2 ConstantValue objects are required.')
    unique_data_types = []
    for v in constant_values:
        if v is None:
            raise ValueError("constant value cannot be 'NoneType'")
        udt = v.get_attribute_value('DataType')
        if udt is not None and udt != '' and not unique_data_types.__contains__(udt):
            unique_data_types.append(udt)
    if len(unique_data_types) != 1:
        raise ValueError('ConstantValue objects must all be of the same DataType')
    constant_values.sort(key=lambda x: x.get_attribute_value('Value'))
    array_data_type = f"{unique_data_types[0]}Array"
    attributes = [
        XmlAttributeAsDict(Name='DataType',Value=array_data_type)
    ]
    return XmlNodeAsDict(NodeName='ConstantValueList',Attributes=attributes,ChildNodes=constant_values)

def new_file_setting(path:str,filter:str,Is64Bit=True,logical_name=McmIdentifier().get_logical_name(object_type_name='File'),external_reference_id:int=None,group_ids:list[int]=None) -> XmlNodeAsDict:
    child_nodes = [
        new_annotation(include_xmlns=True),
        XmlNodeAsDict(NodeName='Path',NodeInnerText=path),
        XmlNodeAsDict(NodeName='Filter',NodeInnerText=filter)
    ]
    attributes = [
        XmlAttributeAsDict(Name='Is64Bit',Value=f"{Is64Bit.__str__().lower()}"),
        XmlAttributeAsDict(Name='LogicalName',Value=logical_name),
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap(namespace_name='DesiredConfiguration')['ns'])
    ]
    file_setting = XmlNodeAsDict(NodeName='File',Attributes=attributes,ChildNodes=child_nodes,external_reference_id=external_reference_id,group_ids=group_ids)
    return file_setting

def get_file_setting_reference_nodes(setting:XmlNodeAsDict,authoring_scope_id:str,application_id:str,setting_options:dict,version:int=1) -> list[XmlNodeAsDict]:
    nodes = []
    attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=application_id),
        XmlAttributeAsDict(Name='Version',Value=version),
    ]
    if setting_options.get('Property') is None:
        attributes.append(XmlAttributeAsDict(Name='DataType',Value='Int64'))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Count')
    elif PropertyPathDataType.__contains__(setting_options.get('Property','')) == False:
        print(f"Property must be null or one of the following: {', '.join(list(PropertyPathDataType.keys()))}`t Actual value: {setting_options.get('Property')}")
        raise ValueError('Invalid Property value.')
    else:
        data_type = PropertyPathDataType.get(setting_options.get('Property'))
        attributes.append(XmlAttributeAsDict(Name='DataType',Value=data_type))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Value')
    attributes.append(XmlAttributeAsDict(Name='SettingLogicalName',Value=setting.get_attribute_value('LogicalName')))
    attributes.append(XmlAttributeAsDict(Name='SettingSourceType',Value='File'))
    attributes.append(method_attribute)
    if method_attribute.get('Value','') == 'Value':
        attributes.append(XmlAttributeAsDict(Name='PropertyPath',Value=setting_options['Property']))
    attributes.append(XmlAttributeAsDict(Name='Changeable',Value='false'))
    nodes.append(XmlNodeAsDict(NodeName='SettingReference',Attributes=attributes))
    if ['Between','OneOf','NoneOf'].__contains__(setting_options.get('Operator')):
        comparisons = []
        for c in setting_options.get('Value',[]):
            item = new_constant_value(value=c,data_type=setting_options.get('DataType',setting_options.get('Property')))
            comparisons.append(item)
        comparison = new_constant_value_list(constant_values=comparisons)
    elif method_attribute.get('Value') == 'Count':
        comparison = new_constant_value(value='0',data_type='Int64')
    else:
        comparison = new_constant_value(value=setting_options['Value'],data_type=setting_options['DataType'])
    nodes.append(comparison)
    return nodes

def new_folder_setting(path,filter,Is64Bit=True,logical_name=McmIdentifier().get_logical_name(object_type_name='Folder'),external_reference_id:int=None,group_ids:list[int]=None) -> XmlNodeAsDict:
    child_nodes = [
        new_annotation(include_xmlns=True),
        XmlNodeAsDict(NodeName='Path',NodeInnerText=path),
        XmlNodeAsDict(NodeName='Filter',NodeInnerText=filter)
    ]
    attributes = [
        XmlAttributeAsDict(Name='Is64Bit',Value=f"{Is64Bit.__str__().lower()}"),
        XmlAttributeAsDict(Name='LogicalName',Value=logical_name),
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap(namespace_name='DesiredConfiguration')['ns'])
    ]
    folder_setting = XmlNodeAsDict(NodeName='Folder',ChildNodes=child_nodes,Attributes=attributes,external_reference_id=external_reference_id,group_ids=group_ids)
    return folder_setting

def get_folder_setting_reference_nodes(setting:XmlNodeAsDict,authoring_scope_id:str,application_id:str,setting_options:dict,version:int=1) -> list[XmlNodeAsDict]:
    nodes = []
    attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=application_id),
        XmlAttributeAsDict(Name='Version',Value=version),
    ]
    if setting_options.get('Property') is not None:
        data_type = PropertyPathDataType.get(setting_options.get('Property'))
        attributes.append(XmlAttributeAsDict(Name='DataType',Value=data_type))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Value')
    else:
        attributes.append(XmlAttributeAsDict(Name='DataType',Value='Int64'))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Count')
    attributes.append(XmlAttributeAsDict(Name='SettingLogicalName',Value=setting.get_attribute_value('LogicalName')))
    attributes.append(XmlAttributeAsDict(Name='SettingSourceType',Value='Folder'))
    attributes.append(method_attribute)
    if method_attribute.get('Value','') == 'Value':
        attributes.append(XmlAttributeAsDict(Name='PropertyPath',Value=setting_options['Property']))
    attributes.append(XmlAttributeAsDict(Name='Changeable',Value='false'))
    nodes.append(XmlNodeAsDict(NodeName='SettingReference',Attributes=attributes))
    if ['Between','OneOf','NoneOf'].__contains__(setting_options.get('Operator')):
        comparisons = []
        for c in setting_options.get('Value',[]):
            comparisons.append(new_constant_value(value=c,data_type=PropertyPathDataType.get(setting_options.get('Property'))))
        comparison = new_constant_value_list(constant_values=comparisons)
    elif method_attribute.get('Value') == 'Count':
        comparison = new_constant_value(value='0',data_type='Int64')
    else:
        comparison = new_constant_value(value=setting_options['Value'],data_type=data_type)
    nodes.append(comparison)
    return nodes

def new_msi_setting(product_code,IsPerUser=False,logical_name=McmIdentifier().get_logical_name(object_type_name='MSI'),external_reference_id:int=None,group_ids:list[int]=None) -> XmlNodeAsDict:
    child_nodes = [
        new_annotation(include_xmlns=True),
        XmlNodeAsDict(NodeName='ProductCode',NodeInnerText=product_code)
    ]
    attributes = [
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap(namespace_name='DesiredConfiguration')['ns']),
        XmlAttributeAsDict(Name='IsPerUser',Value=f"{IsPerUser.__str__().lower()}"),
        XmlAttributeAsDict(Name='LogicalName',Value=logical_name)
    ]
    msi_setting = XmlNodeAsDict(NodeName='MSI',ChildNodes=child_nodes,Attributes=attributes,external_reference_id=external_reference_id,group_ids=group_ids)
    return msi_setting

def get_msi_setting_reference_nodes(setting:XmlNodeAsDict,authoring_scope_id:str,application_id:str,setting_options:dict,version:int=1) -> list[XmlNodeAsDict]:
    nodes = []
    attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=application_id),
        XmlAttributeAsDict(Name='Version',Value=version),
    ]
    if setting_options.get('Operator') is not None:
        attributes.append(XmlAttributeAsDict(Name='DataType',Value='Version'))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Value')
    else:
        attributes.append(XmlAttributeAsDict(Name='DataType',Value='Int64'))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Count')
    attributes.append(XmlAttributeAsDict(Name='SettingLogicalName',Value=setting.get_attribute_value('LogicalName')))
    attributes.append(XmlAttributeAsDict(Name='SettingSourceType',Value='MSI'))
    attributes.append(method_attribute)
    if method_attribute.get('Value') == 'Value':
        property_path = 'ProductVersion'
        attributes.append(XmlAttributeAsDict(Name="PropertyPath",Value=property_path))
    attributes.append(XmlAttributeAsDict(Name='Changeable',Value='false'))
    nodes.append(XmlNodeAsDict(NodeName='SettingReference',Attributes=attributes))
    if method_attribute.get('Value') == 'Count':
        comparison = new_constant_value(value='0',data_type='Int64')
    else:
        comparison = new_constant_value(value=setting_options['Value'],data_type='Version')
    nodes.append(comparison)
    return nodes

def new_registrykey_setting(hive:str,key,Is64Bit=True,logical_name=McmIdentifier().get_logical_name(object_type_name='RegKey'),external_reference_id:int=None,group_ids:list[int]=None) -> XmlNodeAsDict:
    child_nodes = [
        new_annotation(include_xmlns=True),
        XmlNodeAsDict(NodeName='Key',NodeInnerText=key)
    ]
    attributes = [
        XmlAttributeAsDict(Name='Hive',Value=hive),
        XmlAttributeAsDict(Name='Is64Bit',Value=f"{Is64Bit.__str__().lower()}"),
        XmlAttributeAsDict(Name='LogicalName',Value=logical_name),
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap(namespace_name='DesiredConfiguration')['ns'])
    ]
    regkey_setting = XmlNodeAsDict(NodeName='RegistryKey',ChildNodes=child_nodes,Attributes=attributes,external_reference_id=external_reference_id,group_ids=group_ids)
    return regkey_setting

def get_registrykey_setting_reference_nodes(setting:XmlNodeAsDict,authoring_scope_id:str,application_id:str,setting_options:dict=None,version:int=1) -> list[XmlNodeAsDict]:
    nodes = []
    attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=application_id),
        XmlAttributeAsDict(Name='Version',Value=version),
    ]
    attributes.append(XmlAttributeAsDict(Name='DataType',Value='Boolean'))
    method_attribute = XmlAttributeAsDict(Name='Method',Value='Value')
    attributes.append(XmlAttributeAsDict(Name='SettingLogicalName',Value=setting.get_attribute_value('LogicalName')))
    attributes.append(XmlAttributeAsDict(Name='SettingSourceType',Value='RegistryKey'))
    attributes.append(method_attribute)
    attributes.append(XmlAttributeAsDict(Name='PropertyPath',Value='RegistryKeyExists'))
    attributes.append(XmlAttributeAsDict(Name='Changeable',Value='false'))
    nodes.append(XmlNodeAsDict(NodeName='SettingReference',Attributes=attributes))
    comparison = new_constant_value(value='true',data_type='Boolean')
    nodes.append(comparison)
    return nodes

def new_registryvalue_setting(hive,key,value_name,data_type:str,Is64Bit=True,logical_name=McmIdentifier().get_logical_name(object_type_name='RegSetting'),
        create_missing_path:bool=True,depth:str="Base",external_reference_id:int=None,group_ids:list[int]=None) -> XmlNodeAsDict:
    registry_discovery_node_attributes = [
        XmlAttributeAsDict(Name='Hive',Value=hive),
        XmlAttributeAsDict(Name='Depth',Value=depth),
        XmlAttributeAsDict(Name='Is64Bit',Value=f"{Is64Bit.__str__().lower()}"),
        XmlAttributeAsDict(Name='CreateMissingPath',Value=f"{create_missing_path.__str__().lower()}")
    ]
    registry_discovery_node_children = [
        XmlNodeAsDict(NodeName='Key',NodeInnerText=key),
        XmlNodeAsDict(NodeName='ValueName',NodeInnerText=value_name)
    ]
    child_nodes = [
        new_annotation(include_xmlns=True),
        XmlNodeAsDict(NodeName='RegistryDiscoverySource',Attributes=registry_discovery_node_attributes,ChildNodes=registry_discovery_node_children)
    ]
    attributes = [
        XmlAttributeAsDict(Name='LogicalName',Value=logical_name),
        XmlAttributeAsDict(Name='DataType',Value=data_type),
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap(namespace_name='DesiredConfiguration')['ns'])
    ]
    regvalue_setting = XmlNodeAsDict(NodeName='SimpleSetting',ChildNodes=child_nodes,Attributes=attributes,external_reference_id=external_reference_id,group_ids=group_ids)
    return regvalue_setting

def get_registryvalue_setting_reference_nodes(setting:XmlNodeAsDict,authoring_scope_id:str,application_id:str,setting_options:dict,version:int=1) -> list[XmlNodeAsDict]:
    nodes = []
    attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=application_id),
        XmlAttributeAsDict(Name='Version',Value=version),
    ]
    if setting_options.get('DataType') is not None:
        attributes.append(XmlAttributeAsDict(Name='DataType',Value=setting_options['DataType']))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Value')
    else:
        attributes.append(XmlAttributeAsDict(Name='DataType',Value='Int64'))
        method_attribute = XmlAttributeAsDict(Name='Method',Value='Count')
    attributes.append(XmlAttributeAsDict(Name='SettingLogicalName',Value=setting.get_attribute_value('LogicalName')))
    attributes.append(XmlAttributeAsDict(Name='SettingSourceType',Value='Registry'))
    attributes.append(method_attribute)
    attributes.append(XmlAttributeAsDict(Name='Changeable',Value='false'))
    nodes.append(XmlNodeAsDict(NodeName='SettingReference',Attributes=attributes))
    if ['Between','OneOf','NoneOf'].__contains__(setting_options.get('Operator')):
        comparisons = []
        for c in setting_options.get('Value',[]):
            item = new_constant_value(value=c,data_type=setting_options['DataType'])
            comparisons.append(item)
        comparison = new_constant_value_list(constant_values=comparisons)
    elif method_attribute.get('Value') == 'Count':
        comparison = new_constant_value(value='0',data_type='Int64')
    else:
        comparison = new_constant_value(value=setting_options['ValueData'],data_type=setting_options['DataType'])
    nodes.append(comparison)
    return nodes

get_setting_reference = {
    'File': get_file_setting_reference_nodes,
    'Folder': get_folder_setting_reference_nodes,
    'RegistryKey': get_registrykey_setting_reference_nodes,
    'RegistryKeyValue': get_registryvalue_setting_reference_nodes,
    'MSI': get_msi_setting_reference_nodes,
    'SimpleSetting': get_registryvalue_setting_reference_nodes
}

def new_detection_rule_expression(authoring_scope_id:str,application_id:str,deployment_type_id:str,detection_item:dict,is_root:bool=False) -> XmlNodeAsDict:
    attributes = []
    if detection_item['Type'] == 'Group' and is_root == False:
        attributes.append(
            XmlAttributeAsDict(Name='IsGroup',Value='true')
        )
    detection_options = detection_item.get('Options',{})
    if (detection_options.get('Operator','') != ''):
        item_operator = detection_options.get('Operator','')
    elif detection_item.get('Type','') == 'RegistryKey':
        item_operator = 'Equals'
    else:
        raise ValueError(f"Invalid detection rule configuration.::{detection_options.get('Operator','')}/{item_operator}\ttype:{detection_options.get('Type')}")
    operands_child_nodes = []
    if detection_item['Type'] == 'Group':
        for item in detection_item['Options']['Items']:
            operands_child_nodes.append(new_detection_rule_expression(detection_item=item,authoring_scope_id=authoring_scope_id,application_id=application_id,deployment_type_id=deployment_type_id))
    else:
        options_id = id(detection_item['Options'])
        setting = XmlNodeAsDict.instance_map_by_external_id.get(f"{options_id}")
        reference_getter = get_setting_reference[setting.get('NodeName')]
        if reference_getter:
            setting_reference_nodes = reference_getter(setting=setting,authoring_scope_id=authoring_scope_id,application_id=application_id,
                    setting_options=detection_options)
            operands_child_nodes.extend(setting_reference_nodes)
        else:
            raise ValueError("Unknown Type.")
    detection_rule_expression = XmlNodeAsDict(NodeName='Expression',Attributes=attributes,
            ChildNodes=[new_operator(item_operator),XmlNodeAsDict(NodeName='Operands',ChildNodes=operands_child_nodes)],
            external_reference_id=id(detection_options))
    return detection_rule_expression

def new_setting(detection_type:str,options:dict) -> XmlNodeAsDict:
    try:
        setting_detection_type = DetectionType(detection_type)
    except:
        valid = ', '.join(f.value for f in DetectionType)
        raise ProcessorError(f"Invalid detection type: '{detection_type}'. Valid: {valid}")
    if ['CustomScript','Group'].__contains__(setting_detection_type.name):
        raise ProcessorError('Must provide a valid detection type to use new_setting.')
    if setting_detection_type.name == 'File':
        return new_file_setting(path=options['Path'],filter=options['Filter'],Is64Bit=options.get('Is64Bit',True),external_reference_id=id(options))
    elif setting_detection_type.name == 'Folder':
        return new_folder_setting(path=options['Path'],filter=options['Filter'],Is64Bit=options.get('Is64Bit',True),external_reference_id=id(options))
    elif setting_detection_type.name == 'RegistryKey':
        return new_registrykey_setting(hive=options['Hive'],key=options['Key'],Is64Bit=options.get('Is64Bit',True),external_reference_id=id(options))
    elif setting_detection_type.name == 'RegistryKeyValue':
        return new_registryvalue_setting(hive=options['Hive'],key=options['Key'],value_name=options['ValueName'],data_type=options['DataType'],Is64Bit=options.get('Is64Bit',True),external_reference_id=id(options))
    elif setting_detection_type.name == 'MSI':
        return new_msi_setting(product_code=options['ProductCode'],IsPerUser=options.get('IsPerUser',False),external_reference_id=id(options))

def get_nested_settings(detection_config:dict) -> list[XmlNodeAsDict]:
    results = []
    if detection_config['Type'] == 'Group':
        for item in detection_config['Options']['Items']:
            results.extend(get_nested_settings(detection_config=item))
    else:
        results.append(new_setting(detection_type=detection_config['Type'],options=detection_config['Options']))
    return results

def new_detection_rule_node(authoring_scope_id:str,application_id,deployment_type_id:str,detection:dict,severity:str="None",noncompliance_on_nonexistance:bool=False) -> XmlNodeAsDict:
    expression = new_detection_rule_expression(authoring_scope_id=authoring_scope_id,
                    application_id=application_id,deployment_type_id=deployment_type_id,detection_item=detection,is_root=True)
    dt_model_name = f"{authoring_scope_id}/{deployment_type_id}"
    child_nodes = [
            new_annotation(),
            expression
    ]
    attributes = [
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap(namespace_name='Rule')['ns']),
        XmlAttributeAsDict(Name='id',Value=dt_model_name),
        XmlAttributeAsDict(Name='Severity',Value=severity),
        XmlAttributeAsDict(Name='NonCompliantWhenSettingIsNotFound',Value=noncompliance_on_nonexistance.__str__().lower())
    ]
    rule_node = XmlNodeAsDict(NodeName='Rule',Attributes=attributes,ChildNodes=child_nodes,external_reference_id=id(detection))
    return rule_node

def new_enhanced_detection_method_node(authoring_scope_id:str,application_id:str,deployment_type_id:str,detection_config:dict,severity:str='Informational',noncompliance_on_nonexistance:bool=False) -> XmlNodeAsDict:
    setting_nodes = get_nested_settings(detection_config=detection_config)
    settings_node = XmlNodeAsDict(NodeName='Settings',ChildNodes=setting_nodes,Attributes=[XmlAttributeAsDict(Name='xmlns',Value=get_nsmap('AppMgmtDigest')['ns'])])
    rule_node = new_detection_rule_node(authoring_scope_id=authoring_scope_id,application_id=application_id,deployment_type_id=deployment_type_id,detection=detection_config,severity=severity,noncompliance_on_nonexistance=noncompliance_on_nonexistance)
    enhanced_detection_method = XmlNodeAsDict(NodeName='EnhancedDetectionMethod',Attributes=[XmlAttributeAsDict(Name="xmlns",Value=get_nsmap('AppMgmtDigest')['ns'])],xml_declaration=True)
    enhanced_detection_method.append_child_node([settings_node])
    enhanced_detection_method.append_child_node([rule_node])
    return enhanced_detection_method

def new_requirements_rule(rule:dict,rule_id:str,severity='None',noncompliance_on_nonexistance:bool=False) -> XmlNodeAsDict:
    raise Exception("Not supported yet.")
    pass

def new_requirements_rule_from_string(rule:str,rule_id:str,severity='None',noncompliance_on_nonexistance:bool=False) -> XmlNodeAsDict:
    attributes = [
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap('Rule')['ns']),
        XmlAttributeAsDict(Name='id',Value=rule_id),
        XmlAttributeAsDict(Name='Severity',Value=f"{severity}"),
        XmlAttributeAsDict(Name='NonCompliantWhenSettingIsNotFound',Value=f"{noncompliance_on_nonexistance.__str__().lower()}")
    ]
    requirements_rule = XmlNodeAsDict(NodeName='Rule',Attributes=attributes)
    instance = XmlNodeAsDict.from_xml_string_with_tracking(xml_string=rule)
    requirements_rule['ChildNodes'] = instance['ChildNodes']
    return requirements_rule

get_requirements_rule_config = {
    'XmlString': new_requirements_rule_from_string,
    'Dict': new_requirements_rule
}

def new_dependency(authoring_scope_id:str,application_logical_name:str,dt_logical_name:str,auto_install:bool=False) -> XmlNodeAsDict:
    dt_appref_attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=application_logical_name)
    ]
    dt_application_reference = XmlNodeAsDict(NodeName='DeploymentTypeApplicationReference',Attributes=dt_appref_attributes)

    dtref_attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
        XmlAttributeAsDict(Name='LogicalName',Value=dt_logical_name),
        XmlAttributeAsDict(Name='Changeable',Value=auto_install.__str__().lower())
        # Changeable=true = autoinstall(yes)
    ]
    dt_reference = XmlNodeAsDict(NodeName='DeploymentTypeReference',Attributes=dtref_attributes)
    child_nodes = [
        dt_application_reference,
        dt_reference
    ]
    expression_attributes = [
        XmlAttributeAsDict(Name='DesiredState',Value='Required')
    ]
    dependency = XmlNodeAsDict(NodeName='DeploymentTypeIntentExpression',Attributes=expression_attributes,ChildNodes=child_nodes)
    return dependency

def new_dependency_group(rule_name:str,dependencies:list[XmlNodeAsDict],id:str=None) -> XmlNodeAsDict:
    if id is None:
        id = McmIdentifier().get_logical_name(object_type_name='DTRule')
    attributes = [
        XmlAttributeAsDict(Name='xmlns',Value=get_nsmap('Rule')['ns']),
        XmlAttributeAsDict(Name='id',Value=id),
        XmlAttributeAsDict(Name='Severity',Value='Critical')
    ]
    annotation = new_annotation(display_name=rule_name)
    dt_exp_child_nodes = [
        new_operator('Or'),
        XmlNodeAsDict(NodeName='Operands',ChildNodes=dependencies)
    ]
    dt_expression = XmlNodeAsDict(NodeName='DeploymentTypeExpression',ChildNodes=dt_exp_child_nodes)
    child_nodes = [
        annotation,
        dt_expression
    ]
    return XmlNodeAsDict(NodeName='DeploymentTypeRule',Attributes=attributes,ChildNodes=child_nodes)

def new_dependencies_node(dependency_groups:list[XmlNodeAsDict]) -> XmlNodeAsDict:
    dependencies_node = XmlNodeAsDict(NodeName='Dependencies',ChildNodes=dependency_groups)
    return dependencies_node

def new_requirements_node(requirements_rules:list[XmlNodeAsDict]) -> XmlNodeAsDict:
    requirements_node = XmlNodeAsDict(NodeName='Requirements',ChildNodes=requirements_rules)
    return requirements_node

#Installer
def new_process_information(process_name:str,process_display_name:str) -> XmlNodeAsDict:
    process_information = XmlNodeAsDict(
        NodeName='ProcessInformation',Attributes=[
            XmlAttributeAsDict(Name='Name',Value=process_name)
        ],
        ChildNodes=[
            XmlNodeAsDict(
                NodeName='DisplayInfo',Attributes=[
                    XmlAttributeAsDict(Name='DefaultLanguage',Value='')
                ],
                ChildNodes=[
                    XmlNodeAsDict(
                        NodeName='Info',
                        Attributes=[
                            XmlAttributeAsDict(Name='Language',Value=''),
                            XmlAttributeAsDict(Name='DisplayName',Value=process_display_name)
                        ]
                    )
                ]
            )
        ]
    )
    return process_information

def new_install_process_detection(process_information:list[XmlNodeAsDict]) -> XmlNodeAsDict:
    install_process_detection = XmlNodeAsDict(
        NodeName='InstallProcessDetection',
        ChildNodes=[
            XmlNodeAsDict(
                NodeName='ProcessList',
                ChildNodes=process_information
            )
        ]
    )
    return install_process_detection

def new_arg(arg_name:str,arg_type:str,arg_value:any=None) -> XmlNodeAsDict:
    try:
        cls_arg_type = ArgumentType[arg_type]
    except:
        valid = ', '.join(f.value for f in ArgumentType)
        raise ValueError(f"Invalid operator: '{arg_type}'. Valid: {valid}")
    params = {
        "NodeName": "Arg",
        "Attributes": [
            XmlAttributeAsDict(Name='Name',Value=arg_name),
            XmlAttributeAsDict(Name='Type',Value=cls_arg_type.value)
        ]
    }
    if arg_value is None:
        pass
    elif (cls_arg_type.value.endswith('[]')) == False:
        params['NodeInnerText'] = arg_value
    else:
        params["ChildNodes"] = []
        if isinstance(arg_value,str):
            params["ChildNodes"].append(XmlNodeAsDict(NodeName='Item',NodeInnerText=arg_value))
        elif isinstance(arg_value,list):
            for i in arg_value:
                params["ChildNodes"].append(XmlNodeAsDict(NodeName='Item',NodeInnerText=i.__str__()))
        else:
            raise ValueError("Invalid value supplied for arg_value.")
    arg_node = XmlNodeAsDict(**params)
    return arg_node

def new_dt_action(action_type:str,provider:str,args:list[XmlNodeAsDict],content_reference:XmlNodeAsDict=None) -> XmlNodeAsDict:
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
        NodeName=item_action_type.name,
        ChildNodes=[
            XmlNodeAsDict(NodeName='Provider',NodeInnerText=item_provider.name),
            XmlNodeAsDict(NodeName='Args',ChildNodes=args)
        ]
    )
    if content_reference is not None:
        action.append_child_node([content_reference])
    return action

def new_detection_nodes(authoring_scope_id:str,application_id:str,deployment_type_id:str,detection_item:dict,execution_context:str='System') -> list:
    """Output a list of exactly 2 items where item 0 is the DetectAction XmlNodeAsDict object and item 1 is itself a list of the detection nodes needed for the CustomData node."""
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
    if detection_type == 'CustomScript':
        detect_action_params['provider'] = 'Script'
        detect_action_params['args'].append(new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context))
        detect_action_params['args'].append(new_arg(arg_name='ScriptType', arg_type='Int32',arg_value='0'))
        detect_action_params['args'].append(new_arg(arg_name='ScriptBody', arg_type='String',arg_value=detection_item.get('Options',{}).get('ScriptContent','')))
        detect_action_params['args'].append(new_arg(arg_name='RunAs32Bit', arg_type='Boolean',arg_value=bool(detection_item.get('Options',{}).get('RunAs32Bit',False)).__str__().lower()))
        custom_data_nodes.append(XmlNodeAsDict(NodeName='DetectionMethod',NodeInnerText='Script'))
        custom_data_nodes.append(XmlNodeAsDict(
            NodeName='DetectionScript',
            Attributes=[XmlAttributeAsDict(Name='Language',Value='PowerShell')],
            NodeInnerText=detection_item.get('Options',{}).get('ScriptContent',''))
        )
    else:
        enhanced_detection = new_enhanced_detection_method_node(authoring_scope_id=authoring_scope_id,application_id=application_id,deployment_type_id=deployment_type_id,detection_config=detection_item)
        xml_string = enhanced_detection.to_xml_string()
        detect_action_params['provider'] = 'Local'
        detect_action_params['args'].append(new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context))
        detect_action_params['args'].append(new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string))
        custom_data_nodes.append(XmlNodeAsDict(NodeName='DetectionMethod',NodeInnerText='Enhanced'))
        enhanced_detection['Attributes'].clear()
        custom_data_nodes.append(enhanced_detection)
    detect_action = new_dt_action(**detect_action_params)
    return [detect_action,custom_data_nodes]

# Deployment Type
def new_languages_node(languages:list[str]) -> XmlNodeAsDict:
    item_languages = []
    for l in languages:
        if l is not None:
            item_languages.append(XmlNodeAsDict(NodeName='Lang',NodeInnerText=l))
    languages_node = XmlNodeAsDict(NodeName='Languages',ChildNodes=item_languages)
    return languages_node

def get_deployment_type_reference(deployment_type:XmlNodeAsDict) -> XmlNodeAsDict:
    attributes = [
        XmlAttributeAsDict(Name='AuthoringScopeId',Value=deployment_type.get_attribute_value('AuthoringScopeId')),
        XmlAttributeAsDict(Name='LogicalName',Value=deployment_type.get_attribute_value('LogicalName')),
        XmlAttributeAsDict(Name='Version',Value=deployment_type.get_attribute_value('Version'))
    ]
    reference = XmlNodeAsDict(NodeName='DeploymentType',Attributes=attributes)
    return reference
    
# Application
def new_user_categories_node(user_category_unique_ids:list[str]) -> XmlNodeAsDict:
    params = {'NodeName':'UserCategories'}
    if len(user_category_unique_ids) > 0:
        child_nodes = []
        for c in user_category_unique_ids:
            child_nodes.append(
                XmlNodeAsDict(NodeName='Tag',NodeInnerText=c)
            )
        params['ChildNodes'] = child_nodes
    user_categories_node = XmlNodeAsDict(**params)
    return user_categories_node
def new_tags_node(tags:list[str]=[]) -> XmlNodeAsDict:
    tag_list = []
    for t in tags:
        tag_list.append(XmlNodeAsDict(NodeName='Tag',NodeInnerText=t))
    tags_node = XmlNodeAsDict(NodeName='Tags',ChildNodes=tag_list)
    return tags_node
def new_display_info(title:str,language:str='en-US',publisher:str=None,software_version:str=None,release_date:str=datetime.now().strftime("%m/%d/%Y"),
            description:str=None,info_url:str=None,info_url_text:str=None,privacy_url:str=None,user_categories_node:XmlNodeAsDict=None,
            tags:list=None,icon_reference:XmlNodeAsDict=None):
    attributes = [
        XmlAttributeAsDict(Name='Language',Value=language)
    ]
    child_nodes = [
        XmlNodeAsDict(NodeName='Title',NodeInnerText=title),
    ]
    info = XmlNodeAsDict(NodeName='Info',Attributes=attributes,ChildNodes=child_nodes)
    if description is not None and description != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='Description',NodeInnerText=description)
        ])
    if publisher is not None and publisher != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='Publisher',NodeInnerText=publisher)
        ])

    if software_version is not None and software_version != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='Version',NodeInnerText=software_version)
        ])
    if release_date is not None and release_date != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='ReleaseDate',NodeInnerText=release_date)
        ])
    if icon_reference is not None:
        info.append_child_node([
            icon_reference
        ])
    if info_url is not None and info_url != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='InfoUrl',NodeInnerText=info_url)
        ])
    if info_url_text is not None and info_url_text != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='InfoUrlText',NodeInnerText=info_url_text)
        ])
    if privacy_url is not None and privacy_url != '':
        info.append_child_node([
            XmlNodeAsDict(NodeName='PrivacyUrl',NodeInnerText=privacy_url)
        ])
    if user_categories_node is not None:
        info.append_child_node([user_categories_node])
    if len(tags or []) > 0:
        info.append_child_node([new_tags_node(tags=tags)])
    return info

def new_display_info_node(display_infos:list,default_language:str='en-US') -> XmlNodeAsDict:
    display_info_node = XmlNodeAsDict(
        NodeName='DisplayInfo',
        Attributes=[
            XmlAttributeAsDict(Name='DefaultLanguage',Value=default_language)
        ],
        ChildNodes=display_infos
    )
    return display_info_node

__all__ = ["McmSDMPackageXMLGenerator"]

class McmSDMPackageXMLGenerator(Processor):
    description = "Generate an SDMPackageXML string which represents an MCM Application object."
    input_variables = {
        "mcm_application_configuration": {
            "required": True,
            "description": (
                "A nested dictionary object representing the configuration for the application."
            ),
        },
        "keychain_password_service": {
            "required": False,
            "description": "The service name used to store the password. Defaults to com.github.autopkg.iancohn-recipes.mcmapi",
            "default": 'com.github.autopkg.iancohn-recipes.mcmapi'
        },
        "keychain_password_username": {
            "required": False,
            "description": "The username of the credential to retrieve. Defaults to %MCMAPI_USERNAME%"
        },
        "mcm_site_server_fqdn": {
            "required": True,
            "description": "The FQDN of the site server. Ex. mcm.domain.com"
        },
        "mcm_scope_id": {
            "required": False,
            "description": "The authoring scope id for objects in the target MCM site."
        },
        "existing_app_sdmpackagexml": {
            "required": False,
            "description": "The SDMPackageXML property of an existing application which should be updated.",
            "default": None
        },
        "existing_app_ci_id": {
            "required": False,
            "description": "The CI_ID property of the application which should be updated.",
            "default": None
        }
    }
    output_variables = {
        "SDMPackageXML": {"description": "Serialized XML string representing an application object."},
        "mcm_scope_id": {"description": "The authoring scope id for objects in the target MCM site."},
        "mcm_application": {"description": "A dictionary representation of the mcm application"},
        "mcm_application_ci_id": {"description": "The CI_ID where the application should be posted. 0 indicates a new application."},
    }

    __doc__ = description

    def get_mcm_scope_id(self) -> str:
        """Retrieve the MCM scope ID from the site server."""
        if self.env.get("mcm_scope_id", None) is not None:
            self.output("Using existing or already retrieved scope id.", 2)
            return self.env.get("mcm_scope_id")
        
        try:
            self.output(f"Getting scope id from {self.fqdn}", 2)
            url = f"https://{self.fqdn}/AdminService/wmi/SMS_Identification.GetSiteID"
            
            response = requests.request(
                method='Get',
                url=url,
                auth=self.ntlm,
                headers=self.headers,
                timeout=30,
                verify=False
            )
            response.raise_for_status()
            json_response = response.json()
            site_id = json_response.get('SiteID')
            if not site_id:
                raise ProcessorError("No SiteID returned from MCM server")
            self.output(f"Received response {site_id}", 3)
            scope_id = convert_site_id_to_scope_id(site_id)
            self.output(f"Retrieved scope ID: {scope_id}", 2)
            self.env["mcm_scope_id"] = scope_id
            return scope_id
            
        except requests.exceptions.HTTPError as e:
            raise ProcessorError(f"Failed to connect to MCM server: {e}")
        except Exception as e:
            raise ProcessorError(f"Failed to retrieve scope ID: {e}")
    
    def find_application_by_name(self, application_name:str) -> dict:
        self.output(f"Attempting to get application ({application_name}) from {self.fqdn}", 2)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_Application"
        body = {"$filter": f"LocalizedDisplayName eq '{application_name}' and IsLatest eq true",'$select':"CI_ID"}
        appSearchResponse = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False,
            params=body
        )
        self.output(f"Done searching for application. {type(appSearchResponse).__name__} type object returned.",3)
        searchValue = appSearchResponse.json()["value"]
        self.output(f"{searchValue.__len__()} Application objects returned from {self.fqdn}",3)
        if searchValue.__len__() > 1:
            raise ProcessorError("Application_name must be unique and return one or less results")
        elif searchValue.__len__() == 0:
            self.output(f"{application_name} not found in {self.fqdn}",2)
            return None
        self.output(f"Getting SDMPackageXML for {application_name} from {self.fqdn}", 3)
        appUrl = f"https://{self.fqdn}/AdminService/wmi/SMS_Application({searchValue[0].get('CI_ID')})"
        app = requests.request(
            method='GET',
            url=appUrl,
            auth=self.ntlm,
            headers=self.headers,
            verify=False
        )
        self.output("Done getting SDMPackageXML", 3)
        appJson = app.json()
        appValue = appJson['value'] or []
        if len(appValue) == 1 and (sdm_package_xml := appValue[0].get('SDMPackageXML', '')) != '':
            self.output(f"SDMPackageXML length: {len(sdm_package_xml)}")
            return_object = {
                "SDMPackageXML": sdm_package_xml.replace('<?xml version="1.0" encoding="utf-16"?>','',1),
                "ci_id": appValue[0].get("CI_ID")
            }
        else:
            return_object = None
        return return_object

    def find_task_sequence_by_name(self,task_sequence_name:str) -> dict:
        self.output(f"Attempting to get task sequence ({task_sequence_name}) from {self.fqdn}", 2)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_TaskSequencePackage"
        body = {"$filter": f"Name eq '{task_sequence_name}'",'$select':"Name,PackageId"}
        searchResponse = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False,
            params=body
        )
        self.output(f"Done searching for task sequence. {type(searchResponse).__name__} type object returned.",3)
        searchValue = searchResponse.json()["value"]
        self.output(f"{searchValue.__len__()} Application objects returned from {self.fqdn}",3)
        if searchValue.__len__() > 1:
            raise IndexError("task_sequence_name must be unique and return one or less results")
        elif searchValue.__len__() == 0:
            self.output(f"{task_sequence_name} not found in {self.fqdn}")
            return None
        return searchResponse.json()["value"][0]
        
    def get_mcm_ntlm_auth(self, keychain_service_name: str, keychain_username: str) -> HttpNtlmAuth:
        """Create NTLM authentication object from keychain credentials."""
        try:
            password = keyring.get_password(keychain_service_name, keychain_username)
            if password is None:
                raise ProcessorError(f"No password found for {keychain_username} in {keychain_service_name}")
            return HttpNtlmAuth(keychain_username, password)
        except Exception as e:
            raise ProcessorError(f"Failed to retrieve credentials: {e}")

    def get_dt_logicalname_from_application(self,application:XmlNodeAsDict,deployment_type_name_filter:str=None,deployment_type_name_filter_type:str=None) -> str:
        """Return the Logical Name of the deployment type matching the filter type and content"""
        results = []
        application.get_attribute_value
        dts = application.find_children_by_name('DeploymentType')
        if len(dts) == 1 and (deployment_type_name_filter or '') == '':
            self.output("Application has a single Deployment Type, and no filter was specified. Selecting the deployment type.", 2)
            results.append(application.find_children_by_name('DeploymentType')[0].get_attribute_value('LogicalName'))
        elif deployment_type_name_filter_type == 'StartsWith':
            for d in dts:
                if d.find_children_by_name('Title')[0].get('NodeInnerText', '').startswith(deployment_type_name_filter):
                    results.append(d.get_attribute_value('LogicalName'))
        elif deployment_type_name_filter_type == 'Contains':
            for d in dts:
                if d.find_children_by_name('Title')[0].get('NodeInnerText', '').__contains__(deployment_type_name_filter):
                    results.append(d.get_attribute_value('LogicalName'))
        else: #Equals
            for d in dts:
                if d.find_children_by_name('Title')[0].get('NodeInnerText', '') == deployment_type_name_filter:
                    results.append(d.get_attribute_value('LogicalName'))
        self.output(f"{len(results)} matching deployment types found. {', '.join(results)}",3)
        if len(results) == 0:
            raise ProcessorError("Could not find a deployment type with the given name/filter.")
        return results[0]
    def get_dt_logicalname_from_etree_application(self,application:etree.Element,deployment_type_name_filter:str,deployment_type_name_filter_type:str)->str:
        nsmap = self.nsmap
        if (DeploymentTypeFilterType[deployment_type_name_filter_type]):
            pass
        if deployment_type_name_filter_type == 'StartsWith':
            titleFilter = f"starts-with(text(), \"{deployment_type_name_filter}\")"
        elif deployment_type_name_filter_type == 'Contains':
            titleFilter = f"contains(text(), \"{deployment_type_name_filter}\")"
        else:
            titleFilter = f"text()=\"{deployment_type_name_filter}\""
        results = application.xpath(f"/AppMgmtDigest:AppMgmtDigest/AppMgmtDigest:DeploymentType[AppMgmtDigest:Title[{titleFilter}]]/@LogicalName",namespaces=nsmap)
        if len(results) == 0:
            raise ProcessorError("Could not find a deployment type with the given name/filter.")
        return results[0]

    def create_user_category(self, user_category_name:str)-> str:
        self.output(f"Attempting to create user category ({user_category_name}) in {self.fqdn}", 2)
        raise ProcessorError("Creating user categories is not supported.")
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_Application"
        body = {"CategoryTypeName": "CatalogCategories","Cat" : f"'{user_category_name}' and IsLatest eq true",'$select':"CI_ID"}
        appSearchResponse = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False,
            params=body
        )
        self.output(f"Done searching for application. {type(appSearchResponse).__name__} type object returned.",3)
        searchValue = appSearchResponse.json()["value"]
        self.output(f"{searchValue.__len__()} Application objects returned from {self.fqdn}",3)

    def get_user_category_id(self, user_category_name:str) -> str:
        self.output(f"Attempting to get user category ({user_category_name}) from {self.fqdn}", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_CategoryInstance?$filter=LocalizedCategoryInstanceName eq '{user_category_name}'"
        searchResponse = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False         
        )
        self.output(f"Done searching for category. {type(searchResponse).__name__} type object returned.",3)
        searchValue = searchResponse.json()["value"]
        self.output(f"{len(searchValue)} Application objects returned from {self.fqdn}",3)
        if len(searchValue) == 0:
            return None
        elif len(searchValue) > 1:
            raise ProcessorError('Ambiguous user category')
        else:
            return searchValue[0].get('CategoryInstance_UniqueID',None)

    def get_user_category_id(self, user_category_name:str) -> str:
        self.output(f"Attempting to get user category ({user_category_name}) from {self.fqdn}", 3)
        url = f"https://{self.fqdn}/AdminService/wmi/SMS_CategoryInstance?$filter=LocalizedCategoryInstanceName eq '{user_category_name}'"
        searchResponse = requests.request(
            method='GET',
            url=url,
            auth=self.ntlm,
            headers=self.headers,
            verify=False         
        )
        self.output(f"Done searching for category. {type(searchResponse).__name__} type object returned.",3)
        searchValue = searchResponse.json()["value"]
        self.output(f"{len(searchValue)} user category objects returned from {self.fqdn}",3)
        if len(searchValue) == 0:
            return None
        elif len(searchValue) > 1:
            raise ProcessorError('Ambiguous user category')
        else:
            uq_id = searchValue[0].get('CategoryInstance_UniqueID',None)
            self.output(f"User Category UniqueID: {uq_id}", 3)
            return uq_id

    def merge_deployment_types(self,authoring_scope_id:str,dicts:list[dict]=[],existing_deployment_types:list[XmlNodeAsDict]=[],persist_unhandled_deployment_types:bool=False)->list:
        """Match configured deployment types to existing deployment types and return an ordered list of deployment types to add to an application."""
        try:
            self.output("Attempting to merge configured deployment types with those from an existing application.", 2)
            element_lookup = {d.find_children_by_name(node_name='Title')[0].get('NodeInnerText'): d for d in existing_deployment_types}
            result = []
            used_titles = set()
            unreferenced = []
            for ix, item in enumerate(dicts):
                dt_name = item.get('Options',{}).get('DeploymentTypeName','')
                if dt_name == '':
                    raise ProcessorError("Each deployment type must contain a valid name.")
                priority = item.get('Priority')
                self.output(f"Getting existing_match for {dt_name} ({priority})",3)
                existing_match = element_lookup.get(dt_name)
                if existing_match is None:
                    self.output(f"No existing match found for {dt_name}",3)
                else:
                    self.output(f"Found a match for {dt_name}",2)
                dt_logical_name = existing_match.get_attribute_value(attribute_name='LogicalName') if existing_match is not None else McmIdentifier().get_logical_name(object_type_name='DeploymentType')
                dt_revision = (int(existing_match.get_attribute_value(attribute_name='Version'))) if existing_match is not None else 0
                dt_next_revision = dt_revision + 1
                used_titles.add(dt_name)
                if priority is None and existing_match is not None:
                    priority = ix + 1
                result.append({"Type":"dict","Priority":priority,"Object":item,"LogicalName":dt_logical_name,"Version":dt_next_revision})
            if persist_unhandled_deployment_types:
                self.output("Unhandled deployment types will be persisted",3)
                for element in existing_deployment_types:
                    self.output("Begin parsing deployment type", 3)
                    dt_name = element.find_children_by_name(node_name='Title')[0]['NodeInnerText']
                    dt_revision = int(element.get_attribute_value("Version"))
                    dt_logical_name = element.get_attribute_value('LogicalName')
                    self.output(f"Deployment Type: {dt_name}({dt_logical_name}): {dt_revision}",3)
                    if dt_name not in used_titles:
                        self.output(f"{dt_name} will be inserted into the existing application", 3)
                        unreferenced.append(
                            {
                                "Type":"XmlNodeAsDict",
                                "Object":element,
                                "LogicalName":dt_logical_name,
                                "Version": dt_revision
                            }
                        )
                    else:
                        self.output(f"{dt_name} already exists. Skipping it.")
            else:
                self.output("Unhandled deployment types will not be persisted.",3)
            self.output("Ordering deployment types.", 3)
            ordered = sorted([r for r in result if r["Priority"] is not None],
                            key=lambda x: x["Priority"])
            unordered = [r for r in result if r["Priority"] is None]
            final = []
            next_priority = 1
            u_ix = 0
            for r in ordered:
                while u_ix < len(unreferenced) and next_priority < r["Priority"]:
                    final.append({**unreferenced[u_ix], "Priority": next_priority})
                    next_priority += 1
            for rem in unreferenced[u_ix:] + unordered:
                final.append({**rem, "Priority": next_priority})
                next_priority += 1
            self.output("Finished ordering deployment types", 3)
            return final
        except Exception as e:
            raise ProcessorError(e)

    def add_install_action(self,installer_root:XmlNodeAsDict,deployment_type_configuration:dict) -> None:
        #print(f"Executing {sys._getframe().f_code.co_name}")
        try:
            visibility = ProgramVisibility(deployment_type_configuration.get('Options',{}).get('InstallationProgramVisibility','Hidden'))
        except:
            valid = ', '.join(f.value for f in ProgramVisibility)
            raise ProcessorError(f"Invalid installation program visibility: '{deployment_type_configuration.get('Options',{}).get('InstallationProgramVisibility')}'. Valid: {valid}")
        try:
            reboot_behavior = RebootBehavior(deployment_type_configuration.get('Options',{}).get('RebootBehavior','BasedOnExitCode'))
        except:
            valid = ', '.join(f.value for f in RebootBehavior)
            raise ProcessorError(f"Invalid reboot behavior: '{deployment_type_configuration.get('Options',{}).get('RebootBehavior')}'. Valid: {valid}")
        install_action_params = {
            "action_type": "InstallAction",
            "provider": deployment_type_configuration.get('Technology','Script')
        }
        execution_context = BehaviorTypeToContext[deployment_type_configuration.get('Options',{}).get('InstallationBehaviorType','InstallForSystem')]
        if ['MSI','Script'].__contains__(install_action_params['provider']):
            install_action_params["args"] = [
                new_arg(arg_name='InstallCommandLine', arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('InstallationProgram')),
                new_arg(arg_name='WorkingDirectory', arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('InstallationStartIn')),
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context)
            ]
            #Logon Requirement
            if deployment_type_configuration.get('Options',{}).get('LogonRequirementType') == 'OnlyWhenUserLoggedOn':
                install_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String',arg_value='True'))
            elif deployment_type_configuration.get('Options',{}).get('LogonRequirementType') == 'OnlyWhenNoUserLoggedOn':
                install_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String',arg_value='False'))
            else:
                install_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String'))
            # Install settings
            install_action_params['args'].append(new_arg(arg_name='RequiresElevatedRights',arg_type='Boolean',arg_value='false'))
            install_action_params['args'].append(new_arg(arg_name='RequiresUserInteraction',arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('RequiresUserInteraction',False).__str__().lower()))
            install_action_params['args'].append(new_arg(arg_name='RequiresReboot',arg_type='Boolean',arg_value=(reboot_behavior == 'ForceReboot').__str__().lower()))
            install_action_params['args'].append(new_arg(arg_name='UserInteractionMode',arg_type='String',arg_value=visibility.name))
            install_action_params['args'].append(new_arg(arg_name='PostInstallBehavior',arg_type='String',arg_value=reboot_behavior.name))
            estimated_execute_time = deployment_type_configuration.get('Options',{}).get('EstimatedInstallationTimeMins',0)
            if (0 <= estimated_execute_time <= 1440) == False:
                raise ProcessorError("EstimatedInstallationTime must be an integer between 0 and 1440")
            install_action_params['args'].append(new_arg(arg_name='ExecuteTime',arg_type='Int32',arg_value=f"{estimated_execute_time}"))
            max_execute_time = deployment_type_configuration.get('Options',{}).get('MaximumAllowedRuntimeMins',120)
            if (15 <= max_execute_time <= 1440) == False:
                raise ProcessorError("MaximumAllowedRuntimeMins must be an integer between 15 and 1440")
            install_action_params['args'].append(new_arg(arg_name='MaxExecuteTime',arg_type='Int32',arg_value=f"{max_execute_time}"))
            install_action_params['args'].append(new_arg(arg_name='RunAs32Bit',arg_type='Boolean',arg_value=f"{deployment_type_configuration.get('Options',{}).get('Force32BitInstaller',False).__str__().lower()}"))
            # Return Codes
            if deployment_type_configuration.get('Options',{}).get('KeepDefaultReturnCodes',True):
                success_exit_codes = [0,1707]
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
            for rc in deployment_type_configuration.get('Options',{}).get('CustomReturnCodes',[]):
                rc_hash[rc['CodeType']].append(rc['ReturnCode'])
            for rc_type in rc_hash.keys():
                if len(rc_hash[rc_type]) > 0:
                    self.output(f"Adding Exit Code arg for {rc_type}",3)
                    install_action_params['args'].append(new_arg(arg_name=f"{rc_type}ExitCodes",arg_type='Int32Array',arg_value=rc_hash[rc_type]))
            self.output("Done with return codes.", 3)
            # Content Reference
            self.output("Parsing any content references", 1)
            if deployment_type_configuration.get('Options',{}).get('ContentLocation','') != '':
                local_content_path_id = id(deployment_type_configuration.get('Options',{}).get('ContentLocation_Local'))
                self.output(f"Getting content importer with id: {local_content_path_id}", 2)
                content_importer = XmlNodeAsDict.instance_map_by_external_id[f"{local_content_path_id}"]
                self.output("Getting content reference.", 3)
                content_reference = get_content_reference(content_importer)
                self.output("Got content reference.", 3)
                install_action_params['content_reference'] = content_reference
        elif install_action_params['provider'] == 'TaskSequence':
            raise ProcessorError("TaskSequence deployment types are not yet supported")
            install_action_params["args"] = [
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context),
                new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string)
            ]
        elif install_action_params['provider'] == 'Windows8App':
            raise ProcessorError("Windows8App deployment types are not yet supported")
            install_action_params["args"] = [
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context),
                new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string)
            ]
        else:
            raise ProcessorError("Not supported.")
        install_action = new_dt_action(**install_action_params)
        installer_root.append_child_node([install_action])
    def add_uninstall_action(self,installer_root:XmlNodeAsDict,deployment_type_configuration:dict) -> None:
        try:
            visibility = ProgramVisibility(deployment_type_configuration.get('Options',{}).get('InstallationProgramVisibility','Hidden'))
        except:
            valid = ', '.join(f.value for f in ProgramVisibility)
            raise ProcessorError(f"Invalid installation program visibility: '{deployment_type_configuration.get('Options',{}).get('InstallationProgramVisibility')}'. Valid: {valid}")
        try:
            reboot_behavior = RebootBehavior(deployment_type_configuration.get('Options',{}).get('RebootBehavior','BasedOnExitCode'))
        except:
            valid = ', '.join(f.value for f in RebootBehavior)
            raise ProcessorError(f"Invalid reboot behavior: '{deployment_type_configuration.get('Options',{}).get('RebootBehavior')}'. Valid: {valid}")
        uninstall_action_params = {
            "action_type": "UninstallAction",
            "provider": deployment_type_configuration.get('Technology','Script')
        }
        execution_context = BehaviorTypeToContext[deployment_type_configuration.get('Options',{}).get('InstallationBehaviorType','InstallForSystem')]
        if ['MSI','Script'].__contains__(uninstall_action_params['provider']):
            uninstall_action_params["args"] = [
                new_arg(arg_name='InstallCommandLine', arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('UninstallProgram')),
                new_arg(arg_name='WorkingDirectory', arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('UninstallStartIn')),
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context)
            ]
            #Logon Requirement
            if deployment_type_configuration.get('Options',{}).get('LogonRequirementType') == 'OnlyWhenUserLoggedOn':
                uninstall_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String',arg_value='True'))
            elif deployment_type_configuration.get('Options',{}).get('LogonRequirementType') == 'OnlyWhenNoUserLoggedOn':
                uninstall_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String',arg_value='False'))
            else:
                uninstall_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String'))
            # Install settings
            uninstall_action_params['args'].append(new_arg(arg_name='RequiresElevatedRights',arg_type='Boolean',arg_value='false'))
            uninstall_action_params['args'].append(new_arg(arg_name='RequiresUserInteraction',arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('RequiresUserInteraction',False).__str__().lower()))
            uninstall_action_params['args'].append(new_arg(arg_name='RequiresReboot',arg_type='Boolean',arg_value=(reboot_behavior == 'ForceReboot').__str__().lower()))
            uninstall_action_params['args'].append(new_arg(arg_name='UserInteractionMode',arg_type='String',arg_value=visibility.name))
            uninstall_action_params['args'].append(new_arg(arg_name='PostInstallBehavior',arg_type='String',arg_value=reboot_behavior.name))
            estimated_execute_time = deployment_type_configuration.get('Options',{}).get('EstimatedInstallationTimeMins',0)
            if (0 <= estimated_execute_time <= 1440) == False:
                raise ProcessorError("EstimatedInstallationTimeMins must be an integer between 0 and 1440")
            uninstall_action_params['args'].append(new_arg(arg_name='ExecuteTime',arg_type='Int32',arg_value=f"{estimated_execute_time}"))
            max_execute_time = deployment_type_configuration.get('Options',{}).get('MaximumAllowedRuntimeMins',120)
            if (15 <= max_execute_time <= 1440) == False:
                raise ProcessorError("MaximumAllowedRuntimeMins must be an integer between 15 and 1440")
            uninstall_action_params['args'].append(new_arg(arg_name='MaxExecuteTime',arg_type='Int32',arg_value=f"{max_execute_time}"))
            uninstall_action_params['args'].append(new_arg(arg_name='RunAs32Bit',arg_type='Boolean',arg_value=deployment_type_configuration.get('Options',{}).get('Force32BitInstaller',False).__str__().lower()))
            # Return Codes
            if deployment_type_configuration.get('Options',{}).get('KeepDefaultReturnCodes',True):
                success_exit_codes = [0,1707]
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
            for rc in deployment_type_configuration.get('Options',{}).get('CustomReturnCodes',[]):
                rc_hash[rc['CodeType']].append(rc['ReturnCode'])
            for rc_type in rc_hash.keys():
                if len(rc_hash[rc_type]) > 0:
                    uninstall_action_params['args'].append(new_arg(arg_name=f"{rc_type}ExitCodes",arg_type='Int32Array',arg_value=rc_hash[rc_type]))
            # Content Reference
            uninstall_setting = deployment_type_configuration.get('Options',{}).get('UninstallSetting','NoneRequired')
            if uninstall_setting == 'Different' and deployment_type_configuration.get('Options',{}).get('UninstallContentLocation','') != '':
                content_reference = get_content_reference(content_importer=XmlNodeAsDict.instance_map_by_external_id[f"{id(deployment_type_configuration.get('Options',{}).get('UninstallContentLocation_Local'))}"])
                uninstall_action_params['content_reference'] = content_reference
            elif uninstall_setting == 'SameAsInstall':
                content_reference = get_content_reference(content_importer=XmlNodeAsDict.instance_map_by_external_id[f"{id(deployment_type_configuration.get('Options',{}).get('ContentLocation_Local'))}"])
                uninstall_action_params['content_reference'] = content_reference
            elif uninstall_setting == 'Different' and deployment_type_configuration.get('Options',{}).get('UninstallContentLocation','').strip() == '':
                raise ProcessorError("ContentLocation must be specified when UninstallSetting = 'Different'")
        elif uninstall_action_params['provider'] == 'TaskSequence':
            raise ProcessorError("TaskSequence deployment types are not yet supported")
            uninstall_action_params["args"] = [
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context),
                new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string)
            ]
        elif uninstall_action_params['provider'] == 'Windows8App':
            raise ProcessorError("Windows8App deployment types are not yet supported")
            uninstall_action_params["args"] = [
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context),
                new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string)
            ]
        else:
            raise ProcessorError("Not supported.")
        
        uninstall_action = new_dt_action(**uninstall_action_params)
        installer_root.append_child_node([uninstall_action])
    def add_repair_action(self,installer_root:XmlNodeAsDict,deployment_type_configuration:dict) -> None:
        try:
            visibility = ProgramVisibility(deployment_type_configuration.get('Options',{}).get('InstallationProgramVisibility','Hidden'))
        except:
            valid = ', '.join(f.value for f in ProgramVisibility)
            raise ProcessorError(f"Invalid installation program visibility: '{deployment_type_configuration.get('Options',{}).get('InstallationProgramVisibility')}'. Valid: {valid}")
        try:
            reboot_behavior = RebootBehavior(deployment_type_configuration.get('Options',{}).get('RebootBehavior','BasedOnExitCode'))
        except:
            valid = ', '.join(f.value for f in RebootBehavior)
            raise ProcessorError(f"Invalid reboot behavior: '{deployment_type_configuration.get('Options',{}).get('RebootBehavior')}'. Valid: {valid}")
        repair_action_params = {
            "action_type": "RepairAction",
            "provider": deployment_type_configuration.get('Technology','Script')
        }
        execution_context = BehaviorTypeToContext[deployment_type_configuration.get('Options',{}).get('InstallationBehaviorType','InstallForSystem')]
        if ['MSI','Script'].__contains__(repair_action_params['provider']):
            repair_action_params["args"] = [
                new_arg(arg_name='InstallCommandLine', arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('RepairProgram')),
                new_arg(arg_name='WorkingDirectory', arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('RepairStartIn')),
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context)
            ]
            #Logon Requirement
            if deployment_type_configuration.get('Options',{}).get('LogonRequirementType') == 'OnlyWhenUserLoggedOn':
                repair_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String',arg_value='True'))
            elif deployment_type_configuration.get('Options',{}).get('LogonRequirementType') == 'OnlyWhenNoUserLoggedOn':
                repair_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String',arg_value='False'))
            else:
                repair_action_params['args'].append(new_arg(arg_name='RequiresLogOn',arg_type='String'))
            # Install settings
            repair_action_params['args'].append(new_arg(arg_name='RequiresElevatedRights',arg_type='Boolean',arg_value='false'))
            repair_action_params['args'].append(new_arg(arg_name='RequiresUserInteraction',arg_type='String',arg_value=deployment_type_configuration.get('Options',{}).get('RequiresUserInteraction',False).__str__().lower()))
            repair_action_params['args'].append(new_arg(arg_name='RequiresReboot',arg_type='Boolean',arg_value=(reboot_behavior == 'ForceReboot').__str__().lower()))
            repair_action_params['args'].append(new_arg(arg_name='UserInteractionMode',arg_type='String',arg_value=visibility.name))
            repair_action_params['args'].append(new_arg(arg_name='PostInstallBehavior',arg_type='String',arg_value=reboot_behavior.name))
            estimated_execute_time = deployment_type_configuration.get('Options',{}).get('EstimatedInstallationTimeMins',0)
            if (0 <= estimated_execute_time <= 1440) == False:
                raise ProcessorError("EstimatedInstallationTime must be an integer between 0 and 1440")
            repair_action_params['args'].append(new_arg(arg_name='ExecuteTime',arg_type='Int32',arg_value=f"{estimated_execute_time}"))
            max_execute_time = deployment_type_configuration.get('Options',{}).get('MaximumAllowedRuntimeMins',120)
            if (15 <= max_execute_time <= 1440) == False:
                raise ProcessorError("MaximumAllowedRuntimeMins must be an integer between 15 and 1440")
            repair_action_params['args'].append(new_arg(arg_name='MaxExecuteTime',arg_type='Int32',arg_value=f"{max_execute_time}"))
            repair_action_params['args'].append(new_arg(arg_name='RunAs32Bit',arg_type='Boolean',arg_value=deployment_type_configuration.get('Options',{}).get('Force32BitInstaller',False).__str__().lower()))
            # Return Codes
            if deployment_type_configuration.get('Options',{}).get('KeepDefaultReturnCodes',True):
                success_exit_codes = [0,1707]
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
            for rc in deployment_type_configuration.get('Options',{}).get('CustomReturnCodes',[]):
                rc_hash[rc['CodeType']].append(rc['ReturnCode'])
            for rc_type in rc_hash.keys():
                if len(rc_hash[rc_type]) > 0:
                    repair_action_params['args'].append(new_arg(arg_name=f"{rc_type}ExitCodes",arg_type='Int32Array',arg_value=rc_hash[rc_type]))
        elif repair_action_params['provider'] == 'TaskSequence':
            raise ProcessorError("TaskSequence deployment types are not yet supported")
            repair_action_params["args"] = [
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context),
                new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string)
            ]
        elif repair_action_params['provider'] == 'Windows8App':
            raise ProcessorError("Windows8App deployment types are not yet supported")
            repair_action_params["args"] = [
                new_arg(arg_name='ExecutionContext', arg_type='String',arg_value=execution_context),
                new_arg(arg_name='MethodBody', arg_type='String',arg_value=xml_string)
            ]
        else:
            raise ProcessorError("Not supported.")
        
        repair_action = new_dt_action(**repair_action_params)
        installer_root.append_child_node([repair_action])
    def add_technology_specific_custom_data(self,installer_root:XmlNodeAsDict,deployment_type_configuration:dict,detection_nodes:list) -> None:
        custom_data_nodes = detection_nodes
        deployment_technology = deployment_type_configuration.get('Technology')
        if ['MSI','Script'].__contains__(deployment_technology):
            custom_data_nodes.append(XmlNodeAsDict(NodeName='InstallCommandLine',NodeInnerText=deployment_type_configuration.get('Options',{}).get('InstallationProgram')))
        elif deployment_technology == 'TaskSequence':
            custom_data_nodes.append(XmlNodeAsDict(NodeName='InstallCommandLine',NodeInnerText='Task Sequence'))
        if deployment_technology == 'Script':
            custom_data_nodes.append(XmlNodeAsDict(NodeName='RedirectCommandLine',NodeInnerText='true'))
        install_content_local = deployment_type_configuration.get('Options',{}).get('ContentLocation_Local','')
        if ['MSI','Script'].__contains__(deployment_technology):
            if install_content_local != '':
                install_content = XmlNodeAsDict.instance_map_by_external_id[f"{id(install_content_local)}"]
                install_content_id = install_content.get_attribute_value(attribute_name='ContentId')
                custom_data_nodes.append(XmlNodeAsDict(NodeName='InstallContent',Attributes=[XmlAttributeAsDict(Name='ContentId',Value=install_content_id),XmlAttributeAsDict(Name='Version',Value='1')]))
            uninstall_setting = deployment_type_configuration.get('Options',{}).get('UninstallSetting','SameAsInstall')
            uninstall_content_local = deployment_type_configuration.get('Options',{}).get('UninstallContentLocation_Local','')
            if uninstall_setting == 'SameAsInstall' and install_content_local != '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName='UninstallContent',Attributes=[XmlAttributeAsDict(Name='ContentId',Value=install_content_id),XmlAttributeAsDict(Name='Version',Value='1')]))
            elif uninstall_setting == 'Different' and uninstall_content_local != '':
                uninstall_content = XmlNodeAsDict.instance_map_by_external_id[f"{id(uninstall_content_local)}"]
                uninstall_content_id = uninstall_content.get_attribute_value(attribute_name='ContentId')
                custom_data_nodes.append(XmlNodeAsDict(NodeName='UninstallContent',Attributes=[XmlAttributeAsDict(Name='ContentId',Value=uninstall_content_id),XmlAttributeAsDict(Name='Version',Value='1')]))
            uninstall_command_line = deployment_type_configuration.get('Options',{}).get('UninstallProgram','')
            uninstall_start_in = deployment_type_configuration.get('Options',{}).get('UninstallStartIn','')
            if uninstall_command_line != '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName='UninstallCommandLine',NodeInnerText=uninstall_command_line))
                custom_data_nodes.append(XmlNodeAsDict(NodeName='UninstallFolder',NodeInnerText=uninstall_start_in))
            custom_data_nodes.append(XmlNodeAsDict(NodeName='UninstallSetting',NodeInnerText=uninstall_setting))
            repair_command_line = deployment_type_configuration.get('Options',{}).get('RepairProgram','')
            repair_start_in = deployment_type_configuration.get('Options',{}).get('RepairStartIn','')
            if repair_command_line != '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName='RepairCommandLine',NodeInnerText=repair_command_line))
                custom_data_nodes.append(XmlNodeAsDict(NodeName='RepairFolder',NodeInnerText=repair_start_in))
            self.output("Adding MaxExecute node.", 3)
            custom_data_nodes.append(XmlNodeAsDict(NodeName="MaxExecuteTime",NodeInnerText=str(deployment_type_configuration.get('Options',{}).get('MaximumAllowedRuntimeMins',120))))
            self.output("Adding ExecuteTime node.", 3)
            custom_data_nodes.append(XmlNodeAsDict(NodeName="ExecuteTime",NodeInnerText=str(deployment_type_configuration.get('Options',{}).get('EstimatedInstallationTimeMins',0))))
            if deployment_type_configuration.get('Options',{}).get('KeepDefaultReturnCodes',True):
                return_code_nodes = [
                    XmlNodeAsDict(NodeName="ExitCode",Attributes=[XmlAttributeAsDict(Name="Code",Value="0"),XmlAttributeAsDict(Name="Class",Value="Success")]),
                    XmlNodeAsDict(NodeName="ExitCode",Attributes=[XmlAttributeAsDict(Name="Code",Value="1707"),XmlAttributeAsDict(Name="Class",Value="Success")]),
                    XmlNodeAsDict(NodeName="ExitCode",Attributes=[XmlAttributeAsDict(Name="Code",Value="3010"),XmlAttributeAsDict(Name="Class",Value="SoftReboot")]),
                    XmlNodeAsDict(NodeName="ExitCode",Attributes=[XmlAttributeAsDict(Name="Code",Value="1641"),XmlAttributeAsDict(Name="Class",Value="HardReboot")]),
                    XmlNodeAsDict(NodeName="ExitCode",Attributes=[XmlAttributeAsDict(Name="Code",Value="1618"),XmlAttributeAsDict(Name="Class",Value="FastRetry")]),
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
            for rc in deployment_type_configuration.get('Options',{}).get('CustomReturnCodes',[]):
                node_params = {
                    "NodeName": "ExitCode",
                    "Attributes": [
                        XmlAttributeAsDict(Name="Code",Value=str(rc.get('ReturnCode'))),
                        XmlAttributeAsDict(Name="Class",Value=rc_type_hash[rc.get('CodeType')])
                    ]
                }
                if (code_name := rc.get('Name','')) != '':
                    node_params['Attributes'].append(XmlAttributeAsDict(Name="Name",Value=code_name))
                if (code_description := rc.get('Description','')) != '':
                    node_params['NodeInnerText'] = code_description
                return_code_nodes.append(XmlNodeAsDict(**node_params))
            if len(return_code_nodes) > 0:
                custom_data_nodes.append(XmlNodeAsDict(NodeName="ExitCodes",ChildNodes=return_code_nodes))
        detect_processes = deployment_type_configuration.get('Options',{}).get('InstallProcessDetection',[])
        if len(detect_processes) > 0:
            processes = []
            for ipd in detect_processes:
                processes.append(new_process_information(process_name=ipd['ProcessName'],process_display_name=ipd['DisplayName']))
            custom_data_nodes.append(new_install_process_detection(process_information=processes))
        if ['MSI','Script'].__contains__(deployment_technology):
            allow_uninstall = deployment_type_configuration.get('Options',{}).get('AllowUninstall',True)
            if allow_uninstall:
                custom_data_nodes.append(XmlNodeAsDict(NodeName='AllowUninstall',NodeInnerText=allow_uninstall.__str__().lower()))
            source_product_code = deployment_type_configuration.get('Options',{}).get('SourceUpdateProductCode','')
            if source_product_code != '':
                custom_data_nodes.append(XmlNodeAsDict(NodeName='SourceUpdateProductCode',NodeInnerText=source_product_code))
        else: # TaskSequence or Windows8App specific nodes.
            pass
        installer_root.append_child_node([XmlNodeAsDict(NodeName='CustomData',ChildNodes=custom_data_nodes)])
    def new_installer_node(self,authoring_scope_id:str,application_id:str,logical_name:str,version:int,deployment_type_configuration:dict) -> XmlNodeAsDict:
        installer_root = XmlNodeAsDict(NodeName='Installer',Attributes=[XmlAttributeAsDict(Name='Technology',Value=deployment_type_configuration.get('Technology'))])
        requires_logon = 'true' if deployment_type_configuration.get('ExecutionContext','System') == 'System'  or deployment_type_configuration.get('LogonRequirementType','') == 'OnlyWhenUserLoggedOn' else 'false' if deployment_type_configuration.get('LogonRequirementType','') == 'OnlyWhenNoUserLoggedOn' else None
        installer_root.append_child_node([
            XmlNodeAsDict(NodeName='ExecutionContext',NodeInnerText=deployment_type_configuration.get('ExecutionContext','System')),
            XmlNodeAsDict(NodeName='RequiresLogOn',NodeInnerText=requires_logon)
        ])
        content_path = deployment_type_configuration.get('Options',{}).get('ContentLocation')
        local_content_path = deployment_type_configuration.get('Options',{}).get('ContentLocation_Local')
        content_nodes = []
        if [content_path,local_content_path].__contains__(None) == False:
            self.output("Adding install content", 2)
            content_params = {
                "content_location": content_path,
                "content_location_local": local_content_path,
                "enable_peer_cache": deployment_type_configuration.get('Options',{}).get('EnablePeerCache',True),
                "fast_network_action": ContentHandlingMode(deployment_type_configuration.get('Options',{}).get('OnFastNetwork','Download')),
                "slow_network_action": ContentHandlingMode(deployment_type_configuration.get('Options',{}).get('OnSlowNetwork','Download'))
            }
        content_nodes.append(new_content_importer(**content_params))
        uninstall_setting = deployment_type_configuration.get('Options',{}).get('UninstallSetting','NoneRequired')
        if uninstall_setting == 'Different':
            content_params = {
                "content_location": deployment_type_configuration.get('Options',{}).get('UninstallContentLocation',None),
                "content_location_local": deployment_type_configuration.get('Options',{}).get('UninstallContentLocation_Local',None),
                "enable_peer_cache": deployment_type_configuration.get('Options',{}).get('EnablePeerCache',True),
                "fast_network_action": ContentHandlingMode(deployment_type_configuration.get('Options',{}).get('OnFastNetwork','Download')),
                "slow_network_action": ContentHandlingMode(deployment_type_configuration.get('Options',{}).get('OnSlowNetwork','Download'))
            }
            self.output('Adding uninstall content', 3)
            content_nodes.append(new_content_importer(**content_params))
        self.output('Appending collected content nodes', 3)
        installer_root.append_child_node([XmlNodeAsDict(NodeName='Contents',ChildNodes=content_nodes)])
        self.output('Creating detection nodes', 3)
        detection_nodes = new_detection_nodes(authoring_scope_id=authoring_scope_id,application_id=application_id,
                deployment_type_id=logical_name,detection_item=deployment_type_configuration.get('Options',{}).get('Detection'))
        self.output('Adding detection node(s) to installer node', 3)
        installer_root.append_child_node([detection_nodes[0]])
        # Install action
        self.output("Adding install action node", 2)
        self.add_install_action(installer_root=installer_root,deployment_type_configuration=deployment_type_configuration)
        # UninstallAction
        if deployment_type_configuration.get('Options',{}).get('UninstallProgram','').strip() != '':
            self.output("Adding uninstall action node", 2)
            self.add_uninstall_action(installer_root=installer_root,deployment_type_configuration=deployment_type_configuration)
        # RepairAction
        if deployment_type_configuration.get('Options',{}).get('RepairProgram','').strip() != '':
            self.output("Adding repair action node", 2)
            self.add_repair_action(installer_root=installer_root,deployment_type_configuration=deployment_type_configuration)
        # CustomData
        self.output(f"Adding custom data specific to {deployment_type_configuration.get('Technology')} deployment technology.", 3)
        self.add_technology_specific_custom_data(installer_root=installer_root,deployment_type_configuration=deployment_type_configuration,detection_nodes=detection_nodes[1])
        self.output("Finished adding custom data.", 3)
        return installer_root

    def new_deployment_type(self,authoring_scope_id:str,application_id:str,logical_name:str,version:int,deployment_type_configuration:dict) -> XmlNodeAsDict:
        self.output("Generating a deployment type node.", 3)
        attributes = [
            XmlAttributeAsDict(Name='AuthoringScopeId',Value=authoring_scope_id),
            XmlAttributeAsDict(Name='LogicalName',Value=logical_name),
            XmlAttributeAsDict(Name='Version',Value=str(version))
        ]
        try:
            self.output("Getting technology type.", 3)
            technology = DeploymentTechnology(deployment_type_configuration.get('Technology'))
        except:
            valid = ', '.join(f.value for f in DeploymentTechnology)
            raise ProcessorError(f"Invalid deployment technology: '{deployment_type_configuration.get('Technology')}'. Valid: {valid}")
        title = deployment_type_configuration.get('Options',{}).get('DeploymentTypeName','Install')
        node = XmlNodeAsDict(NodeName='DeploymentType',Attributes=attributes)
        child_nodes = [XmlNodeAsDict(NodeName='Title',NodeInnerText=title,Attributes=[new_resource_id_attribute()])]
        # Append administrator comments
        administrator_comment = deployment_type_configuration.get('Options',{}).get('AdministratorComment','')
        if administrator_comment != '':
            child_nodes.append(XmlNodeAsDict(NodeName="Description",Attributes=[new_resource_id_attribute()],NodeInnerText=administrator_comment))
        else:
            child_nodes.append(XmlNodeAsDict(NodeName="Description",Attributes=[new_resource_id_attribute()]))
        # Append languages
        languages = deployment_type_configuration.get('Options',{}).get('Languages','')
        if isinstance(languages,str):
            languages_list = [languages]
        elif isinstance(languages,list):
            languages_list = languages
        if len(languages_list) > 0:
            child_nodes.append(new_languages_node(languages_list))
        # Append requirements
        requirements_rules = []
        requirements = deployment_type_configuration.get('Options',{}).get('Requirements',[])
        self.output(f"Assembling {len(requirements)} requirements", 2)
        for r in requirements:
            rule_config_type = r['Type']
            rule_getter = get_requirements_rule_config[rule_config_type]
            rule_id = McmIdentifier().get_logical_name(object_type_name='Rule')
            self.output(f"Configuring requirement rule '{rule_id}' from {rule_config_type}", 3)
            requirements_rules.append(rule_getter(rule=r['Rule'],rule_id=rule_id))
        if len(requirements_rules) > 0:
            self.output("Adding requirements node", 2)
            child_nodes.append(XmlNodeAsDict(NodeName='Requirements',ChildNodes=requirements_rules))
        
        # Append dependencies
        self.output("Examining dependencies", 3)
        dependency_groups = deployment_type_configuration.get('Options',{}).get('DependencyGroups',[])

        if (len(dependency_groups) > 0):
            self.output("Creating dependency groups", 3)
            dependency_group_nodes = []
            for dg in dependency_groups:
                dependency_nodes = []
                for n in dg.get('Dependencies',[]):
                    required_app_search = self.find_application_by_name(application_name=n['ApplicationName'])
                    if required_app_search is None:
                        raise ProcessorError(f"Application '{['ApplicationName']}' was not found in MCM.")
                    required_app = XmlNodeAsDict.from_xml_string_with_tracking(xml_string = required_app_search['SDMPackageXML'])
                    self.output("Got dependency required app",3)
                    # Select the right deployment type
                    required_app_id = required_app.find_children_by_name('Application')[0].get_attribute_value(attribute_name='LogicalName')
                    self.output(f"This dependency will use application with id: {required_app_id}",3)
                    dt_finder_params = {
                        "application": required_app,
                    }
                    if n.get('DeploymentTypeFilter', '') != '':
                        dt_finder_params['deployment_type_name_filter'] = n.get('DeploymentTypeFilter')
                        dt_finder_params['deployment_type_name_filter_type'] = n.get('DeploymentTypeFilterType','Contains')
                    self.output("Calling get_dt_logicalname_from_application",3)
                    dt_logical_name = self.get_dt_logicalname_from_application(**dt_finder_params)
                    self.output(f"Found dependency: {dt_logical_name}. Adding it to this dependency node.")
                    dependency_nodes.append(new_dependency(authoring_scope_id=authoring_scope_id,
                            application_logical_name=required_app_id,dt_logical_name=dt_logical_name,auto_install=n.get('AutoInstall',False)))
                self.output(f"Finished with the dependency group {dg['DependencyGroupName']}",3)
                dependency_group_nodes.append(new_dependency_group(rule_name=dg["DependencyGroupName"],dependencies=dependency_nodes))
            self.output("Finished constructing dependency groups.",3)
            dependencies_node = new_dependencies_node(dependency_groups=dependency_group_nodes)
            child_nodes.append(dependencies_node)
        self.output("Adding common nodes to deployment type", 3)
        child_nodes.append(XmlNodeAsDict(NodeName='DeploymentTechnology',NodeInnerText=f"GLOBAL/{technology.name}DeploymentTechnology"))
        child_nodes.append(XmlNodeAsDict(NodeName='Technology',NodeInnerText=technology.name))
        child_nodes.append(XmlNodeAsDict(NodeName='Hosting',NodeInnerText=deployment_type_configuration.get('Hosting','Native')))
        # Append installer
        self.output("Adding installer node", 3)
        installer_node = self.new_installer_node(authoring_scope_id=authoring_scope_id,application_id=application_id,
                logical_name=logical_name,version=version,deployment_type_configuration=deployment_type_configuration)
        child_nodes.append(installer_node)
        node.append_child_node(child_nodes)
        return node

    def main(self):
        """Main McmAppXmlGenerator process"""
        self.output("Generating headers.",3)
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        self.output("Checking supplied parameters",3)
        keychainServiceName = self.env.get("keychain_password_service", self.input_variables["keychain_password_service"]["default"])
        keychainUsername = self.env.get("keychain_password_username",self.env.get("MCMAPI_USERNAME",''))
        self.fqdn = self.env.get("mcm_site_server_fqdn", '')

        if (self.fqdn == None or self.fqdn == ''):
            raise ValueError("mcm_site_server_fqdn cannot be blank")

        if (keychainServiceName == None or keychainUsername == ''):
            raise ValueError("keychain_password_service cannot be blank")

        if (keychainUsername == None or keychainUsername == ''):
            raise ValueError("keychain_password_username cannot be blank")
        
        self.output("Generating an NTLM auth object.", 3)
        self.ntlm = self.get_mcm_ntlm_auth(keychain_service_name=keychainServiceName,keychain_username=keychainUsername)
        
        try:
            # Define namespaces
            appNs = get_nsmap('AppMgmtDigest')
            self.nsmap = appNs['nsmap']
            
            self.authoringScope = self.get_mcm_scope_id()
            # Search for existing app
            app = self.env.get('mcm_application_configuration')
            behaviorIfAppExists = app.get('BehaviorIfExists','Exit')
            existing_app_ci_id = self.env.get('existing_app_ci_id',0)
            self.output(f"Existing CI_ID: {existing_app_ci_id}", 3)
            existing_app_sdmpackagexml = self.env.get('existing_app_sdmpackagexml','')
            self.output(f"Existing SDMPackageXML Length: {len(existing_app_sdmpackagexml)}", 3)
            if existing_app_sdmpackagexml != '' and existing_app_ci_id > 0:
                self.output("An existing application with this name was located.", 2)
                existingApp = XmlNodeAsDict.from_xml_string_with_tracking(xml_string = existing_app_sdmpackagexml.replace('<?xml version="1.0" encoding="utf-16"?>','',1))
            isNewApp = True
            appName = app.get('Name')
            if existingApp is not None and behaviorIfAppExists == 'Exit':
                self.output(f"The application already exists and BehaviorIfExists was set to 'Exit'. Nothing to do.",1)
                return
            if existingApp is None:
                pass
            elif behaviorIfAppExists == 'Update':
                isNewApp = False
                self.output('Using the existing Logical Name and CI_ID for the application and incrementing the revision/version.', 1)
                appName = app.get('Name')
                app_nodes = existingApp.find_children_by_name('Application')
                self.output(f"{appName} contains {len(app_nodes)} application nodes.", 3)
                appLogicalName = app_nodes[0].get_attribute_value('LogicalName')
                appVersion = int(existingApp.find_children_by_name('Application')[0].get_attribute_value('Version')) + 1
                self.env['mcm_application_ci_id'] = existing_app_ci_id
            elif behaviorIfAppExists == 'AppendIndex':
                done = False
                index = 1
                while done == False and index < 20:
                    searchName = f"{app.get('Name')} ({index.__str__()})"
                    result = self.find_application_by_name(searchName)
                    if result is None:
                        self.output(f"Appending an index ({index.__str__()}) to the application name.", 3)
                        appName = searchName
                        done = True
                    index += 1
                    if index == 20:
                        self.output("Wow... There are 20 versions of this application. You should probably look at this.", 3)
                        break
                    else:
                        continue
                if done == False:
                    raise ProcessorError("Could not find a name that was not already taken.")
                self.env['mcm_application_ci_id'] = 0
            elif behaviorIfAppExists == 'AppendVersion':
                searchName = f"{app.get('Name')} {app.get('SoftwareVersion')}"
                self.output(f"Checking to see if an app with the version appended exists ({searchName}).", 3)
                result = self.find_application_by_name(searchName)
                if result is None:
                    self.output("Appending the version to the application name.", 3)
                    appName = searchName
                else:
                    raise ProcessorError(f"An application already exists which already includes the version in the title. ({searchName})")
            else:
                raise ProcessorError("Invalid setting for BehaviorIfExists.")
            if isNewApp:
                appVersion = 1
                appLogicalName = McmIdentifier().get_logical_name('Application')
                self.env['mcm_application_ci_id'] = 0            
            self.output(f"\n\tName: {appName}\n\tLogicalName: {appLogicalName}\n\tRevision: {appVersion}\n\tCI_ID: {self.env['mcm_application_ci_id']}",3)
            self.output("Examining deployment types.", 1)
            if self.env.get('mcm_application_ci_id',0) > 0:
                existingDts = existingApp.find_children_by_name(node_name='DeploymentType')
                self.output(f"Comparing configured deployment types to {len(app.get('DeploymentTypes',[]))} deployment types in the existing application.", 3)
                merged = self.merge_deployment_types(authoring_scope_id=self.authoringScope,dicts=app.get('DeploymentTypes',[]),existing_deployment_types=existingDts,persist_unhandled_deployment_types=app.get('PersistUnhandledDeploymentTypes',False))
            else:
                self.output("Deployment types from the supplied configuration will be used.", 3)
                merged = self.merge_deployment_types(authoring_scope_id=self.authoringScope,dicts=app.get('DeploymentTypes',[]),existing_deployment_types=[])
            self.output('Done examining deployment types.', 3)
            dt_list = []
            for dt in merged:
                if dt["Type"] == 'element':
                    dt_list.append(XmlNodeAsDict.convert_element_to_dict(dt['Object'],namespace_mode='PersistAsAttribute',parent_namespace=existingApp.nsmap,is_root=False))
                elif dt["Type"] == "XmlNodeAsDict":
                    self.output("Appending the existing deployment type", 3)
                    dt_list.append(dt['Object'])
                else:
                    self.output("Creating a new deployment type.", 3)
                    dt_list.append(self.new_deployment_type(authoring_scope_id=self.authoringScope,application_id=appLogicalName,
                            logical_name=dt['LogicalName'],version=dt['Version'],deployment_type_configuration=dt['Object']))
            self.output("Creating application object.", 1)
            app_attributes = [
                XmlAttributeAsDict(Name='AuthoringScopeId',Value=self.authoringScope),
                XmlAttributeAsDict(Name='LogicalName',Value=appLogicalName),
                XmlAttributeAsDict(Name='Version',Value=str(appVersion))
            ]
            application = XmlNodeAsDict(NodeName='Application',Attributes=app_attributes)
            # Append display info
            self.output("Creating DisplayInfo", 2)
            configuredDisplayInfo = app.get('DisplayInfo',{})
            configuredInfos = configuredDisplayInfo.get('Infos',[])
            self.output("Getting details for any configured icons.", 3)
            iconFileUnixPaths = []
            if app.get('IconFileUnixPath','') != '':
                iconFileUnixPaths.append(app.get('IconFileUnixPath'))
            for v in [x.get('IconFileUnixPath') for x in configuredInfos if x.get("IconFileUnixPath","") != ""]:
                if not (iconFileUnixPaths.__contains__(v)):
                    iconFileUnixPaths.append(v)
            iconResources = []
            iconResourcesHash = {}
            iconReferencesHash = {}
            allResources = []
            self.output("Getting icon resource hashes.", 3)
            for i in iconFileUnixPaths:
                self.output(f"{i}",3 )
                iconResourcesHash[i] = new_icon_resource(local_path=i)
                iconReferencesHash[i] = get_icon_reference(icon_resource=iconResourcesHash[i])
                allResources.append(iconResourcesHash[i])
                iconResources.append(iconResourcesHash[i])
            self.output(f"Collected {len(list(iconResourcesHash.keys()))} icon resource details.", 3)
            # Get UserCategory info
            self.output("Getting UserCategory details.", 3)
            userCategoryNames = []
            for c in app.get('UserCategories',[]):
                userCategoryNames.append(c)
            for namegroup in [y.get('UserCategories') for y in configuredInfos if len(y.get('UserCategories',[])) > 0]:
                for n in namegroup:
                    if not (userCategoryNames.__contains__(n)):
                        userCategoryNames.append(n)
            userCategories = dict.fromkeys(userCategoryNames)
            for cn in list(userCategories.keys()):
                userCategories[cn] = self.get_user_category_id(cn)
            self.output(f"Collected {len(list(userCategories.keys()))} UserCategory detail objects.", 3)
            # Default DisplayInfo
            self.output("Defining parameters for the default DisplayInfo.", 3)
            defaultInfoParams = {}
            defaultLanguage = app.get('DefaultLanguage', 'en-US')
            defaultInfoParams["language"] = defaultLanguage
            defaultLocalizedDisplayName = app.get('LocalizedDisplayName', app.get('Name',self.env.get('NAME','')))
            if defaultLocalizedDisplayName == '':
                raise ProcessorError('Applications must have a name.')
            defaultInfoParams["title"] = defaultLocalizedDisplayName
            defaultLocalizedDescription = app.get('LocalizedDescription',app.get('Description'))
            defaultInfoParams["description"] = defaultLocalizedDescription
            if defaultLocalizedDescription != '':
                defaultInfoParams["description"] = defaultLocalizedDescription
            defaultIconFileUnixPath = app.get('IconFileUnixPath', None)
            if defaultIconFileUnixPath is not None:
                defaultInfoParams["icon_reference"] = iconReferencesHash[defaultIconFileUnixPath]
            defaultKeywords = app.get('Keyword',[])
            defaultLinkText = app.get('InfoUrlText', None)
            defaultPrivacyUrl = app.get('PrivacyUrl', None)
            defaultUserDocumentation = app.get('UserDocumentation', None)
            publisher = app.get('Publisher')
            defaultInfoParams['publisher'] = publisher
            version = app.get('SoftwareVersion')
            defaultInfoParams['software_version'] = version
            releaseDate = app.get('ReleaseDate',None)
            if releaseDate is not None:
                self.output("Adding release date.",3)
                defaultInfoParams["release_date"] = releaseDate
            self.output("Defining parameters for any additional DisplayInfo objects.", 3)
            display_infos = []
            defaultDisplayInfoConfigured = False
            configuredLanguages = []
            for i in configuredInfos:
                iLanguage = i.get('Language','')
                if iLanguage == '':
                    raise ProcessorError('Each display info must have Language specified.')
                self.output(f"Processing DisplayInfo for {iLanguage}")
                if configuredLanguages.__contains__(iLanguage):
                    raise ProcessorError('DisplayInfo properties for any language can only be configured once.')
                configuredLanguages.append(iLanguage)
                if iLanguage == defaultLanguage:
                    self.output(f"Configuring display properties for the default language ({defaultLanguage}).",2)
                    defaultDisplayInfoConfigured = True
                iParams = {"language":iLanguage}
                iParams['publisher'] = publisher
                iParams['software_version'] = version
                if releaseDate is not None:
                    iParams["release_date"] = releaseDate
                if i.get('LocalizedDisplayName','') == '':
                    iParams['title'] = defaultLocalizedDisplayName
                else:
                    iParams["title"] = i.get('LocalizedDisplayName')
                if i.__contains__('LocalizedDescription'):
                    iParams["description"] = i.get('LocalizedDescription')
                else:
                    iParams["description"] = defaultLocalizedDescription
                if i.__contains__('IconFileUnixPath') and i.get('IconFileUnixPath','') != '':
                    iParams["icon_reference"] = iconReferencesHash[i.get('IconFileUnixPath')]
                elif defaultIconFileUnixPath is not None and defaultIconFileUnixPath != '':
                    iParams["icon_reference"] = iconReferencesHash[defaultIconFileUnixPath]
                if i.__contains__('UserDocumentation'):
                    iParams["info_url"] = i.get('UserDocumentation')
                else:
                    iParams["info_url"] = defaultUserDocumentation
                if i.__contains__('LinkText'):
                    iParams["info_url_text"] = i.get('LinkText')
                else:
                    iParams["info_url_text"] = defaultLinkText
                if i.__contains__('PrivacyUrl'):
                    iParams["privacy_url"] = i.get('PrivacyUrl')
                else:
                    iParams["privacy_url"] = defaultPrivacyUrl
                if i.__contains__('UserCategories'):
                    infoUserCategories =  i.get('UserCategories',[])
                else:
                    infoUserCategories = app.get('UserCategories',[])
                iUserCategories = []
                for c in infoUserCategories:
                    iUserCategories.append(userCategories[c])
                if len(iUserCategories) > 0:
                    iParams["user_categories_node"] = new_user_categories_node(user_category_unique_ids=userCategories)
                if i.__contains__('Keyword'):
                    iParams["tags"] = i.get('Keyword')
                else:
                    iParams["tags"] = defaultKeywords
                self.output(f"Done gathering display info parameters. Generating node.", 3)
                display_infos.append(new_display_info(**iParams))
            if defaultDisplayInfoConfigured == False:
                self.output("Default DisplayInfo was not defined. Creating it now.",2)
                display_infos.append(new_display_info(**defaultInfoParams))
            displayInfoNode = new_display_info_node(display_infos=display_infos,default_language=defaultLanguage)
            application.append_child_node([displayInfoNode])
            # Append deployment type references
            self.output("Adding deployment type references", 2)
            deployment_type_references = []
            for deployment_type in dt_list:
                self.output('Getting reference', 3)
                deployment_type_references.append(get_deployment_type_reference(deployment_type=deployment_type))
            deployment_types_node = XmlNodeAsDict(NodeName='DeploymentTypes',ChildNodes=deployment_type_references)                
            application.append_child_node([deployment_types_node])
            self.output("Adding title",2)
            application.append_child_node([XmlNodeAsDict(NodeName='Title',Attributes=[new_resource_id_attribute()],NodeInnerText=appName)])
            if len(defaultLocalizedDescription or []) > 0:
                self.output("Adding description",2)
                application.append_child_node([XmlNodeAsDict(NodeName='Description',Attributes=[new_resource_id_attribute()],NodeInnerText=defaultLocalizedDescription)])
            if len(publisher or []) > 0:
                self.output("Adding publisher",2)
                application.append_child_node([XmlNodeAsDict(NodeName='Publisher',Attributes=[new_resource_id_attribute()],NodeInnerText=publisher)])
            if len(app.get("SoftwareVersion") or []) > 0:
                self.output(f"Adding software version {app.get('SoftwareVersion')}",2)
                application.append_child_node([XmlNodeAsDict(NodeName='SoftwareVersion',Attributes=[new_resource_id_attribute()],NodeInnerText=app.get("SoftwareVersion"))])
            if len(releaseDate or []) > 0:
                self.output("Adding release date",2)
                application.append_child_node([XmlNodeAsDict(NodeName='ReleaseDate',Attributes=[new_resource_id_attribute()],NodeInnerText=releaseDate)])
            optionalReference = app.get('OptionalReference') or ''
            if len(optionalReference.strip()) > 0:
                self.output(f"Adding optional reference",2)
                application.append_child_node([XmlNodeAsDict(NodeName='CustomId',Attributes=[new_resource_id_attribute()],NodeInnerText=str(app['OptionalReference']).strip())])
            self.output("Adding AutoInstall setting",2)
            application.append_child_node([XmlNodeAsDict(NodeName='AutoInstall',NodeInnerText=str(app.get('AutoInstall',False)).lower())])
            if len(app.get('Owners',[])) > 0:
                self.output("Adding owners",2)
                application.append_child_node([new_owners_node(user_ids=app['Owners'])])
            if len(app.get('SupportContacts',[])) > 0:
                self.output("Adding contacts",2)
                application.append_child_node([new_contacts_node(user_ids=app['SupportContacts'])])
            if bool(app.get('SendToProtectedDP',False)):
                self.output("Allowing send to protected dp",3)
                application.append_child_node([XmlNodeAsDict(NodeName='SendToProtectedDP',NodeInnerText='true')])
            self.output("Creating AppMgmtDigest.", 2)
            appMgmtDigest_root = XmlNodeAsDict(NodeName='AppMgmtDigest',Attributes=[XmlAttributeAsDict(Name='xmlns',Value=get_nsmap('AppMgmtDigest')['ns'])],nsmap=get_nsmap("Default",include_xsi=True)['nsmap'])
            self.output("Adding application node", 3)
            appMgmtDigest_root.append_child_node([application])
            if len(dt_list) > 0:
                self.output('Adding deployment types.', 3)
                appMgmtDigest_root.append_child_node(dt_list)
            if len(allResources) > 0:
                self.output('Adding resources node.', 3)
                resources_node = XmlNodeAsDict(NodeName='Resources',ChildNodes=allResources)
                appMgmtDigest_root.append_child_node([resources_node])
            self.output("Setting mcm_application variable", 3)
            sdm_package_xml_string = appMgmtDigest_root.to_xml_string(xml_declaration=True,encoding='utf-16',pretty_print=True)
            self.output('Setting SDMPackageXML variable', 2)
            self.env["SDMPackageXML"] = sdm_package_xml_string

        except Exception as e:
            self.output("Failed to generate XML.")