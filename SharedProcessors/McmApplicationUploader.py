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

import requests
import keyring
import json
from lxml import etree
from requests_ntlm import HttpNtlmAuth
from enum import Enum,auto
from io import BytesIO

from autopkglib import Processor, ProcessorError

# Utility
def try_cast(type_name,value,default=None):
    try:
        return type_name(value)
    except:
        return default

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

__all__ = ["McmApplicationUploader"]

class McmApplicationUploader(Processor):
    description = """AutoPkg Processor to connect to an MCM Admin Service and retrieve an application object, if it exists."""
    input_variables = {
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
        "mcm_application_ci_id": {
            "required": False,
            "description": "The CI_ID to post the application to. If not specified, or if '0', a new application will be created.",
            "default": 0
        },
        "mcm_application_sdmpackagexml": {
            "required": True,
            "description": "The SDMPackageXML to upload to the MCM site."
        },
        "response_export_properties": {
            "required": False,
            "default": {
                "app_ci_id": {"type": "property", "raise_error": False,"options": {"expression": "CI_ID"}},
                "app_model_name": {"type": "property", "raise_error": True,"options": {"expression": "ModelName"}},
                "app_securityscopes": {"type": "property", "raise_error": False,"options": {"expression": "SecuredScopeNames"}},
                "app_is_deployed": {"type": "property", "raise_error": True, "options": {"expression": "IsDeployed"}},
                "app_logical_name": {"type": "xpath", "raise_error": True,"options": {"select_value_index": '0', "strip_namespaces": False, "property": "SDMPackageXML", "expression": '/*[local-name()="AppMgmtDigest"]/*[local-name()="Application"]/@LogicalName'}},
                "app_content_locations": {"type": "xpath", "raise_error": False,"options": {"select_value_index": '*', "strip_namespaces": True, "property": "SDMPackageXML", "expression": '//Content/Location/text()'}}
            },
            "description": 
                "A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output. "
                "Each key name specified will be used as the AutoPkg variable name; each value should be populated by a dictionary "
                "representing how to retrieve the property from the MCM application. Supported retrieval types are 'property' and 'xpath'. "
                "'raise_error' specifies whether to raise an error if the property cannot be found. "
                ""
                "'property' type options require an 'expression' option specifying the property name to retrieve from the MCM application. "
                "'xpath' type options require a 'property' option specifying the property name (generally 'SDMPackageXML') to run the xpath query against, and an 'expression'. "
                "The 'strip_namespaces' option may also be specified to indicate whether to strip namespaces from the XML before evaluating the xpath expression."
                "The 'select_value_index' option may also be specified to indicate which value to select from the xpath result set (default is '*' (return all values as an array list)). "
                "Positive or negative integers may be specified to select a specific index from the result set (0-based). Negative integers count from the end of the result set (-1 is the last item))."
        }
    }
    output_variables = {}
    
    __doc__ = description

    def convert_site_id_to_scope_id(self,siteId:str) -> str:
        siteIdGuid = siteId.replace('{','').replace('}','')
        scopeId = f"ScopeId_{siteIdGuid}"
        return scopeId

    def get_mcm_ntlm_auth(self, keychainServiceName:str, keychainUsername:str) -> HttpNtlmAuth:
        password = keyring.get_password(keychainServiceName,keychainUsername)
        return HttpNtlmAuth(keychainUsername,password)

    def strip_namespaces(element):
        """Remove all namespaces from an XML element for easier XPath query support"""
        for e in element.iter():
            if e.tag is not etree.Comment:
                e.tag = etree.QName(e).localname
        etree.cleanup_namespaces(element)
        return element

    def main(self):
        """McmApplicationUploader Main Method"""

        try:
            self.output("Generating headers.",3)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            self.output("Checking supplied parameters",3)
            keychainServiceName = self.env.get("keychain_password_service", self.input_variables["keychain_password_service"]["default"])
            keychainUsername = self.env.get("keychain_password_username",self.env.get("MCMAPI_USERNAME",''))
            fqdn = self.env.get("mcm_site_server_fqdn", '')

            if (fqdn == None or fqdn == ''):
                raise ProcessorError("mcm_site_server_fqdn cannot be blank")

            if (keychainServiceName == None or keychainUsername == ''):
                raise ProcessorError("keychain_password_service cannot be blank")

            if (keychainUsername == None or keychainUsername == ''):
                raise ProcessorError("keychain_password_username cannot be blank")

            sdm_package_xml = self.env.get("mcm_application_sdmpackagexml")
            if (sdm_package_xml == None or sdm_package_xml == ''):
                raise ProcessorError("SDMPackageXML cannot be blank")
            ci_id = try_cast(int,self.env.get("mcm_application_ci_id", self.input_variables["mcm_application_ci_id"]["default"]),0)
            self.output("Generating NTLM Auth object.",3)
            ntlm = self.get_mcm_ntlm_auth(
                keychainServiceName=keychainServiceName,
                keychainUsername=keychainUsername
            )
            url = f"https://{fqdn}/AdminService/wmi/SMS_Application"
            if ci_id > 0:
                url += f"({str(ci_id)})"
            self.output("Generating post body",3)
            body = {"SDMPackageXML": sdm_package_xml}
            self.output(f"Posting application to {url}",1)
            postResponse = requests.request(
                method='POST',
                url=url,
                auth=ntlm,
                headers=headers,
                verify=False,
                json=body
            )
            self.output(f"Parsing response: {type(postResponse).__name__}",3)
            postResponseJson = postResponse.json()
            self.output("Got Json body from response", 3)
            export_properties:dict = self.env.get('response_export_properties',self.input_variables['response_export_properties']['default'])
            self.output(f"export_properties config: \n\n{json.dumps(export_properties)}", 3)
            self.output("Setting the value of specified export properties",2)
            for k in list(export_properties.keys()):
                self.output(f"Getting export property '{k}' from a {export_properties.get(k,{}).get('type','TypeNotFound')} expression", 3)
                if export_properties[k]["type"] == 'property':
                    if not postResponseJson.__contains__(export_properties[k]['options']['expression']) and export_properties[k].get('raise_error',False) == True:
                        raise ProcessorError(f"Property {export_properties[k]['options']['expression']} does not exist on the retrieved object. Valid properties are: {', '.join(list(postResponseJson.keys()))}")
                    value = postResponseJson.get(export_properties[k]['options']['expression'],None)
                elif export_properties[k]["type"] == 'xpath':
                    if not postResponseJson.__contains__(export_properties[k]['options']['property']) and export_properties[k].get('raise_error',False) == True:
                        raise ProcessorError(f"Property {export_properties[k]['options']['property']} does not exist on the retrieved object.")
                    elif not postResponseJson.__contains__(export_properties[k]['options']['property']):
                        value = None
                    else:
                        try:
                            xml_element = etree.XML(postResponseJson.get(export_properties[k]['options']['property'],'').replace('<?xml version="1.0" encoding="utf-16"?>','',1).replace("<?xml version='1.0' encoding='utf-16'?>",'',1))
                            if export_properties[k]['options'].get('strip_namespaces',False) == True:
                                self.output("Stripping namespaces from XML element before evaluating xpath expression",3)
                                xml_element = McmApplicationUploader.strip_namespaces(xml_element)
                            xml_xpath_expr = export_properties[k]['options']['expression']
                            results = xml_element.xpath(xml_xpath_expr)
                            self.output("Got results from xpath expression",3)
                            if len(results) == 0:
                                if export_properties[k].get('raise_error',False) == True:
                                    self.output("XPath expression returned no results, and raise_error was set to True",3)
                                    raise ProcessorError(f"XPath expression {export_properties[k]['options']['expression']} on property {export_properties[k]['options']['property']} returned no results.")
                                else:
                                    self.output("XPath expression returned no results, and raise_error was set to False",3)
                                    value = None
                            else:
                                select_value_index = str(export_properties[k]['options'].get('select_value_index','*'))
                                self.output(f"Selecting item {select_value_index} from ({len(results)}) results from xpath expression",3)
                                if str(select_value_index) == '*':
                                    value = [str(r) for r in results]
                                else:
                                    try:
                                        self.output(f"Selecting item {select_value_index} from xpath results",3)
                                        index = int(select_value_index)
                                        value = str(results[index])
                                    except Exception as e:
                                        raise ProcessorError(f"Failed to select index {select_value_index} from xpath results for expression {export_properties[k]['options']['expression']} on property {export_properties[k]['options']['property']}. Error: {str(e)}")
                        except Exception as e:
                            if export_properties[k].get('raise_error',False) == True:
                                raise ProcessorError(f"Failed to evaluate xpath expression {export_properties[k]['options']['expression']} on property {export_properties[k]['options']['property']}. Error: {str(e)}")
                            else:
                                value = None              
                self.output(f"Setting '{k}' export property from a(n) {export_properties[k]['type']} expression which evaluated to ({value if len(str(value)) <= 32 else (str(value)[0:31] + '...') }) on the retrieved application", 3)
                self.env[k] = value
                
        except Exception as e:
            raise e

if __name__ == "__main__":
    PROCESSOR = McmApplicationUploader()
    PROCESSOR.execute_shell()