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
import json
from lxml import etree
from enum import Enum,auto
from io import BytesIO

import keyring
from requests_ntlm import HttpNtlmAuth

from autopkglib import Processor, ProcessorError

# Utility
def try_cast(type_name, value,default = None):
    """Cast the supplied value as the indicated type. If it cannot
    cast, return a default value
    """
    try:
        return type_name(value)
    except:
        return default

class XmlAttributeAsDict(dict):
    """Allow XML attributes to be represented as dict objects"""
    def __init__(self,Name: str, Value: any):
        super().__init__({
            'Name': Name,
            'Value':  try_cast(str,Value,'')
        })

class XmlNodeAsDict(dict):
    """Stub class to allow XmlNodeAsDict to nest inside of itself"""
    pass

class XmlNodeAsDict(dict):
    """Represent an etree.Element object as a dict"""
    instance_map = {}
    instance_map_by_external_id = {}
    def __init__(
            self, NodeName: str, 
            Attributes: list[XmlAttributeAsDict] = [],
            ChildNodes: list[XmlNodeAsDict] = None,
            NodeInnerText: str = None, nsmap: dict = None,
            xml_declaration: bool = False,
            external_reference_id: int = None,
            group_ids: list[int] = []
            ):
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
        """Convert an XML string into an XmlNodeAsDict instance"""
        xml = etree.XML(xml_string)
        return XmlNodeAsDict.convert_element_to_dict(element=xml,namespace_mode=namespace_mode)
    
    @classmethod
    def from_dict(cls, data):
        """Convert an existing dict to an XmlNodeAsDict instance.
        Useful if importing a dict which has been saved to a file as
        json
        """
        instance = cls(data)
        if 'ChildNodes' in instance and isinstance(instance('ChildNodes',list)):
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
    
    def append_child_node(self,ChildNodes:list[XmlNodeAsDict]):
        """Append a list of XmlNodeAsDict instances to the ChildNodes
        of the instance on which this method is called
        """
        for n in ChildNodes:
            self['ChildNodes'].append(n)
    
    def set_node_inner_text(self,NodeInnerText:str):
        """Overwrite the existing NodeInnerText with the supplied
        string
        """
        self['NodeInnerText'] = NodeInnerText
    
    def has_children(self):
        """Return True if the XmlNodeAsDict instance's ChildNodes
        contains one or more XmlNodeAsDict instances
        """
        if len(self.get('ChildNodes',[])) == 0:
            return False
        else:
            return True
    
    def convert_to_xml(self)->etree.Element:
        """Convert the current instance to an etree.Element object"""
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
        """Convert the current instance to a raw xml string"""
        xml = self.convert_to_xml()
        include_xml_declaration = xml_declaration if xml_declaration is not None else self.get('xml_declaration',False)
        xml_string = etree.tostring(xml,pretty_print=pretty_print,xml_declaration=include_xml_declaration,encoding=encoding).decode(encoding)
        return xml_string
    
    def get_attribute_value(self,attribute_name:str)->str:
        """Return the Value property for the XmlAttributeAsDict
        instance attached to this instance for the given attribute
        name
        """
        if (attribute_name,'') == '':
            raise ValueError("Must specify an attribute name to retrieve.")
        result = next((x.get('Value',None) for x in self.get('Attributes',[]) if x.get('Name','') == attribute_name), None)
        return result
    
    @property
    def LogicalName(self):
        """Return the LogicalName attribute value for this instance"""
        return self.get_attribute_value(attribute_name='LogicalName')
    
    @property
    def ResourceId(self):
        """Return the ResourceId attribute value for this instance"""
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
        """Convert element, preserving explicit namespace
        declarations
        """
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
        """Return direct children of this XmlNodeAsDict instance where
        the tag/node name matches the given string
        """
        return [child for child in self.get('ChildNodes',[]) if child.get('NodeName') == node_name]

__all__ = ["McmApplicationUploader"]

class McmApplicationUploader(Processor):
    description = """AutoPkg Processor to connect to an MCM Admin
    Service and upload an application object, if it exists
    """
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
        "mcm_app_uploader_export_properties": {
            "required": False,
            "default": {
                "app_ci_id": {"type": "property", "raise_error": False,"options": {"expression": "CI_ID"}},
                "app_model_name": {"type": "property", "raise_error": True,"options": {"expression": "ModelName"}},
                "object_class": {"type": "property", "raise_error": True,"options": {"expression": "__CLASS"}},
                "current_object_path": {"type":"property", "raise_error": False, "options": {"expression": "ObjectPath"}},
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

    def convert_site_id_to_scope_id(self, site_id: str) -> str:
        """Convert a SiteID string to a scope id"""
        site_id_guid = site_id.replace('{','').replace('}','')
        scope_id = f"ScopeId_{site_id_guid}"
        return scope_id

    def get_mcm_ntlm_auth(
            self, keychain_service_name: str, keychain_username: str
            ) -> HttpNtlmAuth:
        """Get the credential from keychain using the supplied
        parameters and return an HttpNtlmAuth object from the retrieved
        details
        """
        password = keyring.get_password(
            keychain_service_name,keychain_username
            )
        return HttpNtlmAuth(keychain_username,password)

    def strip_namespaces(element):
        """Remove all namespaces from an XML element for easier XPath
        query support
        """
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
            keychain_service_name = self.env.get("keychain_password_service", self.input_variables["keychain_password_service"]["default"])
            keychain_username = self.env.get("keychain_password_username",self.env.get("MCMAPI_USERNAME",''))
            fqdn = self.env.get("mcm_site_server_fqdn", '')

            if (fqdn == None or fqdn == ''):
                raise ProcessorError("mcm_site_server_fqdn cannot be blank")

            if (keychain_service_name == None or keychain_username == ''):
                raise ProcessorError("keychain_password_service cannot be blank")

            if (keychain_username == None or keychain_username == ''):
                raise ProcessorError("keychain_password_username cannot be blank")

            sdm_package_xml = self.env.get("mcm_application_sdmpackagexml")
            if (sdm_package_xml == None or sdm_package_xml == ''):
                raise ProcessorError("SDMPackageXML cannot be blank")
            ci_id = try_cast(int,self.env.get("mcm_application_ci_id", self.input_variables["mcm_application_ci_id"]["default"]),0)
            self.output("Generating NTLM Auth object.",3)
            ntlm = self.get_mcm_ntlm_auth(
                keychain_service_name=keychain_service_name,
                keychain_username=keychain_username
            )
            url = f"https://{fqdn}/AdminService/wmi/SMS_Application"
            if ci_id > 0:
                url += f"({str(ci_id)})"
            self.output("Generating post body",3)
            body = {"SDMPackageXML": sdm_package_xml}
            self.output(f"Posting application to {url}",1)
            post_response = requests.request(
                method='POST',
                url=url,
                auth=ntlm,
                headers=headers,
                verify=False,
                json=body
            )
            self.output(
                f"Parsing response: {type(post_response).__name__}",
                3
                )
            post_json = post_response.json()
            self.output("Got Json body from response", 3)
            if post_json.__contains__("error"):
                self.output(
                    f"\tError Code: {post_json['error']['code']}"
                    "\n\tError Message: "
                    f"{post_json['error']['message']}"
                    )
                self.output(json.dumps(post_json), 4)
            app_value = post_json['value'][0]
            default_export_properties = \
                self.input_variables\
                    ['mcm_app_uploader_export_properties']\
                    ['default']
            export_properties:dict = self.env.get(
                'mcm_app_uploader_export_properties',
                default_export_properties
                )
            self.output(
                "Setting the value of specified export properties",
                2
                )
            for k in list(export_properties.keys()):
                k_type = export_properties.get(k,{}).get(
                    'type','TypeNotFound'
                    )
                self.output(
                    (f"Getting export property '{k}' from a {k_type} "
                    "expression"),
                    3
                    )
                eval_property = export_properties[k]['options']['property']
                if export_properties[k]["type"] == 'property':
                    if not app_value.__contains__(
                        export_properties[k]['options']['expression']
                        ) and export_properties[k].get(
                            'raise_error',False
                            ) == True:
                        raise ProcessorError(
                            f"Property {xml_xpath_expr} does not exist on "
                            "the retrieved object. Valid properties are: "
                            f"{', '.join(list(app_value.keys()))}")
                    value = app_value.get(
                        export_properties[k]['options']['expression'],
                        None
                        )
                elif export_properties[k]["type"] == 'xpath':
                    if not app_value.__contains__(
                        eval_property
                        ) and export_properties[k].get(
                            'raise_error',False
                            ) == True:
                        raise ProcessorError(
                            f"Property {eval_property} "
                            "does not exist on the retrieved object."
                            )
                    elif not app_value.__contains__(eval_property):
                        value = None
                    else:
                        try:
                            xml_element = etree.XML(
                                app_value.get(eval_property,'').replace(
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
                            if export_properties[k]['options'].get(
                                'strip_namespaces',
                                False
                                ) == True:
                                self.output(
                                    "Stripping namespaces from XML element "
                                    "before evaluating xpath expression",
                                    3
                                    )
                                xml_element = McmApplicationUploader.strip_namespaces(
                                    xml_element
                                    )
                            xml_xpath_expr = export_properties[k][
                                'options']['expression']
                            results = xml_element.xpath(xml_xpath_expr)
                            self.output(
                                "Got results from xpath expression",
                                3
                                )
                            if len(results) == 0:
                                if export_properties[k].get(
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
                                    export_properties[k]['options'].get(
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
                            if export_properties[k].get(
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
                    f"{export_properties[k]['type']} expression which "
                    f"evaluated to ({truncated_value}) on the retrieved "
                    "application",
                    3
                    )
                self.env[k] = value
        except Exception as e:
            raise e

if __name__ == "__main__":
    PROCESSOR = McmApplicationUploader()
    PROCESSOR.execute_shell()