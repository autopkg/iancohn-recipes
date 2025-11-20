# About McmProcessors

Processors in this directory were written due to a somewhat immediate need to rapidly scale application packaging needs with a Microsoft Configuration Manager (MCM) environment. As such, the implementation is currently, admittedly crude, and should be regarded as a ~~beta testing~~ alpha testing release.

Some pointers on items which are obviously out of place or ugly or otherwise poorly designed/implemented would be most welcome.

# Installation

## Modules

```zsh
/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3 -m pip install keyring
/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3 -m pip install requests_ntlm
/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3 -m pip install Pillow

```

After installing the above modules, you should also register an MCM credential in keychain. 'com.github.autopkg.iancohn-recipes.mcmapi' is not required for the -s parameter, however if specifying something custom, you'll need to note it and use it to populate the 'keychain_password_service' input variable in the processor(s) you are using manually.

```zsh
username = "username@domain.com"
security add-generic-password -a $username -s com.github.autopkg.iancohn-recipes.mcmapi -T '/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3' -U -w
```

# Common Input Variables

The following input variables are used in most of these processors.

| Variable Name              | Description                                                                        | Default Value                                                                     |
| -------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| keychain_password_service  | The name of the service used to register the credential in Keychain                | com.github.autopkg.iancohn-recipes.mcmapi                                         |
| keychain_password_username | The username for the credential                                                    | `<None>`                                                                        |
| mcm_site_server_fqdn       | The FQDN of the site server hosting the SMS Provider role that you will connect to | `<None>`                                                                        |
| export_properties          | A dictionary of properties to export as autopkg variables                          | The default value differs depending on the processor.[See Below](#export_properties) |

# Processors

The following processors are currently part of this sub group. The names should be intuitive as to their intended purpose.

## McmAppGetter

Get an application object from MCM.
Input Variables:

## McmApplicationUploader

## McmObjectMover

## McmScopeSetter

## McmSDMPackageXMLGenerator

# Complex input variables

## export_properties

A dictionary specifying the properties to retrieve, and the AutoPkg variables to use to store the output.
Each key name specified will be used as the AutoPkg variable name; each value should be populated by a dictionary "
representing how to retrieve the property from the MCM application. Supported retrieval types are 'property' and 'xpath'. "
'raise_error' specifies whether to raise an error if the property cannot be found. "

'property' type options require an 'expression' option specifying the property name to retrieve from the MCM application. "
'xpath' type options require a 'property' option specifying the property name (generally 'SDMPackageXML') to run the xpath query against, and an 'expression'. "
The 'strip_namespaces' option may also be specified to indicate whether to strip namespaces from the XML before evaluating the xpath expression."
The 'select_value_index' option may also be specified to indicate which value to select from the xpath result set (default is '*' (return all values as an array list)). "
Positive or negative integers may be specified to select a specific index from the result set (0-based). Negative integers count from the end of the result set (-1 is the last item)."

### Examples

- **```"existing_app_securityscopes": {"type": "property", "raise_error": False,"options": {"expression": "SecuredScopeNames"}}```**
  An autopkg variable named 'existing_app_securityscopes' will be created based on the 'SecuredScopeNames' property from the object returned. If no object is returned, or if the returned object does not contain a 'SecuredScopeNames' property, no error is raised and autopkg will continue the process.
- **```"app_logical_name": {"type": "xpath", "raise_error": True,"options": {"select_value_index": '0', "strip_namespaces": False, "property": "SDMPackageXML", "expression": '/*[local-name()="AppMgmtDigest"]/*[local-name()="Application"]/@LogicalName'}}```**
  An autopkg variable named 'app_logical_name will be created by executing the xpath expression indicated against the 'SDMPackageXML' property of the returned object. If the property cannot be found an error will be raised.
- **```"app_content_locations": {"type": "xpath", "raise_error": False,"options": {"select_value_index": '*', "strip_namespaces": True, "property": "SDMPackageXML", "expression": '//Content/Location/text()'}}```**
  An autopkg variable named 'app_content_locations' will be populated by executing the xpath expression indicated against the 'SDMPackageXML' property. Namespaces will be stripped from the XML prior to executing the xpath expression. If the property cannot be found, no error is raised.

## mcm_application_configuration
