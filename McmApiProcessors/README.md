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
| *_export_properties        | A dictionary of properties to export as autopkg variables                          | The default value differs depending on the processor.[See Below](#export_properties) |

# Processors

The following processors are currently part of this sub group. The names should be intuitive as to their intended purpose.

## McmAppGetter

Get an application object from MCM.

### Input Variables

| Variable Name                    | Description                                               | Default Value                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| keychain_password_service        | [See Above](#common-input-variables)                         | com.github.autopkg.iancohn-recipes.mcmapi                                                                                                                                                                                                                                                                                                                                                   |
| keychain_password_username       | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_site_server_fqdn             | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_app_getter_export_properties | A dictionary of properties to export as autopkg variables | **existing_app_ci_id** - Populated with the value of the CI_ID property of a returned application object<br />**existing_app_sdmpackagexml** - Populated with the value of the SDMPackageXML property of a returned application object<br />**existing_app_securityscopes** - Populated with the value of the SecuredScopeNames property of a returned application object |
| application_name                 | The name to search for existing applications in MCM       | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
### Output Variables
Dynamic depending upon the configuration of the **mcm_app_getter_export_properties** input variable

## McmApplicationUploader
AutoPkg Processor to connect to an MCM AdminService and retrieve an application object, if it exists

### Input Variables
| Variable Name                    | Description                                               | Default Value                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| keychain_password_service        | [See Above](#common-input-variables)                         | com.github.autopkg.iancohn-recipes.mcmapi                                                                                                                                                                                                                                                                                                                                                   |
| keychain_password_username       | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_site_server_fqdn             | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_app_uploader_export_properties | A dictionary of properties to export as autopkg variables | **app_ci_id** - Populated with the value of the CI_ID property of a response value object. raise_error: false<br />**app_model_name** - Populated with the value of the ModelName property of the response value object. raise_error: true<br />**object_class** - Populated with the value of the __CLASS property of the response value object. raise_error: true<br />**current_object_path** - Populated with the value of the ObjectPath property of the response value object. raise_error: false <br />**app_securityscopes** - Populated with the value of the SecuredScopeNames property of the response value object. raise_error: false <br />**app_is_deployed** - Populated with the value of the "IsDeployed" property of the response value object. raise_error: true<br />**app_logical_name** - Populated with an xpath expression targetting the applications LogicalName from the SDMPackageXML property of the response value object. raise_error: true <br />**app_content_locations** - Populated with a list of Content Locations populated by the result of an xpath expression run against the SDMPackageXML property of the response value object. raise_error: false |
| mcm_application_ci_id                 | The CI_ID to post the application to. If (0), a new application will be created | 0 |
| mcm_application_sdmpackagexml | The raw XML definition for the Application | `<None>`

### Output Variables

Dynamic depending upon the configuration of the **mcm_app_uploader_export_properties** input variable

## McmObjectMover

## McmScopeSetter

## McmSDMPackageXMLGenerator
Generate an SDMPackageXML string which represents an MCM Application object.

### Input Variables

| Variable Name                    | Description                                               | Default Value                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| keychain_password_service        | [See Above](#common-input-variables)                         | com.github.autopkg.iancohn-recipes.mcmapi                                                                                                                                                                                                                                                                                                                                                   |
| keychain_password_username       | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_site_server_fqdn             | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_application_configuration | [See Below](#mcm_application_configuration)

### Output Variables
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

- **``"existing_app_securityscopes": {"type": "property", "raise_error": False,"options": {"expression": "SecuredScopeNames"}}``**
  An autopkg variable named 'existing_app_securityscopes' will be created based on the 'SecuredScopeNames' property from the object returned. If no object is returned, or if the returned object does not contain a 'SecuredScopeNames' property, no error is raised and autopkg will continue the process.
- **``"app_logical_name": {"type": "xpath", "raise_error": True,"options": {"select_value_index": '0', "strip_namespaces": False, "property": "SDMPackageXML", "expression": '/*[local-name()="AppMgmtDigest"]/*[local-name()="Application"]/@LogicalName'}}``**
  An autopkg variable named 'app_logical_name will be created by executing the xpath expression indicated against the 'SDMPackageXML' property of the returned object. If the property cannot be found an error will be raised.
- **``"app_content_locations": {"type": "xpath", "raise_error": False,"options": {"select_value_index": '*', "strip_namespaces": True, "property": "SDMPackageXML", "expression": '//Content/Location/text()'}}``**
  An autopkg variable named 'app_content_locations' will be populated by executing the xpath expression indicated against the 'SDMPackageXML' property. Namespaces will be stripped from the XML prior to executing the xpath expression. If the property cannot be found, no error is raised.

## mcm_application_configuration
The mcm_application_configuration input variable is really the core of this suite of processors and due to its complexity will undoubtedly be the most likely problem child of the bunch.
| Key | Description | Type | Required | Possible Values | Default Value |
| --- | ----------- | ---- | -------- | --------------- | ------------- |
| Name | The name of the application as it will appear in the MCM Admin Console | string | yes | any string | `<None>`
| BehaviorIfExists | What to do if an application with this name already exists in MCM | string | yes | Update, Exit, AppendVersion, AppendIndex | `Exit` |
| Description | A description to show for the application object in the MCM Admin Console | string | no | any string | `<None>`
| Owners | A list of user ids to enter as the Owner for this application object | list(str) | no | a list of any (reasonable) number of user ids | `<None>` |
| SupportContacts | A list of user ids to enter as the Support Contacts for this application object | list(string) | no | a list of any (reasonable) number of user ids | `<None>` |
| OptionalReference | A string to enter for the Optional Reference for the application object. | string | no | any string | `<None>` |
| SendToProtectedDP | If True, enables the 'On demand distribution' checkbox | Boolean | no | `False`, `True`| `False` | 
| AutoInstall | If True, enables the application to be installed from a Task Sequence without being deployed | boolean | no | `False` |
| DefaultLanguage | The default language of the application | string | no | any valid language abbreviation | `en-US` |
| LocalizedDisplayName | A display name to display to users in Software Center/Company Portal if the application is deployed as 'Available' | string | no | Defaults to the value of the **Name** key above |
| LocalizedDescription | A description to display to users in Software Center/Company Portal if the application is deployed as 'Available' | string | no | Defaults to the value of the **Description** key above |
| IconFileUnixPath | A valid unix path to a file to use as the icon. Supports PNG files up to 512x512 | string | no | any valid unix path | `<None>` |
| Keyword | A list of keywords a user may search Software Center/Company Portal for when searching for this application | list(string) | no | a list of any (reasonable) number of strings | `<None>` |
| UserCategories | A list of User Categories to display the application under in Software Center/Company Portal when it is deployed as 'Available' | list(string) | no | a list of any (reasonable) number of strings which match categories which exist in MCM | '<None>' |
| LinkText | The link text for users to retrieve additional information about the application when viewing it in Software Center/Company Portal | string | no | any string | `Additional Information` |
| PrivacyUrl | The privacy policy url to display to users for the application | string | no | any url string | `<None>` |
| UserDocumentation | The user documentation url to display to users for the application | string | no | any url string | `<None>` |
| IsFeatured | Whether or not to feature the application in Software Center/Company Portal where it is deployed as Available | boolean | no | `False`,`True` | `False` |
| DisplayInfo | A list of dictionary objects conforming to the  DisplayInfo dictionary format &nbsp;[See below](#displayinfo) | list(dictionary) | no | A default display info will be created from the information above. |
| Publisher | The publisher for the application | string | no | any string | `<None>` |
| ReleaseDate | The release date of the application | string | no | `mm/dd/yyyy` formatted date | `<None>` |
| SoftwareVersion | The version of the application | string | no | any version string | `<None>` |
| PersistUnhandledDeploymentTypes | Whether to retain deployment types not configured in this dictionary when updating an application rather than creating a new object | boolean | no | `False` |
| DeploymentTypes | A list of dictionary objects conforming to the DeploymentType dictionary format &nbsp;[See below](#deploymenttype) | list(dictionary) | any number of properly configured dictionaries | `<None>`

### DisplayInfo
### DeploymentType