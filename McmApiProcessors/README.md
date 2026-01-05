# About McmProcessors

Processors in this directory were written due to a somewhat immediate need to rapidly scale application packaging needs with a Microsoft Configuration Manager (MCM) environment. As such, the implementation is currently, admittedly crude, and should be regarded as a ~~beta testing~~ alpha testing release.

Some pointers on items which are obviously out of place or ugly or otherwise poorly designed/implemented would be most welcome.

# Installation

To connect to an MCM instance, you will need to create an MCM credential.

## macOS

'com.github.autopkg.iancohn-recipes.mcmapi' is not required for the -s parameter, however if specifying something custom, you'll need to note it and use it to populate the 'keychain_password_service' input variable in the processor(s) you are using manually.

```zsh
username = "username@domain.com"
security add-generic-password -a $username -s com.github.autopkg.iancohn-recipes.mcmapi -T '/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3' -U -w
```

## Windows

```powershell
$credential = Get-Credential
$target = "com.github.autopkg.iancohn-recipes.mcmapi" # Or your preferred service name
& cmdkey /generic:"$target" /user:"$($credential.UserName)" /pass:"$($credential.GetNetworkCredential().Password)"
```

> ℹ️ **Important Note:** These processors have not yet been tested on Windows and are almost certainly NOT functional

# Common Input Variables

The following input variables are used in most of these processors.

| Variable Name              | Description                                                                                                                                                           | Default Value                                                                     |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| keychain_password_service  | The name of the service used to register the credential in Keychain                                                                                                   | com.github.autopkg.iancohn-recipes.mcmapi                                         |
| keychain_password_username | The username for the credential                                                                                                                                       | `<None>`                                                                        |
| mcm_site_server_fqdn       | The FQDN of the site server hosting the SMS Provider role that you will connect to                                                                                    | `<None>`                                                                        |
| mcm_ssl_verification       | Either a boolean, in which case it controls whether we verify the server’s TLS certificate, or a string, in which case it must be a path to a CA .pem bundle to use | False                                                                             |
| *_export_properties        | A dictionary of properties to export as autopkg variables                                                                                                             | The default value differs depending on the processor.[See Below](#export_properties) |

# Processors

The following processors are currently part of this sub group. The names should be intuitive as to their intended purpose

## McmAdminCategorySetter

Set the administrative categories on an application

### McmAdminCategorySetter Input Variables

| Variable Name              | Description                                                                                                                         | Default Value                             |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| keychain_password_service  | [See Above](#common-input-variables)                                                                                                   | com.github.autopkg.iancohn-recipes.mcmapi |
| keychain_password_username | [See Above](#common-input-variables)                                                                                                   | `<None>`                                |
| mcm_site_server_fqdn       | [See Above](#common-input-variables)                                                                                                   | `<None>`                                |
| mcm_ssl_verification       | [See Above](#common-input-variables)                                                                                                   | `False`                                 |
| object_key                 | The object key of the application to set the security scopes on. For applications this is the ModelName attribute                   | Defaults to the value of %app_model_name% |
| action                     | The action to take on the supplied object's category memberships (`add`, `remove`, `replace`)                                 | `replace`                               |
| admin_category_names       | A list of category friendly names to add/remove/replace on the object                                                               | `<None>`                                |
| current_admin_categories   | Pre-populate the administrative categories assigned to the object to reduce queries to MCM. Defaults to the value of app_categories | `[]`                                    |

### Output Variables

None

## McmAppGetter

Get an application object from MCM.

### McmAppGetter Input Variables

| Variable Name                    | Description                                               | Default Value                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| keychain_password_service        | [See Above](#common-input-variables)                         | com.github.autopkg.iancohn-recipes.mcmapi                                                                                                                                                                                                                                                                                                                                                   |
| keychain_password_username       | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_site_server_fqdn             | [See Above](#common-input-variables)                         | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |
| mcm_ssl_verification             | [See Above](#common-input-variables)                         | `False`                                                                                                                                                                                                                                                                                                                                                                                   |
| mcm_app_getter_export_properties | A dictionary of properties to export as autopkg variables | **existing_app_ci_id** - Populated with the value of the CI_ID property of a returned application object<br />**existing_app_sdmpackagexml** - Populated with the value of the SDMPackageXML property of a returned application object<br />**existing_app_securityscopes** - Populated with the value of the SecuredScopeNames property of a returned application object |
| application_name                 | The name to search for existing applications in MCM       | `<None>`                                                                                                                                                                                                                                                                                                                                                                                  |

### Output Variables

Dynamic depending upon the configuration of the **mcm_app_getter_export_properties** input variable

## McmApplicationUploader

Connect to an MCM AdminService and retrieve an application object, if it exists

### McmApplicationUploader Input Variables

| Variable Name                      | Description                                                                     | Default Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| keychain_password_service          | [See Above](#common-input-variables)                                               | com.github.autopkg.iancohn-recipes.mcmapi                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| keychain_password_username         | [See Above](#common-input-variables)                                               | `<None>`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| mcm_site_server_fqdn               | [See Above](#common-input-variables)                                               | `<None>`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| mcm_ssl_verification               | [See Above](#common-input-variables)                                               | `False`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| mcm_app_uploader_export_properties | A dictionary of properties to export as autopkg variables                       | **app_ci_id** - Populated with the value of the CI_ID property of a response value object. raise_error: false<br />**app_model_name** - Populated with the value of the ModelName property of the response value object. raise_error: true<br />**object_class** - Populated with the value of the __CLASS property of the response value object. raise_error: true<br />**current_object_path** - Populated with the value of the ObjectPath property of the response value object. raise_error: false <br />**app_securityscopes** - Populated with the value of the SecuredScopeNames property of the response value object. raise_error: false <br />**app_is_deployed** - Populated with the value of the "IsDeployed" property of the response value object. raise_error: true<br />**app_logical_name** - Populated with an xpath expression targetting the applications LogicalName from the SDMPackageXML property of the response value object. raise_error: true <br />**app_content_locations** - Populated with a list of Content Locations populated by the result of an xpath expression run against the SDMPackageXML property of the response value object. raise_error: false |
| mcm_application_ci_id              | The CI_ID to post the application to. If (0), a new application will be created | 0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| mcm_application_sdmpackagexml      | The raw XML definition for the Application                                      | `<None>`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

### Output Variables

Dynamic depending upon the configuration of the **mcm_app_uploader_export_properties** input variable

## McmObjectMover

### McmObjectMover Input Variables

| Variable Name              | Description                                                                     | Default Value                             |
| -------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------- |
| keychain_password_service  | [See Above](#common-input-variables)                                               | com.github.autopkg.iancohn-recipes.mcmapi |
| keychain_password_username | [See Above](#common-input-variables)                                               | `<None>`                                |
| mcm_site_server_fqdn       | [See Above](#common-input-variables)                                               | `<None>`                                |
| mcm_ssl_verification       | [See Above](#common-input-variables)                                               | `False`                                 |
| object_class               | The class of the object to move                                                 | `<None>`                                |
| object_key                 | The object key of the object that will be moved                                 | `%app_model_name%`                      |
| current_object_path        | The current path of the object. If not populated, McmObjectMover will query MCM | `<None>`                                |
| target_object_path         | The target location for the object                                              | `<None>`                                |

## McmScopeSetter

### McmScopeSetter Input Variables

| Variable Name              | Description                                                                                      | Default Value                             |
| -------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------- |
| keychain_password_service  | [See Above](#common-input-variables)                                                                | com.github.autopkg.iancohn-recipes.mcmapi |
| keychain_password_username | [See Above](#common-input-variables)                                                                | `<None>`                                |
| mcm_site_server_fqdn       | [See Above](#common-input-variables)                                                                | `<None>`                                |
| mcm_ssl_verification       | [See Above](#common-input-variables)                                                                | `False`                                 |
| object_key                 | The object key of the object that will be moved                                                  | `%app_model_name%`                      |
| security_scopes            | A list of at least one security scope to set on the object                                       | `<None>`                                |
| action                     | The action to take on the supplied object and security scopes (`add`, `remove`, `replace`) | `replace`                               |
| existing_security_scopes   | The existing security scopes attached to the item.                                               | %app_securityscopes%                      |

## McmSDMPackageXMLGenerator

Generate an SDMPackageXML string which represents an MCM Application object.

### McmSDMPackageXMLGenerator Input Variables

| Variable Name                 | Description                              | Default Value                             |
| ----------------------------- | ---------------------------------------- | ----------------------------------------- |
| keychain_password_service     | [See Above](#common-input-variables)        | com.github.autopkg.iancohn-recipes.mcmapi |
| keychain_password_username    | [See Above](#common-input-variables)        | `<None>`                                |
| mcm_site_server_fqdn          | [See Above](#common-input-variables)        | `<None>`                                |
| mcm_ssl_verification          | [See Above](#common-input-variables)        | `False`                                 |
| mcm_application_configuration | [See Below](#mcm_application_configuration) | `<None>`                                |

### McmSDMPackageXMLGenerator Output Variables

| Variable Name         | Description                                                                      |
| --------------------- | -------------------------------------------------------------------------------- |
| SDMPackageXML         | Serialized XML string representing an application object.                        |
| mcm_scope_id          | The authoring scope id for objects in the target MCM site.                       |
| mcm_application       | A dictionary representation of the mcm application                               |
| mcm_application_ci_id | The CI_ID where the application should be posted. 0 indicates a new application. |

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

- **``"existing_app_securityscopes": {"type": "property", "raise_error": False,"options": {"property": "SecuredScopeNames"}}``**
  An autopkg variable named 'existing_app_securityscopes' will be created based on the 'SecuredScopeNames' property from the object returned. If no object is returned, or if the returned object does not contain a 'SecuredScopeNames' property, no error is raised and autopkg will continue the process.
- **``"app_logical_name": {"type": "xpath", "raise_error": True,"options": {"select_value_index": '0', "strip_namespaces": False, "property": "SDMPackageXML", "expression": '/*[local-name()="AppMgmtDigest"]/*[local-name()="Application"]/@LogicalName'}}``**
  An autopkg variable named 'app_logical_name will be created by executing the xpath expression indicated against the 'SDMPackageXML' property of the returned object. If the property cannot be found an error will be raised.
- **``"app_content_locations": {"type": "xpath", "raise_error": False,"options": {"select_value_index": '*', "strip_namespaces": True, "property": "SDMPackageXML", "expression": '//Content/Location/text()'}}``**
  An autopkg variable named 'app_content_locations' will be populated by executing the xpath expression indicated against the 'SDMPackageXML' property. Namespaces will be stripped from the XML prior to executing the xpath expression. If the property cannot be found, no error is raised.

## mcm_application_configuration

The mcm_application_configuration input variable is really the core of this suite of processors and due to its complexity will undoubtedly be the most likely problem child of the bunch.

| Key                             | Description                                                                                                                         | Type             | Required | Possible Values                                                                        | Default Value              |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ---------------- | -------- | -------------------------------------------------------------------------------------- | -------------------------- |
| Name                            | The name of the application as it will appear in the MCM Admin Console                                                              | string           | yes      | any string                                                                             | `<None>`                 |
| BehaviorIfExists                | What to do if an application with this name already exists in MCM                                                                   | string           | yes      | Update, Exit, AppendVersion, AppendIndex                                               | `Exit`                   |
| Description                     | A description to show for the application object in the MCM Admin Console                                                           | string           | no       | any string                                                                             | `<None>`                 |
| Owners                          | A list of user ids to enter as the Owner for this application object                                                                | list(str)        | no       | a list of any (reasonable) number of user ids                                          | `<None>`                 |
| SupportContacts                 | A list of user ids to enter as the Support Contacts for this application object                                                     | list(string)     | no       | a list of any (reasonable) number of user ids                                          | `<None>`                 |
| OptionalReference               | A string to enter for the Optional Reference for the application object.                                                            | string           | no       | any string                                                                             | `<None>`                 |
| SendToProtectedDP               | If True, enables the 'On demand distribution' checkbox                                                                              | Boolean          | no       | `False`, `True`                                                                    | `False`                  |
| AutoInstall                     | If True, enables the application to be installed from a Task Sequence without being deployed                                        | boolean          | no       | `False`, `True`                                                                    | `False`                  |
| DefaultLanguage                 | The default language of the application                                                                                             | string           | no       | any valid language abbreviation                                                        | `en-US`                  |
| LocalizedDisplayName            | A display name to display to users in Software Center/Company Portal if the application is deployed as 'Available'                  | string           | no       | Defaults to the value of the&nbsp;**Name** key above                             | `<None>`                 |
| LocalizedDescription            | A description to display to users in Software Center/Company Portal if the application is deployed as 'Available'                   | string           | no       | Defaults to the value of the&nbsp;**Description** key above                      | `<None>`                 |
| IconFileUnixPath                | A valid unix path to a file to use as the icon. Supports PNG files up to 512x512                                                    | string           | no       | any valid unix path                                                                    | `<None>`                 |
| Keyword                         | A list of keywords a user may search Software Center/Company Portal for when searching for this application                         | list(string)     | no       | a list of any (reasonable) number of strings                                           | `<None>`                 |
| UserCategories                  | A list of User Categories to display the application under in Software Center/Company Portal when it is deployed as 'Available'     | list(string)     | no       | a list of any (reasonable) number of strings which match categories which exist in MCM | '`<None>`'               |
| LinkText                        | The link text for users to retrieve additional information about the application when viewing it in Software Center/Company Portal  | string           | no       | any string                                                                             | `Additional Information` |
| PrivacyUrl                      | The privacy policy url to display to users for the application                                                                      | string           | no       | any url string                                                                         | `<None>`                 |
| UserDocumentation               | The user documentation url to display to users for the application                                                                  | string           | no       | any url string                                                                         | `<None>`                 |
| IsFeatured                      | Whether or not to feature the application in Software Center/Company Portal where it is deployed as Available                       | boolean          | no       | `False`,`True`                                                                     | `False`                  |
| DisplayInfo                     | A list of dictionary objects conforming to the  DisplayInfo dictionary format&nbsp;[See below](#displayinfo)                           | list(dictionary) | no       | A default display info will be created from the information above.                     | `<None>`                 |
| Publisher                       | The publisher for the application                                                                                                   | string           | no       | any string                                                                             | `<None>`                 |
| ReleaseDate                     | The release date of the application                                                                                                 | string           | no       | `mm/dd/yyyy` formatted date                                                          | `<None>`                 |
| SoftwareVersion                 | The version of the application                                                                                                      | string           | no       | any version string                                                                     | `<None>`                 |
| PersistUnhandledDeploymentTypes | Whether to retain deployment types not configured in this dictionary when updating an application rather than creating a new object | boolean          | no       | `False`, `True`                                                                    | `False`                  |
| DeploymentTypes                 | A list of dictionary objects conforming to the DeploymentType dictionary format&nbsp;[See below](#deploymenttype)                      | list(dictionary) | no       | any number of properly configured dictionaries                                         | `<None>`                 |

### DisplayInfo

The DisplayInfo key of the [mcm_application_configuration](#mcm_application_configuration) root node can be populated with an array of localized display information objects conforming to the below standard. By default, properties will inherit their values from the default language and root application object. Most properties can be overridden, or set to `Null` or an empty string if they should be left blank.

| Key                  | Description                                                                                             | Type         | Required | Possible Values                               | Default Value                      |
| -------------------- | ------------------------------------------------------------------------------------------------------- | ------------ | -------- | --------------------------------------------- | ---------------------------------- |
| Language             | The language that this localized display info is for                                                    | string       | no       | any unique, valid language string             | `en-US`                          |
| LocalizedDisplayName | The localized display name to display for users in Software Center/Company Portal                       | string       | yes      | any string                                    | Inherits from the default language |
| LocalizedDescription | The localized description to display for users in Software Center/Company Portal                        | string       | no       | any string                                    | `<None>`                         |
| Keyword              | A list of localized keywords users may search for in Software Center/Company Portal                     | list(string) | no       | any (reaonsable) number of strings            | `<None>`                         |
| LinkText             | The display text for a link to display for users                                                        | string       | no       | any string                                    | `Additional Information`         |
| UserDocumentation    | The url to localized user documentation for the application                                             | string       | no       | any non-local uri (cannot point to localhost) | `<None>`                         |
| IsFeatured           | Whether to feature the application in Software Center/Company portal when it is deployed as 'Available' | boolean      | no       | `False`,`True`                            | `False`                          |

### DeploymentType

DeploymentType objects can be somewhat tricky since the available possible values depends on the deployment or detection technology type that is used.

| Key        | Description                                                                 | Type       | Required | Possible Values                                                                                                        | Default Value |
| ---------- | --------------------------------------------------------------------------- | ---------- | -------- | ---------------------------------------------------------------------------------------------------------------------- | ------------- |
| Technology | The deployment technology type                                              | string     | yes      | `Script`, `MSI`, (`TaskSequence` - **Not yet supported**), (`Windows8App` - **Not yet supported**) | `<None>`    |
| Priority   | Explicitly define the ordering of deployment types[See below](#property-notes) | int        | no       | any int                                                                                                                | `<None>`    |
| Options    | A nested dictionary with properties specific to the deployment technology   | dictionary | yes      | [See below](#deployment-technology-options)                                                                               | `<None>`    |

#### Property Notes

* Priority
  In most cases where you are only creating a new application and creating a single deployment type, can be left as Null or ommitted entirely from the dictionary. Even when creating a new app, by default, deployment types will be assigned a priority respective to their order in this list.
  In more complex scenarios when 'Updating' an application object, the following behaviors can be configured where PersistUnhandledDeploymentTypes is set to `True` (setting it to False causes any existing deployment types to be dropped from the updated application object)

  - Configuring Priority to 'null' declares the following intent:
    - If the deployment type already exists, and BehaviorIfExists is set to 'Update', it will maintain its current priority.
    - If the deployment type does not already exist, or if it exists and the deployment type's BehaviorIfExists property is set to 'AppendVersion' or 'AppendIndex', it will be added to the end in the order in which it appears here.
  - Configuring Priority to a non null value will cause the deployment type to be re-ordered depending on the configuration. For example, configuring DeploymentType list objects with priorities 1, 3, and 5 would cause 2 existing deployment types which are not configured in this configuration to be interlaced into positions 2 and 4.

  When in doubt, just leave it Null

### Deployment Technology Options

#### Common Deployment Type Options Properties

The following properties are common to at least two deployment technology types.

| Key                            | Description                                                                                                                                                                                                                                                                                              | Type             | Required                   | Possible Values                                                                                        | Default Value                |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | -------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------- |
| DeploymentTypeName             | The name of the deployment type                                                                                                                                                                                                                                                                          | string           | yes                        | any string                                                                                             | `Install`                  |
| BehaviorIfExists               | How to handle an existing deployment type on the application with the same name                                                                                                                                                                                                                          | string           | yes                        | `Update`, `Skip`, `Exit`, `AppendVersion`, `AppendIndex`                                     | `<None>`                   |
| AdministratorComment           | A comment to describe the deployment type for MCM administrators                                                                                                                                                                                                                                         | string           | no                         | any string                                                                                             | `<None>`                   |
| Languages                      | A list of strings representing the languages to which this deployment type applies                                                                                                                                                                                                                       | list(string)     | no                         | string list values must be valid language abbreviations                                                | `<None>`                   |
| AllowUninstall                 | Whether to allow the user to uninstall the Application (if deployed as 'Available')                                                                                                                                                                                                                      | boolean          | no                         | `False`,`True`                                                                                     | `False`                    |
| InstallProcessDetection        | A list of dictionaries defining processes which must be closed prior to running this deployment type.[See below](#install-process-detection)                                                                                                                                                                | dictionary       | no                         | any valid process detection configuration dictionary                                                   | `<None>`                   |
| ContentLocation                | The path (likely UNC) to the folder of content that will be used for this deployment type                                                                                                                                                                                                                | string           | no                         | any string                                                                                             | `<None>`                   |
| ContentLocation_Local          | The local path to the application's installation content (eg.`/Volumes/MyShare/MyContent`)                                                                                                                                                                                                             | string           | yes, if specifying content | any valid local path                                                                                   | `<None>`                   |
| PersistContentInClientCache    | Whether to keep the content on the client indefinitely after the installation completes                                                                                                                                                                                                                  | boolean          | no                         | `False`,`True`                                                                                     | `False`                    |
| SourceUpdateProductCode        | The GUID of the application                                                                                                                                                                                                                                                                              | string           | no                         | any guid                                                                                               | `<None>`                   |
| InstallationProgram            | The command which begins the installation                                                                                                                                                                                                                                                                | string           | yes                        | any string                                                                                             | `<None>`                   |
| InstallationStartIn            | The folder where the installation should begin, if different from the content folder                                                                                                                                                                                                                     | string           | no                         | Any valid path on the target client system                                                             | `<None>`                   |
| Force32BitInstaller            | Whether install/uninstall/repair commands should run as a 32 bit process on 64 bit systems                                                                                                                                                                                                               | boolean          | no                         | `False`,`True`                                                                                     | `False`                    |
| RequiresUserInteraction        | Allow the user to interact with the installer process                                                                                                                                                                                                                                                    | boolean          | no                         | `False`,`True`                                                                                     | `False`                    |
| UninstallProgram               | The command which begins the uninstall process                                                                                                                                                                                                                                                           | string           | no                         | any string                                                                                             | `<None>`                   |
| UninstallStartIn               | The folder where the uninstall should begin, if different from the content folder                                                                                                                                                                                                                        | string           | no                         | Any valid path on the target client system                                                             | `<None>`                   |
| UninstallSetting               | Describes the content requirement for the uninstall action                                                                                                                                                                                                                                               | string           | no                         | `SameAsInstall`, `NoneRequired`, `Different`                                                     | `SameAsInstall`            |
| UninstallContentLocation       | The path (likely UNC) to the folder of content that will be used for this deployment type's uninstall action                                                                                                                                                                                             | string           | no                         | any string                                                                                             | `<None>`                   |
| UninstallContentLocation_Local | The local path to the application's uninstall content (eg.`/Volumes/MyShare/MyContent`)                                                                                                                                                                                                                | string           | yes, if specifying content | any valid local path                                                                                   | `<None>`                   |
| RepairProgram                  | The command which begins the repair process                                                                                                                                                                                                                                                              | string           | no                         | any string                                                                                             | `<None>`                   |
| RepairStartIn                  | The folder where the repair action should begin                                                                                                                                                                                                                                                          | string           | no                         | Any valid path on the target client system                                                             | `<None>`                   |
| InstallationProgramVisibility  | Whether to display the UI for the install process to the user                                                                                                                                                                                                                                            | string           | no                         | `Normal`,`Minimized`,`Maximized`,`Hidden`                                                      | `Hidden`                   |
| LogonRequirementType           | Describes the logon requirement.[See below](#logon-requirement-type-notes)                                                                                                                                                                                                                                  | string           | no                         | `OnlyWhenUserLoggedOn`, `WhetherOrNotUserLoggedOn`, `OnlyWhenNoUserLoggedOn`                     | `WhetherOrNotUserLoggedOn` |
| InstallationBehaviorType       | The context in which to install the application                                                                                                                                                                                                                                                          | string           | no                         | `InstallForSystem`,`InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser`, `InstallForUser` | `InstallForSystem`         |
| RebootBehavior                 | The reboot behavior of the deployment type                                                                                                                                                                                                                                                               | string           | no                         | `BasedOnExitCode`, `NoAction`, `ProgramReboot`, `ForceReboot`                                  | `BasedOnExitCode`          |
| MaximumAllowedRuntimeMins      | How many minutes the installation should be allowed to run for before killing the process                                                                                                                                                                                                                | int              | no                         | any positive integer between 15 and 1440 (keeping maintenance windows in mind)                         | 120                          |
| EstimatedInstallationTimeMins  | The expected number of minutes the installation should take on healthy clients                                                                                                                                                                                                                           | int              | no                         | any int                                                                                                | 0                            |
| OnSlowNetworkMode              | Content download behavior when on a slow network                                                                                                                                                                                                                                                         | string           | no                         | `Download`, `DoNothing`                                                                            | `Download`                 |
| OnFastNetworkMode              | Content download behavior when on a fast network                                                                                                                                                                                                                                                         | string           | no                         | `Download`, `DoNothing`                                                                            | `Download`                 |
| Requirements                   | A list of dictionaries defining the requirements for this deployment type to be applicable to target systems[See below](#requirements-rules)                                                                                                                                                                | list(dictionary) | no                         | any number of valid requirements dictionaries                                                          | `<None>`                   |
| DependencyGroups               | A list of one or more dependency groups dictionaries[See below](#dependency-groups). Each dependency group is functionally connected with a logical `and` operator, meaning that ALL dependency groups must evaluate to `True` for dependencies to be satisfied and for the deployment type to execute. | dictionary       | no                         | any number of valid dependency group definitions                                                       | `<None>`                   |
| KeepDefaultReturnCodes         | By default MCM will look for common return codes (1707, 3010, 1603). If defining custom return codes in the next property, the default return codes can be kept                                                                                                                                          | bool             | no                         | `False`, `True`                                                                                    | `True`                     |
| CustomReturnCodes              | A list of dictionaries for each return code which needs to be applied[See below](#custom-return-codes)                                                                                                                                                                                                      | list(dictionary) | no                         | any number of custom return code definitions                                                           | `<None>`                   |
| Detection                      | A dictionary representing the definition for how MCM should determine whether the application is successfully installed. This is a complex type[See below](#detection)                                                                                                                                      | dictionary       | yes                        | A valid detection definition                                                                           | `<None>`                   |

#### Logon Requirement Type Notes

Not valid for 'InstallForUser' installation behavior.
'OnlyWhenNoUserIsLoggedOn' is not a valid choice when an installation behavior type of 'InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser' is specified, since that effectively would make it an InstallForSystem installation behavior.

### Install Process Detection

| Key         | Description                                    | Type   | Required | Possible Values | Default Value |
| ----------- | ---------------------------------------------- | ------ | -------- | --------------- | ------------- |
| ProcessName | The name of the executable file with extension | string | yes      | any string      | `<None>`    |
| DisplayName | The display name of the process                | string | no       | any string      | `<None>`    |

### Requirements Rules

As it turns out, creating requirements can be somewhat complex depending whether built in or custom (global condition) requirements are used. As a stop gap for this, requirements rules can be defined using a raw xml string from an existing deployment type on another application object and applied to this deployment type.

| Key  | Description                                                                                                    | Type                                                    | Required | Possible Values         | Default Value |
| ---- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- | -------- | ----------------------- | ------------- |
| Type | The method used to define the requirement                                                                      | string                                                  | yes      | `XmlString`, `Dict` | `<None>`    |
| Rule | The rule definition, either as[XmlString](#requirements-from-xml-strings) or [Dict](#requirements-from-dictionaries) | string, (dictionary -**Not Currently Supported**) | yes      | A valid object          | `<None>`    |

### Requirements From XML Strings

This was easier to implement relative to to the alternative which would have to make several queries to MCM to search for global condition ids, then figure out how to construct the object from these.

**Example:**

```xml
<rule><Annotation>
  <DisplayName Text="Lots of operating systems" />
  <Description Text="" />
</Annotation>
<OperatingSystemExpression>
  <Operator>OneOf</Operator>
  <Operands>
    <RuleExpression RuleId="Windows/All_x64_Windows_7_Client" />
    <RuleExpression RuleId="Windows/All_x86_Windows_7_Client" />
    <RuleExpression RuleId="Windows/x64_Windows_7_Client" />
    <RuleExpression RuleId="Windows/x64_Windows_7_SP1" />
    <RuleExpression RuleId="Windows/x86_Windows_7_Client" />
    <RuleExpression RuleId="Windows/x86_Windows_7_SP1" />
    <RuleExpression RuleId="Windows/All_ARM64_Windows_10_and_higher_Clients" />
    <RuleExpression RuleId="Windows/All_MultiSession_Enterprise_Windows_10_higher" />
    <RuleExpression RuleId="Windows/All_x64_Windows_10_and_higher_Clients" />
    <RuleExpression RuleId="Windows/All_x86_Windows_10_and_higher_Clients" />
    <RuleExpression RuleId="Windows/All_ARM64_Windows_11_and_higher_Clients" />
    <RuleExpression RuleId="Windows/All_MultiSession_Enterprise_Windows_11_higher" />
    <RuleExpression RuleId="Windows/All_x64_Windows_11_and_higher_Clients" />
  </Operands>
</OperatingSystemExpression>
</rule>

```

### Requirements From Dictionaries

Not currently supported

### Dependency Groups

A valid dependency group will have one or more dependency. You cannot create a dependency group with 0 dependencies. All dependencies within a dependency group are functionally connected by a logical `or` operator, meaning that if ANY of the detections on the deployment types referenced in the dependency groups evaluate as installed, the dependency group itself will evaluate to `True`

| Key                 | Description                                                          | Type       | Required | Possible Values                            | Default Value |
| ------------------- | -------------------------------------------------------------------- | ---------- | -------- | ------------------------------------------ | ------------- |
| DependencyGroupName | The name of the dependency group                                     | string     | yes      | any string                                 | `<None>`    |
| Dependencies        | A list of one or more individual dependencies[See below](#dependencies) | dictionary | yes      | any number of valid dependency definitions | `<None>`    |

### Dependencies

Each dependency is defined by a dictionary with the properties below

| Key                      | Description                                              | Type    | Required                                               | Possible Values                          | Default Value |
| ------------------------ | -------------------------------------------------------- | ------- | ------------------------------------------------------ | ---------------------------------------- | ------------- |
| Priority                 | The priority order of the dependency within the group    | int     | yes                                                    | any int > 0                              | `<None>`    |
| Application Name         | The application name (must be precise)                   | string  | yes                                                    | any string                               | `<None>`    |
| AutoInstall              | Whether to install this dependency if it is not detected | boolean | no                                                     | `False`, `True`                      | `False`     |
| DeploymentTypeFilter     | The string to match the deployment type name against     | string  | no (if singleton deployment type, it will be selected) | any string                               | `<None>`    |
| DeploymentTypeFilterType | How to match against the DeploymentTypeFilter string     | string  | yes                                                    | `StartsWith`, `Contains`, `Equals` | `<None>`    |

### Custom Return Codes

| Key         | Description                         | Type   | Required | Possible Values                                                     | Default Value |
| ----------- | ----------------------------------- | ------ | -------- | ------------------------------------------------------------------- | ------------- |
| ReturnCode  | The numeric exit code to define     | int    | yes      | any int > 0                                                         | `<None>`    |
| CodeType    | The return code type                | string | yes      | `Success`, `Failure`, `HardReboot`, `Reboot`, `FastRetry` | `<None>`    |
| Name        | A friendly name for the return code | string | no       | any string                                                          | `<None>`    |
| Description | A description for the return code   | string | no       | any string                                                          | `<None>`    |

### Detection

| Key     | Description                                                                              | Type       | Required | Possible Values                                                                                   | Default Value |
| ------- | ---------------------------------------------------------------------------------------- | ---------- | -------- | ------------------------------------------------------------------------------------------------- | ------------- |
| Type    | What type of detection this is[See below](#detection-type-notes)                            | string     | yes      | `File`, `Folder`, `RegistryKey`, `RegistryKeyValue`, `MSI`, `Group`, `CustomScript` | `<None>`    |
| Options | A dictionary of options consistent with the Type property[See below](#detection-type-notes) | dictionary | yes      | A dictionary valid for the given detection type                                                   | `<None>`    |

#### Detection Type Notes

There are two main categories of detection types:

* **[Custom Script](#custom-script-detection-options)** (CustomScript) - Detect a successful installation with a PowerShell script
  PowerShell scripts which detect the installation will:

  * Output a single string (any string) if the application is installed. To indicate that the application is not installed, the script MUST NOT write out any string (or any object castable as a string)
  * Exit with a '0' exit code. Exiting with a non-zero exit code will cause detection to fail with an error, rather than detecting that the application is or is not installed
* **Enhanced Detection Expression** - enhanced detection expressions can be one of five types

  * **[Group Expression](#group-detection-options)** - (Group)
  * **[File](#file-detection-options)** - (File)
  * **[Folder](#folder-detection-options)** - (Folder)
  * **[Registry Key](#registry-key-detection-options)** - (RegistryKey)
  * **[Registry Key Value](#registry-key-value-detection-options)** - (RegistryKey)
  * **[MSI](#msi-detection-options)** - (MSI)

> ℹ️ **Important Note:** If evaluating a property on any of the above detection methods, *Property*, *Operator*, and *Value* must all be populated. This applies to File, Folder, MSI, and RegistryKeyValue expression types

### Custom Script Detection Options

| Key           | Description                                                                                                               | Type    | Required | Possible Values                                     | Default Value  |
| ------------- | ------------------------------------------------------------------------------------------------------------------------- | ------- | -------- | --------------------------------------------------- | -------------- |
| ScriptType    | The script language. Technically JScript and VBScript are supported by MCM, but this should ALWAYS be set to 'PowerShell' | string  | yes      | `PowerShell`, ~~`VBScript`~~, ~~`JScript`~~ | `PowerShell` |
| ScriptContent | The PowerShell script represented as a string                                                                             | string  | yes      | any valid PowerShell script as a string             | `<None>`     |
| RunAs32Bit    | If `True`, the script will run using 32 bit PowerShell                                                                  | boolean | no       | `False`, `True`                                 | `False`      |

### Group Detection Options

Group expressions evaluate two or more [enhanced detection expressions](#detection-type-notes). Items in a group are connected by either 'and' or 'or' logical operators. Group expressions may contain nested group expressions, and may connect via their operator with either another group type expression or a single expression (eg. File)

| Key      | Description                                                       | Type             | Required | Possible Values                                  | Default Value |
| -------- | ----------------------------------------------------------------- | ---------------- | -------- | ------------------------------------------------ | ------------- |
| Operator | The logical operator to connect items in the Items list           | string           | yes      | `And`, `Or`                                  | `<None>`    |
| Items    | A list of at least two enhanced detection expressions to evaluate | list(dictionary) | yes      | Two or more valid enhanced detection expressions | `<None>`    |

### File Detection Options

| Key      | Description                                                                      | Type                   | Required | Possible Values                                                                                                                                                                                                                     | Default Value |
| -------- | -------------------------------------------------------------------------------- | ---------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Is64Bit  | If `False`, the file is associated with a 32 bit application on 64 bit systems | boolean                | yes      | `False`, `True`                                                                                                                                                                                                                 | `<None>`    |
| Path     | The parent folder path                                                           | string                 | yes      | Any valid path on the target client system                                                                                                                                                                                          | `<None>`    |
| Filter   | The file name                                                                    | string                 | yes      | any string                                                                                                                                                                                                                          | `<None>`    |
| Property | Optionally, evaluate the file properties within this detection                   | string                 | no       | `Size`, `Version`, `DateCreated`, `DateModified`                                                                                                                                                                            | `<None>`    |
| Operator | The comparison operator for the value returned from the file property            | string                 | no       | `Equals`, `NotEquals`, `GreaterThan`, `LessThan`, `Between`, `GreaterEquals`, `LessEquals`, `OneOf`, `NoneOf` [See below - not all operators are valid for all properties](#file-property-comparison-operator-notes) | `<None>`    |
| Value    | The value or list of values to compare the file property value against           | list(string) or string | no       | any string (or list of strings if the operator is an array operator)                                                                                                                                                                | `<None>`    |

#### File Property Comparison Operator Notes

The following operators evaluate against an array of values:

* Between
* OneOf
* NoneOf
  When using an array operator, the Value property should be a list of at least two version strings.
  If using the 'Between' operator, there must be exactly two version strings.

Non-array operators require 'Value' to be populated with a single string

### Folder Detection Options

| Key      | Description                                                                      | Type                   | Required | Possible Values                                                                                                                                                                                                                     | Default Value |
| -------- | -------------------------------------------------------------------------------- | ---------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Is64Bit  | If `False`, the file is associated with a 32 bit application on 64 bit systems | boolean                | yes      | `False`, `True`                                                                                                                                                                                                                 | `<None>`    |
| Path     | The parent folder path                                                           | string                 | yes      | Any valid path on the target client system                                                                                                                                                                                          | `<None>`    |
| Filter   | The file name                                                                    | string                 | yes      | any string                                                                                                                                                                                                                          | `<None>`    |
| Property | Optionally, evaluate the file properties within this detection                   | string                 | no       | `DateCreated`, `DateModified`                                                                                                                                                                                                   | `<None>`    |
| Operator | The comparison operator for the value returned from the file property            | string                 | no       | `Equals`, `NotEquals`, `GreaterThan`, `LessThan`, `Between`, `GreaterEquals`, `LessEquals`, `OneOf`, `NoneOf` [See below - not all operators are valid for all properties](#file-property-comparison-operator-notes) | `<None>`    |
| Value    | The value or list of values to compare the file property value against           | list(string) or string | no       | any string (or list of strings if the operator is an array operator)                                                                                                                                                                | `<None>`    |

### Registry Key Detection Options

Registry key detection is a simple existance check on the registry key, and cannot evaluate any properties on the key.

| Key     | Description                                                                      | Type    | Required | Possible Values                                                                                               | Default Value |
| ------- | -------------------------------------------------------------------------------- | ------- | -------- | ------------------------------------------------------------------------------------------------------------- | ------------- |
| Hive    | The Registry hive to examine                                                     | string  | yes      | `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_CONFIG`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS` | `<None>`    |
| Key     | The path to the registry key. Wildcards are not supported                        | string  | yes      | any valid registry path                                                                                       | `<None>`    |
| Is64Bit | If `False`, the file is associated with a 32 bit application on 64 bit systems | boolean | yes      | `False`, `True`                                                                                           | `<None>`    |

### Registry Key Value Detection Options

| Key       | Description                                                                                                                              | Type                   | Required | Possible Values                                                                                                                                                                                                                           | Default Value |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Hive      | The Registry hive to examine                                                                                                             | string                 | yes      | `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_CONFIG`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS`                                                                                                                             | `<None>`    |
| Key       | The path to the registry key. Wildcards are not supported                                                                                | string                 | yes      | any valid registry path                                                                                                                                                                                                                   | `<None>`    |
| ValueName | The name of the registry value to examine                                                                                                | string                 | yes      | any string                                                                                                                                                                                                                                | `<None>`    |
| DateType  | The data type of the value data that will be retrieved from the registry value                                                           | string                 | no       | `String`, `Version`, `Integer`                                                                                                                                                                                                      | `<None>`    |
| Operator  | The comparison operator for the data returned from the registry value                                                                    | string                 | no       | `Equals`, `NotEquals`, `GreaterThan`, `LessThan`, `Between`, `GreaterEquals`, `LessEquals`, `OneOf`, `NoneOf` [See below - not all operators are valid for all data types](#registry-value-data-comparison-operator-notes) | `<None>`    |
| Value     | The value or list of values to compare the retrieved registry value data against[See below](#registry-value-data-comparison-operator-notes) | list(string) or string | no       | any string (or list of strings if the operator is an array operator)                                                                                                                                                                      | `<None>`    |
| Is64Bit   | If `False`, the file is associated with a 32 bit application on 64 bit systems                                                         | boolean                | yes      | `False`, `True`                                                                                                                                                                                                                       | `<None>`    |

#### Registry Value Data Comparison Operator Notes

If comparing a registry value a 'String' DataType, the following comparison operators may be used

* Equals
* NotEquals
* BeginsWith
* NotBeginsWith
* EndsWith
* NotEndsWith
* Contains
* NotContains
* OneOf
* NoneOf

Additionally, the notes listed under [File Property Comparison Operator Notes](#file-property-comparison-operator-notes) apply here as well.

### MSI Detection Options

| Key         | Description                                          | Type   | Required | Possible Values                                                                             | Default Value |
| ----------- | ---------------------------------------------------- | ------ | -------- | ------------------------------------------------------------------------------------------- | ------------- |
| ProductCode | The MSI product code to search for                   | string | yes      | any valid MSI product code                                                                  | `<None>`    |
| Operator    | The comparison operator to use                       | string | no       | `Equals`, `NotEquals`, `GreaterThan`, `GreaterEquals`, `LessThan`, `LessEquals` | `<None>`    |
| Property    | The MSI Property to evaluate (always ProductVersion) | string | no       | `ProductVersion`                                                                          | `<None>`    |
| Value       | The value to compare the property value against      | string | no       | any string                                                                                  | `<None>`    |
