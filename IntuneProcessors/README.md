# IntuneProcessors
A library of AutoPkg processors for working with Intune (mostly Win32) Application objects. 
Importantly, most of the processors in this library require an Enterprise Application registration in Entra and appropriate permissions to be granted. [See Below](prerequisites)

## Prerequisites
- App Registration
    - OAuth2
- Grant the following permissions at the 'Application' level
    - Group.Read.All (to retrieve entra groups by their name)
    - DeviceManagementServiceConfig.ReadWrite.All (for working with policy set and enrollment profile objects)
    - DeviceManagementConfiguration.ReadWrite.All (for working with device configuration profiles)
    - DeviceManagementApps.ReadWrite.All (for working with applications)
- Make note of the client id
- Create/Make note of a Client Secret