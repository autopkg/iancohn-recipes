# IntuneProcessors
A library of AutoPkg processors for working with Intune (mostly Win32) Application objects. 
Importantly, most of the processors in this library require an Enterprise Application registration in Entra and appropriate permissions to be granted. [See Below](prerequisites)

# Prerequisites
- App Registration
    - OAuth2
- Grant the following permissions at the 'Application' level
    - Group.Read.All (to retrieve entra groups by their name)
    - DeviceManagementServiceConfig.ReadWrite.All (for working with policy set and enrollment profile objects)
    - DeviceManagementConfiguration.ReadWrite.All (for working with device configuration profiles)
    - DeviceManagementApps.ReadWrite.All (for working with applications)
- Make note of the client id
- Create/Make note of a Client Secret

# Installation

To connect to an MCM instance, you will need to create an MCM credential.

## macOS

'com.github.autopkg.iancohn-recipes.intuneprocessors' is not required for the -s parameter, however if specifying something custom, you'll need to note it and use it to populate the 'intune_app_keychain_service' input variable in the processor(s) you are using manually.

When prompted to enter a password, enter the client secret retrieved/created for the app registration.

```zsh
intuneAppName = "<App registration name" # Purely for searchability, does not strictly need to match
security add-generic-password -a $intuneAppName -s com.github.autopkg.iancohn-recipes.intuneprocessors -T '/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3' -U -w
```

## Windows

```powershell
$credential = Get-Credential
$target = "com.github.autopkg.iancohn-recipes.intuneprocessors" # Or your preferred service name
& cmdkey /generic:"$target" /user:"$($credential.UserName)" /pass:"$($credential.GetNetworkCredential().Password)"
```

> ℹ️ **Important Note:** These processors have not yet been tested on Windows and are almost certainly NOT functional
