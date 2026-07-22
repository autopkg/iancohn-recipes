# About SmbCopier

These processors were born out of a somewhat pressing need to copy files/folders to/from SMB file shares without mounting the share, since this has tended (at least in my environment) to not perform well in scenarios where AutoPkg runs from a GitLab/GitHub runner.

I've created a specific directory for this suite of processors since the required modules are 'vendored' with the processors. This keeps modifications from being needed to either AutoPkg or System python versions. It's possible someone has a better way to do this. If so, please contact me or start an Issue.

# Installation

To use this processor, you will need to create a keychain credential. An existing credential can be used if desired (see [McmApiProcessors](../McmApiProcessors/README.md))

## macOS

Decide on a service name, for example 'com.github.autopkg.iancohn-recipes.smbcopier'

```zsh
username = "username@domain.com"
security add-generic-password -a $username -s com.github.autopkg.iancohn-recipes.smbcopier -T '/Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3' -U -w
```

# Processors

## SmbCopier

Copy a folder or file between local/smb paths.

### SmbCopier Input Variables

The following input variables are used by this processor.

| Variable Name                  | Description                                                                     | Default Value |
| ------------------------------ | ------------------------------------------------------------------------------- | ------------- |
| smbcopier_keychain_servicename | The service name used to store the password                                     | `None`      |
| smbcopier_keychain_username    | The username of the credential to retrieve                                      | `None`      |
| source_path                    | A path to a file or folder to copy                                              | `None`      |
| destination_path               | A destination to which the file or folder should be copied                      | `None`      |
| overwrite                      | Whether an existing object in the destination path should be purged/overwritten | `False`     |

## Additional Notes

- Both *source_path* and *destination_path* can be either UNC\SMB or local paths. You can copy from SMB to SMB, SMB to Local, or Local to SMB
- If *destination_path* ends with a trailing slash, the *source_path* item (file or folder) will retain its current name and be copied, as an object, inside of the destination.

## SmbFolderCreator
Create a folder in an SMB path

### SmbFolderCreator Input Variables

## SmbPathChecker
Check an SMB path to see if a path exists

### SmbPathChecker Input Variables