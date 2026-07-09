 # Site configuration
$SiteCode = "XYZ" # Site code 
$ProviderMachineName = "siteServer.fqdn.com" # SMS Provider machine name

# Script Configuration
$approvalScriptName = "AutoPkg Script Approver" # Friendly name for the script approver
$autoPkgScriptsPath = "/AutoPkg/Temp" # Only scripts in this folder will be approved
$autoPkgScriptsSecurityScopes = @("AutoPkg") # Only scripts matching the scopes in this array will be approved
$securityScopeMatchingAlgorithm = "Contains" # Contains, Equals
$approvalComment = "Auto-approved by [$($approvalScriptName)] version [$($approvalScriptVersion)] on $((Get-Date).ToString('yyyy.MM.ddThh:mm'))" # Modify if desired

# Customizations
$initParams = @{}

# Do not change anything below this line
$approvalScriptVersion = '1.0' # Script Version

# Import the ConfigurationManager.psd1 module 
if((Get-Module ConfigurationManager) -eq $null) {
    Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams 
}

# Connect to the site's drive if it is not already present
if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
    New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams | Out-Null
}

# Set the current location to be the site code.
Set-Location "$($SiteCode):\" @initParams | Out-Null

#Begin approval Script
$result = @{
    "ResultStatus" = "Failed";
    "SuccessfullyApproved" = 0;
    "Errors" = 0;
    "ApprovedScripts" = @();
    "ErroredScripts" = @();
}

try {
    <#
    $approvalStates = @{
        0 = "Awaiting Approval";
        1 = "Declined";
        3 = "Approved";
    }
    #>
    #Get Scripts
    $smsScripts = Get-CMScript -Fast
    if (-not ($smsScripts.Count -gt 0)) {
        throw "No Scripts Found"
    }

    $filtered = $smsScripts.Where({$_.ObjectPath -eq $autoPkgScriptsPath}) | Where-Object {
        $o = $_
        Get-CMObjectSecurityScope -InputObject $o -OutVariable scopes | Out-Null
        Compare-Object -ReferenceObject ($scopes.CategoryName) -DifferenceObject $autoPkgScriptsSecurityScopes -OutVariable comparison | Out-Null
        switch ($securityScopeMatchingAlgorithm) {
            "Contains" {
                $r = $comparison.Where({$_.SideIndicator -eq '=>'}).Count -eq 0
                return $r
            }
            "Equals" {
                $r = $comparison.Count -eq 0
                return $r
            }
            DEFAULT {return $false}
        }
    }

    if ($filtered.Count -eq 0) {
        $result['ResultStatus'] = "Success"
    }
    foreach ($s in $filtered) {
        try {
            
            Approve-CMScript -Confirm:$false -InputObject $s -Comment $approvalComment | Out-Null
            $result['SuccessfullyApproved'] ++
            $result['ApprovedScripts'] += @{
                "ScriptGuid" = $s.ScriptGuid;
                "ScriptName" = $s.ScriptName;
            }
        } catch {
            $result['Errors'] ++
            $result['ErroredScripts'] += @{
                "ScriptGuid" = $s.ScriptGuid;
                "ScriptName" = $s.ScriptName;
            }
        }
    }
    if ($result['Errors'] -eq 0) {
        $result['ResultStatus'] = 'Success'
    } elseif ($result['SuccessfullyApproved'] -gt 0) {
        $result['ResultStatus'] = 'SuccessfulWithIssues'
    }
    
} catch {
    
} finally {
    Write-Host ($result | ConvertTo-Json -Depth 10 -Compress)
}
