<#
.SYNOPSIS
    This PowerShell script adds a list of devices (by UUID) into a specified Workspace ONE UEM Smart Group.

.DESCRIPTION
    - Prompts for Workspace ONE API credentials and the tenant API key (aw-tenant-code).
    - Imports a list of devices from a CSV file.
    - Looks up the Smart Group ID based on the given Smart Group name.
    - Iterates through each device from the CSV and sends a PATCH request 
      to add the device to the Smart Group.
    - Outputs progress to the console as devices are processed.

.REQUIREMENTS
    - PowerShell 5.1 or later
    - CSV file with a "GUID" column (device UUIDs).
    - Proper Workspace ONE API credentials with Smart Group management permissions.
    - API version 2 compatibility.

.PARAMETER Workspace ONE Credentials
    The script prompts for Workspace ONE UEM API username and password.

.PARAMETER Tenant Code
    The script prompts for the tenant API key (aw-tenant-code).

.PARAMETER Smart Group Name
    The script prompts for the full Smart Group name to which devices will be added.

.PARAMETER Devices CSV
    Path is hardcoded as "C:\Temp\Devices.csv". The file must contain a column "GUID".

.EXAMPLE
    PS> .\Add-DevicesToSmartGroup.ps1
    Enter your Workspace ONE API user credentials
    Enter your aw-tenant-code (Tenant API Key): ********
    Enter the full Smart Group name: TestGroup
    Loaded 50 devices from C:\Temp\Devices.csv
    Processing 12345678-abcd-efgh-ijkl-9876543210
    Added 12345678-abcd-efgh-ijkl-9876543210 to Smart Group TestGroup

.NOTES
    Author: James Romeo Gaspar
    Date  : September 26, 2025
    Attribution : Derived from the original script written by June Barry Aseo
    Purpose: Bulk-add devices to a Smart Group in Workspace ONE UEM using the REST API.
#>

# Prompt for credentials
$credential = Get-Credential -Message "Enter your Workspace ONE API user credentials"

# Prompt for tenant API key
$tenantCodeSecure = Read-Host "Enter your aw-tenant-code (Tenant API Key)" -AsSecureString
$tenantCode = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tenantCodeSecure)
)

# Clear clipboard for safety
Set-Clipboard -Value " "

# Prompt for Smart Group name
$SmartgroupList = Read-Host "Enter the full Smart Group name"

# Encode credentials
$cred = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().Password)"))
)

# Headers for API calls
$header1 = @{
    "Authorization"  = "Basic " + $cred
    "aw-tenant-code" = $tenantCode
}

$header2 = @{
    "Authorization"  = "Basic " + $cred
    "aw-tenant-code" = $tenantCode
    "Accept"         = "application/json;version=2"
}

# CSV path
$filepath = "C:\Temp\Devices.csv"
$CSVFile = Import-CSV -Path $filepath
Write-Host "Loaded $($CSVFile.Count) devices from $filepath"

foreach ($Device in $CSVFile) {
    $DeviceUUID = $Device.GUID
    Write-Host "Processing $DeviceUUID"

    $restHost   = "https://AS1768.awmdm.com"
    $apiPrefix  = "/API/mdm/"

    # Lookup Smart Group by name
    $searchSmartgroupUri = $restHost + $apiPrefix + "smartgroups/search?name=" + $SmartgroupList
    $restCallResponse    = Invoke-RestMethod -Method GET -Uri $searchSmartgroupUri -Headers $header1 -ContentType "application/json"
    $SmartGroups         = $restCallResponse.SmartGroups

    foreach ($SmartGroup in $SmartGroups) {
        $SGID1 = $SmartGroup.smartGroupUuid
    }

    # JSON patch payload to add device to Smart Group
    $json = @"
[
    { "op": "add",
      "path": "/smartGroupsOperationsV2/devices",
      "value": "$DeviceUUID"
    }
]
"@

    # Patch request to update Smart Group
    $uri1   = $restHost + "/api/mdm/smartgroups/" + $SGID1
    $result = Invoke-RestMethod -Method Patch -Uri $uri1 -Body $json -Headers $header2 -ContentType "application/json-patch+json"

    Write-Host "Added $DeviceUUID to Smart Group $SmartgroupList"
}
