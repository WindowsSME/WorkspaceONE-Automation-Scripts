<#
.SYNOPSIS
    Bulk-add devices to a Workspace ONE UEM Smart Group.

.DESCRIPTION
    This PowerShell script connects to the Workspace ONE UEM API and automates the 
    process of adding multiple devices (by UUID) into a specified Smart Group.

    - Prompts for Workspace ONE API credentials, tenant code, and tenant subdomain.
    - Imports a CSV file containing device UUIDs.
    - Looks up the Smart Group ID by name.
    - Iterates through each device and sends a PATCH request to add it to the Smart Group.
    - Provides console output for progress tracking.

.PARAMETER Workspace ONE Credentials
    The script prompts for Workspace ONE UEM API username and password.

.PARAMETER Tenant Code
    The script prompts for the Workspace ONE tenant API key (aw-tenant-code).

.PARAMETER Tenant Subdomain
    The script prompts for the tenant subdomain (e.g., JG6378) to build the API endpoint.

.PARAMETER Smart Group Name
    The script prompts for the full name of the Smart Group.

.PARAMETER Devices CSV
    Path is hardcoded as `C:\Temp\Devices.csv`. The file must contain a `GUID` column with device UUIDs.

.REQUIREMENTS
    - PowerShell 5.1 or later
    - Valid Workspace ONE UEM API account with Smart Group management permissions
    - API Tenant Code and Subdomain
    - Devices CSV file with UUIDs

.EXAMPLE
    PS> .\Add-DevicesToSmartGroup.ps1
    Enter your Workspace ONE API user credentials
    Enter your aw-tenant-code (Tenant API Key): ********
    Enter the full Smart Group name: TestGroup
    Enter your tenant subdomain (e.g. JG6378): JG6378
    Loaded 50 devices from C:\Temp\Devices.csv
    Processing 12345678-abcd-efgh-ijkl-9876543210
    Added 12345678-abcd-efgh-ijkl-9876543210 to Smart Group TestGroup

.NOTES
    Author: James Romeo Gaspar
    Date  : September 26, 2025
    Attribution : Derived from the original script written by June Barry Aseo
    Purpose: Bulk-add devices to a Smart Group in Workspace ONE UEM using the REST API.
#>

# Prompt for Workspace ONE API credentials
$credential = Get-Credential -Message "Enter your Workspace ONE API user credentials"

# Prompt for tenant API key (aw-tenant-code) and convert it from secure string
$tenantCodeSecure = Read-Host "Enter your aw-tenant-code (Tenant API Key)" -AsSecureString
$tenantCode = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tenantCodeSecure)
)

# Clear clipboard for safety
Set-Clipboard -Value " "

# Prompt for Smart Group name
$SmartgroupList = Read-Host "Enter the full Smart Group name"

# Prompt for Workspace ONE tenant subdomain (required to build REST host URL)
$subDomain = Read-Host "Enter your tenant subdomain (e.g. JG6378)"
$subDomain = $subDomain.Trim()

# Exit script if no subdomain provided
if ([string]::IsNullOrWhiteSpace($subDomain)) {
    Write-Error "Tenant subdomain is required. Exiting."
    exit
}

# Encode credentials (username:password) in Base64 for API authentication
$cred = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().Password)")
)

# Basic authentication header (no version specified)
$header1 = @{
    "Authorization"  = "Basic " + $cred
    "aw-tenant-code" = $tenantCode
}

# Authentication header with JSON response (API version 2)
$header2 = @{
    "Authorization"  = "Basic " + $cred
    "aw-tenant-code" = $tenantCode
    "Accept"         = "application/json;version=2"
}

# Load devices from CSV (must contain column 'GUID')
$filepath = "C:\Temp\Devices.csv"
$CSVFile = Import-CSV -Path $filepath
Write-Host "Loaded $($CSVFile.Count) devices from $filepath"

# Process each device in the CSV
foreach ($Device in $CSVFile) {
    $DeviceUUID = $Device.GUID
    Write-Host "Processing $DeviceUUID"

    # Build REST host URL from subdomain
    $restHost   = "https://" + "$subDomain.awmdm.com"
    $apiPrefix  = "/API/mdm/"

    # Search Smart Group by name to get Smart Group UUID
    $searchSmartgroupUri = $restHost + $apiPrefix + "smartgroups/search?name=" + $SmartgroupList
    $restCallResponse = Invoke-RestMethod -Method GET -Uri $searchSmartgroupUri -Headers $header1 -ContentType "application/json"
    $SmartGroups      = $restCallResponse.SmartGroups

    # Extract Smart Group UUID
    foreach ($SmartGroup in $SmartGroups) {
        $SGID1 = $SmartGroup.smartGroupUuid
    }

    # JSON patch payload to add device to Smart Group
    $json = @"
[
    { op: "add",
      path: "/smartGroupsOperationsV2/devices",
      value: "$DeviceUUID"
    }
]
"@

    # PATCH request to update Smart Group with new device
    $uri1   = $restHost + "/api/mdm/smartgroups/" + $SGID1
    $result = Invoke-RestMethod -Method Patch -Uri $uri1 -Body $json -Headers $header2 -ContentType "application/json-patch+json"

    Write-Host "Added $DeviceUUID to Smart Group $SmartgroupList"
}
