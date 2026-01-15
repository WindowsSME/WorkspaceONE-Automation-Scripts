<#
.SYNOPSIS
    WorkspaceONE Smart Group Membership Manager (Bulk Add/Remove).

.DESCRIPTION
    This script automates the process of adding or removing Windows (WinRT) devices 
    from a specific WorkspaceONE Smart Group based on a list of usernames provided in a CSV.
    It uses the WorkspaceONE REST API (V2 Smart Groups endpoint) to perform Patch operations.

.PREREQUISITES
    1. A CSV file located at "C:\Temp\UserList.csv" with a column header named "Username".
    2. WorkspaceONE admin credentials
    3. API Key

.NOTES
    Author: James Romeo Gaspar
    Created: January 15, 2026

.OUTPUTS
    A timestamped CSV report located in "C:\Temp\" detailing the success/failure of each device operation.
#>

$credential = Get-Credential -Message "Enter Workspace ONE API user credentials"
$tenantCodeSecure = Read-Host "Enter your aw-tenant-code (Tenant API Key)" -AsSecureString
$tenantCode = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($tenantCodeSecure))

Set-Clipboard -Value " "

$subDomain = (Read-Host "Enter your tenant subdomain (e.g., JG6378)").Trim()
$smartGroupName = (Read-Host "Enter the full Smart Group name (e.g., UAT-JamesPogi").Trim()

$mode = Read-Host "Do you want to ADD or REMOVE these devices? (A/R)"
$opType = if ($mode -eq "R") { "remove" } else { "add" }

$inputPath  = "C:\Temp\UserListUAT.csv"
$timestamp  = Get-Date -Format "yyyyMMdd_HHmm"
$outputPath = "C:\Temp\SmartGroup_${opType}_${timestamp}.csv"

if (-not (Test-Path -Path $inputPath)) {
    Write-Host "Error: Could not find the input file at ${inputPath}." -ForegroundColor Red
    return
}

$userName = $credential.UserName
$password = $credential.GetNetworkCredential().Password
$authBytes = [System.Text.Encoding]::UTF8.GetBytes("${userName}:${password}")
$base64Auth = [Convert]::ToBase64String($authBytes)

$headers = @{
    "Authorization"  = "Basic $base64Auth"
    "aw-tenant-code" = $tenantCode
    "Accept"         = "application/json"
    "Content-Type"   = "application/json"
}

$headersV2 = $headers.Clone()
$headersV2["Accept"] = "application/json;version=2"
$headersV2["Content-Type"] = "application/json-patch+json"

$restHost = "https://${subDomain}.awmdm.com"
$sgSearchUrl = "${restHost}/api/mdm/smartgroups/search?name=${smartGroupName}"

Write-Host "`nSearching for Smart Group: ${smartGroupName}..." -ForegroundColor Cyan

try {
    $sgResponse = Invoke-RestMethod -Method GET -Uri $sgSearchUrl -Headers $headers
    $targetGroup = $sgResponse.SmartGroups | Where-Object { $_.Name -eq $smartGroupName }

    if (-not $targetGroup) {
        Write-Host "Error: Smart Group '${smartGroupName}' not found." -ForegroundColor Red
        return
    }
    $sgUuid = $targetGroup.SmartGroupUuid
    Write-Host "Success! Group ID Found: ${sgUuid}" -ForegroundColor Green
} catch {
    Write-Host "Auth Error: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$usernames = Import-CSV -Path $inputPath
$patchOperations = @()
$uploadLog = New-Object System.Collections.Generic.List[PSObject]

Write-Host "`nScanning for Enrolled devices of listed users..." -ForegroundColor Cyan
foreach ($user in $usernames) {
    $uName = $user.Username
    try {
        $deviceUrl = "${restHost}/api/mdm/devices/search?user=${uName}"
        $deviceResponse = Invoke-RestMethod -Method GET -Uri $deviceUrl -Headers $headers
        
        foreach ($device in $deviceResponse.Devices) {
            if ($device.EnrollmentStatus -ilike "*Enrolled*" -and $device.Platform -ilike "*WinRT*") {
                
                $foundFriendlyName = ""
                if ($device.DeviceFriendlyName) { $foundFriendlyName = $device.DeviceFriendlyName }
                elseif ($device.FriendlyName) { $foundFriendlyName = $device.FriendlyName }
                elseif ($device.DisplayName) { $foundFriendlyName = $device.DisplayName }
                else { $foundFriendlyName = "Unknown Name" }

                $patchOperations += @{
                    op    = $opType
                    path  = "/smartGroupsOperationsV2/devices"
                    value = $device.Uuid
                }
                
                $uploadLog.Add([PSCustomObject]@{
                    SmartGroupName     = $smartGroupName
                    Operation          = $opType
                    Username           = $uName
                    DeviceFriendlyName = $foundFriendlyName
                    SerialNumber       = $device.SerialNumber
                    DeviceUUID         = $device.Uuid
                    Status             = "Pending"
                })

                Write-Host "  Matched: ${uName} | Name: ${foundFriendlyName} | SN: $($device.SerialNumber)" -ForegroundColor Gray
            }
        }
    } catch { Write-Host "  Error querying ${uName}" -ForegroundColor Red }
}

if ($patchOperations.Count -gt 0) {
    Write-Host "`nExecuting ${opType} for $($patchOperations.Count) devices..." -ForegroundColor Yellow
    $bodyJson = $patchOperations | ConvertTo-Json -Depth 10
    $patchUri = "${restHost}/api/mdm/smartgroups/${sgUuid}"

    try {
        $null = Invoke-RestMethod -Method Patch -Uri $patchUri -Body $bodyJson -Headers $headersV2
        Write-Host "Processing command..." -ForegroundColor Green
        
        Write-Host "Verifying final membership count..." -ForegroundColor Gray
        Start-Sleep -Seconds 8 
        
        $verifyResponse = Invoke-RestMethod -Method GET -Uri $sgSearchUrl -Headers $headers
        $updatedGroup = $verifyResponse.SmartGroups | Where-Object { $_.Name -eq $smartGroupName }
        
        $finalCount = $updatedGroup.Devices
        Write-Host "Verification Complete: '${smartGroupName}' now has ${finalCount} total devices." -ForegroundColor White
        
        foreach($row in $uploadLog) { $row.Status = "Completed" }
    } catch {
        Write-Host "Verification failed: $($_.Exception.Message)" -ForegroundColor Red
        foreach($row in $uploadLog) { $row.Status = "Check Console" }
    }
} else {
    Write-Host "No matching devices found." -ForegroundColor Red
}

$uploadLog | Export-CSV -Path $outputPath -NoTypeInformation
Write-Host "`nReport saved to: ${outputPath}" -ForegroundColor Green
