# WorkspaceONE Automation Scripts

This repository contains **PowerShell scripts for automating Workspace ONE UEM administration**.  
The scripts are to simplify bulk operations, Smart Group management, and other administrative tasks.

---

## Current Scripts
- [Add-DevicesToSmartGroup.ps1](Add-DevicesToSmartGroup.ps1) → Bulk-add devices (by UUID) into a specified Smart Group.

---

## Requirements
- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core).
- Workspace ONE UEM API credentials with sufficient permissions.
- API Tenant Code (`aw-tenant-code`).
- Internet access to your Workspace ONE UEM environment.

---

## Usage Example (Add Devices to Smart Group)

1. Prepare a CSV with a `GUID` column (device UUIDs).
2. Run the script:
   ```powershell
   .\Add-DevicesToSmartGroup.ps1
