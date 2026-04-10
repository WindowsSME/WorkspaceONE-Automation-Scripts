# WorkspaceONE Automation Scripts

This repository contains **PowerShell scripts for automating Workspace ONE UEM administration**.  
The scripts are designed to simplify bulk operations, Smart Group management, and other administrative tasks.

---

## Current Scripts

- [Add-DevicesToSmartGroup.ps1](./Add-DevicesToSmartGroup.ps1)  
  Bulk-add devices (using Device UUIDs) into a specified Smart Group.

- [Manage-WS1SmartGroupByUser.ps1](./Manage-WS1SmartGroupByUser.ps1)  
  Bulk update Workspace ONE Smart Group membership using User NTIDs instead of Device UUIDs - ideal for user-centric targeting.

- [HubUpgrade_September2025.ps1](./HubUpgrade_September2025.ps1)  
  A specialized deployment script used to automate and track the Workspace ONE Intelligent Hub upgrade process during the September 2025 rollout.

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
   ```

---

## Notes
These scripts were tested against Workspace ONE UEM SaaS environments.
Ensure you test in a dedicated "UAT" or "Dev" Organization Group before applying changes in production.

---

## Contributions
Have your own Workspace ONE or MDM automation scripts? Feel free to fork, add, and open a pull request.

---

## License
MIT License
