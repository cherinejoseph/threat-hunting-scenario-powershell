# Threat Event (Suspicious PowerShell Activity)
**Unauthorized PowerShell Script Execution and Download Attempt**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Open PowerShell Stealthily with Execution Policy Bypass
2. Download a malicious payload from the internet Using ```Invoke-WebRequest```: https://www.eicar.org/download/eicar-com/
3. Rename File Locally Using PowerShell:
   - **Purpose: Attempt to convert the downloaded payload to an executable in preparation for running it.**
4. Attempted Execution of Payload
   - **Note: Execution will fail because renaming the file does not make it a valid Windows executable (corrupted/unreadable).**
5. Delete the file

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect file activity such as downloads, renames, deletions, and general file interactions with suspicious payloads like EICAR.. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect PowerShell execution attempts and process activity.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect any outbound network connections initiated by PowerShell.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table|
| **Purpose**| Provides additional context for interactions with suspicious files, including detections, alerts, and other system-generated events for further investigation.|

---

## Related Queries:
```kql
// Detect suspicious PowerShell activity
DeviceProcessEvents
| where DeviceName == "windows-vm-lab"
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "-ExecutionPolicy Bypass", "-WindowStyle Hidden")
| project Timestamp, DeviceName, ActionType, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc

// Detect file download, rename, and deletion events
DeviceFileEvents
| where DeviceName == "windows-vm-lab"
| where Timestamp >= datetime(2025-09-17T20:43:20) 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

// Check DeviceProcessEvents for execution of EICAR file
DeviceProcessEvents
| where DeviceName == "windows-vm-lab"
| where ProcessCommandLine has_any ("eicar.exe", "eicar.com")
  or FileName in ("eicar.exe", "eicar.com")
| project Timestamp, DeviceName, ActionType, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// Further investigation of Eicar file interactions
DeviceEvents
| where DeviceName == "windows-vm-lab"
| where FileName has_any ("eicar.exe", "eicar.com", "EICAR.txt")
| where ActionType == "AntivirusDetection"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine, ReportId
| order by Timestamp desc

// Check for outbound HTTP requests from PowerShell
DeviceNetworkEvents
| where DeviceName == "windows-vm-lab"
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteUrl contains "eicar.org"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Cherine Joseph
- **Author Contact**: https://www.linkedin.com/in/cherine-joseph/
- **Date**: September 17, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  17, 2025`  | `Cherine Joseph`   
