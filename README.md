# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="517" height="269" alt="image" src="https://github.com/user-attachments/assets/ceb7e6fb-faa4-4bc1-b0d1-9fcedf833c41" />

# Threat Hunt Report: Suspicious Powershell Activity
- [Scenario Creation](https://github.com/cherinejoseph/threat-hunting-scenario-powershell/blob/main/threat-hunting-scenario-powershell.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- PowerShell
- Eicar File 

##  Scenario

A recent cybersecurity news alert highlighted an increase in threat actors abusing PowerShell to download malicious payloads directly from the internet. In response, management directed a proactive hunt on a specific corporate endpoint due to unusual PowerShell activity detected in preliminary logs. The goal was to identify any suspicious PowerShell usage and malicious file interactions on this device.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for file downloads, renames, deletions, and interactions with potentially malicious payloads.
- **Check `DeviceProcessEvents`** for PowerShell process creation with suspicious commands, including attempts to execute downloaded files.
- **Check `DeviceNetworkEvents`** for outbound connections initiated by PowerShell.
- **Check `DeviceEvents`** for additional context, including security alerts and blocked execution attempts.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for instance of PowerShell being executed with -ExecutionPolicy Bypass and Invoke-WebRequest. I discovered that the account “windowsvm” launched PowerShell at 2025-09-17T20:43:20. on windows-vm-lab. The command execution indicates an attempt to run scripts in a stealthy manner, likely to download or manipulate files without user awareness.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-lab"
| where FileName == "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "-ExecutionPolicy Bypass", "-WindowStyle Hidden")
| project Timestamp, DeviceName, ActionType, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc

```
<img width="1309" height="458" alt="image" src="https://github.com/user-attachments/assets/dbaeda6e-a7e1-44cf-84d2-cd80975626c2" />

Expanded result for further observation:

<img width="2458" height="462" alt="image" src="https://github.com/user-attachments/assets/c20a286a-b311-4c45-979c-ff7b633cc81b" />



---

### 2. Searched the `DeviceFilevents` Table

Searched the DeviceFileEvents table for  for file activity on the device “windows-vm-lab” starting at the time PowerShell was launched and discovered the following sequence of events by user "windowsvm":


- Sep 17, 2025 4:44:12 PM – A file named “eicar.com” was created in C:\Users\Public\.
- Sep 17, 2025 4:44:26 PM – The file “eicar.com” was renamed to eicar.exe, indicating preparation for execution.
- Sep 17, 2025 4:45:16 PM – The file eicar.exe was deleted, suggesting either cleanup by the attacker or security controls removing the file.


**Query used to locate event:**

```kql

DeviceFileEvents
| where DeviceName == "windows-vm-lab"
| where Timestamp >= datetime(2025-09-17T20:43:20) 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

```
<img width="2702" height="1096" alt="image" src="https://github.com/user-attachments/assets/5230174f-b1e2-4911-8337-25f5d3aa6ab1" />

---

### 3. Searched the `DeviceProcessEvents` Table for Execution Attempts

Searched DeviceProcessEvents for evidence that “eicar.com” or “eicar.exe” was executed. No process creation events were found. At this stage, there is no indication that the file successfully ran as a process. Further review of DeviceEvents and AlertEvents is required to determine whether an execution attempt was identified. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-lab"
| where ProcessCommandLine has_any ("eicar.exe", "eicar.com")
  or FileName in ("eicar.exe", "eicar.com")
| project Timestamp, DeviceName, ActionType, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc


```
<img width="2670" height="1216" alt="image" src="https://github.com/user-attachments/assets/8225033f-4986-4344-9f9b-52d6c0f5ef3d" />

---

### 4. Searched the `DeviceEvents` Table for further investigation

Searched the DeviceEvents table for evidence of execution of “eicar.com” or “eicar.exe”. Multiple AntivirusDetection events were found for the file EICAR.txt during PowerShell activity. Each event has a unique ReportId (e.g., 6305, 6306, 3351, 3350, 3675, 3676) representing a discrete detection by Microsoft Defender. These events indicate that Defender detected the file, but no process creation events were recorded. This confirms that while the file was present and PowerShell interacted with it, it never successfully ran as a process.


**Query used to locate events:**

```kql
DeviceEvents
| where DeviceName == "windows-vm-lab"
| where ActionType has_any ("AntivirusDetection", "ExploitGuardBlock", "ProgramBlocked", "MalwareDetected", "MalwareStopped")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc

```
<img width="2706" height="1190" alt="image" src="https://github.com/user-attachments/assets/e61b99d2-0122-4e81-bb86-92cd35de99c0" />

---
### 5. Searched the `DeviceNetworkEvents` Table for further investigation

 Searched the DeviceNetworkEvents Table for outbound HTTP requests from PowerShell.
 The query identified a successful connection to “eicar.org” on port 443 at 2025-09-17T17:43:48. This confirms that PowerShell attempted network activity to retrieve the EICAR file from the internet.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-vm-lab"
| where InitiatingProcessFileName == "powershell.exe"
| where RemoteUrl contains "eicar.org"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileName
| order by Timestamp desc

```
<img width="1318" height="537" alt="image" src="https://github.com/user-attachments/assets/5e039514-9425-491e-a95b-ddffded1f503" />


---

## Chronological Event Timeline 

### 1. PowerShell Launch

- **Timestamp:** Sep 17, 2025 4:43:20 PM
- **Event:** The user `windowsvm` launched `powershell.exe` with the intention of downloading a file from the internet.
- **Action:** Process creation detected.
- **Command:** `"powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass`

### 2. File Creation - EICAR Download 

- **Timestamp:** Sep 17, 2025 4:44:12 PM
- **Event:** PowerShell created a file named `eicar.com` in `C:\Users\Public\`.
- **Action:** File creation detected, indicating the download of the EICAR test file.
- **Process:** `powershell.exe`
- **File Path:** `C:\Users\Public\eicar.com`

### 3. File Rename - EICAR

- **Timestamp:** `2025-09-17T16:44:26`
- **Event:** The file `eicar.com` was renamed to `eicar.exe`.
- **Action:** File rename detected.
- **Process:** `powershell.exe`
- **File Path:** `C:\Users\Public\eicar.exe`


### 4. File Deletion - EICAR

- **Timestamp:** `2025-09-17T16:45:16`
- **Event:** The file `eicar.exe` was deleted from the system.
- **Action:** File deletion detected.
- **Process:** `powershell.exe`
- **File Path:** `C:\Users\Public\eicar.exe`

### 5. Attempted Execution / Review of DeviceProcessEvents

- **Timestamp:** `2025-09-17T16:45:20`
- **Event:** Searched for execution of `eicar.com` or `eicar.exe`; no process creation events were found.
- **Action:** Execution attempt review.
- **Process:** N/A
- **File Path:** `C:\Users\Public\eicar.com`, `C:\Users\Public\eicar.exe`

### 6. Device Events - Antivirus Detection

- **Timestamp:** `2025-09-17T16:46:04`
- **Event:** Antivirus detections triggered for the EICAR file.
- **Action:** Alert generated.
- **Process:** `powershell.exe`
- **File Path:** `C:\ProgramData\eicar.ps1`

### 6. Network Connection - EICAR.org

- **Timestamp:** `2025-09-17T13:43:48`
- **Event:** Outbound network connection to `www.eicar.org` established via PowerShell.
- **Action:** Connection success.
- **Remote IP:** `89.238.73.97`
- **Remote Port:** `443`
- **Remote URL:** `www.eicar.org`

---

## Summary

The investigation of ```windows-vm-lab``` revealed suspicious PowerShell activity that downloaded, renamed, and deleted the EICAR test file. No process creation was observed, indicating the file was not successfully executed. Outbound connections to www.eicar.org confirmed network activity consistent with malicious PowerShell behavior.

---

## Response Taken

The activity on ```windows-vm-lab``` was documented for further review. The device remains under monitoring for similar PowerShell behaviors, and IT management has been notified of the findings.

---
