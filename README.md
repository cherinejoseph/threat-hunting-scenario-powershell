# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cherinejoseph/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee015" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-12T20:01:18.1181308Z`. These events began at `2025-09-12T19:51:10.5002119Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "windows-vm-empl"
| where InitiatingProcessAccountName == "employee015"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-12T19:51:10.5002119Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```
<img width="2708" height="1314" alt="image" src="https://github.com/user-attachments/assets/56a12a86-89d8-4b0f-b0e9-13e2d51a36f2" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-09-12T19:52:45.0844675Z`, an employee on the "windows-vm-empl" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "windows-vm-empl"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1329" height="493" alt="image" src="https://github.com/user-attachments/assets/da95fd21-15ce-4e01-81b8-1888a4611c5a" />


Expanded result for further observation:

<img width="956" height="576" alt="image" src="https://github.com/user-attachments/assets/d743841e-793f-472f-afe8-2b5d3ec92f21" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee015" actually opened the TOR browser. There was evidence that they did open it at `2025-09-12T19:52:58.0674538Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-empl"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="2656" height="1304" alt="image" src="https://github.com/user-attachments/assets/8b6d8b2a-e02f-4c9f-b9b2-c2486f0ba0fd" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-09-12T19:54:10.1943861Z`, an employee on the "windows-vm-empl" device successfully established a connection to the remote IP address `81.137.179.68` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee015\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "windows-vm-empl"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="2710" height="1314" alt="image" src="https://github.com/user-attachments/assets/214d7b3c-6c38-4e80-ac88-840af28c2c69" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-12T19:51:10.5002119Z`
- **Event:** The user "employee015" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee015\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-12T19:52:45.0844675Z`
- **Event:** The user "employee015" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe /S`
- **File Path:** `C:\Users\employee015\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-12T19:52:58.0674538Z`
- **Event:** User "employee015" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee015\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-12T19:54:10.1943861Z`
- **Event:** A network connection to IP `81.137.179.68` on port `9001` by user "employee015" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee015\desktop\tor browser\browser\firefox.exe

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-12T19:54:17.5339277Z` - Connected to `64.65.63.44` on port `443`.
  - `2025-09-12T19:55:20.787043Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee015" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-12T20:01:18.1181308Z`
- **Event:** The user "employee015" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee015\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee015" on the "windows-vm-empl" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `windows-vm-empl` by the user `employee015`. The device was isolated, and the user's direct manager was notified.

---
