
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/askonube/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string `tor` in it and discovered what looks like the user `ylavnu` downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-06-15T19:26:08.4779492Z`. These events began at `2025-06-15T19:06:56.4633679Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "win-vm-mde"
| where InitiatingProcessAccountName == "ylavnu"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-15T19:06:56.4633679Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/ac4a02ed-279b-490c-a83c-6e4948ce95f3)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string `tor-browser-windows-x86_64-portable-14.5.3.exe`. Based on the logs returned, at `2025-06-15T19:15:04.2299353Z`, an employee on the `win-vm-mde` device ran the file `tor-browser-windows-x86_64-portable-14.5.3.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "win-vm-mde"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256
```

![image](https://github.com/user-attachments/assets/79602b8a-51f1-4368-b993-67ebe5e9a6de)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user `ylavnu` actually opened the TOR browser. There was evidence that they did open it at `2025-06-15T19:15:50.6163583Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "win-vm-mde"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, SHA256  
| order by Timestamp desc
```
<img width="1364" alt="Screenshot 2025-06-16 142126" src="https://github.com/user-attachments/assets/30ac91d1-994c-4966-8d59-08cad60eca06" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. There were three main instances where the user established connections.

1. At `2025-06-15T19:16:08.062338Z`, the user `ylavnu` on the `win-vm-mde` device successfully established a connection to the remote IP address `193.105.134.150` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\ylavnu\desktop\tor browser\browser\torbrowser\tor\tor.exe`.
   
2. At `2025-06-15T19:16:11.6181618Z`, the user `ylavnu` on the `win-vm-mde` device successfully established a connection to the remote IP address `81.17.28.117` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\ylavnu\desktop\tor browser\browser\torbrowser\tor\tor.exe`.
   
3. At `2025-06-15T19:16:20.2701989Z`, the user `ylavnu` on the `win-vm-mde` device successfully established a connection to the remote IP address `193.11.164.243` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\ylavnu\desktop\tor browser\browser\torbrowser\tor\tor.exe`.

There were also a couple of connections to sites on port `443`.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "win-vm-mde"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
![image](https://github.com/user-attachments/assets/3dfac02d-7e92-48c4-a985-ca518c1e9458)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-15T19:06:56.4633679Z`
- **Event:** The user `ylavnu` downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\ylavnu\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-15T19:15:04.2299353Z`
- **Event:** The user `ylavnu` executed the file `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\ylavnu\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-06-15T19:15:50.6163583Z`
- **Event:** User `ylavnu` opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\ylavnu\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** Three network connections were established using `tor.exe` by the user `ylavnu`. At `2025-06-15T19:16:08.062338Z`, the `win-vm-mde` device successfully established a connection to the remote IP address `193.105.134.150` on port `9001`. At `2025-06-15T19:16:11.6181618Z`, the `win-vm-mde` device successfully established a connection to the remote IP address `81.17.28.117` on port `9001`. At `2025-06-15T19:16:20.2701989Z`, the `win-vm-mde` device successfully established a connection to the remote IP address `193.11.164.243` on port `9001`. These events confirm TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ylavnu\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-06-15T19:16:10.3569535Z` - Connected to `200.122.181.2` on port `443`.
  - `2025-06-15T19:16:11.6106377Z` - Connected to `185.107.57.66` on port `443`.
  - `2025-06-15T19:16:23.1127259Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user `ylavnu` through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-15T19:26:08.4779492Z`
- **Event:** The user `ylavnu` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\ylavnu\Desktop\tor-shopping-list.txt`

---

## Summary

The user `ylavnu` on the `win-vm-mde` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the `shopping list` file.

---

## Response Taken

TOR usage was confirmed on the endpoint `win-vm-mde` by the user `ylavnu`. The device was isolated, and the user's direct manager was notified.

---
