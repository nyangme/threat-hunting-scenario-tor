<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
  
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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-16T22:41:50.6990571Z`. These events began at `2025-09-16T22:22:27.6215455Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "mythreathunt804"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| order by Timestamp desc
```
<img width="2559" height="987" alt="image" src="https://github.com/user-attachments/assets/6984a8fd-b15e-43f1-a2e6-b92429e8c1c6" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.7.exe". There were no logs generated that would suggest that the TOR installer was ran.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "mythreathunt804"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"  
```
<img width="2559" height="353" alt="image" src="https://github.com/user-attachments/assets/90558dbe-d468-4fe6-a81a-bcf6ed80664f" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-09-16T22:27:30.1466258Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards until `2025-09-16T22:32:50.6386543Z`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "mythreathunt804"
| where InitiatingProcessAccountName == "employee"
| where FileName has_any ("tor.exe", "firefox.exe")  
| order by Timestamp desc
```
<img width="2559" height="1321" alt="image" src="https://github.com/user-attachments/assets/371eda8e-d586-47ef-a563-640dc9824548" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR initiating process file names. At `2025-09-16T22:27:07.7385204Z`, an employee on the "mythreathunt804" device successfully established a connection to the localhost IP address `127.0.0.1` on port `9150`. The connection was initiated by the process `firefox.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\firefox.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "mythreathunt804"
| where InitiatingProcessAccountName == "employee"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| order by Timestamp desc 
```
<img width="2559" height="932" alt="image" src="https://github.com/user-attachments/assets/2e0625ec-e625-4851-8bff-45039e2d8f88" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-09-16T22:22:47.1301555Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 2. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-16T22:27:30.1466258Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\firefox.exe`

### 3. Network Connection - TOR Network

- **Timestamp:** `2025-09-16T22:27:07.7385204Z`
- **Event:** A network connection to localhost `127.0.0.1` on port `9150` by user "employee" was established using `firefox.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\firefox.exe`

### 4. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-09-16T22:32:13.6459504Z` - Connected to localhost `127.0.0.1` on port `50784`.
  - `2025-09-16T22:32:30.4079278Z` - Connected to `5.132.159.238` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 5. File Creation - TOR Shopping List

- **Timestamp:** `2025-09-16T22:41:50.6990571Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt.txt`

---

## Summary

The user "employee" on the "mythreathunt804" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `mythreathunt804` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
