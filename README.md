
# Enterprise Threat Detection & Incident Response with Splunk

##  Project Overview
This project demonstrates an end-to-end Security Operations Center (SOC) investigation using **Splunk Enterprise** to analyze endpoint logs (`Sysmon` and `Windows Event Logs`). 

The analysis traces an Advanced Persistent Threat (APT) attack lifecycle following the **MITRE ATT&CK Framework**, covering initial access proxy execution, obfuscated command execution, persistence mechanisms, command-and-control (C2) beaconing, and host reconnaissance.

---

##  Environment & Investigation Details
* **SIEM Platform:** Splunk Enterprise
* **Target System:** `Client2.BCS.local`
* **Affected User Account:** `BCS\alice`
* **Primary Event Sources:**
  * `EventCode 1`: Process Creation (Sysmon / Security)
  * `EventCode 3`: Network Connection (Sysmon)
  * `EventCode 4104`: Script Block Logging (PowerShell)

---

##  Executive SOC Dashboard
Below is an operational overview of the detected malicious activities and threat indicators categorized by attack phase:



---

##  Investigation Workflow & SPL Detection Rules

### Phase 1: Initial Access & Living off the Land (LOLBin Execution)
* **Objective:** Detect execution of malicious HTML Applications (`.hta`) spawned via legitimate native binaries (`mshta.exe`) to bypass standard application whitelisting.
* **SPL Query:**
```
index=* EventCode=1 (Image="*\\mshta.exe" OR CommandLine="*.hta*")
| stats count by ComputerName, User, Image, CommandLine
| sort - count
```
<img width="1720" height="555" alt="Q1" src="https://github.com/user-attachments/assets/dc6ecb12-8495-4fbf-80ed-e8d04467fb1a" />

Findings: The user BCS\alice executed a deceptive file named update.exe.hta located in the Downloads directory using mshta.exe.

MITRE ATT&CK Mapping: T1218.005 - System Binary Proxy Execution: Mshta

Phase 2: Execution & Persistence (Encoded PowerShell & Scheduled Tasks)
Objective: Detect base64-encoded PowerShell command lines and the creation of persistent scheduled tasks.

SPL Query:
```
index=* (EventCode=1 OR EventCode=4104) (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-w Hidden*")
| table _time, ComputerName, User, CommandLine
| sort - _time
```
<img width="1689" height="904" alt="Q2" src="https://github.com/user-attachments/assets/5e55dcae-1f49-4e3d-aaad-9d0246adb2c2" />

Findings: Identified base64 obfuscated PowerShell execution (-noP -w Hidden -enc). Additionally, detected a persistent scheduled task creation via schtasks.exe named Updater set to execute elevated payloads upon system logon (/SC ONLOGON).

MITRE ATT&CK Mapping:

T1059.001 - Command and Scripting Interpreter: PowerShell

T1053.005 - Scheduled Task/Job: Scheduled Task

Phase 3: Command & Control (C2) Network Traffic
Objective: Detect unauthorized outbound network activity originating from native processes (powershell.exe) towards external non-standard ports.

SPL Query:
```
index=* EventCode=3 DestinationIp != "10.*" AND DestinationIp != "192.168.*" AND DestinationIp != "127.*"
| stats count by Image, DestinationIp, DestinationPort
| sort - count
```
<img width="1717" height="540" alt="Q3" src="https://github.com/user-attachments/assets/c48a01f8-1cbf-452f-bbb2-9b5b1f65141d" />

Findings: High-frequency network connections were established from powershell.exe to external C2 IP 3.140.33.120 over non-standard destination ports 9001 (3,510 requests) and 9003 (1,328 requests).

MITRE ATT&CK Mapping: T1071.001 - Application Layer Protocol: Web Protocols

Phase 4: System Reconnaissance & Discovery
Objective: Detect post-compromise commands executed by adversaries to enumerate local user groups and host environment configuration.

SPL Query:
```
index=* EventCode=1 (CommandLine="*whoami*" OR CommandLine="*systeminfo*" OR CommandLine="*net user*")
| stats count by User, CommandLine, ParentImage
| sort - count
```
<img width="1708" height="616" alt="Q4" src="https://github.com/user-attachments/assets/f070656d-7456-4eb7-9a5c-0fcb7f3df003" />

Findings: The spawned powershell.exe process executed system enumeration commands including whoami /groups, whoami /user, and systeminfo.exe.MITRE ATT&CK Mapping:T1033 - System Owner/User DiscoveryT1082 - System Information Discovery

##  MITRE ATT&CK Threat Matrix Summary

| Attack Phase | Technique Name | MITRE ID | Artifact / Detection |
| :--- | :--- | :--- | :--- |
| **Initial Access** | System Binary Proxy Execution: Mshta | `T1218.005` | Execution of `update.exe.hta` via `mshta.exe` |
| **Execution** | Command and Scripting Interpreter: PowerShell | `T1059.001` | Obfuscated Base64 PowerShell (`-enc`, `-w Hidden`) |
| **Persistence** | Scheduled Task/Job: Scheduled Task | `T1053.005` | Task creation `schtasks /Create /TN Updater` |
| **Command & Control** | Application Layer Protocol | `T1071.001` | Traffic to `3.140.33.120:9001` via `powershell.exe` |
| **Discovery** | System Information / User Discovery | `T1082` / `T1033` | Execution of `whoami /groups` & `systeminfo` |

## Remediation & Response PlaybookEndpoint Isolation: 
1-Immediately isolate Client2.BCS.local from the network to sever external C2 channels.

2- Persistence Removal: Delete the malicious scheduled task using:
DOS
```
schtasks /delete /tn "Updater" /f
```

3-Network Containment: Block target C2 IP 3.140.33.120 and associated egress ports (9001, 9003) on border firewalls/web proxies.

4- Credential Revocation: Reset credentials and force session termination for user BCS\alice.

5-Attack Surface Reduction: Restrict mshta.exe and powershell.exe execution policies using AppLocker or Windows Defender Application Control (WDAC).
