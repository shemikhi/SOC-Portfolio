# Sysmon Event ID 10 — Credential Dump Detection (ProcessAccess)

## 1. Overview
**Event ID:** 10  
**Source:** Microsoft-Windows-Sysmon  
**Category:** ProcessAccess  
**Purpose:** Indicates that one process attempted to open a handle to another process.

This event is generated when a process tries to access another process’s memory or internal structures.  
Event 10 is critical in SOC investigations because unauthorized access to lsass.exe is strongly associated with credential dumping.

---

## 2. Event Details (from the forensic artifact)

### Key Fields Extracted
- **SourceImage:** C:\Windows\system32\wbem\wmiprvse.exe  
- **TargetImage:** C:\Windows\system32\lsass.exe  
- **SourceProcessId:** 3800  
- **TargetProcessId:** 1656  
- **User:** NT AUTHORITY\NETWORK SERVICE  
- **RuleName:** ProcessAccess  
- **CallTrace:** Stack trace showing API calls used during memory access attempts

---

## 3. What Accessing LSASS Means
lsass.exe (Local Security Authority Subsystem Service) stores:

- NTLM password hashes  
- Kerberos tickets  
- Authentication tokens  
- DPAPI secrets  

Accessing LSASS memory is commonly associated with:

- Mimikatz  
- comsvcs.dll MiniDump technique  
- procdump credential harvesting  
- Credential theft malware  
- Post-exploitation frameworks (e.g., Cobalt Strike)

Because LSASS contains sensitive authentication material, any unauthorized handle access is considered high risk.

---

## 4. Why Event ID 10 Matters in SOC Investigations

### 1. Detecting Credential Dumping  
Event ID 10 is a reliable indicator of credential harvesting attempts against LSASS.

### 2. Identifying Post-Exploitation  
Attackers typically access LSASS after obtaining initial system access.

### 3. Detecting Unauthorized Handle Access  
GrantedAccess values can reveal the level of memory access requested.

### 4. Correlating with Other Telemetry  
Used with Sysmon Event IDs 1, 7, 11, 13 and Windows Security logs to reconstruct attack chains.

---

## 5. MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| T1003 – OS Credential Dumping | Accessing LSASS to obtain credential material |
| T1047 – WMI | wmiprvse.exe involvement indicates WMI-based enumeration |
| T1059 – Command Execution | Common method used to trigger LSASS access |
| T1106 – Native API | Low-level API calls observed in CallTrace |

---

## 6. Detection Use Cases

### 1. Unauthorized LSASS Access  
Any non-security tool accessing lsass.exe should be treated as a high-severity alert.

### 2. WMI or PowerShell Accessing LSASS  
Access through wmiprvse.exe can indicate attacker living-off-the-land techniques.

### 3. Suspicious GrantedAccess Values  
Values such as 0x1410, 0x1010, or 0x1fffff indicate credential dumping behavior.

---

## 7. Forensic Interpretation of This Event

- Source process: wmiprvse.exe  
- Target process: lsass.exe  
- Action: Process handle access  
- Severity: High  
- Behavior: Consistent with credential reconnaissance or dumping  
- Context: Generated in a lab environment but represents real-world attacker behavior  

This event forms a baseline for monitoring unauthorized access to LSASS.

---

## 8. Screenshot
https://github.com/shemikhi/SOC-Portfolio/blob/main/Incident-Response/sysmon-event-id-10.png

---

## 9. Conclusion
Sysmon Event ID 10 provides high-confidence detection of attempts to access LSASS, often signaling credential theft activity.  
Monitoring Event ID 10 is an essential capability for SOC analysts and blue teams.  
When correlated with other events, it enables early detection of post-compromise attacker behavior.
