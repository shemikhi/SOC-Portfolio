# Sysmon Event ID 1 – Process Creation Analysis

## 1. Investigation Overview
Goal: Analyze a Sysmon Event ID 1 log and document key process execution details for triage and detection engineering.

As part of my SOC Home Lab, I generated controlled activity within a Windows 10 VM, using Sysmon to capture detailed process execution events.

---

## 2. Event Summary
**Event ID:** 1  
**Event Type:** Process Create  
**Source:** Sysmon  
**RuleName:** ProcessCreate  
**UtcTime:** (Timestamp in the screenshot)

The event represents a process execution on the endpoint. Sysmon captures detailed metadata, including the executable path, command line arguments, file hashes, execution context, and parent process information.

---

## 3. Key Fields Extracted
From the event:

- **Image:** `C:\Windows\System32\mmc.exe`  
- **OriginalFileName:** `mmc.exe`  
- **Description:** Microsoft Management Console  
- **CommandLine:**  
"C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s

- **ParentImage:** `C:\Windows\System32\explorer.exe`  
- **User:** DESKTOP-2012U93\sam  
- **LogonGuid:** {…}

---

## 4. Why This Event Matters in SOC Work
Event ID 1 is one of the **most important detections in endpoint security**.

### SOC Relevance:
- Attackers frequently launch processes that look normal but are used for privilege escalation, lateral movement, or persistence.
- Process creation logs help detect:
- Suspicious PowerShell usage  
- LOLBins (Living Off The Land Binaries) like `mmc.exe`, `regsvr32.exe`, `rundll32.exe`
- Malware execution  
- Unusual command parameters  
- Privilege escalation attempts  

In this case, the event shows the execution of Microsoft Management Console (mmc.exe) to open Event Viewer — a normal action during system inspection.

---

## 5. MITRE ATT&CK Mapping
- **T1059 – Command and Scripting Interpreter**  
- **T1218 – Signed Binary Proxy Execution (LOLBins)**  
- **T1105 – Ingress Tool Transfer** (if PowerShell or network events follow)  
- **T1036 – Masquerading** (if executable name is abused)

---

## 6. Conclusion
This investigation demonstrates:
- A functioning Sysmon configuration
- Ability to generate and analyze endpoint telemetry
- Understanding of how to extract forensic fields from Event ID 1
- How process creation logs support threat detection and SOC triage

This is the first building block of a complete SOC home lab for incident response and threat hunting.
