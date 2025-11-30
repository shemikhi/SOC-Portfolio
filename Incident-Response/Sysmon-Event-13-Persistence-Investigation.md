# Sysmon Event ID 13 — Registry Persistence (Run Key Modification)

## Summary
Sysmon detected a registry modification on workstation **DESKTOP-2012UJ93**.  
PowerShell created a new registry Run key entry pointing to **malware-dropper.exe**, enabling the file to automatically execute upon user logon. This activity is a common persistence technique used by malware, droppers, trojans, and threat actors to maintain execution after reboot.

---

## Sysmon Event ID 13 — Registry Value Set

**Image:**  
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**EventType:**  
SetValue

**TargetObject:**  
HKU\S-1-5-21-3366750395-3220040588-3669521184-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater

**Details:**  
C:\Users\Public\Downloads\malware-dropper.exe

**User:**  
DESKTOP-2012UJ93\sam

**ProcessId:**  
7324

**ProcessGuid:**  
{8ffed2b6-9eeb-692b-0408-000000000500}

**UtcTime:**  
2025-11-30 02:06:38.617

---

## Why This Event Is Suspicious
- A new **Run key** was created under the current user hive (`HKCU` equivalent).
- The Run key launches **malware-dropper.exe**, an executable previously created by PowerShell.
- Malware frequently uses registry Run keys for persistence.
- PowerShell is a known LOLBAS tool abused for stealthy persistence setup.
- No legitimate software normally writes `.exe` entries to Run keys via PowerShell.

This combination strongly suggests **malicious persistence**.

---

## MITRE ATT&CK Mapping

**T1060 — Registry Run Keys / Startup Folder**  
Threat actors add values to Windows Run keys to achieve persistence.

**T1059.001 — PowerShell**  
PowerShell is used to modify registry values and execute persistence commands.

**T1105 — Ingress Tool Transfer**  
The dropped file may be part of a downloaded payload.

**T1547 — Boot or Logon Autostart Execution**  
The Run key ensures execution at logon.

---

## Analysis
The modification of a Windows **Run** registry key by `powershell.exe` is a highly suspicious action. This is a classic persistence mechanism used by:

- Droppers  
- RATs (Remote Access Trojans)  
- Ransomware  
- Infostealers  
- Adversaries establishing long-term access  

The value set (`malware-dropper.exe`) aligns with previously observed suspicious behavior from earlier cases, including file creation (Event ID 11) and PowerShell execution (Event ID 1).

This event indicates that the system may be compromised and requires immediate attention.

---

## Recommended SOC Actions

1. **Investigate the Dropped File**
   - Hash the file and check against threat intelligence.
   - Submit for AV/EDR scan.
   - Quarantine or delete if malicious.

2. **Search for Additional Persistence**
   - Other Run keys (HKLM / HKCU)
   - Scheduled tasks
   - Services (Event ID 7045)
   - Startup folder entries

3. **Review Related PowerShell Activity**
   - Event ID 1 (Process Creation)
   - Event ID 4104 (Script Block Logging)
   - Any network activity

4. **Inspect User Behavior**
   - Was this action intentional?
   - Check login events (4624) around the same timestamp.

5. **Consider Host Containment**
   - If malware is confirmed, isolate the device
   - Block outbound communication
   - Review logs for lateral movement indicators

---

## Evidence

- `sysmon-event-id-13-persistence.png`

---

## Conclusion
Sysmon Event ID 13 revealed that PowerShell created a registry-based persistence mechanism that executes **malware-dropper.exe** at logon. This behavior is strongly associated with malware activity and should be treated as a high-severity security incident requiring immediate remediation and further forensic investigation.

