# Sysmon Event ID 11 — Suspicious File Creation (Malware Dropper Simulation)

## Summary
A suspicious file creation event was detected on workstation **DESKTOP-2012UJ93**.  
Sysmon Event ID **11 (FileCreate)** recorded that PowerShell created an executable file named **malware-dropper.exe** in the `C:\Users\Public\Downloads\` directory. This behavior is strongly associated with malware staging, payload delivery, or attacker activity.

---

## Sysmon Event ID 11 — File Creation Details

**Image:**  
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**TargetFilename:**  
C:\Users\Public\Downloads\malware-dropper.exe

**User:**  
DESKTOP-2012UJ93\sam

**RuleName:** Downloads  
**ProcessId:** 7324  
**ProcessGuid:** {8ffed2b6-9eeb-692b-0408-000000000500}  
**CreationUtcTime:** 2025-11-30 01:59:53.016

---

## Why This Event Is Suspicious

- An **.exe** file was created in a user-accessible directory (`Public\Downloads`).
- Executable file creation via **powershell.exe** is a common technique used by:
  - Malware downloaders
  - Initial access scripts
  - Fileless malware that drops a payload
  - Living-off-the-land (LOLBAS) attacks
- Legitimate users almost never generate `.exe` files manually.
- Attackers often use PowerShell for dropping payloads to disk before execution.

This aligns with common malware dropper behavior seen in real-world attacks.

---

## MITRE ATT&CK Mapping

**T1105 — Ingress Tool Transfer**  
Malware frequently downloads or creates executable payloads.

**T1059.001 — PowerShell**  
Adversaries use PowerShell to write or drop files.

**T1204 — User Execution**  
Payloads are often dropped in Downloads to trick users into running them.

**T1566 — Phishing (Staged Payload)**  
Malware frequently drops executables into common folders after initial phishing.

---

## Analysis

The file **malware-dropper.exe** was created through PowerShell using a command that simulates malware staging. The creation of any executable file by PowerShell is high-risk and strongly correlates with:

- Downloader scripts
- Malware staging
- Trojan or ransomware payload drop
- Persistence installers

The choice of the **Public Downloads** directory is also notable, as it is writable by all users, commonly abused by malware, and often overlooked by defenders.

This behavior warrants further investigation to determine if additional artifacts or follow-up execution occurred.

---

## Recommended SOC Actions

1. **Check for Process Execution (Event ID 1 or 4688)**  
   Verify if malware-dropper.exe was executed after being created.

2. **Search for Similar File Drops**  
   Review:
   - C:\Users\Public\  
   - Downloads, Temp, AppData folders

3. **Scan the System for Malware**
   - Use Defender/AV/EDR to scan the file  
   - Check reputation and hash values  

4. **Review PowerShell Logs**
   - Look for additional commands  
   - Search for Event ID 4104 script blocks  

5. **Block and Contain (if malicious)**
   - Quarantine the file  
   - Block related IOC destinations  
   - Isolate the endpoint if C2 activity is detected  

---

## Evidence

- `powershell-event-id-11.png`

---

## Conclusion
Sysmon Event ID 11 revealed that PowerShell created a suspicious executable file in a high-risk directory. This behavior is consistent with malware droppers, staged payloads, and attacker activity. The event should be treated as potentially malicious and followed up with host-based triage, process analysis, and system scanning.

