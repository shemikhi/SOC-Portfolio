# Suspicious PowerShell Execution — Investigation Report

## Summary
A suspicious PowerShell process was executed on **DESKTOP-2012UJ93** using variable assignment and indirect command execution (`iex`).  
This behavior is commonly associated with reconnaissance, payload staging, or obfuscated malware activity.

---

## Sysmon Event ID 1 — Process Creation

**Image:**  
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**User:**  
`DESKTOP-2012UJ93\sam`

**Integrity Level:**  
High (process was executed with elevated permissions)

**Key Indicators:**
- PowerShell launched directly with custom parameters  
- Use of variables inside command  
- Potential obfuscation patterns  
- Invocation via `iex` (Invoke-Expression)

**Screenshot:**  
`powershell-event-id-1.png`

---

## Sysmon Event ID 3 — Network Connection (if from PowerShell)

If PowerShell initiated outbound traffic, Sysmon would show:

- **SourceIP:** 192.168.x.x  
- **DestinationIP:** External IP  
- **DestinationPort:** 80 or 443  
- **Protocol:** TCP  
- **Image:** powershell.exe  

This may indicate:
- Payload retrieval  
- C2 (Command-and-Control) behavior  
- Web-based recon

**Screenshot:**  
`powershell-event-id-3.png`

---

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| **T1059.001** | PowerShell Execution |
| **T1027** | Obfuscated/Encrypted Command Execution |
| **T1105** | Ingress Tool Transfer (Invoke-WebRequest) |
| **T1082** | System Discovery |
| **T1218** | Signed Binary Proxy Execution (PowerShell.exe) |

---

## Analysis

The PowerShell process shows traits common in early-stage attacker behavior:
- Obfuscated variables  
- Indirect execution via `iex`  
- Possible external communication  
- High-integrity execution (Admin)  

Even if only Event ID 1 is present, this is still a suspicious event that justifies further investigation.

---

## Recommended SOC Actions

1. Review user logon events (4624) before execution  
2. Search for additional PowerShell events (4103, 4104)  
3. Check for persistence mechanisms (registry run keys, services)  
4. Analyze if the same user executed more PowerShell commands  
5. Validate that no unauthorized downloads or scripts were executed  

---

## Evidence Files
- `powershell-event-id-1.png`  
- `powershell-event-id-3.png`  

---

## Conclusion
This PowerShell execution event contains multiple indicators associated with suspicious or malicious activity.  
Further analysis of system behavior and related logs is recommended to rule out compromise.
