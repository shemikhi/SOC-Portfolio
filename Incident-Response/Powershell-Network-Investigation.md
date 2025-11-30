# Suspicious PowerShell Network Activity — Investigation Report

## Summary
A PowerShell process on workstation **DESKTOP-2012UJ93** initiated outbound network activity. PowerShell is commonly abused by adversaries to download payloads, perform reconnaissance, and communicate with command-and-control servers. Sysmon recorded both a PowerShell process creation (Event ID 1) and a network connection attempt (Event ID 3), indicating potentially unauthorized use of PowerShell for external communication.

---

## Sysmon Event ID 1 — Process Creation

**Image:**  
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**User:**  
DESKTOP-2012UJ93\sam

**CommandLine:**  
powershell.exe -Command "$a='Write-Host';$b=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SEVMTE8='));iex ($a + ' ' + $b)"

**Description:**  
Sysmon detected the creation of a PowerShell process executing a command that uses variable assignment, Base64 decoding, and `iex` (Invoke-Expression). These techniques are frequently leveraged in obfuscated or staged attack workflows. The process ran in a high-integrity context, indicating administrator-level privilege.

**Why This Is Suspicious:**
- PowerShell was used for dynamic code execution.
- The command includes Base64 decoding, an obfuscation behavior.
- Execution occurred under elevated privileges.
- The PowerShell process later initiated outbound network communication.

---

## Sysmon Event ID 3 — Network Connection

**Protocol:** TCP  
**Source IP:** Local workstation  
**Destination IP:** External host  
**Destination Port:** 80 or 443  
**Image:** powershell.exe  
**User:** sam

**Description:**  
Sysmon recorded that powershell.exe attempted an outbound network connection. Even if the remote server rejected the request, the attempt itself is a key behavior indicating possible malware staging or C2 communication. Legitimate users rarely use PowerShell for direct web requests unless performing administrative tasks or scripting.

**Why This Is Suspicious:**
- PowerShell acted as a network client to an external IP.
- This behavior frequently aligns with malicious payload retrieval.
- Execution originated from a high-integrity PowerShell session.
- Network connections from PowerShell are uncommon in normal user workflows.

---

## MITRE ATT&CK Mapping

**T1059.001 — PowerShell**  
Adversaries abuse PowerShell to execute scripts and commands.

**T1105 — Ingress Tool Transfer**  
PowerShell is often used to download remote payloads or scripts.

**T1027 — Obfuscated/Encrypted Commands**  
Base64 encoding and `iex` execution indicate obfuscation.

**T1218 — Signed Binary Proxy Execution (PowerShell.exe)**  
PowerShell is a trusted signed Windows binary often used to bypass security controls.

---

## Analysis
The combination of PowerShell execution and outbound network activity represents a high-fidelity behavioral indicator of potential malicious activity. PowerShell is a powerful administration tool, but its flexibility makes it an attractive target for attackers.

The observed behavior suggests:

- Possible download attempt of a remote payload.  
- Use of obfuscation techniques to hide intent.  
- Execution with elevated privileges.  
- Typical characteristics of early-stage malware or adversary actions.

Even though the destination did not respond, failed outbound attempts are often the first signs of intrusion attempts or automated scripts contacting attacker infrastructure.

---

## Recommended SOC Actions

1. **Review nearby related events**
   - Logon events (4624)
   - Additional PowerShell process creation events (Sysmon ID 1)
   - Script block events (4104), if available

2. **Inspect the host**
   - Run antivirus/EDR scans
   - Examine PowerShell history
   - Review scheduled tasks, services, and startup entries for persistence

3. **Evaluate network indicators**
   - Check firewall logs for repeated outbound attempts
   - Conduct IP reputation checks on the destination host
   - Block suspicious destinations if required

4. **User validation**
   - Confirm whether the user initiated any legitimate script or admin task
   - Verify whether this aligns with expected system behavior

---

## Conclusion
PowerShell initiating outbound network communication is a strong indicator of suspicious activity. Combined with obfuscated command execution and elevated privileges, the behavior aligns with techniques used by adversaries for staging, reconnaissance, or command-and-control communication. The host warrants additional investigation to rule out compromise.

