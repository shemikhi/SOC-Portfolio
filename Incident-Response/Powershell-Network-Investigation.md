# Suspicious PowerShell Network Activity — Investigation Report

## Summary
A PowerShell process on workstation **DESKTOP-2012UJ93** initiated outbound network connections.  
This behavior is commonly associated with:

- Malware contacting a command-and-control (C2) server  
- Payload downloading  
- Remote command execution frameworks  
- Automated reconnaissance scripts  

Sysmon recorded both **Event ID 1 (process creation)** and **Event ID 3 (network connection)**.

---

## Sysmon Event ID 1 — Process Creation

**Image:**  
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**User:**  
`DESKTOP-2012UJ93\sam`

**CommandLine:**  
*(Insert the actual command line shown in your event)*

**IntegrityLevel:**  
High (Administrator execution)

**Why This Is Suspicious:**
- PowerShell executed unexpectedly  
- High integrity indicates elevated privileges  
- Potential LOLBAS (living-off-the-land) behavior  
- Parent process should be validated (cmd.exe / explorer.exe)

**Screenshot:**  
`powershell-network-event-id-1.png`

---

## Sysmon Event ID 3 — Network Connection

**Protocol:** tcp  
**SourceIp:** *(example)* 192.168.223.131  
**SourcePort:** *(example)* Random ephemeral port  
**DestinationIp:** *(PowerShell target)*  
**DestinationPort:** 80 / 443  
**Image:** powershell.exe  
**User:** sam  

**Suspicious Indicators:**
- Direct outbound connection from PowerShell  
- PowerShell acting as a network client → typical for malware  
- High-integrity process contacting external host  
- Unusual destination outside the local network  

**Screenshot:**  
`powershell-network-event-id-3.png`

---

## MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| **T1059.001** | PowerShell Execution |
| **T1105** | Ingress Tool Transfer (downloads via PowerShell) |
| **T1027** | Obfuscated/Encoded Commands |
| **T1083** | System Discovery |
| **T1218** | Signed Binary Proxy Execution (PowerShell.exe) |

---

## Analysis

The presence of **PowerShell network connections** is a strong behavioral indicator of malicious activity.  
Most legitimate software does not use PowerShell as a network client, except:

- Admin scripts  
- Automation frameworks  
- Local dev tools  

Indicators point to:

- Potential payload retrieval  
- Contact with an external host  
- Reconnaissance or staging behavior  
- Abnormal execution context (elevated PowerShell)

Even if the target host did not respond, the *attempt* is enough to be suspicious.

---

## Recommended SOC Actions

1. **Correlate surrounding events**
   - Review logon (4624)
   - Review process creation (4688)
   - Review registry and file create events

2. **Verify legitimacy**
   - Was the user sam supposed to run PowerShell?
   - Was this part of admin or dev activity?

3. **Check for persistence**
   - Run key modifications (Sysmon ID 13)
   - Scheduled tasks (ID 4698)
   - Startup folders

4. **Inspect the host**
   - Run AV/EDR scan
   - Check for unsigned binaries
   - Look for additional PowerShell history

5. **Network**
   - Check firewall logs for follow-up connections
   - Block suspicious destination IPs if unknown

---

## Evidence Files

- `powershell-network-event-id-1.png`  
- `powershell-network-event-id-3.png`  

---

## Conclusion
PowerShell initiating outbound network connections is a high-value SOC alert.  
The behavior observed here aligns with malware staging or command-and-control techniques and requires further threat-hunting and host triage.

