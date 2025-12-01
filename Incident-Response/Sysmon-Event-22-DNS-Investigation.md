# Sysmon Event ID 22 — Suspicious DNS Query Investigation

## Summary
Sysmon detected a DNS query event from **powershell.exe** on workstation **DESKTOP-2012UJ93**.  
DNS is commonly used by malware for command-and-control (C2), domain generation algorithms (DGA), reconnaissance, and network discovery.  
Event ID 22 captures detailed DNS activity, making it a critical source for detecting malicious domain lookups.

---

## Sysmon Event ID 22 — DNS Query Details

**Image:**  
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**User:**  
DESKTOP-2012UJ93\sam

**QueryName:**  
example.com  
*(Used in this test to simulate a DNS request from PowerShell.)*

**QueryResults:**  
Multiple IP addresses were returned by the DNS server.

**ProcessId:**  
3540

**UtcTime:**  
2025-11-17 00:19:23.071

**Additional Data:**  
The event included a list of resolved DNS server IP responses as expected for DNS resolution.

---

## Why This Event Is Suspicious

- PowerShell generated a manual DNS query.  
- Malware frequently uses DNS for:
  - C2 beaconing  
  - Payload staging  
  - Host discovery  
  - DNS tunneling  
  - DGA-based callbacks  
- Legitimate users rarely perform DNS lookups with PowerShell unless testing connectivity or scripting.

Even though the domain used in this test is benign, the **behavior** is what SOC analysts flag.

---

## MITRE ATT&CK Mapping

**T1071.004 — Application Layer Protocol: DNS**  
C2 channels often hide inside DNS traffic.

**T1059.001 — PowerShell**  
Threat actors use PowerShell to craft DNS queries or communicate with C2.

**T1027 — Obfuscated or Encrypted Artifacts**  
DNS traffic is often used for stealthy DNS-based exfiltration.

**T1082 — System Information Discovery**  
DNS lookups can be part of recon to map network boundary behavior.

---

## Analysis

This event shows that PowerShell executed a DNS query, which is uncommon for normal user activity.  
Attackers often rely on DNS because:

- It bypasses many firewalls  
- It is almost never blocked  
- It blends into normal network traffic  
- DNS logs are often neglected in SOC environments

Event ID 22 is crucial for detecting:

- Dynamic DNS C2  
- Beaconing intervals  
- Malware contacting suspicious domains  
- Unknown or untrusted hostnames  
- DNS anomalies (too many responses, rare domains)

The presence of multiple DNS server responses suggests normal DNS operation, but the PowerShell origin remains notable.

---

## Recommended SOC Actions

1. **Verify User Intent**
   - Confirm whether the user performed the lookup intentionally.

2. **Cross-Check DNS Traffic**
   - Review firewall or DNS server logs for unusual patterns.
   - Look for repeated DNS lookups within short intervals.

3. **Check for Related Events**
   - Sysmon Event ID 1 (PowerShell execution)
   - Sysmon Event ID 3 (network connections)
   - Sysmon Event ID 11 (file drops)
   - Sysmon Event ID 13 (persistence changes)

4. **Evaluate Domain Reputation**
   - Check if the domain belongs to risky TLDs or known malicious infrastructure.

5. **Threat Hunting**
   - Hunt for similar DNS queries from other hosts.

---

## Evidence

- `sysmon-event-id-22-dns.png`

---

## Conclusion
Sysmon Event ID 22 revealed DNS activity initiated by PowerShell.  
Although the tested domain was benign, the behavior pattern aligns with techniques used by malware families that rely on DNS-based communication and reconnaissance. DNS query analysis is an essential component in detecting stealthy C2 behavior and early-stage compromise.

