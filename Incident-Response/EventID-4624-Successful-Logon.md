# Windows Event ID 4624 – Successful Logon Analysis

## 1. Overview
Event ID **4624 (Successful Logon)** is generated whenever an authentication attempt succeeds.  
This event is essential for SOC investigations because it helps analysts:

- Confirm successful access after failed attempts  
- Detect lateral movement  
- Identify privilege escalation  
- Track service account behavior  
- Detect suspicious login types (RDP, network logon, service logons)

This analysis focuses on a specific 4624 event generated during my SOC Home Lab.

---

## 2. How the Event Was Generated (Lab Steps)
This 4624 event was produced automatically by the system during normal OS operations.  
No manual login was performed.

To collect the event:

1. Opened **Event Viewer**
2. Navigated to:  
   **Windows Logs → Security**
3. Filtered by **Event ID = 4624**
4. Selected one entry for detailed analysis

---

## 3. Extracted Event Details (From Log)

| Field | Value | Description |
|-------|--------|-------------|
| **Event ID** | 4624 | Successful authentication |
| **TargetUserName** | **SYSTEM** | Windows built-in system account |
| **TargetDomainName** | NT AUTHORITY | Local system security authority |
| **TargetUserSid** | S-1-5-18 | SID for SYSTEM |
| **LogonType** | **5** | Service logon (service started) |
| **LogonProcessName** | Advapi | Windows authentication process |
| **AuthenticationPackageName** | Negotiate | Chooses Kerberos or NTLM |
| **ProcessName** | C:\Windows\System32\services.exe | Process responsible for logon |
| **SubjectUserName** | DESKTOP-2012U93$ | Computer account performing logon |
| **KeyLength** | 0 | No session key (SYSTEM account) |

---

## 4. LogonType Analysis

### ✔ **LogonType 5 — Service Logon**
This logon type means:

- A **Windows service** started  
- The service runs under **SYSTEM**  
- No user interaction  
- Normal background OS behavior  

**This is not a user logging in.**

SOC relevance:

- Helps establish a **baseline** for normal system activity  
- Allows detection of **malicious services**  
- Attackers often install persistence via services (MITRE T1543.003)

---

## 5. Why This Event Matters in SOC Work

Even though it's a system/service logon, analysts use 4624 to:

### 🔍 Detect suspicious activity
- Unexpected LogonType 10 (RDP)
- Unexpected LogonType 3 (network)
- Logons from unknown IPs
- Logons outside business hours

### 🔍 Correlate attacks
If an attacker brute forces an account (4625), a **successful 4624** shortly after may indicate:

- Password guessed  
- Stolen credentials used  
- Lateral movement successful  

### 🔍 Investigate persistence
Malware often installs:

- Fake services  
- Backdoored services  
- Autostart behavior (LogonType 5 events)

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| **Valid Accounts** | T1078 | Using valid credentials to authenticate |
| **Windows Service Creation** | T1543.003 | Persistence through system services |
| **Privilege Escalation** | T1068/T1055 | SYSTEM account logon helps attackers escalate |
| **Lateral Movement** | T1021 | Authentication across machines |

---

## 7. Detection Use Cases

### ✔ A. Unexpected LogonType 5 Events  
- If services start with unusual accounts  
- If unknown services generate SYSTEM logons  

### ✔ B. Correlate 4624 + 4625  
Detect brute force success:
- Many failed 4625 attempts  
- Followed by 4624 for the same account

### ✔ C. Investigate High-Privilege Accounts  
SYSTEM, Administrator, LocalService, NetworkService

### ✔ D. ProcessName Review  
If **ProcessName ≠ expected service executables**  
→ possible malware-created service

---

## 8. Screenshot (Evidence)


[`event-4624.png`](https://github.com/shemikhi/SOC-Portfolio/blob/main/Incident-Response/EventID-4624-Successful-Logon.png)

---

## 9. Conclusion
Event ID **4624** is one of the most important logs for authentication monitoring in Windows.  
In this example, the event is a normal **service logon** (LogonType 5), but it serves as a foundation for:

- Tracking system behavior  
- Identifying malicious services  
- Correlating successful and failed logons  
- Monitoring attacker lateral movement  

Understanding how to interpret 4624 events is essential for SOC analysts and detection engineers.

---
