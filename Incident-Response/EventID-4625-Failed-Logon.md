# Windows Event ID 4625 – Failed Logon Analysis

## 1. Overview
Event ID **4625 (Failed Logon)** is generated whenever an authentication attempt fails on a Windows system.  
This event is crucial for detecting:

- Brute force attacks  
- Password spraying  
- Unauthorized internal access  
- RDP or SMB authentication failures  
- Malicious enumeration  

SOC analysts monitor these to identify early-stage attacker behavior.

---

## 2. How the Event Was Generated (Lab Steps)
To reproduce real-world authentication failures:

1. Locked the Windows 10 VM with **Win + L**
2. Entered several incorrect passwords for the user **sam**
3. Logged back in successfully
4. Collected Event ID 4625 logs from the Windows Security log

This created multiple failed logon entries.

---

## 3. Event Details (Extracted From Log)

### 🔍 **Key fields from the captured event:**

| Field | Value | Description |
|-------|--------|-------------|
| **Event ID** | 4625 | Failed logon |
| **Status** | 0xC000006D | General logon failure |
| **SubStatus** | 0xC000006A | Incorrect password |
| **TargetUserName** | sam | Account that failed to authenticate |
| **TargetDomainName** | DESKTOP-2012U93 | Machine the account belongs to |
| **LogonType** | **2** | Interactive logon (local machine) |
| **LogonProcessName** | User32 | Standard Windows logon process |
| **AuthenticationPackageName** | Negotiate | Windows chooses best authentication (NTLM/Kerberos) |
| **ProcessName** | C:\Windows\System32\svchost.exe | Process handling authentication |
| **IpAddress** | 127.0.0.1 | Local machine (loopback) |
| **WorkstationName** | DESKTOP-2012U93 | Host system name |

---

## 4. LogonType Analysis

### ✔ **LogonType 2 — Interactive Logon**
This indicates the login attempt happened **locally at the keyboard**.

No network or RDP involvement.

Attack relevance:

- Local brute-force attempts  
- Insider misuse  
- Someone physically at the machine  
- Malware attempting system access  

---

## 5. Failure Status Codes

### **0xC000006D – STATUS_LOGON_FAILURE**  
Generic login failure.

### **0xC000006A – STATUS_WRONG_PASSWORD**  
Password is incorrect, but the **username is valid**.

This is important:  
If an attacker brute forces usernames, this event tells them which accounts **exist**.

---

## 6. Why Event 4625 Matters in SOC Work

### 🔴 **Detect attackers early**
Most attacks start with **authentication probing**.

### 🟠 **Identify password attacks**
Repeated Event 4625 logs = brute force or password spraying.

### 🟡 **Reveal insider attempts**
Someone trying to access an account they shouldn’t.

### 🟢 **Correlate suspicious behavior**
4625 → followed by → 4624 (successful logon)  
This is a red flag: attacker guessed the password.

---

## 7. MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| **Brute Force** | T1110 | Attempting multiple passwords |
| **Password Spraying** | T1110.003 | One password, many accounts |
| **Valid Accounts** | T1078 | Attempt to gain access to real accounts |
| **Remote Services** | T1021 | Failed RDP/SMB authentication |

---

## 8. Detection Ideas (SIEM Rules)

### A. **High-Frequency Failed Logons**
Alert when:
- 5+ failed logons within 1 minute (same user)  
- 10+ failures within 5 minutes (same workstation)

### B. **Password Spraying Detection**
Look for:
- Many usernames  
- Same source IP  
- Same failure SubStatus 0xC000006A  

### C. **Local Brute Force**
- Many LogonType 2 failures on a workstation  
- Followed by successful login (4624)

### D. **RDP Attack Pattern** (if LogonType = 10)
- Continuous failures  
- Same external IP  
- Often at night

---

## 9. Screenshot (Forensic Evidence)
https://github.com/shemikhi/SOC-Portfolio/blob/main/Incident-Response/event_4625_failed_logon.png

---

## 10. Conclusion
Event ID 4625 is one of the most important Windows security logs.  
Understanding how to generate, interpret, and correlate this event is a core skill for SOC analysts.

This lab demonstrates:

- Hands-on log generation  
- Log analysis  
- Security context interpretation  
- MITRE mapping  
- Practical detection ideas  

This is essential knowledge for real-world security monitoring and detection engineering.

---
