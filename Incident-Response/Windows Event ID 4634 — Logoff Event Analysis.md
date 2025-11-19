# Windows Event ID 4634 — Logoff Event Analysis

## 1. Overview
**Event ID:** 4634  
**Source:** Microsoft-Windows-Security-Auditing  
**Category:** Logoff  
**Purpose:** Indicates that a user session has ended.

This event is generated when a logon session terminates (manual logoff, timeout, or forced end).  
Event 4634 is essential for building complete authentication timelines in SOC investigations.

---

## 2. Event Details (from the forensic artifact)

### Key Fields Extracted
- **TargetUserName:** `sam`
- **TargetDomainName:** `DESKTOP-2012U93`
- **TargetUserSid:** `S-1-5-21-3366750395-3220040588-3669521184-1000`
- **TargetLogonId:** `0x8bff4a`
- **LogonType:** `2`

---

## 3. What LogonType 2 Means
**LogonType 2 = Interactive Logon**

This occurs when the user logs on **physically at the machine**.

➡️ This event means:  
User **sam** logged **off** from a **local interactive session**.

---

## 4. Why Event 4634 Matters in SOC Investigations

### 🔍 1. Tracking User Activity
4634 + 4624 (logon) shows complete session behavior.

### 🔐 2. Detecting Lateral Movement
Attackers often create short remote sessions.

### ⚠️ 3. Bruteforce Success Confirmation
Pattern:
- 4625 (failed attempts)
- 4624 (successful logon)
- 4634 (immediate logoff)

### 🧹 4. Session Cleanup by Malware
Malware often logs on, executes, and logs off quickly.

---

## 5. MITRE ATT&CK Mapping

| Technique | Description |
|----------|-------------|
| **T1078 – Valid Accounts** | Attackers using valid credentials leave normal-looking logon/logoff traces. |
| **T1069 – Permission Groups Discovery** | Multiple rapid logons/offs during enumeration. |
| **T1021 – Remote Services** | Remote logon sessions, followed by logoff. |
| **T1070 – Indicator Removal** | Malware logging off to hide activity. |

---

## 6. Detection Use Cases

### ✔️ Use Case 1: Fast Logoff After Successful Logon
Indicates scripted access or attacker activity.

### ✔️ Use Case 2: High Frequency Logon/Logoff
Possible credential stuffing or automated malware.

### ✔️ Use Case 3: Unusual LogonType
Log off from LogonType 10 (RDP) or 3 (Network) when the user normally logs in locally.

---

## 7. Forensic Interpretation of This Event

- User: **sam**
- LogonType: **2 (Interactive)**
- Domain: **Local machine**
- Behavior: Normal user logoff
- No suspicious indicators present

This forms a **baseline** for future comparisons.

---

## 8. Screenshot
https://github.com/shemikhi/SOC-Portfolio/blob/main/Incident-Response/EventID-4634-Logoff.png


---

## 9. Conclusion
Event ID 4634 is crucial for reconstructing authentication behavior.  
Together with 4624 and 4625, it provides a full picture of user authentication activity.

This is a required skill for SOC Analysts and Blue Team work.
