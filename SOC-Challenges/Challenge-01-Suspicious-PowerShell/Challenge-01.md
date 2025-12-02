# Challenge 01 — Suspicious PowerShell Execution (False Start Attack)

## 1. Executive Summary
A security alert was triggered for a suspicious PowerShell process launched with obfuscation and stealth flags (`-nop`, `-w hidden`, `-enc`).  
The decoded Base64 payload appeared incomplete, suggesting a failed or partially captured malicious execution attempt.  
No follow-up activity (network, persistence, file creation) was identified, indicating a **false start** — an attack attempt that did not progress.

This investigation demonstrates real SOC analysis: correlating telemetry, identifying malicious patterns, and determining the absence of further compromise.

---

## 2. Alert Details
**Source:** Behavioral EDR  
**Alert:** Suspicious PowerShell Command Execution  
**Command Observed:**


---

## 3. Decoded Payload Analysis
Base64-decoded content:$

### Interpretation
- This indicates the payload was incomplete or truncated.
- Attackers often split encoded payloads into chunks.
- EDR solutions sometimes capture only the first bytes of encoded commands.

Although the decoded content appears benign, the **execution pattern is highly suspicious**.

---

## 4. Sysmon Event Analysis

### Event: **Sysmon Event ID 1 — Process Create** 
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "powershell.exe" -nop -w hidden -enc JABmAG8AbwA9ACIA
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: DESKTOP-2O12U93\sam
IntegrityLevel: High
Hashes: SHA256=B4E7BC24BF3...
ProcessId: 9580


### Suspicious Indicators
- Hidden window execution (`-w hidden`)
- Encoded command (`-enc`)
- No profile (`-nop`)
- PowerShell spawning PowerShell
- High integrity level
- No legitimate reason for obfuscation

These indicators align strongly with **malicious PowerShell tradecraft**.

---

## 5. Timeline Reconstruction

### **T0 — Alert Triggered**
EDR detects encoded PowerShell with hidden window.

### **T1 — Sysmon Reports Process Creation**
- Process ID: 9580
- User: sam
- Parent: PowerShell.exe
- Flags consistent with malicious behavior

### **T2 — Log Correlation**
Search for:
- PowerShell ScriptBlock (4104)
- Network connections (ID 3)
- File creations (ID 11)
- Registry persistence (ID 12/13)
- DLL loads (ID 7)
- Credential access attempts (ID 10)

### **T3 — No Additional Activity Found**
The process **did not**:
- Connect to a remote host  
- Drop files  
- Modify registry  
- Spawn child processes  
- Load unusual DLLs  
- Establish persistence  

This indicates a **failed execution**, staging test, or truncated payload.

---

## 6. MITRE ATT&CK Mapping

| Technique | ID | Why It Applies |
|----------|----|----------------|
| PowerShell | **T1059.001** | Use of encoded and hidden PowerShell |
| Obfuscated Commands | **T1027** | Base64 execution |
| Command & Scripting Abuse | **T1059** | Use of native tools |
| Execution Guardrails | **T1620** | Partial/incomplete script may indicate staging |

---

## 7. Final Assessment
### **Verdict:** Suspicious Activity, No Evidence of Follow-Through

Although the decoded payload itself was incomplete, the execution method is **highly consistent with malicious intent**.

No follow-up events were detected, meaning:
- The script likely failed to run
- The payload was incomplete
- Or EDR captured only the initial portion

This is classified as a **false start attack** — malicious attempt with no progression.

---

## 8. Recommendations
- Continue monitoring for additional PowerShell executions.
- Alert if the user executes encoded PowerShell again.
- Enable or verify Script Block Logging (Event ID 4104).
- Consider restricting PowerShell encoded commands in the environment.

---

## 9. Evidence Screenshots
`SOC-Challenges/Challenge-01-Suspicious-PowerShell/Images/`

Recommended screenshots:
- Sysmon Event ID 1 (process creation)
- Base64 decoding
- Any timeline views or filters used

Example:

---

## 10. Analyst Notes
This case demonstrates a realistic scenario where malicious execution does not always produce full behavior traces.  
Effective SOC investigation includes confirming **both the presence AND absence** of follow-up actions.

This is a core skill for Tier 1–2 SOC analysts.


