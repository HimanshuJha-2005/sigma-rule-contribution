# Sigma Rule Candidates — Research Log

**Date:** 2026-09-25  
**Goal:** Identify 5 high-value, mergeable detection rules not yet in Sigma HQ (or significantly improvable)

---

## Candidate 1: PowerShell Encoded Command Execution
- **MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell)
- **Log Source:** Windows Event Log 4104 (Script Block Logging), 4688 (Process Creation)
- **Detection Logic:** `-EncodedCommand` or `-e` flag + base64 blob in command line
- **Prior Art:** Existing rules cover `-EncodedCommand` but often miss `-e` shorthand, bypasses (`-enc`, `-en`, etc.), or nested encoding
- **Gap:** Comprehensive coverage of all encoded command variants + FP tuning for legitimate admin scripts
- **Mergeability:** High — core technique, clear detection value

## Candidate 2: Living Off The Land Binary (LOLBAS) — Certutil Download
- **MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1218.004 (Signed Binary Proxy Execution: Certutil)
- **Log Source:** Windows Event Log 4688, Sysmon Event ID 1
- **Detection Logic:** `certutil.exe` with `-urlcache`, `-split`, `-f` flags + HTTP/HTTPS URL
- **Prior Art:** Basic certutil rules exist; gap in detecting `-split` reassembly, `-verifyctl` abuse, and certificate store manipulation
- **Gap:** Full flag combination coverage + legitimate admin usage differentiation
- **Mergeability:** High — certutil is top-10 LOLBAS

## Candidate 3: WMI Process Creation via Win32_Process.Create
- **MITRE ATT&CK:** T1047 (Windows Management Instrumentation)
- **Log Source:** Sysmon Event ID 1 (Process Create), WMI Activity Event Log
- **Detection Logic:** `wmiprvse.exe` spawning unusual children (cmd, powershell, rundll32) + correlation with WMI Event 5857/5858/5860/5861
- **Prior Art:** Some WMI rules exist; gap in correlating process tree with WMI operation events for higher fidelity
- **Gap:** Multi-log correlation (Sysmon + WMI) + parent-child anomaly scoring
- **Mergeability:** Medium — requires multi-log source, but high signal

## Candidate 4: Scheduled Task Creation via COM Handler (Schtasks / Task Scheduler)
- **MITRE ATT&CK:** T1053.005 (Scheduled Task/Job: Scheduled Task)
- **Log Source:** Windows Event Log 4698 (Task Created), 4702 (Task Updated), Sysmon Event ID 1
- **Detection Logic:** Task with `ComHandler` action, unusual CLSID, or execution from non-standard paths (`%TEMP%`, `%APPDATA%`)
- **Prior Art:** Basic 4698 rules exist; COM handler abuse is under-covered
- **Gap:** CLSID reputation mapping + path anomaly detection
- **Mergeability:** Medium — niche but high-value for persistence detection

## Candidate 5: DLL Search Order Hijacking via Phantom DLL
- **MITRE ATT&CK:** T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)
- **Log Source:** Sysmon Event ID 7 (Image Load), Event ID 1 (Process Create)
- **Detection Logic:** Process loading DLL from non-standard path (not System32, not app dir) + DLL not on disk (phantom) or recently written
- **Prior Art:** Some DLL hijack rules; phantom DLL + recent write correlation is rare
- **Gap:** Combining Image Load + File Creation time proximity + path anomaly
- **Mergeability:** Medium-High — strong signal, but requires Sysmon Event ID 7 (often disabled)

---

## Comparison Matrix

| Candidate | ATT&CK Coverage | Log Availability | FP Risk | Sigma HQ Gap | Effort | Score |
|-----------|-----------------|------------------|---------|--------------|--------|-------|
| PowerShell Encoded Command | T1059.001 | High (4104, 4688) | Medium | High | Low | 9/10 |
| Certutil Download | T1105, T1218.004 | High (4688, Sysmon 1) | Low | Medium | Low | 8/10 |
| WMI Process Creation | T1047 | Medium (Sysmon + WMI) | Medium | High | Medium | 7/10 |
| Scheduled Task COM Handler | T1053.005 | High (4698, 4702) | Low | Medium | Low | 7/10 |
| Phantom DLL Hijack | T1574.001 | Medium (Sysmon 7) | Low | High | Medium | 7/10 |

---

## Decision
**Chosen:** **Candidate 1 — PowerShell Encoded Command Execution**  
**Justification:** Highest hireability signal (core red/blue technique), best log availability, clear Sigma HQ gap in variant coverage, lowest implementation risk for 5-day timeline. Demonstrates detection engineering fundamentals cleanly.

**Next Steps (Day 2):**
1. Audit existing Sigma rules for PowerShell encoded command
2. Enumerate all bypass variants (`-e`, `-enc`, `-en`, `-encoded`, case permutations, spacing tricks)
3. Draft detection logic with modifiers for base64 entropy, length, character set
4. Build test corpus (positive: real attack samples; negative: legit admin scripts)