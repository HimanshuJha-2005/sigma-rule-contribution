# PR Description — PowerShell Encoded Command Execution Detection

## Summary
Adds detection rule for PowerShell encoded command execution (MITRE ATT&CK T1059.001) covering all known flag variants and evasion techniques.

## Detection Coverage

| Variant | Example | Covered |
|---------|---------|---------|
| Standard | `powershell -EncodedCommand <base64>` | ✅ |
| Shorthand | `powershell -e <base64>` | ✅ |
| Abbreviated | `powershell -enc/-en/-encoded <base64>` | ✅ |
| Case evasion | `powershell -EnCoDeDcOmMaNd <base64>` | ✅ |
| Spacing tricks | `powershell - EncodedCommand <base64>` | ✅ |
| Nested encoding | Double/triple base64 wrapping | ✅ |

## False Positive Mitigation

- **Minimum base64 length:** 40 characters (excludes trivial one-liners)
- **Admin allowlist:** Filters known legitimate patterns:
  - `Backup-Script` (scheduled admin backups)
  - `az deployment` (Azure DevOps pipelines)
  - `Install-Application` (SCCM/Intune)
  - `Microsoft.ConfigurationManagement` (ConfigMgr)
- **Entropy recommendation:** Backend-level Shannon entropy > 3.5 (not enforceable in Sigma)

## Test Results

| Test Case | Type | Result |
|-----------|------|--------|
| Empire stager | Positive | ✅ Match |
| CobaltStrike beacon (nested) | Positive | ✅ Match |
| Custom payload (case evasion) | Positive | ✅ Match |
| Admin backup script | Negative | ✅ No match (allowlisted) |
| Azure DevOps pipeline | Negative | ✅ No match (allowlisted) |
| Low-entropy encoding | Negative | ✅ No match (<40 chars) |

## Validation

```bash
# Lint check
sigma check rules/windows/powershell_encoded_command.yml
# Result: 0 errors, 0 issues

# Compile to major backends
sigma convert -t splunk rules/windows/powershell_encoded_command.yml
sigma convert -t elasticsearch rules/windows/powershell_encoded_command.yml
sigma convert -t kql rules/windows/powershell_encoded_command.yml
# All compile successfully
```

## Files Changed

- `rules/windows/powershell_encoded_command.yml` — New rule
- `tests/positive/` — 3 attack simulation test cases
- `tests/negative/` — 3 legitimate admin test cases
- `docs/false_positive_analysis.md` — Detailed FP analysis

## Checklist

- [x] Rule follows Sigma naming convention (`powershell_encoded_command.yml`)
- [x] All required fields present (title, id, status, description, author, date, logsource, detection, falsepositives, level, tags)
- [x] Valid MITRE ATT&CK tags (`attack.execution`, `attack.t1059.001`)
- [x] Logsource uses standard categories (`windows`, `process_creation`)
- [x] Condition uses proper Sigma syntax (no custom modifiers)
- [x] False positives documented with mitigation
- [x] Test cases included (positive + negative)
- [x] `sigma check` passes with 0 errors, 0 issues
- [x] Rule compiles to Splunk, Elasticsearch, KQL

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/
- PowerShell -EncodedCommand: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe
- LOLBAS PowerShell: https://lolbas-project.github.io/lolbas/Binaries/Powershell/
- Sigma Rule Format: https://github.com/SigmaHQ/sigma/wiki/Rule-Format

## Author

Himanshu Jha — 4th Year CSE, Cybersecurity Portfolio Project