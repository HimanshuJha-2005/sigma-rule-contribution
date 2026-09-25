# Sigma Detection Rule — PowerShell Encoded Command Execution

Production-grade Sigma rule detecting PowerShell encoded command execution across all known bypass variants. Submitted to [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

## Technique

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) — Command and Scripting Interpreter: PowerShell

**Tactics:** Execution

## Detection Coverage

| Variant | Flag | Example | Covered |
|---------|------|---------|---------|
| Standard | `-EncodedCommand` | `powershell -EncodedCommand <base64>` | ✅ |
| Shorthand | `-e` | `powershell -e <base64>` | ✅ |
| Abbreviated | `-enc`, `-en`, `-encoded` | `powershell -enc <base64>` | ✅ |
| Case evasion | `-EnCoDeDcOmMaNd` | `powershell -EnCoDeDcOmMaNd <base64>` | ✅ |
| Spacing tricks | `- EncodedCommand`, `-Encoded Command` | `powershell - EncodedCommand <base64>` | ✅ |
| Nested encoding | Base64-wrapped base64 | `powershell -e <base64(base64(payload))>` | ✅ |

## Log Sources

| Source | Event ID | Channel |
|--------|----------|---------|
| PowerShell Script Block Logging | 4104 | `Microsoft-Windows-PowerShell/Operational` |
| Process Creation | 4688 | `Security` |
| Sysmon | 1 | `Microsoft-Windows-Sysmon/Operational` |

## Rule Logic

- **Selection:** CommandLine containing PowerShell executable + encoded command flag variants
- **Condition:** Base64 entropy/length heuristics + flag presence + legitimate admin script exclusion
- **False Positive Mitigation:** Allowlist known admin scripts, require minimum entropy threshold

## Files

```
.
├── rules/
│   └── windows_powershell_encoded_command.yml
├── tests/
│   ├── positive/
│   │   ├── empire_stager.yml
│   │   ├── cobaltstrike_beacon.yml
│   │   └── custom_payload.yml
│   └── negative/
│       ├── admin_backup_script.yml
│       ├── azure_deployment.yml
│       └── legitimate_encoding.yml
└── README.md
```

## Validation

```bash
# Lint
sigma check rules/windows_powershell_encoded_command.yml

# Compile to Splunk/Elastic/KQL/etc.
sigma convert -t splunk rules/windows_powershell_encoded_command.yml
```

## Test Results

| Test Case | Expected | Result |
|-----------|----------|--------|
| Empire stager (base64) | Match | ✅ |
| CobaltStrike beacon (nested) | Match | ✅ |
| Custom payload (case evasion) | Match | ✅ |
| Admin backup script | No match | ✅ |
| Azure deployment script | No match | ✅ |
| Legitimate encoding (low entropy) | No match | ✅ |

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [PowerShell EncodedCommand Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe)
- [Sigma Rule Format Specification](https://github.com/SigmaHQ/sigma/wiki/Rule-Format)
- [LOLBAS PowerShell](https://lolbas-project.github.io/lolbas/Binaries/Powershell/)

## License

This rule is contributed under the same license as SigmaHQ/sigma (LGPL-2.1-or-later).