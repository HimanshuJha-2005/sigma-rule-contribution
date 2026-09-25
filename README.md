# Sigma HQ Detection Rule Contribution

## Project Overview
Contributing a production-grade Sigma detection rule to the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) repository. This project demonstrates:
- Threat detection engineering
- MITRE ATT&CK mapping expertise
- False-positive analysis and tuning
- Open-source contribution workflow

## Timeline
- **Start:** 2026-09-25
- **Target Completion:** 2026-09-29 (5 days)
- **Daily Commit Target:** 3+

## Scope
**Rule Selection Criteria:**
1. High MITRE ATT&CK technique prevalence
2. Detectable via Windows Event Logs / Sysmon
3. Not already covered in Sigma HQ (or significantly improvable)
4. Real-world attack relevance

**Chosen Technique:** **PowerShell Encoded Command Execution** (T1059.001)
- **Justification:** Highest hireability signal, best log availability (Event 4104, 4688), clear Sigma HQ gap in variant coverage (`-e`, `-enc`, `-en`, `-encoded`, case/spacing bypasses), lowest implementation risk
- **Research Details:** See `research/candidates.md`

## Repository Structure
```
.
├── README.md
├── research/
│   └── candidates.md
├── rules/
│   └── (final rule YAML)
└── tests/
    └── (test cases)
```

## Progress Log
| Day | Focus | Status |
|-----|-------|--------|
| 1 | Recon & Rule Selection | ✅ Complete |
| 2 | Rule Development — Core Logic | 🟡 In Progress |
| 3 | Validation & Hardening | ⏳ Pending |
| 4 | Submission Prep & PR | ⏳ Pending |
| 5 | Follow-up & Polish | ⏳ Pending |

## Skills Demonstrated
- Sigma rule syntax & best practices
- Log source analysis (Windows, Sysmon)
- Detection logic design (selection, aggregation, modifiers)
- False-positive quantification
- CI/CD validation (sigmalint, GitHub Actions)
- Open-source contribution etiquette

---
*Last updated: 2026-09-25*