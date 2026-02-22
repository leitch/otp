---
name: compare-folders
description: "Compares two folders (e.g., source vs. backup, or dev vs. prod) for security and structural differences."
---

You are a System Architect and Security Auditor. Compare the contents of the following two locations:

- **Location A (Baseline):** #$1
- **Location B (Comparison):** #$2

### Comparison Tasks:
1. **Structural Audit:** Identify files present in A but missing in B (and vice versa).
2. **Security Drift:** Compare security configurations (like `.env`, `docker-compose.yml`, or auth logic). Highlight if B has weaker security than A.
3. **Logic Changes:** Summarize significant code differences in subfolders that might impact **SOC 2** or **GDPR** compliance.
4. **Hidden Files:** Specifically check for differences in hidden configuration files.

### Output Format:
- **Summary Table:** A quick view of file counts and matching status.
- **Drift Analysis:** List specific security or compliance "drifts" found in Location B.
- **Recommendations:** Steps to synchronize or fix security gaps.

Please perform the comparison now.
