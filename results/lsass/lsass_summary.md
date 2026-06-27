# LSASS Credential Dump — Detection Summary

**Technique:** T1003.001 (Credential Access)
**Rule:** detections/T1003.001_lsass.yaml

## Measurement (clean windows)
- Attack: 06/25 16:23 — rundll32 comsvcs.dll MiniDump against lsass (PPL blocked the dump)
- Benign: 06/25 18:07–18:48

| Metric                        | Rule (comsvcs MiniDump command pattern) |
|-------------------------------|-----------------------------------------|
| True positive (attack caught) | Yes (attempt detected via EID 1)        |
| False positives (benign)      | 0                                       |

## Why this is high-signal (no tuning needed)
`comsvcs.dll MiniDump` invoked against a process is not something any legitimate software or admin does. The command pattern is inherently malicious, so the rule is high-precision out of the box — FP-before = 0 in the benign window, and no tuning is required.

## Key environment finding — EID 10 vs EID 1 under PPL
- Attempted to detect via Sysmon EID 10 (process opening lsass with memory-read access). Result: ALL EID 10 lsass access was benign svchost.exe (GrantedAccess 0x1000); excluding svchost returned ZERO events.
- Reason: LSA Protection (RunAsPPL=2) blocked the dump tools at the kernel before they obtained a read handle, so no malicious ProcessAccess was ever logged.
- Conclusion: under PPL, the access-based (EID 10) detection has nothing to catch; the command/process-level detection (EID 1, comsvcs+MiniDump) is the only viable method, and it catches the attempt regardless of whether the dump succeeds.

## Limitations (accepted blind spots)
- The EID 1 command-string rule is NARROW: it catches the comsvcs method only. Other dump methods (procdump, nanodump, direct API) would need their own command patterns or the EID 10 access rule.
- The EID 10 access-mask rule (catching read access to lsass) is the broader, method-agnostic approach but is NOT viable here because PPL blocks the access from occurring/logging. In an environment WITHOUT PPL, that rule would be the stronger primary detection.
- Defense-in-depth note: PPL itself is the real mitigation; detection is the backstop for when PPL is absent or bypassed.