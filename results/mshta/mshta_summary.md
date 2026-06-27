# Mshta LOLBin Execution — Detection Summary

**Technique:** T1218.005 (Defense Evasion)
**Rule:** detections/T1218.005_mshta.yaml

## Measurement (clean windows)
- Attack: 06/25 17:26 — mshta.exe vbscript:Execute(CreateObject("Wscript.Shell").Run ...)
- Benign: 06/25 18:07–18:48

| Metric                        | Broad (any mshta) | Precise (mshta + script/URL/.hta) |
|-------------------------------|-------------------|-----------------------------------|
| True positive (attack caught) | Yes               | Yes                               |
| False positives (benign)      | 0                 | 0                                 |

## Why high-signal
mshta.exe rarely runs on a normal workstation, and almost never with inline script (vbscript:/javascript:) or a remote URL. The command pattern is inherently suspicious, so FP-before = 0 with no tuning needed.

## Refinement (precision, not FP reduction)
Broad rule = any mshta.exe execution. Precise rule = mshta running inline script (vbscript:/javascript:), a URL, or an .hta file — matching the actual abuse pattern. Both caught the attack with 0 FP here; the precise version reduces risk of flagging rare legitimate HTA apps.

## Limitations (accepted blind spots)
- Legitimate enterprise HTA applications would match the broad rule (not seen in this lab, but possible in some environments) — the precise rule mitigates this.
- An attacker using a different LOLBin (rundll32, regsvr32, wmic) evades an mshta-specific rule; full coverage needs per-LOLBin detections.
- Stronger context: parent process (Office/Outlook → mshta = phishing) would raise confidence further.