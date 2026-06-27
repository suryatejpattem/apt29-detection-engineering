# PowerShell Encoded Command — Tuning Summary

**Technique:** T1059.001 (Execution)
**Rule:** detections/T1059.001_powershell_encoded.yaml

## Measurement (clean windows)
- Attack: 06/23 19:26 (Splunk time) — powershell.exe -e <base64>, parent cmd.exe
- Benign window: 06/25 18:07–18:48 (Splunk time)

| Metric                        | Layer 1: flag (-e/-enc) | Layer 2: content (4104) |
|-------------------------------|-------------------------|-------------------------|
| True positive (attack caught) | Yes                     | N/A(test payload benign)|
| False positives (benign)      | 1                       | 0                       |

## Tuning applied
This is a high-signal rule; tuning is precision-based, not threshold-based.
- Layer 1 detects the encoded-command flag (-e/-enc/-EncodedCommand) in EID 1 — high recall, but flags benign encoded commands too (FP=1).
- Layer 2 inspects the DECODED script via PowerShell Script Block Logging (EID 4104), flagging malicious decoded patterns (DownloadString, IEX, FromBase64String, Net.WebClient, etc.).

## Honest result
Both the ART test payload and the benign command decode to harmless Write-Host content, so Layer 2 correctly flags neither. This demonstrates the design: in a real intrusion where the encoded payload decodes to a download/execute cradle, Layer 2 flags the attack while continuing to clear benign encoded commands — converting the Layer-1 false positive into a true negative. No malicious-decode FP-reduction number is claimed, because the benign-by-design test payload does not exercise it.

## Limitations
- Layer 1 alone is low-precision (any encoded command fires).
- Layer 2 catches only known malicious decoded patterns; a novel payload avoiding those keywords requires manual review of ScriptBlockText.
- Attackers can obfuscate decoded content to evade keyword matching (observed earlier: string-concat + gcm reassembly).