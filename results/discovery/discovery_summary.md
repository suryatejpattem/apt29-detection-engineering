# Discovery Detection — Tuning Summary

**Technique:** T1087.002 / T1033 / T1016 / T1018 / T1082 / T1069.002 (Discovery)
**Rule:** detections/T1087_discovery.yaml

## Telemetry finding
`net group`/`net user` execute internally as `net1.exe` — a rule matching only `net ` misses the `net1` variants. Match strings corrected to catch both. (See discovery_net1_finding.png)

## Measurement (clean windows)
- Attack burst: 06/25 11:42–11:44 (Splunk time)
- Benign window: 06/25 18:07–18:48 (Splunk time)

|         Metric          |       Naive rule      | Tuned rule (≥5 distinct/5min) |
|-------------------------|-----------------------|-------------------------------|
| True positives (attack) | 27 events/17 distinct | fires (17 distinct ✓)         |
| False positives (benign)|            9          |                  0            |

## Tuning applied
Behavioral threshold: alert only when ≥5 distinct discovery commands occur per host per 5-min window. Threshold chosen from observed separation — benign admin peaked at 4 distinct, attack reached 17.

## Limitations (accepted blind spots)
- A slow attacker spacing discovery commands >5 min apart, or running ≤4 distinct commands, evades the threshold.
- A genuinely busy admin running 5+ distinct diagnostic commands in 5 min would re-trigger a false positive.
- Mitigation not yet applied: layer parent-process context (e.g., discovery from non-interactive/unusual parents) to partially cover the slow-attacker case.