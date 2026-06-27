# Scheduled Task Persistence — Tuning Summary

**Technique:** T1053.005 (Persistence/Execution)
**Rule:** detections/T1053.005_scheduled_task.yaml

## Measurement (clean windows)
- Attack: 06/25 10:14 — 2 tasks (T1053_005_OnStartup, OnLogon), action: cmd.exe /c calc.exe
- Benign: 06/25 18:37 — MyUpdateTask, action: C:\Program Files\MyApp\update.exe

| Metric                        | Naive (any task created) | Tuned (task runs interpreter/LOLBin) |
|-------------------------------|--------------------------|--------------------------------------|
| True positive (attack caught) | Yes (2)                  | Yes (2)                              |
| False positives (benign)      | 1                        | 0                                    |

## Tuning applied
Naive rule fires on any scheduled-task creation (4698). Tuned rule flags only tasks whose action launches a command interpreter or LOLBin (cmd, powershell, mshta, rundll32, wscript, cscript) or runs from AppData/Temp, clearing tasks that run a normal installed application.

## Implementation note (honest)
The task action lives in the 4698 task XML. Splunk's extracted Task_Content field held only the XML header, not the <Command> body, so the tuned rule matches against _raw event text. This works but is less precise — a production rule should extract the <Command> value into its own field (rex/field extraction) and match that, to avoid matching the term elsewhere in the event.

## Other notes
- 4698 requires "Other Object Access Events" audit policy (was off by default; enabled during lab).

## Limitations (accepted blind spots)
- A task launching a renamed/legit-looking binary from a trusted path evades the interpreter filter.
- Raw-text matching is coarser than field extraction (see implementation note).