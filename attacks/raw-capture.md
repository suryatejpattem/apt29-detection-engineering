## T1059.001 — PowerShell (Execution)
- Test: #17 (PowerShell Command Execution)
- Command: cmd.exe /c powershell.exe -e <base64> (decodes to Write-Host hello)
- Time run: 06/23/2026 04:26:41.230 PM
- Telemetry seen:
  - Sysmon EID 1: CommandLine had "-e <base64>", Parent cmd.exe -> powershell.exe
  - PowerShell EID 4104: logged 4 script blocks. Key one = decoded payload "Write-Host 'Hello, from PowerShell!'"; also captured the    OBFUSCATED form (string-concat + gcm) showing why literal-match detection fails. Confirms 4104 reveals intent that EID 1's base64 hides.
- Status: confirmed in Splunk (EID 1 ✓, 4104 ✓)

