# Attack Timeline

Reconstructed from correlation of Windows Security Logs and PowerShell Operational Logs.

| Step | Event ID | Description | Screenshot |
|------|----------|-------------|------------|
| 1 | 4624 | Attacker gains initial access | - |
| 2 | 4720 | Backdoor user account created | ![New Account](../screenshots/06-New-User-Account-Details.png) |
| 3 | 4657 | Registry modified for persistence | ![Registry](../screenshots/08-Registry-Persistence-Details.png) |
| 4 | 4648 | Attacker uses explicit credentials | ![Credential Use](../screenshots/09-Account-Creation-Correlation.png) |
| 5 | 4688 | WMIC used for remote command execution | - |
| 6 | 4688 | PowerShell launched with encoded payload | ![PowerShell](../screenshots/11-PowerShell-Event-Search.png) |
| 7 | 4103 | Script Block Logging disabled | ![Script Block](../screenshots/13-Encoded-PowerShell-Search.png) |
| 8 | 4103 | AMSI bypassed | ![AMSI](../screenshots/13-Encoded-PowerShell-Search.png) |
| 9 | 4103 | WebClient created, payload downloaded | ![Payload](../screenshots/15-Encoded-Payload-Review.png) |
| 10 | 4103 | RC4 decryption, in-memory execution (IEX) | ![Decoded](../screenshots/19-Decoded-PowerShell-Script-Part2.png) |
