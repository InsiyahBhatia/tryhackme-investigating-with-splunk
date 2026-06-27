# TryHackMe — Investigating with Splunk

![TryHackMe](https://img.shields.io/badge/TryHackMe-Investigating%20with%20Splunk-red?style=for-the-badge&logo=tryhackme)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-black?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange?style=for-the-badge)

A SOC investigation using **Splunk Enterprise** to analyze a simulated Windows compromise. This lab covers Windows Event Log analysis, registry persistence detection, malicious PowerShell investigation, Base64 payload decoding, and IOC extraction — following a structured incident response workflow.

---

## Scenario

SOC Analyst Johny detects suspicious activity across several Windows hosts. Windows Event Logs have been pre-ingested into Splunk under the `main` index. The objective is to investigate the incident, identify attacker actions, and reconstruct the complete attack chain.

---

## Investigation Workflow

```mermaid
flowchart TD
    A([🚨 Alert Generated]) --> B[Open Splunk]
    B --> C[Establish Event Baseline]
    C --> D[Investigate User Account Creation]
    D --> E[Investigate Registry Modifications]
    E --> F[Investigate Process Creation]
    F --> G[Investigate Authentication Events]
    G --> H[Investigate PowerShell Logs]
    H --> I[Decode Obfuscated Payload]
    I --> J[Extract IOCs]
    J --> K([✅ Reconstruct Attack Timeline])
```

---

## Lab Environment

| Component | Detail |
|-----------|--------|
| SIEM | Splunk Enterprise 8.2.6 |
| Log Source | Windows Event Logs (pre-ingested JSON) |
| Index | `main` |
| Log Types | Security, PowerShell Operational, Sysmon |

---

## Windows Event IDs Investigated

| Event ID | Description |
|----------|-------------|
| 4103 | PowerShell Module Logging |
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Logon Using Explicit Credentials |
| 4657 | Registry Value Modification |
| 4688 | Process Creation |
| 4720 | User Account Created |

---

## Phase 1 — Environment Verification

Confirmed that Windows Event Logs were successfully indexed into Splunk before starting the investigation.

**Screenshots**

| # | Screenshot |
|---|-----------|
| 01 | ![Index Verification](screenshots/01-Index-Verification.png) |
| 02 | ![Sourcetype Verification](screenshots/02-Sourcetype-Verification.png) |

---

## Phase 2 — Event Enumeration

Used SPL to enumerate all available Event IDs and establish an investigation baseline.

```spl
index=main
| stats count by EventID
| sort - count
```

**Screenshots**

| # | Screenshot |
|---|-----------|
| 03 | ![EventCode Search](screenshots/03-EventCode-Search.png) |
| 04 | ![EventCode Statistics](screenshots/04-EventCode-Statistics.png) |

---

## Phase 3 — Windows Security Investigation

Investigated Event ID **4720** to identify malicious account creation.

```spl
index=main EventID=4720
| table _time, ComputerName, SubjectUserName, TargetUserName
```

**Findings:** Detected a suspicious backdoor account created by an attacker-controlled user on a compromised host.

**Screenshots**

| # | Screenshot |
|---|-----------|
| 05 | ![New User Account Query](screenshots/05-New-User-Account-Query.png) |
| 06 | ![New User Account Details](screenshots/06-New-User-Account-Details.png) |

---

## Phase 4 — Registry & Persistence Analysis

Analyzed Event ID **4657** to identify registry-based persistence mechanisms used by the attacker.

```spl
index=main EventID=4657
| table _time, ComputerName, SubjectUserName, ObjectName, ObjectValueName, OldValue, NewValue
```

**Screenshots**

| # | Screenshot |
|---|-----------|
| 07 | ![Registry Modification Search](screenshots/07-Registry-Modification-Search.png) |
| 08 | ![Registry Persistence Details](screenshots/08-Registry-Persistence-Details.png) |

---

## Phase 5 — User Account Investigation

Correlated Event IDs **4720** and **4648** to identify the attacker's account manipulation and credential usage.

```spl
index=main EventID=4648
| table _time, ComputerName, SubjectUserName, TargetUserName, ProcessName
```

**Screenshots**

| # | Screenshot |
|---|-----------|
| 09 | ![Account Creation Correlation](screenshots/09-Account-Creation-Correlation.png) |
| 10 | ![EventID 4720 Investigation](screenshots/10-EventID-4720-Investigation.png) |

---

## Phase 6 — PowerShell Investigation

Examined PowerShell Operational Logs (Event ID **4103**) to identify malicious cmdlets, encoded payloads, and suspicious execution patterns on host `James.browne`.

```spl
index=main EventID=4103
| table _time, Hostname, UserID, Payload

index=main Hostname="James.browne" EventID=4103
| stats count
```

**Screenshots**

| # | Screenshot |
|---|-----------|
| 11 | ![PowerShell Event Search](screenshots/11-PowerShell-Event-Search.png) |
| 12 | ![PowerShell Operational Logs](screenshots/12-PowerShell-Operational-Logs.png) |
| 13 | ![Encoded PowerShell Search](screenshots/13-Encoded-PowerShell-Search.png) |

---

## Phase 7 — Malware Analysis

Extracted the encoded PowerShell payload and decoded it using **CyberChef**.

### Attacker Execution Chain

```mermaid
flowchart TD
    A([powershell.exe -nop -sta -w 1 -enc]) --> B[Disable Script Block Logging]
    B --> C[Disable AMSI via Reflection]
    C --> D[Create System.Net.WebClient]
    D --> E[Set IE User-Agent & Cookie]
    E --> F[Decode Hidden C2 Server]
    F --> G[DownloadData from C2 URL]
    G --> H[RC4 Decrypt Payload]
    H --> I([Invoke-Expression — In-Memory Execution])
```

### Decoding Steps

| Step | Method | Tool |
|------|--------|------|
| 1 | Extract `-enc` argument from Event ID 4103 | Splunk |
| 2 | Base64 decode outer layer | CyberChef |
| 3 | Decode UTF-16LE encoding | CyberChef |
| 4 | Extract nested Base64 strings | Manual analysis |
| 5 | Reconstruct C2 URL | Manual analysis |

**Screenshots**

| # | Screenshot |
|---|-----------|
| 14 | ![PowerShell Script Extraction](screenshots/14-PowerShell-Script-Extraction.png) |
| 15 | ![Encoded Payload Review](screenshots/15-Encoded-Payload-Review.png) |
| 16 | ![CyberChef Initial Decoding](screenshots/16-CyberChef-Initial-Decoding.png) |
| 17 | ![Base64 UTF16 Decoding](screenshots/17-Base64-UTF16-Decoding.png) |
| 18 | ![Decoded Script Part 1](screenshots/18-Decoded-PowerShell-Script-Part1.png) |
| 19 | ![Decoded Script Part 2](screenshots/19-Decoded-PowerShell-Script-Part2.png) |

---

## Phase 8 — IOC Extraction

**Screenshots**

| # | Screenshot |
|---|-----------|
| 20 | ![C2 URL Extraction](screenshots/20-C2-URL-Extraction.png) |

See [`docs/iocs.md`](docs/iocs.md) for the full IOC list.

---

## Attack Timeline

See [`docs/attack_timeline.md`](docs/attack_timeline.md) for full timeline.

| Step | Event ID | Action |
|------|----------|--------|
| 1 | 4624 | Attacker gains initial access |
| 2 | 4720 | Backdoor account created |
| 3 | 4657 | Registry modified for persistence |
| 4 | 4648 | Explicit credential usage |
| 5 | 4688 | WMIC executes remote commands |
| 6 | 4688 | PowerShell launched with encoded payload |
| 7 | 4103 | Script Block Logging disabled |
| 8 | 4103 | AMSI bypassed |
| 9 | 4103 | Payload downloaded via WebClient |
| 10 | 4103 | RC4 decryption + in-memory IEX execution |

---

## MITRE ATT&CK Mapping

See [`docs/mitre_mapping.md`](docs/mitre_mapping.md) for full mapping.

| Technique | ID | Tactic |
|-----------|----|--------|
| PowerShell | T1059.001 | Execution |
| Obfuscated Files or Information | T1027 | Defense Evasion |
| Indicator Removal on Host | T1070 | Defense Evasion |
| WMIC Proxy Execution | T1218 | Defense Evasion |
| User Account Creation | T1136 | Persistence |
| Registry Modification | T1112 | Persistence |
| Ingress Tool Transfer | T1105 | C2 |

---

## Detection Opportunities

- PowerShell launched with `-enc` or `-encodedcommand` flag
- `System.Net.WebClient` instantiation in PowerShell logs
- `DownloadData()` or `DownloadString()` calls
- `Invoke-Expression` / `IEX` execution
- AMSI bypass patterns (reflection-based)
- Script Block Logging tampering (registry write to `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell`)
- Event ID 4720 — unexpected account creation
- Event ID 4688 — WMIC spawning child processes

---

## Repository Structure

```
tryhackme-investigating-with-splunk/
│
├── README.md
├── screenshots/
│   ├── 01-Index-Verification.png
│   ├── 02-Sourcetype-Verification.png
│   ├── ...
│   └── 20-C2-URL-Extraction.png
├── queries/
│   ├── baseline.spl
│   ├── account_creation.spl
│   ├── registry.spl
│   ├── process_creation.spl
│   ├── powershell.spl
│   └── ioc_extraction.spl
└── docs/
    ├── attack_timeline.md
    ├── mitre_mapping.md
    └── iocs.md
```

---

## Skills Demonstrated

`Splunk SPL` `Windows Event Log Analysis` `PowerShell Forensics` `Threat Hunting` `Incident Response` `Digital Forensics` `IOC Extraction` `Malware Analysis` `Base64 Decoding` `Log Correlation` `MITRE ATT&CK` `SIEM Investigation` `Registry Analysis` `Defense Evasion Detection`
