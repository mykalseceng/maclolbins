# MITRE ATT&CK for the MacLOLBins catalogue

The catalogue maps each binary to ATT&CK Enterprise techniques; tactics are derived from them.
The report and the MCP server show the catalogue's IDs and names. Link them as below, and add the
v20 notes where they apply.

## Links

- Technique: `https://attack.mitre.org/techniques/<ID with . as />/`, e.g. T1059.002 →
  https://attack.mitre.org/techniques/T1059/002/ (`get_lolbin` returns this as `url`)
- Tactic: `https://attack.mitre.org/tactics/<TA ID>/`
- macOS matrix: https://attack.mitre.org/matrices/enterprise/macos/

## Tactics used by the catalogue

| Catalogue tactic | ID | Link | ATT&CK v20 |
|---|---|---|---|
| Collection | TA0009 | https://attack.mitre.org/tactics/TA0009/ | unchanged |
| Command and Control | TA0011 | https://attack.mitre.org/tactics/TA0011/ | unchanged |
| Credential Access | TA0006 | https://attack.mitre.org/tactics/TA0006/ | unchanged |
| Defense Evasion | TA0005 | https://attack.mitre.org/tactics/TA0005/ | split: TA0005 is now **Stealth**; tampering with defences moved to **Defense Impairment** ([TA0112](https://attack.mitre.org/tactics/TA0112/)) |
| Discovery | TA0007 | https://attack.mitre.org/tactics/TA0007/ | unchanged |
| Execution | TA0002 | https://attack.mitre.org/tactics/TA0002/ | unchanged |
| Exfiltration | TA0010 | https://attack.mitre.org/tactics/TA0010/ | unchanged |
| Impact | TA0040 | https://attack.mitre.org/tactics/TA0040/ | unchanged |
| Lateral Movement | TA0008 | https://attack.mitre.org/tactics/TA0008/ | unchanged |
| Persistence | TA0003 | https://attack.mitre.org/tactics/TA0003/ | unchanged |
| Privilege Escalation | TA0004 | https://attack.mitre.org/tactics/TA0004/ | unchanged |

`list_lolbins(tactic=...)` matches the catalogue's names, so filter with "Defense Evasion", not
"Stealth".

## ATT&CK v20 changes affecting catalogue techniques

ATT&CK v20 was released on 13 October 2026. These are every catalogue technique whose status,
name or tactics differ in v20 (checked against MITRE's v20.0 STIX data). Techniques not listed
are unchanged. Revoked technique pages still resolve on attack.mitre.org and point to the
replacement.

| Catalogue technique | Catalogue tactic(s) | v20 |
|---|---|---|
| T1070.002 Indicator Removal: Clear Linux or Mac System Logs | Defense Evasion | **revoked** → [T1685.006](https://attack.mitre.org/techniques/T1685/006/) Clear Linux or Mac System Logs (Defense Impairment) |
| T1562.001 Impair Defenses: Disable or Modify Tools | Defense Evasion | **revoked** → [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools (Defense Impairment) |
| T1562.004 Impair Defenses: Disable or Modify System Firewall | Defense Evasion | **revoked** → [T1686](https://attack.mitre.org/techniques/T1686/) Disable or Modify System Firewall (Defense Impairment) |
| T1222.002 File and Directory Permissions Modification: Linux and Mac | Defense Evasion | renamed "Linux and Mac Permissions"; tactic Defense Impairment |
| T1553.001 Subvert Trust Controls: Gatekeeper Bypass | Defense Evasion | tactic Defense Impairment |
| T1553.002 Subvert Trust Controls: Code Signing | Defense Evasion | tactic Defense Impairment |
| T1553.004 Subvert Trust Controls: Install Root Certificate | Defense Evasion | tactic Defense Impairment |
| T1647 Plist File Modification | Defense Evasion | tactic Defense Impairment |
| T1027 Obfuscated Files or Information | Defense Evasion | tactic Stealth |
| T1070.006 Indicator Removal: Timestomp | Defense Evasion | tactic Stealth |
| T1140 Deobfuscate/Decode Files or Information | Defense Evasion | tactic Stealth |
| T1564.001 Hide Artifacts: Hidden Files and Directories | Defense Evasion | tactic Stealth |
| T1497.001 Virtualization/Sandbox Evasion: System Checks | Defense Evasion, Discovery | tactics Stealth, Discovery |
| T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching | Privilege Escalation, Defense Evasion | tactic Privilege Escalation only |

How to write it: catalogue ID and link first, because that is what the report shows, then the
v20 equivalent. For example: "[T1562.001](https://attack.mitre.org/techniques/T1562/001/)
Impair Defenses: Disable or Modify Tools (revoked in v20 by
[T1685](https://attack.mitre.org/techniques/T1685/), under Defense Impairment)".
