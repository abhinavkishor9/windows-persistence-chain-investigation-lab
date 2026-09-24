# Lab 86 — Windows Persistence Chain Reconstruction

## Overview

This lab investigates whether multiple Windows persistence artifacts can be connected into a single execution chain.

The investigation covers Registry Run Keys, Startup folders, Scheduled Tasks, Windows Services, Image File Execution Options (IFEO), Sysmon process telemetry, Wazuh registry monitoring, and endpoint telemetry.

The investigation follows an evidence-first approach:

```text
Persistence Artifact
        ↓
Referenced Command/File
        ↓
Trigger
        ↓
Process Creation
        ↓
Child Activity
        ↓
Network/Endpoint Telemetry
```

A persistence artifact alone does not prove that execution occurred. The investigation therefore distinguishes between persistence configuration, execution, correlation, and confirmed activity.

## Lab Environment

- Hostname: `DESKTOP-9MMM37V`
- Manufacturer: Dell Inc.
- Model: Latitude 5420
- Operating System: Windows 11 Pro
- Version: `10.0.26200`
- Build: `26200`
- Domain: `WORKGROUP`
- Domain Role: `0`
- Wazuh Agent: `001`
- Sysmon: Enabled
- Elastic Endpoint: Installed
- Investigation Directory: `C:\PersistenceChainLab`
- Evidence Directory: `C:\PersistenceChainLab\Evidence`

## Investigation Objectives

- Identify common Windows persistence locations.
- Examine Registry Run and RunOnce keys.
- Inspect Windows Startup folders.
- Review Scheduled Tasks for suspicious execution mechanisms.
- Enumerate Windows Services and their executable paths.
- Investigate Image File Execution Options.
- Identify PowerShell-related persistence references.
- Validate referenced files and collect metadata.
- Calculate SHA256 hashes for relevant files.
- Review Sysmon process creation events.
- Investigate parent and child process relationships.
- Review Sysmon network telemetry.
- Correlate endpoint findings with Wazuh and Elastic telemetry.
- Reconstruct the persistence chain using only supported evidence.
- Distinguish persistence configuration from confirmed execution.

## Persistence Locations Investigated

### Registry Run Keys

The following locations were examined:

```text
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

The HKLM Run key contained:

```text
SecurityHealth
RtkAudUService
WavesSvc
```

The HKCU Run key contained several application startup entries, including:

```text
Adobe Acrobat Synchronizer
MicrosoftEdgeAutoLaunch_*
OneDrive
Mozilla-Firefox-308046B0AF4A39CB
MEmuSVC
MicrosoftCopilotAutoLaunch_*
SOCLab
```

The investigation-specific entry was:

```text
SOCLab = notepad.exe
```

The Run entry confirms that a persistence configuration existed. It does not independently prove that the referenced executable was launched through the Run mechanism.

### Startup Folders

The user Startup folder was:

```text
C:\Users\Dell\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

The collected contents included:

```text
desktop.ini
```

No additional executable or script was identified from the collected Startup folder output.

### Scheduled Tasks

The Scheduled Task inventory identified:

```text
CompromiseLab-Persistence
```

with the following execution target:

```text
powershell.exe
```

Other tasks referenced legitimate Windows utilities such as:

```text
rundll32.exe
cmd.exe
dsregcmd.exe
MpcCmdRun.exe
```

These were not automatically treated as malicious because the executable name alone does not establish malicious activity.

### Windows Services

Automatic services were enumerated.

Examples included:

```text
AdobeARMservice
ClickToRunSvc
DiagTrack
Dnscache
Elastic Agent
ElasticEndpoint
EventLog
```

No service was confirmed as malicious from the collected service configuration alone.

### Image File Execution Options

The following registry location was examined:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Multiple executable-specific IFEO keys were present.

Examples included:

```text
Acrobat.exe
AcrobatInfo.exe
AcroRd32.exe
DefenderAgentScan.exe
elastic-endpoint.exe
excel.exe
GoogleUpdate.exe
LSASS.exe
```

A separate check was performed for `Debugger` values.

No suspicious Debugger value was established from the collected evidence.

## Referenced File Investigation

The `SOCLab` Run entry referenced:

```text
notepad.exe
```

The candidate file investigated was:

```text
C:\Windows\System32\notepad.exe
```

The file existed.

Collected metadata:

```text
Length:        360448 bytes
CreationTime:  09-09-2026 09:56:13
LastWriteTime: 09-09-2026 09:56:13
LastAccessTime: 24-09-2026 07:42:54
```

SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The file was successfully validated and hashed.

However, file existence and hashing do not establish that the file was executed through the persistence mechanism.

## Process Investigation

A running Notepad process was investigated:

```text
ProcessId:       23160
ParentProcessId: 21680
Name:            Notepad.exe
```

The observed executable path was:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

The parent process was:

```text
ProcessId:       21680
Name:            explorer.exe
ExecutablePath:  C:\WINDOWS\Explorer.EXE
CommandLine:     C:\WINDOWS\Explorer.EXE
```

The observed relationship was:

```text
explorer.exe
    |
    +-- notepad.exe
```

An important distinction was identified during the investigation.

The Run entry referenced:

```text
notepad.exe
```

while the observed process was the WindowsApps version of Notepad.

Therefore, the observed process cannot automatically be attributed to the `SOCLab` Run entry.

## Sysmon Process Creation

Sysmon Event ID `1` was reviewed for process creation activity.

One collected event showed:

```text
UtcTime:       2026-09-24 02:03:21.605
ProcessId:     17748
Image:         C:\Windows\System32\cmd.exe
FileVersion:   10.0.26100.9278
Description:   Windows Command Processor
Product:       Microsoft® Windows® Operating System
Company:       Microsoft Corporation
OriginalFileName: Cmd.Exe
```

This confirms that Sysmon process creation telemetry was available.

However, the collected `cmd.exe` event was not directly correlated with:

```text
SOCLab
CompromiseLab-Persistence
notepad.exe PID 23160
```

It was therefore retained as a separate process execution observation.

## Sysmon Network Activity

Sysmon Event ID `3` was queried for the investigated process.

The filtered query returned no matching result.

The correct assessment is:

```text
Network activity for the investigated process:
Not established.
```

This does not prove that the process had no network activity.

Possible explanations include:

- No network connection occurred.
- The wrong process was investigated.
- The relevant event was outside the retrieved event range.
- Sysmon configuration did not capture the expected activity.
- Process and network events occurred at different times.

## Wazuh Evidence

Wazuh generated a registry monitoring event with:

```text
decoder.name:
syscheck_registry_value_deleted
```

The affected registry value referenced:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-51198790-337801975-322838354-1001\\Device\HarddiskVolume4\Program Files\Microvirt\tempDir\Setup.exe
```

The rule description was:

```text
Registry Value Entry Deleted.
```

The rule had fired five times according to the collected event.

This demonstrates registry-value deletion telemetry.

The event was not directly correlated with:

```text
SOCLab
CompromiseLab-Persistence
notepad.exe
```

It was therefore treated as separate supporting endpoint telemetry.

## Key Findings

### Finding 1 — Registry Run Key

The following persistence artifact was identified:

```text
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
SOCLab = notepad.exe
```

Assessment:

```text
Persistence configuration: Confirmed
Referenced command: Confirmed
Referenced file: Validated
Execution through Run key: Not established
```

### Finding 2 — Scheduled Task

The following scheduled task was identified:

```text
CompromiseLab-Persistence
```

The configured action referenced:

```text
powershell.exe
```

Assessment:

```text
Task configuration: Confirmed
PowerShell action: Confirmed
Task execution: Not established
PowerShell execution from task: Not established
```

### Finding 3 — Notepad Process

A Notepad process was observed:

```text
PID: 23160
Parent PID: 21680
Parent: explorer.exe
```

Assessment:

```text
Notepad execution: Observed
Execution through SOCLab Run key: Not established
```

### Finding 4 — IFEO

Multiple IFEO application keys were present.

Assessment:

```text
IFEO configuration: Present
Suspicious Debugger value: Not established
```

### Finding 5 — Network Activity

The Sysmon Event ID `3` query returned no matching network event for the investigated process.

Assessment:

```text
Network activity: Not established
```

### Finding 6 — Wazuh Registry Activity

Wazuh recorded deletion of a registry value associated with:

```text
Program Files\Microvirt\tempDir\Setup.exe
```

Assessment:

```text
Registry deletion: Confirmed
Relationship to persistence chain: Not established
```

## Evidence Assessment

| Artifact | Observation | Assessment |
|---|---|---|
| HKCU Run | `SOCLab = notepad.exe` | Persistence configured |
| Scheduled Task | `CompromiseLab-Persistence -> powershell.exe` | Persistence-related configuration identified |
| Startup Folder | `desktop.ini` | No suspicious startup executable identified |
| Services | Automatic services enumerated | No confirmed malicious service |
| IFEO | Multiple application keys | No confirmed suspicious Debugger |
| Notepad | PID `23160` observed | Execution observed |
| Notepad Parent | `explorer.exe` | Parent relationship observed |
| Sysmon Event 1 | `cmd.exe` process creation | Process creation observed |
| Sysmon Event 3 | No matching output for investigated PID | Network activity not established |
| Wazuh | Registry value deletion | Supporting endpoint telemetry |

## Persistence Chain Reconstruction

### Candidate Chain A

```text
HKCU Run
   |
   +-- SOCLab
         |
         +-- notepad.exe
```

Evidence status:

```text
Persistence configuration: Confirmed
Referenced executable: Confirmed
Referenced file exists: Confirmed
Matching execution: Not established
```

### Candidate Chain B

```text
Scheduled Task
   |
   +-- CompromiseLab-Persistence
          |
          +-- powershell.exe
```

Evidence status:

```text
Task configuration: Confirmed
PowerShell action: Confirmed
Task execution: Not established
```

### Candidate Chain C

```text
Wazuh Registry Deletion
        |
        +-- BAM registry value
                |
                +-- Microvirt\tempDir\Setup.exe
```

Evidence status:

```text
Registry deletion: Confirmed
Relationship to other persistence artifacts: Not established
```

## Investigation Conclusion

The investigation identified multiple persistence-related artifacts, including:

- A user-level Registry Run entry named `SOCLab`.
- A Scheduled Task named `CompromiseLab-Persistence`.
- A PowerShell execution reference within the scheduled task.
- Multiple Windows services.
- Multiple IFEO application keys.
- A Wazuh registry deletion event.
- Observed process execution through Sysmon and live process inspection.

However, the available evidence does not establish a single continuous persistence-to-execution chain.

The investigation therefore records:

```text
Persistence configuration: Identified
Referenced files/commands: Identified
Process activity: Observed
Direct persistence-to-process correlation: Not established
Network correlation: Not established
Complete persistence chain: Not confirmed
```

## Investigation Principle

The lab follows three important distinctions:

```text
Artifact != Execution

Execution != Maliciousness

Correlation strengthens the conclusion
```

The objective is to reconstruct what the evidence supports without treating every persistence artifact as proof of compromise.

## Evidence Files

```text
00-investigation-time.txt
01-host-information.txt
02-registry-run-keys.txt
03-system-startup.csv
03-user-startup.csv
04-scheduled-tasks.csv
05-services.csv
06-ifeo-debuggers.csv
07-persistence-file-hash.txt
07-persistence-file-metadata.txt
08-sysmon-process-creation.txt
09-sysmon-network-connections.txt
10-persistence-chain-summary.txt
```

## MITRE ATT&CK Mapping

Potentially relevant techniques investigated in this lab include:

- `T1547.001` — Registry Run Keys / Startup Folder
- `T1053.005` — Scheduled Task/Job: Scheduled Task
- `T1543.003` — Windows Service
- `T1546.012` — Event Triggered Execution: Image File Execution Options Injection
- `T1059.001` — Command and Scripting Interpreter: PowerShell

These mappings describe the persistence or execution mechanisms investigated. They do not by themselves establish that the technique was successfully abused.

## Skills Demonstrated

- Windows persistence investigation
- Registry analysis
- Scheduled Task analysis
- Windows service investigation
- IFEO analysis
- Startup folder investigation
- PowerShell investigation
- Sysmon process analysis
- Parent/child process analysis
- Network telemetry review
- Wazuh investigation
- Elastic endpoint telemetry correlation
- File metadata collection
- SHA256 hashing
- Timeline reconstruction
- Evidence-based SOC investigation
