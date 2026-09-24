# Lab 86 — Investigation Notes

## Investigation Scope

The investigation examined a Windows 11 workstation for persistence mechanisms and attempted to determine whether the identified artifacts could be connected to observed process activity.

The investigation focused on:

- Registry Run and RunOnce keys
- Startup folders
- Scheduled Tasks
- Windows Services
- Image File Execution Options
- PowerShell references
- Referenced executable validation
- Sysmon process creation
- Parent/child process relationships
- Sysmon network activity
- Wazuh registry telemetry
- Elastic endpoint telemetry

## Investigation Workspace

```text
C:\PersistenceChainLab
```

Evidence directory:

```text
C:\PersistenceChainLab\Evidence
```

Investigation start time:

```text
24 September 2026 07:20:51
```

## Host Profile

```text
Hostname: DESKTOP-9MMM37V
Manufacturer: Dell Inc.
Model: Latitude 5420
Operating System: Windows 11 Pro
Version: 10.0.26200
Build: 26200
Domain: WORKGROUP
Domain Role: 0
```

The system was identified as a standalone WORKGROUP workstation.

## Registry Run Key Investigation

### HKLM Run

The machine-wide Run key contained:

```text
SecurityHealth
RtkAudUService
WavesSvc
```

The referenced paths were associated with Windows Security Health and audio-related software.

No PowerShell or `pwsh.exe` execution command was identified in the collected HKLM Run output.

### HKCU Run

The current-user Run key contained several application startup entries.

Relevant entries included:

```text
Adobe Acrobat Synchronizer
OneDrive
Mozilla-Firefox-308046B0AF4A39CB
MEmuSVC
MicrosoftCopilotAutoLaunch_*
```

The investigation-specific entry was:

```text
SOCLab = notepad.exe
```

This establishes a user-level persistence configuration.

It does not establish that the configured command was executed through the Run mechanism.

## Startup Folder Investigation

The user Startup folder contained:

```text
desktop.ini
```

No additional executable, script, or suspicious shortcut was identified from the collected output.

## Scheduled Task Investigation

The Scheduled Task inventory identified:

```text
CompromiseLab-Persistence
```

with:

```text
Execute: powershell.exe
```

This is relevant because Scheduled Tasks can be used for persistence.

However, the investigation distinguishes between:

```text
Task exists
```

and:

```text
Task executed
```

and:

```text
Task executed successfully
```

The collected evidence establishes the first condition only.

Other tasks referenced common Windows utilities including:

```text
rundll32.exe
cmd.exe
dsregcmd.exe
MpcCmdRun.exe
```

These were not automatically treated as malicious.

## Windows Service Investigation

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

The service configuration alone did not establish malicious activity.

A service being configured as `Auto` is normal Windows behavior and therefore requires additional context.

## IFEO Investigation

The following location was examined:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Multiple executable-specific entries were present.

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

A separate query checked for `Debugger` values.

No suspicious Debugger value was established.

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

Metadata:

```text
Length: 360448
CreationTime: 09-09-2026 09:56:13
LastWriteTime: 09-09-2026 09:56:13
LastAccessTime: 24-09-2026 07:42:54
```

SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The file was successfully validated and hashed.

## Process Investigation

A Notepad process was observed:

```text
ProcessId: 23160
ParentProcessId: 21680
Name: Notepad.exe
```

Observed executable:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

Command line:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

Parent process:

```text
ProcessId: 21680
Name: explorer.exe
ExecutablePath: C:\WINDOWS\Explorer.EXE
```

Observed relationship:

```text
explorer.exe
    |
    +-- notepad.exe
```

## Important Process Correlation Finding

The Registry Run entry referenced:

```text
SOCLab = notepad.exe
```

The observed process was:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

The candidate file investigated was:

```text
C:\Windows\System32\notepad.exe
```

Because the executable paths differ, the observed Notepad process cannot automatically be attributed to the `SOCLab` Run entry.

This is an important correlation limitation.

## Sysmon Process Creation

Sysmon Event ID `1` was reviewed.

One event showed:

```text
UtcTime: 2026-09-24 02:03:21.605
ProcessId: 17748
Image: C:\Windows\System32\cmd.exe
Description: Windows Command Processor
Company: Microsoft Corporation
```

The event confirms process creation telemetry was available.

However, the event was not directly correlated with:

```text
SOCLab
CompromiseLab-Persistence
PID 23160
```

The event was therefore treated as a separate process creation observation.

## Sysmon Network Investigation

Sysmon Event ID `3` was queried for the investigated process.

No matching event was returned.

Assessment:

```text
Network activity:
Not established.
```

This does not prove that no network activity occurred.

Possible limitations include:

- No network activity occurred.
- Wrong PID was investigated.
- Relevant event was outside the retrieved range.
- Sysmon configuration limitations.
- Process and network events occurred at different times.

## Wazuh Investigation

Wazuh generated a registry monitoring alert with:

```text
decoder.name:
syscheck_registry_value_deleted
```

The affected registry value referenced:

```text
Program Files\Microvirt\tempDir\Setup.exe
```

Rule description:

```text
Registry Value Entry Deleted.
```

The event showed:

```text
rule.firedtimes: 5
```

The event confirms registry-value deletion activity.

However, no direct correlation was established between this event and:

```text
SOCLab
CompromiseLab-Persistence
notepad.exe
```

## Persistence Chain Candidate A

```text
HKCU Run
    |
    +-- SOCLab
          |
          +-- notepad.exe
```

Evidence:

```text
Run key configuration: Confirmed
Referenced command: Confirmed
Referenced file: Validated
Matching execution: Not established
```

## Persistence Chain Candidate B

```text
Scheduled Task
    |
    +-- CompromiseLab-Persistence
            |
            +-- powershell.exe
```

Evidence:

```text
Task configuration: Confirmed
PowerShell action: Confirmed
Task execution: Not established
```

## Persistence Chain Candidate C

```text
Wazuh Registry Deletion
        |
        +-- BAM registry value
                |
                +-- Microvirt\tempDir\Setup.exe
```

Evidence:

```text
Registry deletion: Confirmed
Relationship to other artifacts: Not established
```

## Analytical Assessment

The investigation identified multiple persistence-related artifacts.

However, the available evidence does not demonstrate a complete chain such as:

```text
Persistence
    ↓
Trigger
    ↓
Process Creation
    ↓
Child Process
    ↓
Network Activity
```

The evidence supports:

```text
Persistence configuration identified
        +
Process activity observed
        +
Registry activity observed
        +
Network correlation not established
        +
Direct persistence-to-execution correlation not established
```

## Analyst Principle

The investigation avoids the assumption:

```text
Persistence artifact
    ↓
Process exists
    ↓
Therefore persistence executed
```

Instead, the investigation follows:

```text
Identify artifact
    ↓
Identify referenced command
    ↓
Validate referenced file
    ↓
Search execution telemetry
    ↓
Compare executable path
    ↓
Compare command line
    ↓
Identify parent process
    ↓
Correlate timestamps
    ↓
Investigate child activity
    ↓
Investigate network activity
    ↓
Assess confidence
```

## Final Assessment

```text
Persistence configuration: Identified
Referenced commands/files: Identified
Process execution: Observed
Direct persistence-to-process correlation: Not established
Network correlation: Not established
Complete persistence chain: Not confirmed
```
