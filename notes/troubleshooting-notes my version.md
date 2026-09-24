# Troubleshooting Notes

## 1. Recursive Registry Search Was Too Slow

### Problem

An unrestricted registry search was initially performed using recursive enumeration combined with `Get-ItemProperty`.

This approach can become slow because a large number of registry keys and values may be traversed.

### Resolution

Use targeted persistence locations first:

```text
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Only expand to broader recursive searches when the investigation requires it.

## 2. PowerShell Matching Returned Registry Provider Metadata

### Problem

A broad registry query combined with `Select-String` returned properties such as:

```text
PSPath
PSParentPath
PSChildName
PSDrive
PSProvider
```

These are PowerShell registry-provider properties rather than actual persistence values.

### Resolution

Inspect registry properties individually:

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" |
ForEach-Object {
    $_.PSObject.Properties |
    Where-Object {
        $_.Value -is [string] -and
        $_.Value -match '(?i)(powershell|pwsh|\.ps1)'
    } |
    Select-Object Name, Value
}
```

This reduces false matches caused by PowerShell's registry-provider metadata.

## 3. Notepad Process Did Not Match the Candidate System32 File

### Observation

The persistence entry referenced:

```text
SOCLab = notepad.exe
```

The candidate file was:

```text
C:\Windows\System32\notepad.exe
```

However, the observed process used:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

### Resolution

Do not automatically treat the observed process as execution from the Run entry.

Compare:

```text
Image
ExecutablePath
CommandLine
ProcessId
ParentProcessId
ProcessGuid
UtcTime
```

before establishing attribution.

## 4. Notepad Parent Process Was explorer.exe

The investigated Notepad process had:

```text
ProcessId: 23160
ParentProcessId: 21680
```

The parent was:

```text
explorer.exe
```

The observed relationship was:

```text
explorer.exe
    |
    +-- notepad.exe
```

### Investigation Impact

This establishes the observed process relationship.

It does not establish:

```text
Run Key
    |
    +-- notepad.exe
```

The parent process alone cannot identify which persistence mechanism caused the process to launch.

## 5. Sysmon Network Query Returned No Results

### Problem

The Sysmon Event ID `3` query for the investigated PID returned no output.

### Resolution

Record the result as:

```text
Network activity not established.
```

Do not record it as:

```text
No network activity occurred.
```

The absence of an event does not prove the absence of activity.

Possible explanations include:

- No connection occurred.
- The wrong PID was investigated.
- The event was outside the retrieved range.
- Sysmon configuration did not capture the activity.
- Process and network events occurred at different times.

## 6. PID-Based Correlation Has Limitations

Process IDs are not permanent identifiers.

A PID can be reused after a process terminates.

For historical Sysmon correlation, prefer:

```text
ProcessGuid
UtcTime
ProcessId
Image
CommandLine
ParentProcessId
```

rather than relying only on a PID.

## 7. Scheduled Task Search Returned Many Legitimate Tasks

The Scheduled Task search looked for:

```text
powershell
pwsh
cmd
wscript
cscript
mshta
rundll32
```

This returned multiple Windows tasks.

Examples included:

```text
PcaPatchDbTask
StartupAppTask
CleanupTemporaryState
AppInstallerUpdater
Monitoring
Windows Defender Scheduled Scan
Automatic-Device-Join
```

### Resolution

The presence of a command interpreter or LOLBin does not automatically indicate malicious activity.

For suspicious tasks, examine:

```text
TaskName
TaskPath
Execute
Arguments
Author
Triggers
Principal
RunLevel
LastRunTime
NextRunTime
```

Then correlate the task with process telemetry.

## 8. IFEO Listing Contained Many Executables

### Observation

The IFEO registry contained multiple executable names.

### Resolution

The existence of an IFEO subkey is not sufficient to establish abuse.

The investigation specifically checks for:

```text
Debugger
```

A stronger IFEO finding requires evidence of suspicious execution redirection and, where possible, corresponding process execution.

## 9. Startup Folder Path

The correct user Startup path is:

```powershell
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

Use:

```powershell
Get-ChildItem `
"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" `
-Force `
-ErrorAction SilentlyContinue
```

Avoid adding a leading backslash before `$env:APPDATA`.

## 10. Evidence Directory

The investigation workspace was created with:

```powershell
$LabPath = "C:\PersistenceChainLab"
$EvidencePath = "$LabPath\Evidence"

New-Item -ItemType Directory -Path $EvidencePath -Force
```

Verify the directories with:

```powershell
Test-Path $LabPath
Test-Path $EvidencePath
```

Expected result:

```text
True
True
```

## 11. File Hash Collection

The candidate executable was hashed using:

```powershell
Get-FileHash $Candidate -Algorithm SHA256
```

Collected SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The hash provides a stable identifier for the collected file.

It does not independently establish maliciousness.

## 12. Evidence Attribution

A recurring investigation challenge is connecting artifacts that look related but lack direct evidence connecting them.

For example:

```text
SOCLab = notepad.exe
```

and:

```text
notepad.exe is running
```

do not automatically prove:

```text
SOCLab launched notepad.exe
```

A stronger correlation requires:

```text
Persistence artifact
    ↓
Referenced executable
    ↓
Matching executable path
    ↓
Process creation event
    ↓
Timestamp correlation
    ↓
Parent/child relationship
```

