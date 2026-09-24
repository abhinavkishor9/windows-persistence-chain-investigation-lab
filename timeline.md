# Lab 86 — Timeline

## Investigation Timeline

| Time | Source | Event / Observation | Assessment |
|---|---|---|---|
| 09-09-2026 09:56:13 | File metadata | `C:\Windows\System32\notepad.exe` creation time | File metadata |
| 23-09-2026 22:19:33 | Windows OS | Last boot time recorded | Host baseline |
| 24-09-2026 02:03:21.605 UTC | Sysmon Event ID 1 | `cmd.exe` process creation | Process execution observed |
| 24-09-2026 07:20:51 | PowerShell | Investigation workspace initialized | Investigation started |
| 24-09-2026 07:42:54 | File metadata | `notepad.exe` LastAccessTime observed | File metadata collected |
| 23-09-2026 16:21:02.114 | Wazuh | Registry value deletion detected | Registry activity observed |

## Persistence Artifacts

### Registry Run Key

```text
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
    |
    +-- SOCLab = notepad.exe
```

Assessment:

```text
Persistence configuration: Confirmed
Referenced command: Confirmed
Execution through Run key: Not established
```

### Scheduled Task

```text
CompromiseLab-Persistence
    |
    +-- powershell.exe
```

Assessment:

```text
Scheduled Task configuration: Confirmed
PowerShell action: Confirmed
Task execution: Not established
```

### Startup Folder

User Startup folder:

```text
C:\Users\Dell\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Observed:

```text
desktop.ini
```

Assessment:

```text
No additional suspicious startup executable identified.
```

### IFEO

Registry location:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Multiple executable-specific keys were present.

Assessment:

```text
IFEO configuration: Present
Suspicious Debugger: Not established
```

### Wazuh Registry Activity

Wazuh recorded deletion of a registry value associated with:

```text
Program Files\Microvirt\tempDir\Setup.exe
```

Assessment:

```text
Registry deletion: Confirmed
Connection to other persistence artifacts: Not established
```

## File Timeline

Candidate file:

```text
C:\Windows\System32\notepad.exe
```

Metadata:

```text
CreationTime: 09-09-2026 09:56:13
LastWriteTime: 09-09-2026 09:56:13
LastAccessTime: 24-09-2026 07:42:54
```

SHA256:

```text
468FFE129C395ABF6B21A09EFDF261910A95FB98AA982EAD73CAA7B2B684577E
```

The file was validated as existing on the system.

## Process Timeline

### Notepad Process

Observed process:

```text
ProcessId: 23160
ParentProcessId: 21680
Name: Notepad.exe
```

Observed executable:

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

Assessment:

```text
Notepad execution: Observed
Execution through SOCLab Run key: Not established
```

## Sysmon Process Creation

Sysmon Event ID `1` recorded:

```text
UtcTime: 2026-09-24 02:03:21.605
ProcessId: 17748
Image: C:\Windows\System32\cmd.exe
```

Assessment:

```text
Process creation: Confirmed
Connection to persistence artifacts: Not established
```

## Sysmon Network Activity

Sysmon Event ID `3` was queried for the investigated process.

Result:

```text
No matching network event returned.
```

Assessment:

```text
Network activity: Not established
```

This should not be interpreted as proof that no network activity occurred.

## Candidate Chain A

```text
HKCU Run
    |
    +-- SOCLab
          |
          +-- notepad.exe
```

Evidence status:

```text
Run key: Confirmed
Referenced executable: Confirmed
Referenced file: Confirmed
Matching execution: Not established
```

## Candidate Chain B

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
Execution: Not established
```

## Candidate Chain C

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
Connection to other persistence artifacts: Not established
```

## Final Timeline Assessment

The collected evidence shows multiple persistence-related and endpoint artifacts.

However, the evidence does not establish a continuous chain of:

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

The current evidence supports:

```text
Persistence artifacts identified
        +
Process activity observed
        +
Registry activity observed
        +
Network correlation not established
        +
Direct persistence-to-execution correlation not established
```

## Timeline Conclusion

The investigation supports the presence of persistence-related configuration and endpoint activity, but a complete persistence execution chain was not established.

The key distinction is:

```text
Observed artifact
        !=
Confirmed execution
        !=
Confirmed malicious execution
```
