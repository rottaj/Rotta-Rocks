---
description: >-
  Searching for sensitive log files & Events can be lead to valuable information
  about a system and may lead to escalating privileges.
---

# Searching Logs & Event Viewer

## PowerShell **Script Block Logging**

Two important logging mechanisms for PowerShell are:

* _PowerShell Transcription_
* _PowerShell Script Block Logging_.

### Get-WinEvent

```
Get-WinEvent Microsoft-Windows-PowerShell/Operational | Where-Object Id -eq 4104 | Out-GridView
```

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

```
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### req query

```
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

## Event Viewer

If we have access to RDP we can use the Event Viewer GUI to search for logs and event files.

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-03 133017.png" alt=""><figcaption></figcaption></figure>
