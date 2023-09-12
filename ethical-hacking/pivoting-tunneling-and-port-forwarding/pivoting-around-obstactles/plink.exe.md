---
description: >-
  Plink, short for PuTTY Link, is a Windows command-line tool that comes as a
  part of PuTTY. The tool is a choice for many sysadmins.
---

# plink.exe

Before 2018, Windows did not have a native SSH client so users would have to install their own. Starting with Windows 10 & Windows Server 2019 have a built-in SSH client called Ssh.exe (based on OpenSSH).

Instead of pulling our own tools onto a host and risk the chance of being exposed, we can live off the land and use what is already there.



**Using Plink.exe**

```bash
plink -D 9050 jump-host@10.129.15.50
```

The `-D` flag sets up dynamic port forward. The client listens on port `9050` and implements a SOCKS server.

Another Windows-based tool called [Proxifier](https://www.proxifier.com/) can be used to start a SOCKS tunnel via the SSH session we created.&#x20;
