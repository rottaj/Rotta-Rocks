---
description: >-
  Netsh is a native Windows command-line tool that can help with the network &
  firewall configuration of a particular Windows system.
---

# netsh

_**Netsh can be used for:**_

* `Finding routes`
* `Viewing the firewall configuration`
* `Adding proxies`
* `Creating port forwarding rules`

## Using Netsh to Port Forward

### Port Forward - Cmd

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

**connectaddress** & **connectport** is the computer we're pivoting to.

**listenaddress** & **listenport** is the jump host

### Verifying Port Forward

```powershell
C:\Windows\system32> netsh.exe interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.25     3389
```

```powershell
C:\Windows\system32>netstat -anp TCP | find "2222"
  TCP    192.168.50.64:2222     0.0.0.0:0              LISTENING

C:\Windows\system32>
```

### Adding Port to Firewall rules

Now that we've successfully opened a new port, we need to configure it to the firewall

```powershell
C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
Ok.

C:\Windows\system32>
```

### Confirming Port Forward

We can confirm the port is open on our kali host by scanning the open ports

```shell-session
kali@kali$ nmap -p2222 -Pn 192.168.234.64
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-26 22:00 EST
Nmap scan report for 192.168.234.64
Host is up (0.20s latency).

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds

```

### Confirming Success

Let's connect to the port we just set up. This will tunnel the traffic through our jump host to the desired box.

```shell-session
ssh database_admin@192.168.234.64 -p2222    
The authenticity of host '[192.168.234.64]:2222 ([192.168.234.64]:2222)' can't be established.
ED25519 key fingerprint is SHA256:oPdvAJ7Txfp9xOUIqtVL/5lFO+4RY5XiHvVrZuisbfg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.234.64]:2222' (ED25519) to the list of known hosts.
database_admin@192.168.234.64's password: 
```

### Cleaning up - Deleting Firewall rule

Once we're finishing using our pivot, we want to clean up the machine. Let's delete the firewall rules

```powershell
C:\Users\Administrator>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

Deleted 1 rule(s).
Ok.
```

We can also do so with the following:

```powershell
C:\Windows\Administrator> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64

C:\Windows\Administrator>
```
