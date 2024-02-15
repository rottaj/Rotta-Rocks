---
description: >-
  Before we can pivot into other networks, we need to perform some recon and
  discover other hosts on our network.
---

# Scanning for Hosts

Using the proper port scanning methodology when scanning for hosts is incredibly important. Port scanning is intrusive in nature, and can often have adverse affects. It is important to take your time and be cautious while performing host checks.



### Netcat

```
kali@kali:~$ nc -nvv -w 1 -z 192.168.50.152 3388-3390
```

```
kali@kali:~$ nc -nvv -w 1 -z 192.168.50.152 139,445
```

```
kali@kali:~$ nc -nv -u -z -w 1 192.168.50.149 120-123 # UDP -u
```

## Nmap

We should start by scanning the network for specific ports. Here are some initial ports:

* **Web Servers** - `80 and 443`
* **SMB File Shares** - `139 and 445`.
* **RDP** - `3388-3390`.





_**Scanning Subnet:**_

```
kali@kali:~$ nmap -sP 192.168.2.1/24
```

```
kali@kali:~$ nmap -sP 192.168.0.0/16
```

```
kali@kali:~$ proxychains nmap -sT -p135 10.4.0.0/16 --min-rate=10000
```

## Ping Sweep

#### For Loop on Linux Jump Host:

```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

#### For Loop Using CMD

```bash
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### For Loop Using Powershell

<pre class="language-powershell"><code class="lang-powershell"><strong>1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
</strong></code></pre>

_<mark style="color:red;">**Note:**</mark>_ Windows defender defaults to blocking ICMP packets. Additionally, ping sweeps should be carried out at least 2 times to get an effective scope of the network.

#### Meterpreter

If we have a meterpreter session, we can perform:

```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```
