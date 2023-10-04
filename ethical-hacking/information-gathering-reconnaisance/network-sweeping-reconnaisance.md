---
description: >-
  Before we can pivot into other networks, we need to perform some recon and
  discover other hosts on our network.
---

# Reconnaisance

## Ping Sweep

#### Meterpreter

If we have a meterpreter session, we can perform:

```bash
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

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

_<mark style="color:red;">**Note:**</mark>_ It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

_<mark style="color:red;">**Note:**</mark>_ There also may be scenarios where the host's firewall blocks ping (ICMP). Windows defender blocks this by default.
