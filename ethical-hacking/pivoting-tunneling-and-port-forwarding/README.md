---
description: >-
  Pivoting is the idea of moving to other networks through a compromised host to
  find more target son different network segments.
---

# Pivoting, Tunneling, and Port Forwarding

There are many terms to describe a compromised host that we use to pivot:

* `Pivot Host`
* `Proxy`
* `Foothold`
* `Beach Head system`
* `Jump Host`

_**The purpose of pivoting is to defeat segmentation (physically and virtually) and to access an isolated network.**_



### Lateral Movement

Lateral movement is like pivoting & tunneling but not entirely the same. Because attackers want to stay beneath the radar, they often avoid known malware and exploits that will trigger signature-based intrusion alarms. Instead, they will attempt to steal or guess passwords and then login to remote machines or escalate privileges.&#x20;

We like to 'live off the land", using benign processes and tools already installed on the system to further our attacks.

We want to utilize tools like Powershell, Windows Management Instrumentation (WMI), and PsExec, to Perform network discovery and lateral movement.



I
