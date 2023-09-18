---
description: >-
  Link-Local Multicast Name Resolution(LLMNR) & NetBIOS Name Service (NBT-NS)
  are alternative methods to host identification. There can be used if DNS
  fails.
---

# LLMNR/NBT-NS Poisoning

NBT-NS utilizes port `137` over UDP.

LLMNR utilized port `5355` over UDP.

_<mark style="color:red;">**IMPORTANT:**</mark>_ When LLMNR/NBT-NS are used for name resolution, _**ANY**_ host can reply. We can poison these requests with tools like _**Responder**_.

### Procedure Examples <a href="#examples" id="examples"></a>

| ID                                               | Name                                                   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------ | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [S0363](https://attack.mitre.org/software/S0363) | [Empire](https://attack.mitre.org/software/S0363)      | [Empire](https://attack.mitre.org/software/S0363) can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.[\[8\]](https://github.com/PowerShellEmpire/Empire)[\[9\]](https://github.com/Kevin-Robertson/Inveigh)                                                                                                                                                                                                                                    |
| [S0357](https://attack.mitre.org/software/S0357) | [Impacket](https://attack.mitre.org/software/S0357)    | [Impacket](https://attack.mitre.org/software/S0357) modules like ntlmrelayx and smbrelayx can be used in conjunction with [Network Sniffing](https://attack.mitre.org/techniques/T1040) and [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001) to gather NetNTLM credentials for [Brute Force](https://attack.mitre.org/techniques/T1110) or relay attacks that can gain code execution.[\[10\]](https://www.secureauth.com/labs/open-source-tools/impacket) |
| [G0032](https://attack.mitre.org/groups/G0032)   | [Lazarus Group](https://attack.mitre.org/groups/G0032) | [Lazarus Group](https://attack.mitre.org/groups/G0032) executed [Responder](https://attack.mitre.org/software/S0174) using the command `[Responder file path] -i [IP address] -rPv` on a compromised host to harvest credentials and move laterally.[\[11\]](https://securelist.com/lazarus-threatneedle/100803/)                                                                                                                                                                               |
| [S0378](https://attack.mitre.org/software/S0378) | [PoshC2](https://attack.mitre.org/software/S0378)      | [PoshC2](https://attack.mitre.org/software/S0378) can use Inveigh to conduct name service poisoning for credential theft and associated relay attacks.[\[12\]](https://github.com/nettitude/PoshC2\_Python)                                                                                                                                                                                                                                                                                     |
| [S0192](https://attack.mitre.org/software/S0192) | [Pupy](https://attack.mitre.org/software/S0192)        | [Pupy](https://attack.mitre.org/software/S0192) can sniff plaintext network credentials and use NBNS Spoofing to poison name services.[\[13\]](https://github.com/n1nj4sec/pupy)                                                                                                                                                                                                                                                                                                                |
| [S0174](https://attack.mitre.org/software/S0174) | [Responder](https://attack.mitre.org/software/S0174)   | [Responder](https://attack.mitre.org/software/S0174) is used to poison name services to gather hashes and credentials from systems within a local network.[\[7\]](https://github.com/SpiderLabs/Responder)                                                                                                                                                                                                                                                                                      |
| [G0102](https://attack.mitre.org/groups/G0102)   | [Wizard Spider](https://attack.mitre.org/groups/G0102) | [Wizard Spider](https://attack.mitre.org/groups/G0102) has used the Invoke-Inveigh PowerShell cmdlets, likely for name service poisoning.[\[14\]](https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html)                                                                                                                                                                                                                                     |

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

| **Tool**                                              | **Description**                                                                                     |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [Responder](https://github.com/lgandx/Responder)      | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| [Inveigh](https://github.com/Kevin-Robertson/Inveigh) | Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks.      |
| [Metasploit](https://www.metasploit.com/)             | Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks.  |

### These tools can attack the following protocols:

* LLMNR
* DNS
* MDNS
* NBNS
* DHCP
* ICMP
* HTTP
* HTTPS
* SMB
* LDAP
* WebDAV
* Proxy Auth

Responder also has support for:

* MSSQL
* DCE-RPC
* FTP, POP3, IMAP, and SMTP auth

### Quick Example - LLMNR/NBT-NS Poisoning

Let's walk through a quick example of the attack flow at a very high level:

1. A host attempts to connect to the print server at \\\print01.inlanefreight.local, but accidentally types in \\\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

