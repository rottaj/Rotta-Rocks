---
description: >-
  PowerView / SharpView is a suite of useful powershell scripts we can transfer
  to the target computer to interact with AD.
---

# PowerView / SharpView

PowerView and it's successor SharpView are two popular tools that are used for penetration testing Active Directory.

{% embed url="https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1" %}
PowerView
{% endembed %}

{% embed url="https://github.com/tevora-threat/SharpView" %}
SharpView
{% endembed %}

## PowerView

### Import Powerview

```powershell
PS C:\Tools> powershell -ep bypass
PS C:\Tools> Import-Module .\PowerView.ps1
```

### Get-NetComputer

Enumerates the computer objects in the domain.

```powershell
PS C:\Tools> Get-NetComputer

pwdlastset                    : 9/26/2023 2:03:46 AM
logoncount                    : 701
msds-generationid             : {249, 114, 167, 231...}
serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 10/12/2023 4:45:50 PM
name                          : DC1
objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
samaccountname                : DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 10/12/2023 11:45:50 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC1,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=corp,DC=com
objectguid                    : 8db9e06d-068f-41bc-945d-221622bca952
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata         : {9/2/2022 11:10:48 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {TERMSRV/DC1, TERMSRV/DC1.corp.com, Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC1.corp.com,
                                ldap/DC1.corp.com/ForestDnsZones.corp.com...}
usncreated                    : 12293
lastlogon                     : 10/12/2023 4:45:50 PM
badpwdcount                   : 0
cn                            : DC1
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 9/2/2022 11:10:48 PM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 532581
ridsetreferences              : CN=RID Set,CN=DC1,OU=Domain Controllers,DC=corp,DC=com
dnshostname                   : DC1.corp.com
```



### Get-NetComputer  with filters

```
PS C:\Tools> Get-NetComputer | select operatingsystem,dnshostname

operatingsystem              dnshostname
---------------              -----------
Windows Server 2022 Standard DC1.corp.com
Windows Server 2022 Standard web04.corp.com
Windows Server 2022 Standard FILES04.corp.com
Windows 11 Pro               client74.corp.com
Windows 11 Pro               client75.corp.com
Windows 10 Pro               CLIENT76.corp.com
```



### Get-NetGroup - Just names

```
PS C:\Tools> Get-NetGroup | select cn

cn
--
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Storage Replica Administrators
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
```



### Get-NetGroup - Members

<pre><code><strong>PS C:\Tools> Get-NetGroup "Domain Admins" | select member
</strong>
member
------
{CN=nathalie,CN=Users,DC=corp,DC=com, CN=jeffadmin,CN=Users,DC=corp,DC=com, CN=Administrator,CN=Users,DC=corp,DC=com}


PS C:\Tools>
</code></pre>



### Get-NetUser - List Important Attributes

```
PS C:\Tools> Get-NetUser | select cn,pwdlastset,lastlogon

cn            pwdlastset             lastlogon
--            ----------             ---------
Administrator 8/16/2022 5:27:22 PM   10/16/2023 10:47:39 AM
Guest         12/31/1600 4:00:00 PM  12/31/1600 4:00:00 PM
krbtgt        9/2/2022 4:10:48 PM    12/31/1600 4:00:00 PM
dave          9/7/2022 9:54:57 AM    10/16/2023 10:47:42 AM
stephanie     9/2/2022 4:23:38 PM    10/16/2023 10:40:12 AM
jeff          9/2/2022 4:27:20 PM    9/27/2023 3:42:05 AM
jeffadmin     9/2/2022 4:26:48 PM    9/27/2023 6:08:57 AM
iis_service   9/7/2022 5:38:43 AM    3/1/2023 3:40:02 AM
pete          9/6/2022 12:41:54 PM   2/1/2023 2:42:42 AM
jen           9/6/2022 12:43:01 PM   3/8/2023 11:39:06 PM
nathalie      10/16/2023 10:37:36 AM 12/31/1600 4:00:00 PM
fred          10/16/2023 10:37:36 AM 12/31/1600 4:00:00 PM
bob           10/16/2023 10:37:36 AM 12/31/1600 4:00:00 PM
robert        10/16/2023 10:37:36 AM 12/31/1600 4:00:00 PM
dennis        10/16/2023 10:37:36 AM 12/31/1600 4:00:00 PM
michelle      10/16/2023 10:37:36 AM 12/31/1600 4:00:00 PM
```



### Get-NetUser  - Single User

```
PS C:\Tools> Get-NetUser "fred"


logoncount                 : 0
badpasswordtime            : 12/31/1600 4:00:00 PM
distinguishedname          : CN=fred,CN=Users,DC=corp,DC=com
objectclass                : {top, person, organizationalPerson, user}
name                       : fred
physicaldeliveryofficename : OS{7188de949bb6a096fd7c10a419a54564}
objectsid                  : S-1-5-21-1987370270-658905905-1781884369-19102
samaccountname             : fred
codepage                   : 0
samaccounttype             : USER_OBJECT
accountexpires             : NEVER
countrycode                : 0
whenchanged                : 10/16/2023 5:37:36 PM
instancetype               : 4
usncreated                 : 532614
objectguid                 : 5a4a0666-238a-4c48-ba9f-75d508dd01cf
lastlogoff                 : 12/31/1600 4:00:00 PM
objectcategory             : CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata      : 1/1/1601 12:00:00 AM
lastlogon                  : 12/31/1600 4:00:00 PM
badpwdcount                : 0
cn                         : fred
useraccountcontrol         : NORMAL_ACCOUNT
whencreated                : 10/16/2023 5:37:36 PM
primarygroupid             : 513
pwdlastset                 : 10/16/2023 10:37:36 AM
usnchanged                 : 532618
```



### Find-DomainShare

Get all shares in Domain.

```powershell
PS C:\Tools> Find-DomainShare

Name           Type Remark                 ComputerName
----           ---- ------                 ------------
ADMIN$   2147483648 Remote Admin           DC1.corp.com
C$       2147483648 Default share          DC1.corp.com
IPC$     2147483651 Remote IPC             DC1.corp.com
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com
ADMIN$   2147483648 Remote Admin           web04.corp.com
backup            0                        web04.corp.com
C$       2147483648 Default share          web04.corp.com
IPC$     2147483651 Remote IPC             web04.corp.com
ADMIN$   2147483648 Remote Admin           FILES04.corp.com
C                 0                        FILES04.corp.com
C$       2147483648 Default share          FILES04.corp.com
docshare          0 Documentation purposes FILES04.corp.com
IPC$     2147483651 Remote IPC             FILES04.corp.com
Tools             0                        FILES04.corp.com
Users             0                        FILES04.corp.com
Windows           0                        FILES04.corp.com
ADMIN$   2147483648 Remote Admin           client74.corp.com
C$       2147483648 Default share          client74.corp.com
IPC$     2147483651 Remote IPC             client74.corp.com
ADMIN$   2147483648 Remote Admin           client75.corp.com
C$       2147483648 Default share          client75.corp.com
IPC$     2147483651 Remote IPC             client75.corp.com
sharing           0                        client75.corp.com
```
