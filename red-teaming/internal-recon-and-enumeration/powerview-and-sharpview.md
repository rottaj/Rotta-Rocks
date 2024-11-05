# PowerView & SharpView

## PowerView

[PowerView](https://github.com/PowerShellMafia/PowerSploit) returns queries in PowerShell objects, which can be piped to other cmdlets. This allows us to chain multiple commands together. View "Penetration Testing" & "Active Directory" pages for more. This page will cover PowerView for Cobalt Strike beacons & other C2s.

#### Import PowerView - CS Beacon

```powershell
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
```

## SharpView

[SharpView](https://github.com/tevora-threat/SharpView) is a C# port of PowerView. It has the same functionality. However, does not have the same piping capability.

#### Use SharpView - CS Beacon

We can execute the same PowerView commands we would with execute-assembly. Below we execute PowerView's `Get-Domain.`

```powershell
beacon> execute-assembly C:\Tools\SharpView.exe Get-Domain 
```

\


## Get-Domain

```powershell
beacon> powershell Get-Domain

Forest                  : rotta.dev
DomainControllers       : {dc2.dev.rotta.dev}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : rotta.dev
PdcRoleOwner            : dc2.dev.rotta.dev
RidRoleOwner            : dc2.dev.rotta.dev
InfrastructureRoleOwner : dc2.dev.rotta.dev
Name                    : dev.rotta.dev
```

## Get-DomainController

Returns the domain controllers for the current domain.

```powershell
beacon> powershell Get-DomainController | select Forest, Name, OSVersion | fl

Forest    : rotta.dev
Name      : dc2.dev.rotta.dev
OSVersion : Windows Server 2022 Datacenter
```

## Get-ForestDomain

Returns all domains for the current forest or the forest specified by `-Forest`.

```powershell
beacon> powershell Get-ForestDomain

Forest                  : rotta.dev
DomainControllers       : {dc.rotta.dev}
Children                : {dev.rotta.dev}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : 
PdcRoleOwner            : dc.rotta.dev
RidRoleOwner            : dc.rotta.dev
InfrastructureRoleOwner : dc.rotta.dev
Name                    : rotta.dev

Forest                  : rotta.dev
DomainControllers       : {dc2.dev.rotta.dev}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : rotta.dev
PdcRoleOwner            : dc2.dev.rotta.dev
RidRoleOwner            : dc2.dev.rotta.dev
InfrastructureRoleOwner : dc2.dev.rotta.dev
Name                    : dev.rotta.dev
```

## Get-DomainPolicyData

Returns the default domain policy or the domain controller policy. Good for finding password policy.

```powershell
beacon> powershell Get-DomainPolicyData | select -expand SystemAccess

MinimumPasswordAge           : 1
MaximumPasswordAge           : 42
MinimumPasswordLength        : 7
PasswordComplexity           : 1
PasswordHistorySize          : 24
LockoutBadCount              : 0
RequireLogonToChangePassword : 0
ForceLogoffWhenHourExpire    : 0
ClearTextPassword            : 0
LSAAnonymousNameLookup       : 0
```

## Get-DomainUser

```powershell
beacon> powershell Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl

displayname : Samantha Coolio
memberof    : {CN=Internet Users,CN=Users,DC=dev,DC=rottadev,DC=io, CN=IT & PC Support
,CN=Users,DC=dev,DC=rotta,DC=dev}
```

<mark style="color:red;">**Note**</mark>: Most privileges in a domain are delegated for groups, and not individual users. Samantha Coolio is part of IT & PC Support, we can assume they have high privileges.

## Get-DomainComputer

Return all computers.

```powershell
beacon> powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName

dnshostname              
-----------              
dc2.dev.rotta.dev
sql.dev.rotta.dev
internal-web.dev.rotta.dev
pwnbox.dev.rotta.dev
win10.dev.rotta.dev
```

## Get-DomainOU

Search for all organization units (OUs).

```powershell
beacon> powershell Get-DomainOU -Properties Name | sort -Property Name

name              
----              
Domain Controllers    
SQL Servers       
Internal Web Servers       
Workstations
```

## Get-DomainGPO

Return all Group Policy Objects (GPOs) or a specific GPO object. <mark style="color:red;">**Note**</mark>: To enumerate all GPOs that are applied to a particular machine, use `-ComputerIdentity`.

```powershell
beacon> powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName

displayname                      
-----------                      
Computer Certificates
Default Domain Controllers Policy
Default Domain Policy
LAPS
Proxy Settings
Server Admins
Vulnerable GPO
Windows Defender
Windows Firewall
Workstation Admins
```

## Get-DomainGroupMember

Return members of specified group.

```powershell
beacon> powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName

MemberDistinguishedName                             
-----------------------                             
CN=Robert Dumpster,CN=Users,DC=dev,DC=rotta,DC=dev
CN=Administrator,CN=Users,DC=dev,DC=rotta,DC=dev
```



## Get-DomainGPOLocalGroup

Returns all GPOs that modify local group membership through Restricted Groups or Group Policy Preferences.

```powershell
beacon> powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName

GPODisplayName     GroupName            
--------------     ---------            
Workstation Admins DEV\IT & PC Support
Server Admins      DEV\IT & PC Support
```

<mark style="color:red;">Note</mark>: "IT & PC Support" group is assigned access to the machines these apply to. Machines connected to "Workstation Admins" & "Server Admins". A big one we're looking for is "Remote Desktop Users".





## Get-DomainGPOUserLocalGroupMapping

Enumerates the machines where a specific domain user/group is a member of a specific local group. <mark style="color:red;">**Note**</mark>: Useful for finding where domain groups have local admin access.

```powershell
beacon> powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

ObjectName     : IT & PC Support
GPODisplayName : Server Admins
ContainerName  : {OU=Servers,DC=dev,DC=rotta,DC=dev}
ComputerName   : {internal-website.dev.rotta.dev, sql.dev.rotta.dev}

ObjectName     : IT & PC Support
GPODisplayName : Workstation Admins
ContainerName  : {OU=Workstations,DC=dev,DC=rotta,DC=dev}
ComputerName   : {win10.dev.rotta.dev, win10.dev.rotta.dev}
```

## Get-DomainTrust

Return all domain trusts for the current or specified domain.\


```powershell
beacon> powershell Get-DomainTrust

SourceName      : dev.rotta.dev
TargetName      : rotta.dev
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 8/15/2022 4:00:00 PM
WhenChanged     : 8/15/2022 4:00:00 PM
```
