---
description: >-
  Using legacy tools that are preinstalled on the hosts machine is always the
  most optimal approach in a OPSEC perspective
---

# Enumeration Using Legacy Tools

***

## Enumerating with net.exe

### Get Users in Domain

```powershell
PS C:\Users\stephanie> net user /domain
The request will be processed at a domain controller for domain corp.com.


User accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
Administrator            dave                     Guest
iis_service              jeff                     jeffadmin
jen                      krbtgt                   pete
stephanie
The command completed successfully.

```

### Get Domain User Information

```powershell
PS C:\Users\stephanie> net user stephanie /domain
The request will be processed at a domain controller for domain corp.com.

User name                    stephanie
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/2/2022 4:23:38 PM
Password expires             Never
Password changeable          9/3/2022 4:23:38 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/11/2023 3:38:56 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Sales Department
The command completed successfully.
```

### Get Groups in Domain

```powershell
PS C:\Users\stephanie> net groups /domain
The request will be processed at a domain controller for domain corp.com.


Group Accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Debug
*Development Department
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Management Department
*Protected Users
*Read-only Domain Controllers
*Sales Department
*Schema Admins
The command completed successfully.

PS C:\Users\stephanie>
```

### Get Users in Group

```powershell
PS C:\Users\stephanie> net group "Domain Admins" /domain
The request will be processed at a domain controller for domain corp.com.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            jeffadmin
The command completed successfully.
```

