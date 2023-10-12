---
description: >-
  Being able to develop tools on the fly is a valuable skill in engagements. We
  can create tools in Powershell & .NET that can be run with basic privileges.
---

# Powershell & .NET Classes

***

## Bypassing Security

Chances are Administrators have set some type of security in place to restrict PowerShell scripts.

### Change Execution Policy

[Set-ExecutionPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.3) determines what scripts and files are allowed to run on the current session. It can be Restricted, AllSigned, RemoteSigned Unrestricted, and Bypass.

```powershell
PS C:\> powershell -ep bypass
```

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\ Set-ExecutionPolicy -ExecutionPolicy bypass -Scope CurrentUser
</strong></code></pre>

## Developing Powershell Scripts

### .NET _System.DirectoryServices.ActiveDirectory_

In Microsoft .NET classes related to AD are found in the _System.DirectoryServices.ActiveDirectory namespace._

#### Get Current Domain

```powershell
PS C:\Users\stephanie> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```

Let's making this into a PowerShell script file. We'll call it `testing.ps1`.

<figure><img src="../../../.gitbook/assets/Screenshot_20231012_021545.png" alt=""><figcaption><p>Powershell ISE ftw. Change ExecutionPolicy before running!</p></figcaption></figure>

Active Directory relies on [LDAP](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/lightweight-directory-access-protocol-ldap-api) as it's communication protocol. Like other protocls we can specity a URI scheme. This scheme is known as the **LDAP ADsPath**.

```
LDAP://HostName[:PortNumber][/DistinguishedName]
```

We can build out this path and use it to create our own custom communication scripts to enumerate active directory.

#### Powershell .NET script to retrieve ADsPath

```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

## Active Directory Service Interfaces (ADSI)

We can use [ADSI](https://learn.microsoft.com/en-us/windows/win32/adsi/active-directory-service-interfaces-adsi) directly in PowerShell. This is a powerful tool when developing scripts.

```powershell
PS C:\Users\stephanie\Desktop> ([adsi]'').distinguishedName

DC=corp,DC=com
```

