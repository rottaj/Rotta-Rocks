---
description: >-
  Once we have access to a low level user on the system, we want to elevate our
  privileges. Before we can do so, there is important information we have to
  obtain.
---

# Initial Enumeration

_<mark style="color:red;">**IMPORTANT:**</mark>_ Stomping these commands on a computer can be a loud process, always practice good opsec when enumerating!

## Initial Enumeration

There are several key pieces of information we should always initilally obtain:

* Username & hostname
* Group memberships of the current user
* Existing users and groups
* Operating system, version and architecture
* Network information
* Installed applications
* Running processes

### Display Groups - whoami

```
C:\Users\dave> whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                    
====================================== ================ ============================================== 
Everyone                             Well-known group S-1-1-0                                        
```

### Display Local Users - Get-LocalUser

```
PS C:\Users\dave> Get-LocalUser
Get-LocalUser

Name               Enabled Description                                                                              
----               ------- -----------                                                                              
Administrator      False   Built-in account for administering the computer/domain
BackupAdmin        True
dave               True    dave 
daveadmin          True 
```

### Display Local Groups - Get-LocalGroup

```
PS C:\Users\dave> Get-LocalGroup
Get-LocalGroup

Name                                Description                                                                      
----                                -----------                                                                     
adminteam                  Members of this group are admins to all workstations on the second floor
BackupUsers 
helpdesk
...
```

### Display Group Members - GetLocalGroupMember

```
PS C:\Users\dave> Get-LocalGroupMember Administrators
Get-LocalGroupMember Administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK220\Administrator Local          
User        CLIENTWK220\daveadmin     Local
User        CLIENTWK220\backupadmin   Local  
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

### Display OS, Version, & Architecture

```
PS C:\Users\dave> systeminfo

Host Name:                 Computer
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22621 N/A Build 22621
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          dave@gmail.com
Registered Organization:
```

### Display Routing Table - route print

```
PS C:\Users\dave> route print
route print
===========================================================================
Interface List
  6...00 50 56 8a 80 16 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   192.168.50.254   192.168.50.220    271
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.50.0    255.255.255.0         On-link    192.168.50.220    271
   192.168.50.220  255.255.255.255         On-link    192.168.50.220    271
```

### List Active Network Connections - netstat

```
PS C:\Users\dave> netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       6824
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       960
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       6824
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1752
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1084
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       3288
```

### List Installed Programs - Get ItemProperty

```
PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname 
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

displayname                                                       
-----------                                                       
KeePass Password Safe 2.51.1                                      
Microsoft Edge                                                    
Microsoft Edge Update                                             
Microsoft Edge WebView2 Runtime                                   
...
Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913    
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913       
Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913

PS C:\Users\dave> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

DisplayName                                                   
-----------                                                   
7-Zip 21.07 (x64)                                             
...
XAMPP
VMware Tools                                                  
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913  
```

### List Running Processes

```
PS C:\Users\dave> Get-Process
Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                               
-------  ------    -----      -----     ------     --  -- -----------                                                
     49      12      528       1152       0.03   2044   0 access
...
    477      49    17328      23904              6068   0 httpd
    179      29     9608      19792              6824   0 httpd
...                                                 
    174      16   210620      29048              1752   0 mysqld
...                                                  
    825      40    75804      14404       5.91   6332   0 powershell
...                                                
    379      24     6864      30236              2272   1 xampp-control
```
