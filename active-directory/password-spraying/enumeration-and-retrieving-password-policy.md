# Enumeration & Retrieving Password Policy

### Tools and their ports:

Depending on the ports exposed, we may be able to discover the entities password policy using the correct tool.

| Tool      | Ports                                             |
| --------- | ------------------------------------------------- |
| nmblookup | 137/UDP                                           |
| nbtstat   | 137/UDP                                           |
| net       | 139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535 |
| rpcclient | 135/TCP                                           |
| smbclient | 445/TCP                                           |

### Enumerating the Password Policy - from Linux - Credentialed

With valid domain credentials, the password policy can also be obtained remotely using tools such as [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or `rpcclient`.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
</strong>
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password history length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Maximum password age: Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password Complexity Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Refuse Password Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Store Cleartext: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Lockout Admins: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Clear Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Anon Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Complex: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password age: 1 day 4 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Reset Account Lockout Counter: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Locked Account Duration: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Account Lockout Threshold: 5
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Forced Log off Time: Not Set
</code></pre>

### Enumerating the Password Policy - from Linux - SMB NULL Sessions

Without credentials, we may be able to obtain the password policy via an SMB NULL session or LDAP anonymous bind. . For enumeration, we can use tools such as `enum4linux`, `CrackMapExec`, `rpcclient`, etc.

\
**Using rpcclient**

```shell-session
attacker@kali$ rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
```

\
**Obtaining the Password Policy using rpcclient**

```shell-session
rpcclient $> querydominfo

Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```

\
**Using enum4linux**

```shell-session
$ enum4linux -P 172.16.5.5

<SNIP>

 ================================================== 
|    Password Policy Information for 172.16.5.5    |
 ================================================== 

[+] Attaching to 172.16.5.5 using a NULL share
[+] Trying protocol 139/SMB...


[+] Password Info for Domain: INLANEFREIGHT

	[+] Minimum password length: 8
	[+] Password history length: 24
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000001
```

**Using enum4linux-ng (rewrite of enum4linux in python)**

```shell-session
$ enum4linux-ng -P 172.16.5.5 -oA ilfreight
 =======================================
|    Policies via RPC for 172.16.5.5    |
 =======================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: 24
  min_pw_length: 8
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
```

### Enumerating the Password Policy - from Linux - LDAP Anonymous Bind

[LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
</strong>
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
</code></pre>

### Enumerating the Password Policy - from Windows

If we can authenticate to the domain from a Windows host, we can use built-in windows libraries such as net.exe.

**Using net.exe**

```cmd-session
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

**Using PowerView**

```powershell-session
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

### Enumerating Null Session - from Windows

\
**Establish a null session from windows**

```cmd-session
C:\htb> net use \\DC01\ipc$ "" /u:""
The command completed successfully.
```

\
**Error: Account is Disabled**

```cmd-session
C:\htb> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.
```

**Error: Password is Incorrect**

```cmd-session
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.
```

**Error: Account is locked out (Password Policy)**

```cmd-session
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.
```

\


## Analyzing the Password Policy

Most password policies now-a-days are as follows:

* Minimum length of 8 is very common, but nowadays, we are seeing more and more organizations enforce a 10-14 character password
* The account lockout threshold is 5. 3 Is not uncommon.
* The lockout duration is 30 minutes (or higher)
* Accounts unlock automatically
* Password complexity is enabled, meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (`Password1` or `Welcome1` would satisfy the "complexity")

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |

Now that we have the password policy in hand, we need to create a target user list to perform our password spraying attack.
