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

## Privilege Escalation

* [ ] PayloadAllTheThings&#x20;

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md" %}



## Lateral Movement

*
