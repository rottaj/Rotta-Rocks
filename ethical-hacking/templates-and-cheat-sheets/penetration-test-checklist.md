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

*



## Lateral Movement

*
