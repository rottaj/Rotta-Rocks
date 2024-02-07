---
description: >-
  Windapsearch is another handy Python script we can use to enumerate users,
  groups, and computers from a Windows domain by utilizing LDAP queries.
---

# Windapsearch & Ldapsearch

***

{% embed url="https://github.com/ropnop/windapsearch.git" %}

## **Windapsearch**

**Windapsearch is a fantastic tool to utilize to enumerate an AD network once we have access to a domain user.** <mark style="color:yellow;">We can view, SPN's, connected computers, group policy objects, and more. Read the github above.</mark>

### Get **Domain Admins**

```shell-session
attacker@kali$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 u:INLANEFREIGHT\forend
[+] Attempting to enumerate all Domain Admins
[+] Using DN: CN=Domain Admins,CN=Users.CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]	Found 28 Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local
```

### **Get Privileged Users**

```shell-session
attacker@kali$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as:
[+]      u:INLANEFREIGHT\forend
[+] Attempting to enumerate all AD privileged users
[+] Using DN: CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 28 nested users for group Domain Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Angela Dunn
userPrincipalName: adunn@inlanefreight.local

cn: Matthew Morgan
userPrincipalName: mmorgan@inlanefreight.local

cn: Dorothy Click
userPrincipalName: dclick@inlanefreight.local

<SNIP>

[+] Using DN: CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[+]     Found 3 nested users for group Enterprise Admins:

cn: Administrator
userPrincipalName: administrator@inlanefreight.local

cn: lab_adm

cn: Sharepoint Admin
userPrincipalName: sp-admin@INLANEFREIGHT.LOCAL
```

### Get Service Principal Names

```shell-session
attacker@kali$ ./windapsearch.py --dc-ip 192.168.191.122 -u "fmcsorley@hutch.offsec" -p "CrabSharkJellyfish192" --user-spns         
[+] Using Domain Controller at: 192.168.191.122
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=hutch,DC=offsec
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      u:HUTCH\fmcsorley
[+] Attempting to enumerate all User objects with SPNs
[+]     Found 0 Users with SPNs:


[*] Bye!

```

## Ldapsearch&#x20;

We can use ldapsearch for an initial foothold if we don't have access to a user account but can anonymously query LDAP.

### Get extensive output

```shell-session
attacker@kali$ ldapsearch -x -H ldap://192.168.213.122 -b "dc=hutch,dc=offsec" > ldap_search.txt
```

### Grep for goodies

```shell-session
attacker@kali$ cat ldap_search.txt | grep description
description: Built-in account for guest access to the computer/domain
description: All workstations and servers joined to the domain
description: Members of this group are permitted to publish certificates to th
description: All domain users
description: All domain guests
description: Members in this group can modify group policy for the domain
description: Servers in this group can access remote access properties of user
description: Members in this group can have their passwords replicated to all 
description: Members in this group cannot have their passwords replicated to a
description: Members of this group are Read-Only Domain Controllers in the ent
description: Members of this group that are domain controllers may be cloned.
description: Members of this group are afforded additional protections against
description: DNS Administrators Group
description: DNS clients who are permitted to perform dynamic updates on behal
description: Password set to CrabSharkJellyfish192 at user's request. Please c

```



### Recommended Command

```
ldapsearch -x -H ldap://dc.support.htb -D 'SUPPORT\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=SUPPORT,DC=HTB" | tee ldap_dc.support.htb.txt

#
# LDAPv3
# base <CN=Users,DC=SUPPORT,DC=HTB> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# Users, support.htb
dn: CN=Users,DC=support,DC=htb
objectClass: top
objectClass: container
cn: Users
description: Default container for upgraded user accounts
distinguishedName: CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528110155.0Z
whenChanged: 20220528110155.0Z
uSNCreated: 5660
uSNChanged: 5660
showInAdvancedViewOnly: FALSE
name: Users
objectGUID:: fvT3rPs5nUaComz/MQQwrw==
systemFlags: -1946157056
objectCategory: CN=Container,CN=Schema,CN=Configuration,DC=support,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20220528110344.0Z
dSCorePropagationData: 16010101000001.0Z

# krbtgt, Users, support.htb
dn: CN=krbtgt,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user

```
