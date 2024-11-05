# ADSearch

## AdSearch

ADSearch has fewer buil-in queries than PowerView / SharpView. However, it allows for customer Lightweight Directory Access Protocol (LDAP) queries. These can be used to identify entries in the directory that match a given criteria.

## Custom LDAP Queries

### Search All Objects by Category "User"

The below LDAP query returns all domain users.

```powershell
beacon> execute-assembly C:\ToolsADSearch.exe --search "objectCategory=user"

[*] No domain supplied. This PC's domain will be used instead
[*] LDAP://DC=dev,DC=rotta,DC=dev
[*] CUSTOM SEARCH: 

[*] TOTAL NUMBER OF SEARCH RESULTS: 8
	[+] cn : Administrator
	[+] cn : Guest
	[+] cn : krbtgt
	[+] cn : CYBER$
	[+] cn : Samantha Coolio
	[+] cn : Robert Dumpster
	[+] cn : Cassy Pawnster
	[+] cn : MS SQL Service
```

### Applying Filters for admin users

We can apply a filter to our LDAP query to search for names that end with "Admins".

```
 beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"

[*] No domain supplied. This PC's domain will be used instead
[*] LDAP://DC=dev,DC=rotta,DC=dev
[*] CUSTOM SEARCH: 
[*] TOTAL NUMBER OF SEARCH RESULTS: 2
	[+] cn : Domain Admins
	[+] cn : MS SQL Admins
```

### AND, OR, NOT Conditions

We can build more complex conditional queries.

```
beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=group)(cn=Global Admins))" --attributes cn,member

[*] TOTAL NUMBER OF SEARCH RESULTS: 1
	[+] cn     : Global Admins
	[+] member : CN=Developers,CN=Users,DC=dev,DC=rotta,DC=dev
```

### Output to JSON

The `--json` parameter can be used to format the output in JSON.\


```powershell
[
  {
    "cn": "MS SQL Admins",
    "member": "CN=Developers,CN=Users,DC=dev,DC=rotta,DC=dev"
  }
]
```
