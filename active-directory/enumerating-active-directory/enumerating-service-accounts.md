---
description: >-
  When a User executes an application, that user account defines the context.
  Services run under Service accounts, which may have higher privileges. Here is
  how we can enumerate Services.
---

# Enumerating Service Accounts

## &#x53;_&#x65;rvice Principal Name_ (SPN)

_Service Principal Name_ (SPN) associates a service account to a specific service in Active Directory.

We can obtain IP addresses and port numbers of applications running on Active Directory by simply enumerating all SPN's in the domain. All information is stored on the Domain Controller.

## Query Domain Controller - **setspn.exe**

We discovered a "_iis\_service" Service Account. Let's enumerate it with setspn.exe._

```powershell
c:\Tools>setspn -L iis_service
Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web04.corp.com
        HTTP/web04
        HTTP/web04.corp.com:80
```

## Query Domain Controller - PowerView

A easier way is to let PowerView query all accounts on the domain and filter by SPN.

```powershell
PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname

samaccountname serviceprincipalname
-------------- --------------------
krbtgt         kadmin/changepw
iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}
```

## Further Enumeration&#x20;

Going backt to the "iis\_service" account we discovered we notice it's running a web server. We can get the IP address by querying with nslookup

```powershell
PS C:\Tools\> nslookup.exe web04.corp.com
Server:  UnKnown
Address:  192.168.50.70

Name:    web04.corp.com
Address:  192.168.50.72
```

<mark style="color:red;">**NOTE:**</mark> We can browser to that IP address, for now we'll document that it's attached to a Service Account which is likely higher privilege than a User Account.



## Impacket GetUserSPNs

If we have credentials to a domain user we can use Impacket's GetUserSPN's script

```sh
GetUserSPNs.py -outputfile kerberoastables.txt -hashes 'LMhash:NThash' -dc-ip $KeyDistributionCenter 'DOMAIN/USER'
```
