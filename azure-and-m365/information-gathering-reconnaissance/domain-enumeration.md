# Domain Enumeration



### Check if company is utilizing Azure AD

We can visit the url below to see if a company is utilizing Azure AD. Replace "COMPANY' with the domain name.

```url
https://login.microsoftonline.com/getuserrealm.srf?login=username@COMPANY.onmicrosoft.com&xml=1
```

We can see below that the domain (rottadev) is utilizing Azure AD

<figure><img src="../../.gitbook/assets/Screenshot 2024-07-15 at 4.04.08 PM.png" alt=""><figcaption></figcaption></figure>

### Enumerate Subdomains

We can utilize the tool [MicroBurst](https://github.com/NetSPI/MicroBurst) to perform subdomain enumeration.

```powershell
PS> Invoke-EnumerateAzureSubDomains -Base rottadev -verbose

rottadevimages.sharepoint.com                SharePoint
images-rottadev.sharepoint.com               SharePoint
imagesrottadev.sharepoint.com                SharePoint
internal-dist-rottadev.sharepoint.com        SharePoint
internal-distrottadev.sharepoint.com         SharePoint
rottadev-internal-dist.sharepoint.com        SharePoint
internalrottadev.sharepoint.com              SharePoint
rottadevinternal.sharepoint.com              SharePoint
```
