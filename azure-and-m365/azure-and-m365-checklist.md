# Azure & M365 Checklist

TODO: Add notes



## Post Compromise - Enumeration



### Device Registration with Azure AD (EntraID)

#### dnsregcmd

We can see if the device is joined, and is using a [Primary Refresh Token](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token) (PRT).

```
PS> dsregcmd /status

+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : YES
              DomainJoined : YES
           Virtual Desktop : NOT SET
               Device Name : DESKTOP-30DTGNU
               ...
+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : YES
```
