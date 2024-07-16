# AADInternals

Full documentation can be found below

{% embed url="https://aadinternals.com/aadinternals/" %}

### Install AADInternals

To install AADInternals open an administrator powershell terminal and run the following command. <mark style="color:red;">**Note**</mark>: you may need to run "powershell -ep bypass" depending on your systems security settings.

```powershell
PS> Install-Module AADInternals
```

### Using AADInterals

Once we've installed AADInternals we can import it into our current powershell prompt.

```powershell
> Import-Module AADInternals
    ___    ___    ____  ____      __                        __
   /   |  /   |  / __ \/  _/___  / /____  _________  ____ _/ /____
  / /| | / /| | / / / // // __ \/ __/ _ \/ ___/ __ \/ __ `/ / ___/
 / ___ |/ ___ |/ /_/ _/ // / / / /_/  __/ /  / / / / /_/ / (__  )
/_/  |_/_/  |_/_____/___/_/ /_/\__/\___/_/  /_/ /_/\__,_/_/____/

 v0.9.3 by @DrAzureAD (Nestori Syynimaa)
```





### Invoke-AADIntReconAsOutsider

Starts tenant recon of the given domain. Gets all verified domains of the tenant and extracts information such as their type.

Also checks whether Desktop SSO (aka Seamless SSO) is enabled for the tenant.

```powershell
PS> Invoke-AADIntReconAsOutsider -DomainName rottadev.onmicrosoft.com | Format-Table
Tenant brand:       Rotta
Tenant name:        rottadev.onmicrosoft.com                                                                            Tenant id:          4229582f-b81c-4623-b205-723775863d4f                                                                Tenant region:      NA                                                                                                  DesktopSSO enabled: False                                                                                                                                                                                                                       Name                      DNS   MX  SPF DMARC  DKIM MTA-STS Type    STS
----                      ---   --  --- -----  ---- ------- ----    ---
rottadev.onmicrosoft.com True True True False False   False Managed
```
