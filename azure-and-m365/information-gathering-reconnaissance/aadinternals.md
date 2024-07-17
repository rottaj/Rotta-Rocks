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



### Get Tenant ID from Domain

Login information, including tenant ID

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> Get-AADIntTenantID -Domain rotta.dev
</strong>f2a9b807-95f4-4a5f-9783-eaf2e0f18c7b
</code></pre>

API: login.microsoftonline.com//.well-known/openid-configuration

### Get All domains of the tenant

All domains of the tenant

```powershell
PS> Get-AADIntTenantDomains -Domain rotta.dev
NETORGFT16900538.onmicrosoft.comrotta.dev
```

API: autodiscover-s.outlook.com/autodiscover/autodiscover.svc

### Check if User Exists

```powershell
PS> Invoke-AADIntUserEnumerationAsOutsider -UserName alice@rottadev.onmicrosoft.com

UserName                       Exists
--------                       ------
alice@rottadev.onmicrosoft.com   True
```

### Check if User Exists (wordlist)

We can quickly check for users using a wordlist.

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal
</strong>
UserName                        Exists
--------                        ------
trey@rottadev.onmicrosoft.com    False
robert@rottadev.onmicrosoft.com  False
alice@rottadev.onmicrosoft.com    True
bob@rottadev.onmicrosoft.com      True
admin@rottadev.onmicrosoft.com   False
ga_admin@rottadev.onmicrosof...   True
admin_ga@rottadev.onmicrosof...  False
</code></pre>

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
