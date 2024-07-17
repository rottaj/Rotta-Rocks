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

## Outsider Recon

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



## Guest Recon

### Authenticate as Guest

We can authenticate with a user and password using AADInternals. It will prompt for MFA.

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
</strong></code></pre>

### List Tenants

```powershell
PS> Get-AADIntAzureTenants

Id                                   Country Name  Domains
--                                   ------- ----  -------
4229582f-b81c-4623-b205-723775863d4f US      Rotta {rottadev.onmicrosoft.com}
```

### Login to Tenant as Guest

Any user can authenticate to a tenant as guest if they have a valid microsoft account and the tenant ID. This will prompt for MFA

```powershell
PS> Get-AADIntAccessTokenForAzureCoreManagement 
-Tenant 4229582f-b81c-4623-b205-723775863d4f -SaveToCache
```

### Invoke Recon as Guest

```powershell
PS> $results = Invoke-AADIntReconAsGuest

Tenant brand:                Rotta
Tenant name:                 rottadev.onmicrosoft.com
Tenant id:                   4229582f-b81c-4623-b205-723775863d4f
Azure AD objects:            213/50000
Domains:                      ( verified)
Non-admin users restricted?  False
Users can register apps?     True
Directory access restricted? False
Guest access:                Normal
CA policies:                 0
Access package admins:       0
```

### List all domains

This displays all the domains, their authentication type, verification status, supported servers, and password validity period.&#x20;

```powershell
PS> $results.domains | Select-Object id,authen*,isverified,supported*,password* | Format-Table

id                       authenticationType isVerified supportedServices                   passwordValidityPeriodInDays passwordNotificationWindowInD
                                                                                                                                                  ays
--                       ------------------ ---------- -----------------                   ---------------------------- -----------------------------
rottadev.onmicrosoft.com Managed                  True {Email, OfficeCommunicationsOnline}                   2147483647                            14
```

<mark style="color:red;">**Note**</mark>: The password validity period of 2147483647 (0x7FFFFFFF) indicates that passwords do not expire.

### List allowed actions

We can see rights the user has access to. (I authenticated as admin so everything).

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> $results.allowedActions
</strong>

administrativeunit              : {create, read, update, delete...}
application                     : {create, read, update, delete...}
approleassignment               : {create, read, update, delete...}
collaborationspace              : {create, read, update, delete...}
contact                         : {create, read, update, delete...}
contract                        : {create, read, update, delete...}
</code></pre>



### Enumerate Users

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> $results = Invoke-AADIntUserEnumerationAsGuest -GroupMembers 
</strong>-Manager -Subordinates -Roles

Tenant brand: Rotta
Tenant name:  rottadev.onmicrosoft.com
Tenant id:    4229582f-b81c-4623-b205-723775863d4f
Logged in as: jack@rottadev.onmicrosoft.com
Users:        5
Groups:       2
Roles:        0
</code></pre>

### Enumerate Groups

#### Enumerate Membership rules

List some relevant information from the returned groups:

```powershell
PS> $results.Groups | Select-Object displayName,id,membershiprule,description

displayName          id                                   membershipRule                                                             description                   
-----------          --                                   --------------                                                             -----------                   
All guests           b4c40137-6d42-4102-aa3b-023ba7d6e484 (user.userType -eq "Guest") or (user.userPrincipalName -match ".*#EXT#.*") All guests and externals users
Teams with externals b25791fc-7c20-4027-93d8-4a39a9ed186c   
```

#### Enumerate Members

List users within a group:

```
PS> $results.Groups | Select-Object displayName,id,members
displayName          id                                   members                                                                                                                                                              
-----------          --                                   -------                                                                                                                                                              
All guests           b4c40137-6d42-4102-aa3b-023ba7d6e484 {user_gmail.com#EXT#@Mcompany.onmicrosoft.com, user_outlook.com#EXT#@company.onmicrosoft.com, ...}
Teams with externals b25791fc-7c20-4027-93d8-4a39a9ed186c {user@company.com, admin@company.onmicrosoft.com, user_outlook.com#EXT#@Mcompany.onmicrosoft.com} 
```

<mark style="color:red;">**Note**</mark>: Many organizations have created a [dynamic group](https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/groups-create-rule) to contain all guest and/or extrernal users. Usually this is used to assign conditional access rules etc. to these users. However, the group will contain all guests of the organization, including business partners, clients, etc. And yes, **guest users can list the members of any group**!

Enumerating members is massive for us. We can use the information to conduct phishing campaigns and brute forcing.

### Group Member Enumeration

The following will extract all users from all the groups the given user is member of:

```powershell
PS> $results = Invoke-AADIntUserEnumerationAsGuest -UserName "user@company.com" -GroupMembers 
-Manager -Subordinates -Roles

Tenant brand: Company Ltd
Tenant name:  company.onmicrosoft.com
Tenant id:    6e3846ee-e8ca-4609-a3ab-f405cfbd02cd
Logged in as: live.com#user@outlook.com
Users:        32
Groups:       4
Roles:        3
```

#### List Group Information

```powershell
PS> $results.Groups | Select-Object displayName,id,membershiprule,description

displayName          id                                   membershipRule               description                                                                                     
-----------          --                                   --------------               -----------                                                                                     
Secret stuff teams   740f43a5-c7f8-4a1a-a6b8-2d57a1f6cda6                              This teams is meant for internal secret stuff! Mostly sensitive discussions with M&A candidates.
Teams with externals b25791fc-7c20-4027-93d8-4a39a9ed186c                              Teams with externals                                                                            
abc                  9202b94b-5381-4270-a3cb-7fcf0d40fef1                              abc                                                                                             
All company          2ce444bc-6112-4429-922c-dbf6be59a6c3 (user.userType -eq "Member") All company users 
```

#### List Role Information

```powershell
PS> $results.Roles | Select-Object id,members

id                                   members                                                                                                                                   
--                                   -------                                                                                                                                   
8b517a6e-d13e-4e97-a2c0-278ae38d46a6 {test.user@company.com}                                                                                                         
294cdfc8-abb4-419f-bdbb-c5d616644f9a {Sync_SERVER1_895b43df@company.com}
028e7f7b-c99a-41bb-9d5c-2d22457b5549 {admin@company.com, admin@company.onmicrosoft.com}     
```



## Insider Recon



### Authenticate as Insider

We can authenticate with a username and password

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
</strong></code></pre>

### Invoke Insider Recon

```powershell
PS> $results = Invoke-AADIntReconAsInsider

Tenant brand:                Rotta
Tenant name:                 rottadev.onmicrosoft.com
Tenant id:                   4229582f-b81c-4623-b205-723775863d4f
Tenant SKU:
Azure AD objects:            213/50000
Domains:                      ( verified)
Non-admin users restricted?  False
Users can register apps?     True
Directory access restricted? False
Directory sync enabled?      false
Global admins:               2
CA policies:                 0
MS Partner IDs:
MS Partner DAP enabled?      False
MS Partner contracts:        0
MS Partners:                 0
```

### User Enumeration

```powershell
PS> $results = Invoke-AADIntUserEnumerationAsInsider -Groups
Users:        4
Groups:       3
```

#### List Users

```
PS> $results.Users


id                              : be7cc3bb-fe07-401d-aa27-50420392b009
displayName                     : alice
userPrincipalName               : alice@rottadev.onmicrosoft.com
userType                        : Member
onPremisesImmutableId           :
onPremisesLastSyncDateTime      :
onPremisesSamAccountName        :
onPremisesSecurityIdentifier    :
onPremisesDistinguishedName     :
refreshTokensValidFromDateTime  : 2024-07-09T19:00:53Z
signInSessionsValidFromDateTime : 2024-07-09T19:00:53Z
proxyAddresses                  : {}
businessPhones                  : {}
identities                      : {@{signInType=userPrincipalName; issuer=rottadev.onmicrosoft.com; issuerAssignedId=alice@rottadev.onmicrosoft.com}}

id                              : fdbd3d73-b316-4bd0-ab55-d5ef650e53da
displayName                     : bob
userPrincipalName               : bob@rottadev.onmicrosoft.com
userType                        : Member
onPremisesImmutableId           :
onPremisesLastSyncDateTime      :
onPremisesSamAccountName        :
...
```

<mark style="color:red;">**Note**</mark>: We can list one by $results.Users\[x]

## Global Admin Recon

### Authenticate as Global Admin

```powershell
# Get an access token and save it to the cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

# Grant Azure User Access Administrator role 
Grant-AADIntAzureUserAccessAdminRole

# Update the access token after elevation and save to cache
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache

```

### List Subscriptions of current Tenant

```
PS> Get-AADIntAzureSubscriptions

subscriptionId                       displayName          state
--------------                       -----------          -----
f14038db-c8d7-48df-8d66-adf35489efc4 Azure subscription 1 Enabled
```

###
