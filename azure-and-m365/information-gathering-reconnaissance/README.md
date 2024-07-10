# Information Gathering / Reconnaissance



## Introduction

We can use public API's to reveal information about an organizations Azure environment. The goal of our information gathering / reconnaissance is to determine the following:

* Domain names
* User login information
* Desktop SSO information
* Tenant names and additional information
* Any resources that exist on the azure environment







## DNS Suffixes

There is a long list of [DNS suffixes](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains) that we can use to perform reconnaissance on a target to determine if certain resources exist within a tenant.

## Azure AD reconnaissance <a href="#azure-a-d-reconnaissance" id="azure-a-d-reconnaissance"></a>

[AADInternals](https://github.com/Gerenios/AADInternals) is a great tool to perform reconnaissance on any Azure AD tenant:

There are several publicly available APIs which will expose information of any Azure AD tenant:

<table data-full-width="true"><thead><tr><th>API</th><th>Information</th><th>AADInternals function</th></tr></thead><tbody><tr><td>login.microsoftonline.com/&#x3C;domain>/.well-known/openid-configuration</td><td>Login information, including tenant ID</td><td>Get-AADIntTenantID -Domain &#x3C;domain></td></tr><tr><td>autodiscover-s.outlook.com/autodiscover/autodiscover.svc</td><td>All domains of the tenant</td><td>Get-AADIntTenantDomains -Domain &#x3C;domain></td></tr><tr><td>login.microsoftonline.com/GetUserRealm.srf?login=&#x3C;UserName></td><td>Login information of the tenant, including tenant Name and domain authentication type</td><td>Get-AADIntLoginInformation -UserName &#x3C;UserName></td></tr><tr><td>login.microsoftonline.com/common/GetCredentialType</td><td>Login information, including Desktop SSO information</td><td>Get-AADIntLoginInformation -UserName &#x3C;UserName></td></tr></tbody></table>
