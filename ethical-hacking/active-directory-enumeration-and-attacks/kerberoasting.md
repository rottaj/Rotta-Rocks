---
description: >-
  Kerberoasting is a lateral movement/privilege escalation technique in Active
  Directory environments. This attack targets Service Principal Names (SPN)
  accounts.
---

# Kerberoasting

[Service Principal Names (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) are unique identifiers that Kerberos uses to map a service instance to a service account.

More information on Kerberos:

{% embed url="https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview" %}

_<mark style="color:red;">**NOTE:**</mark>_ All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

