---
description: >-
  Privileges on the Windows operating system refer to the permissions of a
  specific account to perform system-related local operations.
---

# Windows Privilege Escalation

## Here's a nice checklist&#x20;

{% embed url="https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation" %}

## Important Information

Below is important information on the Windows security model. This contains information about users, groups, security tokens, and access control.&#x20;

### Security Identifier (SID)

**Security Identifier (SID)**: Each user and group is assigned a unique SID. Each account or group, or each process that runs in the security context of the account, has a unique SID that's issued by an authority, such as a Windows domain controller.

_<mark style="color:red;">**NOTE:**</mark>_ Windows uses SID, not usernames, to identify principles for access control management. The SID is stored in a security database. When a new account or group is created, a SID is created to go with it.&#x20;

_<mark style="color:red;">**NOTE:**</mark>_ SIDs are a fundamental building block of the Windows security model.

### Security Identifier (SID) Architecture

Security Identifier is a data structure in binary format.

A SID looks like:

```
S-1-5-21-1004336348-1177238915-682003330-512
```

<figure><img src="../../.gitbook/assets/Screenshot 2023-10-02 183310.png" alt=""><figcaption></figcaption></figure>

The first values in the structure contain information about the SID structure.

The remaining values are arranged in a hierarchy (similar to a telephone number)

The individual values of a SID are described in the following table:

| Comment              | Description                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Revision             | Indicates the version of the SID structure that's used in a particular SID.                                                                                                                                                                                                                                                                                                                                                               |
| Identifier authority | Identifies the highest level of authority that can issue SIDs for a particular type of security principal. For example, the identifier authority value in the SID for the Everyone group is 1 (World Authority). The identifier authority value in the SID for a specific Windows Server account or group is 5 (NT Authority).                                                                                                            |
| Subauthorities       | Holds the most important information in a SID, which is contained in a series of one or more subauthority values. All values up to, but not including, the last value in the series collectively identify a domain in an enterprise. This part of the series is called the domain identifier. The last value in the series, which is called the relative identifier (RID), identifies a particular account or group relative to a domain. |

###

### User Account Control (UAC):

**User Account Control (UAC)**: UAC helps protect the system by requiring administrative approval or credentials for certain tasks, even when logged in as an administrator.



### Access Tokens:

**Access Tokens**: Access tokens are data structures associated with a user or process.

Each time a user logs in, Windows creates an access token for that user. The access token contains the users SID, user rights, and the SIDs for any groups the user belongs to. This token is used for whatever action the user performs on that computer. Here's a full list of it's contents:

* The [security identifier](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers) (SID) for the user's account
* SIDs for the groups of which the user is a member
* A [_logon SID_](https://learn.microsoft.com/en-us/windows/desktop/SecGloss/l-gly) that identifies the current [_logon session_](https://learn.microsoft.com/en-us/windows/desktop/SecGloss/l-gly)
* A list of the [privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges) held by either the user or the user's groups
* An owner SID
* The SID for the primary group
* The default [DACL](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) that the system uses when the user creates a securable object without specifying a [_security descriptor_](https://learn.microsoft.com/en-us/windows/desktop/SecGloss/s-gly)
* The source of the access token
* Whether the token is a [_primary_](https://learn.microsoft.com/en-us/windows/desktop/SecGloss/p-gly) or [impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) token
* An optional list of [restricting SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
* Current impersonation levels
* Other statistics

#### Access Token Impersonation:



### Access Control Lists (ACLs)

**Access Control Lists (ACLs)**: ACLs are used to specify the permissions associated with an object. They list the users or groups and their corresponding access rights.
