# Impacket Cheat Sheet

## Executing Remote Commands

### psexec

[psexec.py](https://github.com/kavika13/RemCom) provides functionality similar to PSEXEC, utilizing RemComSvc.

```shell-session
python psexec.py domain/user:password@target_machine
```

### smbexec

smbexec.py is another approach to PSEXEC, yet it does not require RemComSvc. It creates a local smb server to collect commands.

```shell-session
python smbexec.py domain/user:password@target_machine
```

### wmiexec

wmiexec.py offers a semi-interactive shell used through Windows Management Instrumentation (WMI).

```
python wmiexec.py domain/user:password@target_machine
```

### dcomexec

dcomexec.py offers a semi-interactive shell akin to wmiexec.py but employs different DCOM endpoints.

```
python dcomexec.py domain/user:password@target_machine
```



## Kerberos

### GetTGT.py: Requesting a Ticket Granting Ticket

GetTGT.py enables you to request a Ticket Granting Ticket (TGT) and save it as ccache, given a password, hash, or aesKey.

```
python GetTGT.py domain/user:password
```

### GetST.py: Requesting a Service Ticket

GetST.py is designed to request a Service Ticket (ST) and save it as ccache given a password, hash, aesKey, or TGT in ccache. -impersonate to request the ticket on behalf of another user.

```
python GetST.py domain/user:password -impersonate victim_user
```

### GetPac.py: Acquiring PAC Structure

GetPac.py uses a mix of \[MS-SFU]’s S4USelf + User to User Kerberos Authentication to acquire the PAC (Privilege Attribute Certificate) structure of a target user by having normal authenticated user credentials.

```
python GetPac.py domain/user:password target_user
```

### GetUserSPNs.py: Fetching Service Principal Names

GetUserSPNs.py finds and fetches Service Principal Names (SPNs) associated with normal user accounts

```
python GetUserSPNs.py domain/user:password
```



###

## Windows Swag

### SecretsDump.py: Dumping Secrets

SecretsDump.py is a potent script that allows for the dumping of password hashes, LSA secrets, cached credentials, and other sensitive information from a Windows system.

```
python SecretsDump.py domain/user:password@target
```

### Kerbrute.py: Brute Forcing Kerberos

Kerbrute.py is a very handy tool for brute-forcing user/password combinations against Kerberos. This can be quite helpful in enumerating valid users or discovering weak passwords within a given domain.&#x20;

```
python Kerbrute.py -userfile userlist.txt -password Passw0rd! domain.com
```

### karmaSMB.py: SMB Relay Attack

karmaSMB.py allows for the execution of an SMB relay attack. This is where authentication attempts from a client are intercepted and relayed to a third-party target, potentially allowing for unauthorized access.&#x20;

```
python karmaSMB.py -h target
```

### karmaTFTP.py: TFTP Relay Attack

karmaTFTP.py performs a similar function to karmaSMB.py, but operates over TFTP instead. The usage of this script is pretty similar:

```
python karmaTFTP.py -h target
```

## Windows Secrets

### secretsdump.py

For SAM and LSA Secrets, including cached credentials, the script attempts to read as much data as possible from the registry.

```
python secretsdump.py domain/user:password@target
```

### mimikatz.py

Mimikatz.py is a mini-shell that controls a remote mimikatz RPC server. Can also perform pass-the-hash, pass-the-ticket, or build Golden tickets.

```
python mimikatz.py domain/user:password@target
```

## SMB/MSRPC



## Database Tools







###

## Local Server Tools

### ntlmrelayx.py

Ntlmrelayx.py executes NTLM Relay Attacks by setting up an SMB, HTTP, WCF, and RAW Server and relaying credentials to multiple protocols (SMB, HTTP, MSSQL, LDAP, IMAP, POP3, etc.). The script can be used with predefined attacks that can be activated when a connection is relayed (for example, creating a user through LDAP), or it can be run in SOCKS mode. In SOCKS mode, for every connection relayed, it becomes available to be used multiple times later through a SOCKS proxy. Here’s an example of this command:

```
python ntlmrelayx.py -h target
```

### karmaSMB.py

KarmaSMB.py is an SMB Server that responds with specific file contents, regardless of the SMB share and pathname specified. It is a part of MiTM attacks, where authentication attempts from a client are intercepted and relayed to a third-party target, potentially allowing unauthorized access. Here’s an example of how to use this script:

```
python karmaSMB.py -h target
```

### smbserver.py

SMBserver.py is a Python implementation of an SMB server. It allows for the quick setup of shares and user accounts. This tool can be useful in various scenarios including file sharing, systems management, and [penetration testing](https://aardwolfsecurity.com/). Here’s an example of how to use this script:

```
python smbserver.py SHARE_NAME PATH_TO_SHARE
```

## Exploiting Known Vulnerabilities

#### goldenPac.py

GoldenPac.py is an exploit script for MS14-068. It saves the golden ticket and also launches a PSEXEC session at the target. This could be useful in situations where elevation of privilege is required, as the golden ticket provides access as a domain administrator. An example command for using this script is:

```
python goldenPac.py domain/user:password@target
```

#### sambaPipe.py

SambaPipe.py is a script designed to exploit CVE-2017-7494. It uploads and executes the shared library specified by the user through the -so parameter. This could be useful in situations where the target system is vulnerable and code execution is desired. Here’s an example of using this script:

```
python sambaPipe.py -so /path/to/shared/library.so domain/user:password@target
```

#### smbrelayx.py

Smbrelayx.py is an exploit script for CVE-2015-0005 that uses an SMB Relay Attack. If the target system is enforcing signing and a machine account was provided, the module will attempt to gather the SMB session key through NETLOGON. This can potentially provide unauthorized access. An example of how to use this script is:

```
python smbrelayx.py -h target
```
