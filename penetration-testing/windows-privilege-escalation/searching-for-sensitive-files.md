---
description: >-
  Here are some commands to look for sensitive files. Be careful, stay quiet my
  friend.
---

# Searching For Sensitive Files

##

## dir

```powershell
dir /A C:\Users\
```

```bash
dir /s/b *.log
```

```powershell
dir /s/b *.txt
```

```bash
dir /s/b *.kdbx
```



## env & path

When a program is executed, the system first searches the current working directory and then searches the path. Check for any PATH variables that may have write privileges.

```powershell
$env
$env:path
```

## Get-ChildItem

Here are some useful searches using `Get-ChildItem`

_<mark style="color:red;">**NOTE:**</mark>_ Searching like this can **LOUD**! Be careful!

### Search for KeePass Files

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

### Search for Files within a Directory

```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

### Search for Files in Home Directory&#x20;

```powershell
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

### Useful Commands

```powershell
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\`$Recycle.Bin\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue
```

## Type (Grep in Powershell)

### Return Console History

<pre class="language-powershell"><code class="lang-powershell">PS C:\Users\dave> type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
<strong>
</strong><strong>whoami
</strong>clientwk220\dave
PS C:\Users> type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
whoami
ls
$PSVersionTable
Register-SecretVault -Name pwmanager -ModuleName SecretManagement.keepass -VaultParameters $VaultParams
Set-Secret -Name "Server02 Admin PW" -Secret "paperEarMonitor33@" -Vault pwmanager
cd C:\
ls
cd C:\xampp
ls
type passwords.txt
Clear-History
Start-Transcript -Path "C:\Users\Public\Transcripts\transcript01.txt"
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
exit
Stop-Transcript

</code></pre>

##

## Runas Other User

```powershell
PS C:\Users> net user

User accounts for \\CLIENTWK221

-------------------------------------------------------------------------------
Administrator            damian                   DefaultAccount
Guest                    mac                      milena
moss                     offsec                   richmond
roy                      WDAGUtilityAccount
The command completed successfully.
```

If we have found credentials, we should try them on all users.

```powershell
PS C:\Users\steve> runas /user:roy cmd
```

