# Escalating Privilege

## Checking Groups - net user&#x20;

Another way we can check groups a user belongs to is using `net user`

```powershell
PS C:\Users\tony> net user tony
User name                    tony
Full Name                    Nothing Stops
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/16/2023 1:57:34 PM
Password expires             Never
Password changeable          6/16/2023 1:57:34 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
```

## Runas Command

If we've gained access to a plaintext password, it's possible to use the [`runas` ](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\))command to execute commands as that user.

```powershell
PS C:\Users\steve> runas /user:backupadmin cmd
Enter the password for backupadmin:
Attempting to start cmd as user "CLIENTWK220\backupadmin" ...
PS C:\Users\steve> 
```

