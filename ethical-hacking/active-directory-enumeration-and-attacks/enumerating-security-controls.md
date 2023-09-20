---
description: >-
  After gaining a foothold, we want to use this access to get a feel for the
  defensive state of the network & its hosts.
---

# Enumerating Security Controls

_**It is important to understand the security controls in place in an organization as the products in use can affect the tools we use for our AD enumeration, as well as exploitation and post-exploitation.**** **<mark style="color:red;">**NOTE:**</mark>** ****This section does not cover bypassing EDR or any other defensive measures. it's strictly for enumerating them.  Refer to my "Malware Development" section to dive further into bypassing EDR/AV & other security measures.**_



***



### Windows Defender

**Checking the Status of Defender with Get-MpComputerStatus**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-20 123147.png" alt=""><figcaption></figcaption></figure>



### AppLocker

AppLocker is an application whitelist that only allows approved software and gives system administrators control over which applications and files users can run.&#x20;

It is common for organizations to block cmd.exe and Powershell.exe and write access to certain directories. But as you guessed, this can be bypassed.

_<mark style="color:red;">**NOTE:**</mark>_ Organizations also often focus on blocking the `PowerShell.exe` executable, but forget about the other [PowerShell executable locations](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.&#x20;

We can see that this is the case in the `AppLocker` rules shown below. All Domain Users are disallowed from running the 64-bit PowerShell executable located at:

`%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`

**Using Get-AppLockerPolicy cmdlet**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-20 123556.png" alt=""><figcaption></figcaption></figure>

### PowerShell Constrained Language Mode

\
PowerShell [Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) locks down many of the features needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, and more.&#x20;

**Enumerating Language Mode**

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-20 123929.png" alt=""><figcaption></figcaption></figure>

### LAPS

The Microsoft [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.  We can enumerate what domain users can read the LAPS password set for machines with LAPS installed and what machines do not have LAPS installed. The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) greatly facilitates this with several functions.

**Using Find-LAPSDelegatedGroups**

The _**Find-LAPSDelegatedGroups**_ will show groups specifically delegated to read LAPS passwords, which are often users in protected groups. This can help target AD users who can read LAPS passwords.

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-20 124049.png" alt=""><figcaption></figcaption></figure>

**Using Find-AdmPwdExtendedRights**

The Using _**Find-AdmPwdExtendedRights**_ will show the rights on each computer with LAPS enabled. Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups. This is worth checking for.

<figure><img src="../../.gitbook/assets/Screenshot 2023-09-20 124240.png" alt=""><figcaption></figcaption></figure>

**Using Get-LAPSComputers**

&#x20; The _**Get-LAPSComputers**_ function will show computers that have LAPS enabled, when passwords expire, and even the randomized passwords in cleartext if our current user has accessed.



<figure><img src="../../.gitbook/assets/Screenshot 2023-09-20 124438.png" alt=""><figcaption></figcaption></figure>
