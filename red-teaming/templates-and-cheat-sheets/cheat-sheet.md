# Cheat sheet



{% embed url="https://swisskyrepo.github.io/InternalAllTheThings/command-control/cobalt-strike/" %}



### Recon & Enumeration (Windows)

#### List named pipes (SMB)

```powershell
PS C:\> ls \\.\pipe\
```

#### tcp connections

```powershell
PS> netstat -anop tcp
```

```powershell
PS> netstat -anop tcp | findstr 1337
```

