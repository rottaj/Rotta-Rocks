# Cheat sheet



{% embed url="https://swisskyrepo.github.io/InternalAllTheThings/command-control/cobalt-strike/" %}





## Windows Command Line tools

### Debugging & Helper commands.

#### View error message

```powershell
[-] could not upload file: 32 - ERROR_SHARING_VIOLATION
C:\>net helpmsg 32
The process cannot access the file because it is being used by another process.
```

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

