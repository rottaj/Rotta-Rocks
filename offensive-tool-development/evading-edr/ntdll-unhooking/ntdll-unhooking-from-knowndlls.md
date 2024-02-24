# NTDLL Unhooking - From KnownDlls



## Introduction

The Windows KnownDlls Directory is a directory of commonly used system DLLs that the Windows loader leverages to optimize the application startup process.

This approach saves memory by reducing the need to map each required DLL from disk.



## Inspecting KnownDLLs

Using **SysInternals** **WinObj** we can inspect the KnownDLLs directory.

[![Download](https://learn.microsoft.com/en-us/sysinternals/downloads/media/shared/download\_sm.png)](https://download.sysinternals.com/files/WinObj.zip) [**Download WinObj**](https://download.sysinternals.com/files/WinObj.zip) **(1.8 MB)**\
**Run now** from [Sysinternals Live](https://live.sysinternals.com/Winobj.exe).

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>



## Retrieving Ntdll.dll from KnownDlls

