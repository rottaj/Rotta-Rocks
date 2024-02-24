# NTDLL Unhooking

## Introduction

This method avoids userland hooks by replacing the hooked NTDLL.DLL with an unaltered version that is not hooked. There are many ways we can achieve this, here are a few:

* **From Disk** - This is where the `ntdll.dll` binary is saved `C:\Windows\System32\ntdll.dll`.
* **From KnownDlls Directory** - A directory in the Windows OS that contains a group of DLLs and is used by the Windows loader for performance reasons.
* **From a Suspended Process** - Where `ntdll.dll` is read from another remote suspended process.
* **From a Webserver** - Where `ntdll.dll` is read from a web server, which in this case will be [Winbindex](https://winbindex.m417z.com/).

##

## Replacing .text section

The .text section of a PE contains the export functions, which is where the potential hooked functions are. <mark style="color:yellow;">**Replacing the .text section requires it's base address and size.**</mark>&#x20;

`IMAGE_OPTIONAL_HEADER` header has `BaseCode` and `SizeOfCode`. This is the address and size of the .text section.

In order to write data we need to change the memory permissions to allow write access to ntdll.dll. Default permissions are RX.

```c
    DWORD       SizeOfCode; // Size of .text section
    DWORD       BaseOfCode; // RVA to start of the .text section.
```

###

## .text section alignment

**IMPORTANT:**

<mark style="color:yellow;">**The offset of a DLL on disk and in memory are different**</mark>. **0x400** for on disk, **0x1000** for in memory:

The offset of the .text section for most DLL's <mark style="color:yellow;">**on disk**</mark> is 0x400 (1024).

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

When a DLL is mapped into <mark style="color:yellow;">**memory of a process**</mark>, the .text section is mainly set to an offset of 0x1000 (4096).

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>
