# NTDLL Unhooking - From KnownDlls

## Introduction

The Windows KnownDlls Directory is a directory of commonly used system DLLs that the Windows loader leverages to optimize the application startup process.

This approach saves memory by reducing the need to map each required DLL from disk.

The KnowDLLs directory location is:

```c
\KnownDlls\
```

## Inspecting KnownDLLs

Using **SysInternals** **WinObj** we can inspect the KnownDLLs directory.

[![Download](https://learn.microsoft.com/en-us/sysinternals/downloads/media/shared/download\_sm.png)](https://download.sysinternals.com/files/WinObj.zip) [**Download WinObj**](https://download.sysinternals.com/files/WinObj.zip) **(1.8 MB)**\
**Run now** from [Sysinternals Live](https://live.sysinternals.com/Winobj.exe).

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Retrieving Ntdll.dll from KnownDlls

To retrieve DLL's mapped in the KnowDlls directory requires a handle. Two functions are required:

* `NtOpenSection` to obtain the section handle for ntdll.dll. (`OpenFileMapping` Always fails with `ERROR_BAD_PATHNAME`, this is it's NTAPI equivalant.). &#x20;
* `MapViewOfFile` to map ntdll.dll to memory.

View Calling NTAPI Directly for help

```c
// getting the handle of ntdll.dll from KnownDlls
STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAtr);
if (STATUS != 0x00) {
	printf("[!] NtOpenSection Failed With Error : 0x%0.8X \n", STATUS);
	goto _EndOfFunc;
}
```



## Code

The code only includes reading KnownDLL into a buffer, the function for copying memory over can be found above in previous pages.

```c
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <ntdef.h>

#define NTDLL   L"\\KnownDlls\\ntdll.dll"

typedef NTSTATUS (NTAPI* fnNtOpenSection) (
    PHANDLE             SectionHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes
    );

int wmain() {

    OBJECT_ATTRIBUTES objAtr        = { 0 };
    UNICODE_STRING    unicodeString = { 0 };
    PVOID pBuffer = 0;
    HANDLE hSection;


    unicodeString.Buffer = (PWSTR)NTDLL;
    unicodeString.Length = wcslen(NTDLL) * sizeof(WCHAR);
    unicodeString.MaximumLength = unicodeString.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&objAtr, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtOpenSection");

    NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ, &objAtr);
    if (status != 0x00) {
        printf("[!] NtOpenSection Failed With Error : 0x%0.8X \n", status);
        return -1;
    }

    pBuffer = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (MapViewOfFile == NULL) {
        wprintf(L"[!] MapViewOfFile Failed %d\n", GetLastError());
        return -1;
    }


    wprintf(L"Testing %p", pBuffer);

    // Include SWAP NTDLL's here. (Refer to previous page www.rotta.rocks)
    getchar();
    return 0;
}
```
