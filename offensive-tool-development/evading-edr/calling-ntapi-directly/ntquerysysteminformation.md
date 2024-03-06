# NtQuerySystemInformation



## Introduction&#x20;

NtQuerySystemInformation uses `SYSTEM_PROCESS_INFORMATION`, this struct is mostly undocumented and we will have to implement our own struct when using it. It can be found [here](https://ntdoc.m417z.com/system\_process\_information) or below.



## Process Enumeration

##

## Thread Enumeration





### SYSTEM\_INFORMATION\_CLASS

SYSTEM\_INFORMATION\_CLASS is an enum. For Thread & Process enumeration we will use `SystemProcessInformation`

<figure><img src="../../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

**The return value is a SYSTEM\_PROCESS\_INFORMATION struct. More info found** [**here**](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)

<figure><img src="../../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

### SYSTEM\_PROCESS\_INFORMATION

When `SystemProcessInformation` enum is used, the output buffer is a SYSTEM\_PROCESS\_INFORMATION structure.

<figure><img src="../../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

**Within** [**SYSTEM\_PROCESS\_INFORMATION**](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm) **is the following:**

* **NumberOfThreads**: Size of Threads array.
* **Threads**: Array of `SYSTEM_THREAD_INFORMATION`. Each element represents a running thread.
* The start of the next item in the array is the address of the previous item plus the value in the `NextEntryOffset` member. For the last item in the array, NextEntryOffset is 0.

**Initialzing & Allocating SYSTEM\_PROCESS\_INFORMATION.**

To use SYSTEM\_PROCESS\_INFORMATION we need to allocate a buffer. We can get the size by running `pNtQuerySystemInformation` with NULL values except for `dwSizeWritten`.

```c
PSYSTEM_PROCESS_INFORMATION pSystemProcessInfo;

// Allocate Buffer for SYSTEM_PROCESS_INFORMATION
pSystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), 0, dwSize1);
if (pSystemProcessInfo == NULL) {
    wprintf(L"[!] HeapAlloc Failed %d\n", GetLastError());
}

```

### SYSTEM\_THREAD\_INFORMATION

SYSTEM\_THREAD\_INFORMATION is located at the last undocumented parameter of SYSTEM\_PROCESS\_INFORMATION. To acccess it use `SystemProcInfo->Threads`

```c
typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
```

The member of particular interest is `ClientId`

### CLIENT\_ID

```c
typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
```

* `UniqueProcess` and `UniqueThread` are defined as handles, but in reality, their values are process and thread IDs respectively.
* `UniqueThread` enables one to open a thread handle through the `OpenThread` WinAPI function.



## Example

Below is the example of using NtQuerySystemInformation to enumerate threads.

```c
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <winternl.h>


typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

typedef struct _SYSTEM_PROC_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads; // Size of the Threads member
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1]; // Threads member
} SYSTEM_PROC_INFO, *PSYSTEM_PROC_INFO;

#define STATUS_SUCCESS 0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004



int wmain() {


    NTSTATUS STATUS;
    PSYSTEM_PROC_INFO SystemProcInfo;
    PVOID							pValueToFree                = NULL;

    ULONG uReturnLen1 = 0;
    ULONG uReturnLen2 = 0;

    // Fetching NtQuerySystemInformation's address from ntdll.dll
    fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        return -1;
    }

    // First NtQuerySystemInformation call - retrieve the size of the return buffer (uReturnLen1)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
        printf("[!] NtQuerySystemInformation [1] Failed With Error : 0x%0.8X \n", STATUS);
        return -1;
    }

    // Allocating buffer of size "uReturnLen1"
    SystemProcInfo = (PSYSTEM_PROC_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return -1;
    }

    // Setting a fixed variable to be used later to free, because "SystemProcInfo" will be modefied
    pValueToFree = SystemProcInfo;

    // Second NtQuerySystemInformation call - returning the SYSTEM_PROCESS_INFORMATION array (SystemProcInfo)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2)) != STATUS_SUCCESS) {
        printf("[!] NtQuerySystemInformation [2] Failed With Error : 0x%0.8X \n", STATUS);
        return -1;
    }


    while (TRUE) {

        wprintf(L"[+] %ls\n", SystemProcInfo->ImageName.Buffer);

        if (wcsncmp(L"query.exe", SystemProcInfo->ImageName.Buffer, SystemProcInfo->ImageName.Length / sizeof(WCHAR)) == 0) {
            for (int i=0; i<=SystemProcInfo->NumberOfThreads; i++) {
                wprintf(L"TID: %d\n", SystemProcInfo->Threads[i].ClientId.UniqueThread);
            }
        }

        // If we reached the end of the SYSTEM_PROCESS_INFORMATION structure
        if (!SystemProcInfo->NextEntryOffset)
            break;
        // Calculate the next SYSTEM_PROCESS_INFORMATION element in the array
        SystemProcInfo = (PSYSTEM_PROC_INFO)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }
    getchar();
    return 0;
}
```

<figure><img src="../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>
