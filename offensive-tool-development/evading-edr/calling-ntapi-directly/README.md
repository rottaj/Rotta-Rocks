# Calling NTAPI Directly



## Introduction

Calling NTAPI functions directly can increase the chances of bypassing EDR over the use of userland functions. Using NTAPI functions instead of a technique like direct syscalls can actually be a preferred scenario as direct syscalls (Executing from within NTDLL.dll) is something that EDR's are heavily searching for now with call stack tracing.

Lots of legitimate applications use NTAPI functions so it shouldn't be an IOC if a program is making use of them.&#x20;

## Using NTAPI

### Microsoft Documentation:

Below is the spec for NTAPI function NtOpenSection

<figure><img src="../../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

### Using in code

Here is how we can use it in our code.

**Define a functions:**

```c
typedef NTSTATUS (NTAPI* fnNtOpenSection)(
	PHANDLE               SectionHandle,
	ACCESS_MASK           DesiredAccess,
	POBJECT_ATTRIBUTES    ObjectAttributes
);
```

#### Get Process Address:

```c
// getting NtOpenSection address
fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtOpenSection");
// getting the handle of ntdll.dll from KnownDlls
STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAtr);
     if (STATUS != 0x00) {
          printf("[!] NtOpenSection Failed With Error : 0x%0.8X \n", STATUS);
     }
```

**Confirming**:

<figure><img src="../../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

**NOTE:** When using NTAPI it's suggested to create your own versions for GetProcAddress & GetModuleHandle preferably with string hashing.

It's that easy!



## Common Structures & Variables

When using NTAPI functions you typically run into undocumented structures, for this reason we will have to manually implement them ourselves. Here are some common ones:

### OBJECT\_ATTRIBUTES

The [OBJECT\_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-\_object\_attributes) struct specifies the object name and other attributes. It's initialized with [InitializeObjectAttributes](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-initializeobjectattributes) macro. It takes the following parameters:

* `p` - A pointer to an empty `OBJECT_ATTRIBUTES` structure that will be initialized.
* `n` - A pointer to a `UNICODE_STRING` structure that contains the name of the object for which a handle is to be opened.
* `a` - Should be set to `OBJ_CASE_INSENSITIVE` to perform a case-insensitive comparison for the name of the object for which a handle is to be opened.

```c
#include <ntdef.h>

OBJECT_ATTRIBUTES ObjAtr = { 0 };
UNICODE_STRING    UniStr = { 0 };
// Typically have to construct UNICODE_STRING 
// Below example will contain the '\KnownDlls\ntdll.dll' string
UniStr.Buffer = (PWSTR)NTDLL;
UniStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);
```



### SYSTEM\_PROCESS\_INFORMATION

SYSTEM\_PROCESS\_INFORMATION is vaguely documented by Microsoft. Here is the full structure found here:

{% embed url="https://ntdoc.m417z.com/system_process_information" %}

{% embed url="https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h#L1736" %}

```c
typedef struct _SYSTEM_PROCESS_INFORMATION
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
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
```
