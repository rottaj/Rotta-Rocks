# Processes & PEB Structure

## Introduction

In short, a process is an instance of an executing program. It consists of various resources such as threads, handles, memory, and security contexts.

A process in Windows includes:

* **A Unique Process ID (PID)**
* **Virtual Address Space (VAS)**: Every process is allocated it's own Virtual Address Space. This VAS is compartmentalized into PE sections (code, data, stack).
* **Executable Code (PE Image)**: The image of the file stored on disk.
* **Handle Table**: Holds the handles that are opened.&#x20;
* **Access Tokens (Security Context)**: Access tokens encapsulate information about the processes security privileges. Includes the user account and it's access rights.
* **Threads**: Processes run atlest 1 or more threads. Threads enable concurrent execution.



## Process Initialization and csrss.exe

Normally, a new process is created with `CreateProcess` (or one of it's variants). Here is the general flow:

* NtCreateProcess is called.
  * The target exe file is opened and the .text section is called.
  * The initial thread and stack are created along with it's security context.
* Windows subsystem initialization is performed
  * A message is sent to the Client/Server Runtime Subsystem (csrss.exe) to notify the creation of a new process.
  * csrss performs it's own initialization (such as allocating structures for new process)
* The initial thread is resumed
* Process initialization is performed in the security context of the new process.

The first thread that a process runs is `LdrInitializeThunk`. This is the initialization function before execution is transferred to the user-supplied thread entry point.







## PEB Structure

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

* **Ldr**: A pointer to a [PEB\_LDR\_DATA](https://learn.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-peb\_ldr\_data) structure that contains information about the loaded DLL's
* **BeingDebugged**: Is the process in debugging mode.

## Access Local PEB (x64)

```c
#include <winternl.h>
// Get PEB structure
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

// HELPER FUNCTIONS
// Get of current process (call pLdr->DllBase to get base address)
PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)(pPeb->Ldr->InMemoryOrderModuleList.Flink - 0x10)
```

##

### Get Local Base Address (NTDLL)

Flink actually returns the address of the end of the structure. Which is why we subtract 0x10 (size of entry) to get to the beginning.

```c
PVOID FetchLocalNtdllAddress() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
    return pLdr->DllBase;
}
```

##

## Access Remote PEB (x64)

To access a remote processes PEB structure & get the remote address of entry point we can use the following:



## Suspended Processes

Suspended processes can be a nice trick when it comes to EDR since they can't load their hooks into a process that is suspended

### Create Suspended Process

```c
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};

si->cb = sizeof(si);
// Just a POC: Update this with the dynamic filepath fetch for "svchost.exe"
if (CreateProcessW(L"C:\\Windows\\System32\\svchost.exe", 
 NULL,
 NULL, 
 NULL, 
 FALSE, 
 DEBUG_PROCESS, // Can use CREATE_SUSPENDED also both work fine. 
 NULL, 
 NULL, 
 si, 
 pi
) == 0) {
    wprintf(L"CreateProcessW Failed %d", GetLastError()) ;
    return FALSE;
};
// Modify suspended process

ResumeThread (pi.hThread);
```

