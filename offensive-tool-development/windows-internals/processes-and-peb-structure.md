---
description: >-
  Processes & the Process Environment Block (PEB) is  crucial to understand
  thoroughly. There's a lot to it, I'll try to cover most of it here.
---

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

Much of the PEB is undocumented. Use [http://undocumented.ntinternals.net/](http://undocumented.ntinternals.net/) for more info.

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

### PEB\_LDR\_DATA

The PEB\_LDR\_DATA structure contains informations about the loaded DLL's

```c
typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
      InLoadOrderModuleList;
      InMemoryOrderModuleList;
      InInitializationOrderModuleList;
     PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

* **InMemoryOrderModuleList**: Doubly linked list of LIST\_ENTRYs containing pointers to a loaded DLL.&#x20;
* **Length**: Length of the list.

### LIST\_ENTRY

LIST\_ENTRY contains pointers to [LDR\_DATA\_TABLE\_ENTRY](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr\_data\_table\_entry.htm) (the loaded DLL).

```c
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

* **Flink**: points to the next entry in the list.
* **Blink**: points to the previous entry in the list
* <mark style="color:yellow;">**IMPORTANT**</mark>: Flink and Blink don't point to the start of the struct. They point to the InMemoryOrderModuleList member of the struct. <mark style="color:yellow;">To get the start of</mark>`LDR_DATA_TABLE_ENTRY` <mark style="color:yellow;">from them, subtract InMemoryOrderModuleList offset</mark> `(0x10)`<mark style="color:yellow;">. Or</mark> `CONTAINING_RECORD` <mark style="color:yellow;">macro.</mark>
* <mark style="color:green;">Example</mark>: (->Flink - 0x10) Full example below.

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



## Additional



### Iterate through LDR\_DATA\_TABLE\_ENTY Linked List

LDR\_DATA\_TABLE\_ENTRY is an important data structure in the PEB. There's some important information here so strap in.

**Iterate through linked list:**

```c
// Get PPEB
PPEB pPeb = (PPEB)__readgsqword(0x60);
PPEB_LDR_DATA          pLdr   = (PPEB_LDR_DATA)(pPeb->Ldr);

// Point to the first entry in linked list.
PLDR_DATA_TABLE_ENTRY   pDte   = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

// Not null means there are more entrys in the list.
while (pDte) {
    if (pDte->FullDllName.Buffer == 0) {
        break;
    }
    wprintf(L"[+] %ls ", pDte->FullDllName.Buffer);
    wprintf(L"%p\n", pDte);
    
    // Dereference and advance
    pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte); 
}

```

* The `pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);` is a common method for advancing in linked lists in C.
* In this linked list, the pointer to the next node is obtained by derefencing the current node. This is because the nodes embedded within a larger structure (`PLDR_DATA_TABLE_ENTRY`), and the linked list pointers are part of that structure.

To understand more how this works, let's examine the following code:.&#x20;

```c
pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
```

\
The above command derefernces the value stored at the address pointed to by `pDte` and then casting the result to a pointer to the `PLDR_DATA_TABLE_ENTRY` structure. This is simply how linked lists work. It looks like this:

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### LDR\_DATA\_TABLE\_ENTRY

This is a node of the doubly linked list that contains loaded DLL information. Look above to enumerate.

This is the documented version of LDR\_DATA\_TABLE\_ENTRY.&#x20;

```c
typedef struct _LDR_DATA_TABLE_ENTRY
{
      InLoadOrderLinks;
      InMemoryOrderLinks;
      InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
      FullDllName;
      BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
           HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     _ACTIVATION_CONTEXT * EntryPointActivationContext;
     PVOID PatchInformation;
      ForwarderLinks;
      ServiceTagLinks;
      StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

* <mark style="color:yellow;">**InInitializationOrderLinks.Flink**</mark>: `This is the base address of the DLL.` It is `Reserved2[0]` in WinAPI. The name doesn't suggest it, but Microsoft likes to confuse people.

