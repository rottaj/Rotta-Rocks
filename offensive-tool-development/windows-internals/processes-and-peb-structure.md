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

## Access PEB (x64)

```c
#include <winternl.h>
PPEB pPeb = (PPEB)__readgsqword(0x60);
```
