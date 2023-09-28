---
description: >-
  Like we can for processes, we can enumerate threads with
  CreateToolhelp32Snapshot.
---

# CreateToolhelp32Snapshot



```c
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <tlhelp32.h>

int wmain(int argc, wchar_t* argv[]) {

    HANDLE hSnapshot = NULL; 
    HANDLE hThread = NULL;
    THREADENTRY32 threadEntry = { 0 };
    threadEntry.dwSize = sizeof(THREADENTRY32);

    DWORD PID = 0;

    if (argc < 2) {
        wprintf(L"Insufficient arguments passed to main function\n");
        return -1;
    }

    PID = _wtoi(argv[1]);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
    if (hSnapshot == NULL) {
        wprintf(L"Failed to Create Snapshot %d\n", GetLastError());
        return -1;
    }

    if (!Thread32First(hSnapshot, &threadEntry)) {
        wprintf(L"Failed to Get First Thread %d\n", GetLastError());
        return -1;
    }

    DWORD threadCount = 0;
    do {
        if (threadEntry.th32OwnerProcessID == PID) {
            dwThreadId  = Thr.th32ThreadID;
	    hThread     = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID)
            wprintf(L"Thread Id: %d\n", threadEntry.th32ThreadID);
            threadCount +=1;
        }

    } while (Thread32Next(hSnapshot, &threadEntry));

    wprintf(L"Total Threads: %d\n", threadCount);
    return 0;
}
```

