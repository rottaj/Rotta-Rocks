---
description: >-
  Memory allocation functions in Windows can serve various purposes, and the
  choice of which on to use depends on your specific requirements and
  programming context.
---

# Private Memory Allocation

***

_<mark style="color:red;">**Note:**</mark>_ The process of allocating private memory using functions like: VirtualAlloc/VirtualAllocEx & VirtualProject/VirtualProtectEx are heavily monitored WinAPI functions.

### Malloc and new (C and C++):

These are standard memory allocation function in C and C++. Use them for general-purpose allocation when working with non-Windows specific code.

```c
int* myInt = (int*)malloc(sizeof(int));
if (myInt != nullptr) {
    *myInt = 42;
}
```

### HeapAlloc:

Use HeapAlloc when you want to allocate memory in a private heap that is associated with a  specific process.

```c
HANDLE hHeap = HeapCreate(0, 0, 0);
LPVOID pData = HeapAlloc(hHeap, 0, 1024);
// Use pData
HeapFree(hHeap, 0, pData); // Free the memory
HeapDestroy(hHeap);
```

### LocalAlloc:

Use LocalAlloc for allocating memory that is specific to the current processes and is not intended for sharing across multiple processes.

```c
LPVOID pData = LocalAlloc(LPTR, 1024);
// use PData
LocalFree(pData) // Free the memory
```

### VitualAlloc:

Use VirtualAlloc when you need to allocate memory and also specific characteristics. Such as reserving space, commiting memory pages, or definining privileges

```c
LPVOID pAddr = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// Use the Memory
VirtualFree(pAddr, 0, MEM_RELEASE);
```

### NtAllocateVirtualMemory:

NtAllocateVirtualMemory is the NTAPI equivalant to VirtualAlloc. It offers a lower level of abstraction and more granular control over memory allocation.

```c
#include <Windows.h>
#include <ntdll.h>

int main() {
    HANDLE hProcess = GetCurrentProcess();
    PVOID pBaseAddress = NULL;
    SIZE_T dwSize = 4096;
    ULONG flAllocationType = MEM_COMMIT | MEM_RESERVE;
    ULONG flProtect = PAGE_READWRITE;

    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &pBaseAddress, 0, &dwSize, flAllocationType, flProtect);
    if (NT_SUCCESS(status)) {
        // Memory allocation succeeded
        // Use pBaseAddress for your data storage

        // Free the memory when done
        NtFreeVirtualMemory(hProcess, &pBaseAddress, &dwSize, MEM_RELEASE);
    }

    return 0;
}
```

### CoTaskMemAlloc:

Use this function when you need to allocate memory for COM (Component Object Model) objects or data that will be shared across COM interfaces.

```cpp
HRESULT hr = CoInitialize(NULL);
if (SUCCEEDED(hr)) {
    LPVOID pData = CoTaskMemAlloc(sizeof(DATA));
    // Use pData
    CoTaskMemFree(pData); // Don't forget to free the memory
    CoUninitialize();
}
```

### GlobalAlloc:

Use this function to allocate memory that can be accessed accross multiple processes. _<mark style="color:red;">**NOTE:**</mark>_ This approach is outdated, and modern Windows programming tends to avoid it.

```c
HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, 1024);
LPVOID pData = GlobalLock(hMem);
// Use pData
GlobalUnlock(hMem);
GlobalFree(hMem); // Free the memory when done
```

