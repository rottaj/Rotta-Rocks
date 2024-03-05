# Hardcoing WinAPI Functions

## Introduction

Like NTAPI, there may be reasons why we want to hard-code our own WinAPI functions. One example is when creating PIC code, the WinAPI uses offsets to calculate the address of functions. This will cause your code to crash.&#x20;



## Declaring WinAPI Function

Here are some common examples.

{% code fullWidth="true" %}
```c
typedef HMODULE (WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);

typedef LPVOID (WINAPI* fnVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef BOOL (WINAPI* fnVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef BOOLEAN (WINAPI* fnRtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);

typedef NTSTATUS (NTAPI* fnNtFlushInstructionCache)(HANDLE hProcess, PVOID BaseAddress, ULONG NumberOfBytesToFlush);

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);
```
{% endcode %}



## Loading WinAPI Functions

We can load the WinAPI function with GetModuleHandle & GetProcAddress.

{% code fullWidth="true" %}
```c
fnLoadLibraryA pLoadLibraryA  = (fnLoadLibraryA)GetProcAddressWd(GetModuleHandleWd(L"KERNEL32.dll"), "LoadLibraryA");
```
{% endcode %}
