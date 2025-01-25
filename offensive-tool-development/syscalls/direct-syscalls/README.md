# Direct Syscalls

<mark style="color:red;">**NOTE:**</mark> **As of May 2023, direct syscalls may not be sufficient enough to bypass EDR as more vendors are adding callbacks to their solutions**. These callbacks determine where the return statements are happening in memory, if the memory address is outside of ntdll.dll this is a clear IOC.&#x20;

We should replace direct syscalls with indirect syscalls.&#x20;

## Introduction

Direct syscalls work by reading the syscall number from the functions assembly code. It's works by getting the assembly call to the SSN (System Security Number) by it's syscall stub offset.

_**Example - Direct Syscalls:**_

```c
extern NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,    // Handle to the process in which to allocate the memory
    PVOID* BaseAddress,      // Pointer to the base address
    ULONG_PTR ZeroBits,      // Number of high-order address bits that must be zero in the base address of the section view
    PSIZE_T RegionSize,      // Pointer to the size of the region
    ULONG AllocationType,    // Type of allocation
    ULONG Protect            // Memory protection for the region of pages
);

int main() {
    // Get a handle to the ntdll.dll library
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

    // Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
    UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    // Read the syscall number from the NtAllocateVirtualMemory function in ntdll.dll
    // This is typically located at the 4th byte of the function
    wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemory + 4))[0];
    
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&allocBuffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
}
```

The important thing to notice is that we are using GetProcAddress to obtain a pointer to the memory address of the specific function we are looking for, we then caculate the offset based on the assembly stub.&#x20;

```c
HANDLE hNtdll = GetModuleHandleA("ntdll.dll");

// Declare and initialize a pointer to the NtAllocateVirtualMemory function and get the address of the NtAllocateVirtualMemory function in the ntdll.dll module
UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(hNtdll, "NtAllocateVirtualMemory")
```

<mark style="color:red;">**NOTE:**</mark> The important difference between this and using the NtAPI, where we are just using a function through it's declared prototype. When using the native API we are not diving into any of the assembly details or syscall numbers.  <mark style="color:red;">**IMPORTANT**</mark>: **Many legitimate applications use NtAPI functions directly, which is not an IOC imo.** Direct syscalls, calling NtAPI functions from outside ntdll memory is always a clear IOC.&#x20;



All syscalls return a NTSTATUS value that indicates the status (or error) code of the operation.&#x20;

The majority of syscalls are not documented by Microsoft, therefore the syscall modules will reference the documentation shown below.

* [Undocumented NTinternals](https://web.archive.org/web/20230401045934/http://undocumented.ntinternals.net/)
* [ReactOS's NTDLL Reference](https://doxygen.reactos.org/dir_a7ad942ac829d916497d820c4a26c555.html)
* Disassembling ntdll.dll in IDA can also be beneficial.

The majority of the syscalls are exported from ntdll.dll. We can view them by opening ntdll.dll in IDA.

_<mark style="color:red;">**NOTE:**</mark>_ Syscalls provide low-level access to the operating system, by calling these functions directly acts as a bypass to EDR hooks set in place at the higher level API functions. (VirtualAlloc, CreateProcess, CreateThread, etc.)

## Syscall Service Number (SSN)

Every syscall has a Syscall Service Number (SSN). These numbers are what the kernel uses to distinguish syscalls from each other and are executed in the syscall stub (explained below). IMPORTANT: syscall service numbers are not static throughout all version of windows as they have changed over time. See the table below:

{% embed url="https://j00ru.vexillium.org/syscalls/nt/64/" %}

{% embed url="https://github.com/hfiref0x/SyscallTables" %}

{% embed url="https://github.com/ikermit/11Syscalls" %}

## Syscall Stub

The syscall stub or syscall structure will look like the snippet shown below.

```c
mov r10, rcx
mov eax, SSN
syscall
```

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-24 190908.png" alt=""><figcaption><p>Syscall Stub for NtCreateProcess</p></figcaption></figure>

### Syscall Stub Explained

`mov r10, rcx` This moves the value of `rcx` register into `r10` register.  _<mark style="color:red;">**NOTE:**</mark>_ The `rcx` register typically holds the first argument to a function or syscall.

`mov eax, SSN` This moves the constant value SSN into the eax register. The eax register is used to specify syscall numbers, which determines which syscall the program should invoke.

`syscall` The syscall instruction when executed triggers a switch from user mode to kernel mode, transfering control to the operating systems kernel. invokes the current syscall in the eax register.

_<mark style="color:red;">**IMPORTANT:**</mark>_ &#x20;

The kernel uses the values in registers like `rax`, `rdi`, `rsi`, `rdx`, `r10`, and others to determine which syscall is being requested and to access the syscall's arguments.

`rax`: Contains the syscall number (which was loaded with `mov eax, SSN` in this case).

`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`: These registers are used to pass arguments to the syscall.

* `rcx` holds the address of the application to be executed.
* `rdx` holds the command-line arguments.
* `r8` holds the security attributes.
* `r9` holds the security attributes for the thread.

**Test & Jne Instructions**

The `test` and `jne` instructions are for [WoW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details) purposes which are meant to allow 32-bit processes to run on a 64-bit machine. These instructions do not affect the execution flow when the process is a 64-bit process.



_**Verifying SSN Number:**_

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-24 190650.png" alt=""><figcaption><p>We can check the SSN number with one of thel links above.</p></figcaption></figure>

## Syscalls In Memory

Each syscall number in memory is equal to the previous SSN + 1. For example: the first Syscall (mov eax, 0) is ZwAccessCheck and the second (mov eax,1) is NtWorkFactoryWorkReady so on so forth.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-09-24 191544.png" alt=""><figcaption></figcaption></figure>

_<mark style="color:red;">**NOTE:**</mark>_ Understanding that the syscalls have a relation to one another will come in handy for evasion purposes in upcoming syscall modules.

## NTAPIs that arn't syscalls

_<mark style="color:red;">**NOTE:**</mark>_ while some NtAPIs return `NTSTATUS`, they are not necessarily syscalls.&#x20;

If they don't have a SSN number or lack the `mov r10, rcx` then they do not comply as a syscall.

Example of NtAPIS that are not syscalls:

* `LdrLoadDll` - This is used by the `LoadLibrary` WinAPI to load an image to the calling process.
* `SystemFunction032` and `SystemFunction033` - These NtAPIs were introduced earlier and perform RC4 encryption/decryption operations.
* `RtlCreateProcessParametersEx` - This is used by the `CreateProcess` WinAPI to create arguments of a process.
