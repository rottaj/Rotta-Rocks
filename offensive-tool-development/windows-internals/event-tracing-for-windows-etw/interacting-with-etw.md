# Interacting with ETW



## Introduction

ETW components are built-in to the Windows kernel. They are exposed to user mode applications through a set of WinAPI functions:

* [EventWrite](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwrite) and [EventWriteEx](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwriteex) - Write an event to the ETW event stream. These WinAPIs are also named `EtwEventWrite` and `EtwEventWriteEx`, respectively.
* [StartTraceA](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracea) and [StopTraceA](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-stoptracea) - Start and stop an ETW tracing session.
* [QueryAllTraces](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesa) - Retrieves the properties for all running ETW tracing sessions.



## Kernel-level ETW

`ntoskrnl.exe` is responsible for process handling, memory management, and hardware abstraction. It is the "_Windows Operating System Kernel Executable_"'

The kernel implementation is done with the `EtwTi` function inside `ntoskrnl.exe`

The `Ti` in `EtwTi` represents "Threat Intelligence".

The name of the `EtwTi` function will generally indicate what's being logged. A few examples are provided below to further clarify this point.

* `EtwTiLogSetContextThread` - Called from`PspSetContextThreadInternal` and `PspWow64SetContextThread` kernel functions. **This `EtwTi` function is triggered when updating a thread's context.**
* `EtwTiLogSuspendResumeProcess` - Called from multiple kernel functions, from which the `PsMultiResumeProcess` and `PsSuspendProcess` functions are the most interesting. **This `EtwTi` function is triggered when suspending or resuming a process.**
* `EtwTiLogAllocExecVm` - Called from `MiAllocateVirtualMemory` kernel function. **This `EtwTi` function is triggered when allocating executable memory.**
* `EtwTiLogProtectExecVm` - Called from `NtProtectVirtualMemory` syscall (in the kernel). **This `EtwTi` function is triggered when updating memory permissions to executable.**



### Bypassing ETW

Bypassing ETW is not an easy task and typically requires access to the kernel.&#x20;

{% embed url="https://undev.ninja/introduction-to-threat-intelligence-etw/" %}

{% embed url="https://jsecurity101.medium.com/uncovering-windows-events-b4b9db7eac54" %}
