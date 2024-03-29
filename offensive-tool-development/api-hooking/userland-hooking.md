---
description: >-
  Security solutions frequently hook syscalls to enable analysis and monitoring.
  Userland hooks are installed before the syscall, which is the last step for a
  syscall function in user mode.
---

# Userland Hooking

_<mark style="color:red;">**NOTE:**</mark>_ As stated previously  security solutions can access any memory region with executable permissions and scan it for known signatures. Furthermore, it's possible for a program to be blocked entirely if memory with RWX permissions is detected.

The power of API hooking to detect and monitor programs at runtime is massive. EDR's will typically hook a wide range of syscalls & monitor memory regions for RWX permissions.

***

## API Hooking

Here is a diagram of your typical EDR. Including a driver callback and Userland hooking.

<figure><img src="../../.gitbook/assets/Syscall-EDR-Hook.png" alt=""><figcaption><p>Slide from Christopher Vella</p></figcaption></figure>

## Bypassing Userland Hooks

There are several methods we can use to call syscalls stealthily. I'll cover them briefly on this page and in more detail later.

* Using Direct Syscalls
* Using Indirect Syscalls
* Unhooking

## Direct Syscalls

Directy calling syscalls is when we obtain a version of the syscall stub and call it direclty in assembly. Eliminating the need to call an API. To do this, we obtain the Syscall Service Number (SSN). This can be hardcoded or determined dynamically. More on this later.

This method is utilized in tools such as [SysWhispers](https://github.com/jthuraisamy/SysWhispers) and [HellsGate](https://github.com/am0nsec/HellsGate)

## Indirect Syscalls

Instead of calling the syscall directly, indirect syscalls jump to a syscall. For this reason, Indirect syscalls are more likely to slip through security solutions. This is because security solutions look for syscalls being made outside of `ntdll.dll` and consider them suspicious. Since we jump to the ntdll.dll memory space we can mitigate detection.

## Unhooking

Unhooking is the hooked NTAPI function is replaced with an unhooked version. More on this later.
