---
description: >-
  The choice between direct or indirect syscalls depends on the security of our
  target. Indirect syscalls are an evolution to direct syscalls.Kris Kr
---

# Indirect Syscalls

_<mark style="color:red;">**NOTE:**</mark>_**&#x20;As EDR vendors improve, it's becoming harder and harder to use direct syscalls for red-teaming. Welcome, indirect syscalls.**

## Introduction

Indirect Syscalls are an evolution of direct syscalls. They allow for functions to be executed in the memory of **`ntdll.dll`**, rather than in the memory of the .exe being used.

### Recap on User mode API Hooking

Usermode API hooking gives EDR the ability to inspect the behavior of code being executed in the context of Windows API or other Native API's. Hooking can come in many forms, but most EDR's use [`inline hooking`](https://malwaretech.com/2015/01/inline-hooking-for-programmers-part-1.html). **Inline hooking intercepts calls by replacing the `mov` opcode with a `jmp` instruction. The `jmp` instruction redirects execution to the EDR's `hooking.dll` to be examined for malicious content.** The execution only returns to the original memory space (syscall) if the EDR determines the content is safe.

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>





## Indirect Syscalls

* The execution of the syscall command takes place within the memory ntdll.dll and is therefore legitimate to EDR.
* The return statement happens within the memory of ntdll.dll and points from the memory of ntdll.dll.





reference:

{% embed url="https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls" %}
