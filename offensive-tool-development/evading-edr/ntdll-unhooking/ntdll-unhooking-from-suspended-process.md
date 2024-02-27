# NTDLL Unhooking - From Suspended Process

## Introduction

An alternate approach to loading NTDLL is to read it from a suspended process. This works because EDR's require a running process to to install their hooks. Here's how it works:

* We create a process in a suspended state. (Contains clean ntdll.dll)
* Get local base address of ntdll.dll. (Imported dlls share the same base address between processes)

Do to ASLR, the virtual address of an imported library will be the same throughout all processes that import it. This is shared below:

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>
