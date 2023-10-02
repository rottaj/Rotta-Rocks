---
description: >-
  Detours is a software package for re-routing Win32 APIs underneath
  applications.
---

# Microsoft's Detours Library

{% embed url="https://www.microsoft.com/en-us/research/project/detours/" %}
Microsoft Documentation
{% endembed %}

{% embed url="https://github.com/microsoft/Detours" %}
Package Source
{% endembed %}

{% embed url="https://github.com/microsoft/Detours/wiki/" %}
Wiki
{% endembed %}

## How it works

The Detours library replaces the first few instructions of the function we are hooking with a jump instruction to the user-provided detour function. **This jump is called a trampoline.**

The library uses transactions to install and uninstall hooks from the targeted function.



## Using the Detours Library

_<mark style="color:red;">**IMPORTANT:**</mark>_ To use the Detours library's functions, the Detours repository must be downloaded and compiled to get the static library files (.lib) files needed for the compilation. In addition to that the [detours.h](https://github.com/microsoft/Detours/blob/master/src/detours.h) header file should be included, this is explained in the Detours wiki under the [Using Detours](https://github.com/microsoft/Detours/wiki/Using-Detours) section.

For additional help adding .lib files to a project, review [Microsoft's documentation](https://learn.microsoft.com/en-us/cpp/build/reference/dot-lib-files-as-linker-input?view=msvc-170).

## Detour Functions

* [DetourTransactionBegin](https://github.com/microsoft/Detours/wiki/DetourTransactionBegin) - Begin a new transaction for attaching or detaching detours. This function should be called first when hooking and unhooking.
* [DetourUpdateThread](https://github.com/microsoft/Detours/wiki/DetourUpdateThread) - Update the current transaction. This is used by Detours library to _Enlist_ a thread in the current transaction.
* [DetourAttach](https://github.com/microsoft/Detours/wiki/DetourAttach) - Install the hook on the target function in a current transaction. This won't be committed until `DetourTransactionCommit` is called.
* [DetourDetach](https://github.com/microsoft/Detours/wiki/DetourDetach) - Remove the hook from the targeted function in a current transaction. This won't be committed until `DetourTransactionCommit` is called.
* [DetourTransactionCommit](https://github.com/microsoft/Detours/wiki/DetourTransactionCommit) - Commit the current transaction for attaching or detaching detours.

## Using Detour Functions

### Retrieve Hook Function Address

When using any hooking method, the first step is to get the memory address of the function to be hooked. Refer back to previous sections on custom `GetProcAddress`, `GetModuleHandle` functions to retrieve the memory address.

### Replacing the Hooked Function

Next we create a function to replace the function we are hooking. The replacement function should be the same datatype, and preferably take the same parameters.

```c
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  // we can check hWnd - lpText - lpCaption - uType parametes
}
```

