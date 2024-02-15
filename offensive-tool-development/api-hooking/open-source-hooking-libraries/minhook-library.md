---
description: >-
  In comparison to other hooking libraries, MinHook is simpler and offers
  lightweight APIs, making it easier to work with.
---

# MinHook Library

***

{% embed url="https://github.com/TsudaKageyu/minhook" %}

## Using the MinHook Library

Similarly to the Detours library, the Minhook library requires the static `.lib` file and the [MinHook.h](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h) header file to be included in the Visual Studio project.



## MinHook Functions

We can think of MinHook functions like we do with CRUD.&#x20;

_<mark style="color:red;">**NOTE:**</mark>_ `MH_Initialize` & `MH_Unitialize` should be called once, at the beginning of the program and at the end.

* [MH\_Initialize](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L96) - Initializes the HOOK\_ENTRY structure.
* [MH\_CreateHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L111) - Create the hooks.
* [MH\_EnableHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L154) - Enables the created hooks.
* [MH\_DisableHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L161) - Remove the hooks.
* [MH\_Uninitialize](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L100) - Cleanup the initialized structure.

The Minhook APIs return a `MH_STATUS` value.`MH_OK` value, which is a 0, is returned if the function succeeds and a non-zero value is returned if an error occurs.

