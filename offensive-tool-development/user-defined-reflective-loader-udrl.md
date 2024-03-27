# User Defined Reflective Loader (UDRL)



## Introduction

The **User Defined Reflective Loader (UDRL)** is a way for Cobalt Strike operators to write their own reflective loader for Beacons. They are particularly helpful for increasing evasiveness by allowing operators the flexibility of not being constrained to the default loader.

In general, reflective DLL injection is typically used as a persistence mechanism after initial access has been achieved through other means like malicious Office macros or executable files.

## Reflective Loading

A Cobalt Strike beacon is just a DLL. Fundamentally, a reflective loader must:

* Allocate some memory.
* Copy the target DLL into that memory allocation.
* Parse the target DLL’s imports/load the required modules/resolve function addresses.
* Fix DLL base relocations.
* Locate the DLL’s Entry Point.
* Execute the Entry Point.

## Configuring Compiler

To compile the project and ensure it executes properly we need to add the following flags in our compiler options. I'm using Mingw32.

* Set Entrypoint: `-e DllMain`
* Link Windows DLL's `-lntdll -luser32 -DWIN_X64`
* Create standalone, and add extra: `-g -s -w -Wall -Wextra -masm=intel -shared`

```makefile
x86_64-w64-mingw32-gcc LdrDll.c -g -s -w -Wall -Wextra -masm=intel -shared -fPIC -e DllMain -Os -fno-asynchronous-unwind-tables Src/* -o RflDll.dll -lntdll -luser32 -DWIN_X64
```

Mingw32 compiler flags can be found [here](https://caiorss.github.io/C-Cpp-Notes/compiler-flags-options.html).

These are the outlines from Fortas site:

* [Entry Point](https://learn.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol?view=msvc-170) (_ReflectiveLoader_) – This setting changes the default starting address to Stephen Fewer’s `ReflectiveLoader()` function. A custom entry point would normally be problematic for a traditional PE file and require some manual initialization. However, Stephen Fewer’s code is _position independent_, so this won’t be a problem.
* [Enable Intrinsic Functions](https://learn.microsoft.com/en-us/cpp/build/reference/oi-generate-intrinsic-functions?view=msvc-170) (_Yes_) – [Intrinsic functions](https://learn.microsoft.com/en-us/cpp/intrinsics/compiler-intrinsics?view=msvc-170) are built into the compiler and make it possible to “_call_” certain assembly instructions. These functions are “_inlined_” automatically which means the compiler inserts them at compile time.
* [Ignore All Default Libraries](https://learn.microsoft.com/en-us/cpp/build/reference/nodefaultlib-ignore-libraries?view=msvc-170) (_Yes_) – This setting will alert us when we call external functions (as that would not be _position independent_).
* [Basic Runtime Checks](https://learn.microsoft.com/en-us/cpp/build/reference/rtc-run-time-error-checks?view=msvc-170) (_Default_) – This setting is configured correctly in _Release_ mode by default, but changing it in the _Debug_ configuration disables some runtime error checking that will throw an error due to our custom entry point.
* Optimization – We’ve enabled several of Visual Studio’s different Optimization settings and opted to favor smaller code where possible. However, at certain points in the template we’ve disabled it to ensure our code works as expected.\




## Building Reflective Loader

There are many methods we can use to create a Reflective Loader. Here are some common ones.



## Double Pulsar Approach

The Double Pulsar approach differs from traditional Reflective Loaders as it is not compiled directly into the DLL, but prepended in front of it. This approach allows it to reflectively load ANY DLL.

<mark style="color:yellow;">**This works by extracting the loader from the compiled executable and prepending it to the Beacon.**</mark>

Below shows the difference between Double Pulsar & Stephen Fewers Reflective Loader.

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Taken from Forta <a href="https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development">https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development</a></p></figcaption></figure>



### Function Positioning

As stated above, the Double Pulsar approach prepends the loader at the very start of the Beacon file. For this to work we need to know the following:

* Make sure the loaders entry point sits at the very start of the Beacons shellcode.
* Make sure we can find the end of the loader. (In order to find the start of the Beacon). (**code\_seg)**

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Taken from Forta <a href="https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development">https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development</a></p></figcaption></figure>

Positioning works by telling the linker what PE sections store specified functions. This can be accomplished with  the [code\_seg](https://learn.microsoft.com/en-us/cpp/preprocessor/code-seg?view=msvc-170) [pragma directive](https://learn.microsoft.com/en-us/cpp/preprocessor/pragma-directives-and-the-pragma-keyword?view=msvc-170). These sections can then be ordered using [alphabetical values](https://devblogs.microsoft.com/oldnewthing/20181107-00/?p=100155) e.g `.text$a`.&#x20;

* We will place `ReflectiveLoader()` function within `.text$a` to ensure that it is positioned at the start of the `.text.`&#x20;
* All remaining functions will be in `.text$b` to ensure they come after ReflectiveFunction().
* The final `LdrEnd` function will be `.text$z`. This is an important function as it allows us to find the end of the loader, and the start of the Beacons shellcode.

```c
#pragma code_seg(".text$a")
ULONG_PTR WINAPI ReflectiveLoader(VOID) {
[…SNIP…]
}
#pragma code_seg(".text$b")
[…SNIP…]

#pragma code_seg(".text$z")
void LdrEnd() {}
```
