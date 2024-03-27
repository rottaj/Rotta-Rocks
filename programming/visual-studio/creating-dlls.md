# Creating DLL's

## Introduction

I greatly prefer a UNIX development environment, but sometimes It seems I'm almost forced to develop in Visual Studio (I.E building reflective DLLs). Here are some notes on building DLL's with Visual Studio.&#x20;

## Creating a DLL

To create a DLL in Visual Studio click: Create a Project, set the programming language to C++,  and select Dynamic Link Library (DLL).

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### Adding external functions.

To add an external function use the extern keyword

```cpp
extern __declspec(dllexport) BOOL ReflectiveFunction() {
}
```



## Template

<pre class="language-c"><code class="lang-c"><strong>#include &#x3C;windows.h>
</strong><strong>#include &#x3C;stdio.h>
</strong><strong>
</strong><strong>VOID PayloadFunction() {
</strong>
    MessageBoxA(NULL, "Foo", "Bar", MB_OK | MB_ICONINFORMATION);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            PayloadFunction();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}


extern __declspec(dllexport) BOOL ReflectiveFunction() {
}
</code></pre>



###

## Extra

### Best Practices

{% embed url="https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices?redirectedfrom=MSDN" %}

### Makefile

I know I'll be looking for this somewhere so here's the Makefile. If developing on linux, it's crucial we compile the DLL correctly.

```makefile
x86_64-w64-mingw32-gcc LdrDll.c -s -w -Wall -Wextra -masm=intel -shared -fPIC -e DllMain -Os -fno-asynchronous-unwind-tables Source/* -I Include -o Reflective.dll -lntdll -luser32 -DWIN_X64
```
