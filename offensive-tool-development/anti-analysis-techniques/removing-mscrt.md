# Removing MSCRT

## Introduction

**The Microsoft C Run-Time Library** is a set of low level functions and macros that provide support for C & C++ programs. It includes functions for memory management, string manipulations, and I/O functions.

The reason why we'd want to do this is to reduce entropy in the binary.&#x20;

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption><p>PE size w/ Microsoft CRT</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption><p>PE size w/ out Microsoft CRT</p></figcaption></figure>

Depending on the compiler you use, the CRT DLL library names will differ. Below are screenshots of the&#x20;

### Microsoft Visual Studio Compiler

Visual Studio is as follows:  `vcruntimeXXX.dll` where XXX is the version number of the CRT library used. There's also `api-ms-win-crt-stdio-l1-1-0.dll`, `api-ms-win-crt-runtime-l1-1-0.dll` and `api-ms-win-crt-locale-l1-1-0.dll` that are also related to the CRT library. Each exporting it's own functions.

<figure><img src="../../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Mingw2 Compiler

MinGW stands for "minimalist GNU". Mingw uses `msvcrt.dll` to export all functions.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



## Removing CRT Mingw2

To remove CRT in mingw2, we can add these additional flags to our Mafefile.

&#x20;**`-nostartfiles` , `-nostdlib`**, **`-static-libgcc`**, and **`-static`**

<mark style="color:red;">**Note:**</mark>**&#x20;The only one we really need is `-nostartfiles`**

**Example Makefile:**

```makefile
run:
    x86_64-w64-mingw32-gcc main.c -o Playground.exe -municode -static -nostdlib -nostartfiles
```

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Replacing CRT Library Functions w/ our own.

Now that our our code is running independent from the C Standard Library, writing one's own version of functions such as `printf`, `strlen`, `strcat`, `memcpy` is necessary.&#x20;

Libraries like [VX-API](https://github.com/vxunderground/VX-API) may be used for this purpose. For example, [StringCompare.cpp](https://github.com/vxunderground/VX-API/blob/main/VX-API/StringCompare.cpp) replaces the `strcmp` function for string comparison.



### Replacing printf

```c
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  
```

### Import Table after Custom printf

We are now only importing KERNEL32.dll & USER32.dll (wsprintf).

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>



## An important thing to remember



### Building CRT independant malware

When building CRT independent malware it's important to keep in mind that <mark style="color:yellow;">**some functions and macros use CRT to perform tasks.**</mark>

**ZeroMemory:** Uses CRT memset to populate it's buffer with zeros. We need to find an alternative method then. The [CopyMemoryEx.cpp](https://github.com/vxunderground/VX-API/blob/main/VX-API/CopyMemoryEx.cpp) function can be used as a replacement.

We can manually set custom versions of CRT-based functions like `memset`. Forcing the compiler to deal with this custom function instead of using the CRT exported version. Macros like `ZeroMemory` will also use this custom function.



### Replacing Memset

Our custom version of the **`memset`** function can be specified to the compiler in the following manner, using the **`intrinsic`** keyword. The intrinsic function is a function that the compiler implements directly when possible.

**Intrinsic functions are provided by the compiler**, and do not require a #include like inline functions.

```c
#include <Windows.h>

// The `extern` keyword sets the `memset` function as an external function.
extern void* __cdecl memset(void*, int, size_t);

// The `#pragma intrinsic(memset)` and #pragma function(memset) macros are Microsoft-specific compiler instructions.
// They force the compiler to generate code for the memset function using a built-in intrinsic function.
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	// logic similar to memset's one
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}


int main() {
	
	PVOID pBuff = HeapAlloc(GetProcessHeap(), 0, 0x100);
	if (pBuff == NULL)
		return -1;

    // this will use our version of 'memset' instead of CRT's Library version 
	ZeroMemory(pBuff, 0x100);

	HeapFree(GetProcessHeap(), 0, pBuff);

	return 0;
}
```
