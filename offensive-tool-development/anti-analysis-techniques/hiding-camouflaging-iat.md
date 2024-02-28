# Hiding / Camouflaging IAT

## Introduction

This is a continuation of the [Hiding & Obfuscating IAT](../bypassing-av/hiding-and-obfuscating-iat.md) and [Removing MSCRT](removing-mscrt.md) pages.

IMPORTANT: By removing CRT from the binary file, along with other reductions of the IAT import functions like [String Hashing](../bypassing-av/string-hashing.md), <mark style="color:yellow;">**this can raise suspicion because of too few or zero function functon imports.**</mark>

<mark style="color:yellow;">**It is important for our malware to appear normal, this includes a usual number of import functions in the IAT.**</mark>

In this page I will go over how to make a fake IAT and show why it's more effective than having no IAT.



## Binary with few IAT imports

### Example Code:

Here are two examples of a basic process.

```c
#include <windows.h>
//#include <stdio.h>

int wmain() {
    //WaitForSingleObject((HANDLE)-1, INFINITE);
    getchar();
    return 0;
}
```

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Note that we can still use msvcrt.dll even though we remove it from loading on startup. However, the IAT functions will not work. (printf, memcpy, memset, etc.)</p></figcaption></figure>

#### We see that because there is only one import in the IAT, process hacker show it as a "<mark style="background-color:purple;">packed process</mark>".

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



## Camouflaging IAT

We can camouflage the IAT by adding WinAPI functions that do not change the behavior of the program. We can initialize the WinAPI functions w/ NULL, or by executing them on dummy data. We can also inclose them in if statements that will never be executed. Be creative!

### Example - Dead End If Statement

```c
        int z = 4;

	// Impossible if-statement that will never run
	if (z > 5) {
  
		// Random benign WinAPIs
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}
```



### Trick compiler&#x20;

In order for the compiler to believe that this if statement is valid, thus adding the functions to IAT we need to trick it.

```c
// Generate a random compile-time seed
int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
}


// A dummy function that makes the if-statement in 'IatCamouflage' interesting
PVOID Helper(PVOID *ppAddress) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;
	
	// setting the first 4 bytes in pAddress to be equal to a random number (less than 255)
	*(int*)pAddress = RandomCompileTimeSeed() % 0xFF;
	
	// saving the base address by pointer, and returning it 
	*ppAddress = pAddress;
	return pAddress;
}


// Function that imports WinAPIs but never uses them
VOID IatCamouflage() {

	PVOID		pAddress	= NULL;
	int*		A		    = (int*)Helper(&pAddress);
	
	// Impossible if-statement that will never run
	if (*A > 350) {

		// some random whitelisted WinAPIs
		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	// Freeing the buffer allocated in 'Helper'
	HeapFree(GetProcessHeap(), 0, pAddress);
}

int wmain() {
	WaitForSingleObject((HANDLE)-1, INFINITE)
}

```

<mark style="color:red;">**NOTE:**</mark> We don't actually every instanitate the function, it's just there to load the WinAPIs and trick the compiler.

### It works!

Compiling this, if using mingw2 will cause lots of warnings.

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



## A point to remember

This is enough to camouflage the IAT and make our binary appear safe. On the other hand, <mark style="color:yellow;">**we still need to obfuscate & hide our malicious WinAPI imports with string hashing.**</mark>&#x20;
