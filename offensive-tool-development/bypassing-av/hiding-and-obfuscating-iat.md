---
description: >-
  The Import Address Table (IAT) contains information regarding a PE file, such
  as the functions used and the DLLs exporting them. This type of information
  can be used to signature and detect the binary
---

# Hiding & Obfuscating IAT

***

## Dynamic Load at Runtime

It's possible to use `GetProcAddress`, `GetModuleHandle`, and `LoadLibrary` to dynamically load WINAPI functions at runtime.&#x20;

```c
typedef LPVOID (WINAPI* fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

//...
fnVirtualAllocEx pVirtualAllocEx = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "VirtualAllocEx");
pVirtualAllocEx(...);
```

_<mark style="color:red;">**NOTE:**</mark>_ This is not a very good solution as these functions will appear in the IAT, which by itself is signatured.&#x20;

## Creating Custom WinAPI Functions

For a better overview view:

{% embed url="https://app.gitbook.com/o/KN1jS9mFcRAy3dgznyeV/s/Ntkym7wd1H5AXS7YaAHH/~/changes/73/malware-development/bypassing-av/custom-winapi-functions" %}
Custom WINAPI Functions
{% endembed %}

### Custom GetProcAddress

The `GetProcAddress` WinAPI retrieves the address of an exported function from a specified module handle. The function returns NULL if the function name is not in the specified module handle.

#### How it works

```c
FARPROC GetProcAddress(
  [in] HMODULE hModule,
  [in] LPCSTR  lpProcName
);
```

* `hModule` Base address of the loaded DLL. This is the address where the DLL module is found in the address space of the process.
* `lpcProcName` Retrieving a function's address is found by looping through the exported functions inside the provided DLL and checking if the target function's name exists.

#### Export Table Structure

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

The relevant members of this structure for this module are the last three.

* `AddressOfFunctions` - Specifies the address of an array of addresses of the exported functions.
* `AddressOfNames` - Specifies the address of an array of addresses of the names of the exported functions.
* `AddressOfNameOrdinals` - Specifies the address of an array of _ordinal numbers_ for the exported functions.

#### Accessing Exported Functions

```c
for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
  // Searching for the target exported function 
}
```

### GetProcAddress Code

{% code fullWidth="true" %}
```c
#include <stdio.h>
#include <wchar.h>
#include <windows.h>



PVOID GetProcAddressR(HMODULE hModule, LPCSTR lpProcName) {

    // Optionally, create a LoadLibrary check to see if hModule is loaded.

    // IMPORTANT - Must cast handle address to PBYTE or header parsing will fail
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if(pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        wprintf(L"Failed to Get Optional Header");
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // Getting the function's names array pointer
    PDWORD FunctionNameArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfNames);

    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray 	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // Getting the name of the function
        CHAR *pFunctionName = (CHAR *) (pBase + FunctionNameArray[i]);
        // Getting the address of the function
        PVOID pFunctionAddress = (PVOID) (pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
        // Getting the ordinal of the function
        WORD wFunctionOrdinal = FunctionOrdinalArray[i];

        if (strcmp((LPCSTR) lpProcName, pFunctionName) == 0) {
            // Return function address
            return pFunctionAddress;
        }
    }
}

```
{% endcode %}



***

### Custom GetModuleHandle

The WinAPI function GetModuleHandle retrieves the handle for a specified DLL. The function returns a handle or NULL if the DLL does not exist in the calling process. <mark style="color:yellow;">This handle is actually just the base address to the module. So we are just trying to retreive the base address of the DLL.</mark>

```c
HMODULE GetModuleHandle(IN LPCWSTR szModuleName){}
```

#### How GetModuleHandle Works

The HMODULE data type is the base address of the loaded DLL which is where the DLL is located in the memory space of the process. Our replacement function will therefore return the base address of the DLL.

#### Implementation

The first step is access the PEB (Process Environment Block) structure so we can get information on the process & it's loaded modules. The process of retrieving the PEB on 64-Bit & 32-Bit systems are different, the pointer to the PEB is found in the TEB (Thread Environment Block) structure.

#### Retrieving PEB on 64-Bit System

```c
PPEB pPeb2 = (PPEB)(__readgsqword(0x60));
```

#### Retrieving PEB on 32-Bit System

```c
PPEB pPeb2 = (PPEB)(__readfsdword(0x30));
```

```c
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB;
```

#### Enumerating Loaded Modules

Now that we have access to PEB, we can enumerate the loaded modules. Information on loaded modules are found in the `PEB_LDR_DATA` loaderData structure.

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

```

`LIST_ENTRY InMemroyOrderModuleList` is a Doubly-linked list of all the loaded modules.

```c
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

* `Flink`: Points to next Entry
* `Blink`: Points to revious Entry.

Each entry in the linked list is a pointer to a loaded DLL. Loaded DLL's use the `LDR_DATA_TABLE_ENTRY` data structure.

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];					
    LIST_ENTRY InMemoryOrderLinks;	// doubly-linked list that contains the in-memory order of loaded modules
    PVOID Reserved2[2];			
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;		// 'UNICODE_STRING' structure that contains the filename of the loaded module
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```



####

### GetModuleHandle Code

GetModuleHandle returns a handle to the DLL specified. This handle is actually just the base address of the loaded DLL in memory. So we just have to locate this base address and return it.



{% code fullWidth="true" %}
```c
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

// This is for 64-bit windows.
int wmain() {
    HMODULE hModule = NULL;
    hModule = GetModuleHandleR(L"NTDLL.DLL");
    if (hModule == NULL) {
        wprintf(L"GetModuleHandleR Failed!");
        return -1;
    }
    wprintf(L"Loaded Handle! %p", hModule);
    getchar();

}

// Custom GetModuleHandle
HMODULE GetModuleHandleR(IN LPCWSTR szModuleName) {

    // 64 bit
    PPEB pPeb = (PPEB)(__readgsqword(0x60));

    // Getting Ldr
	PPEB_LDR_DATA		    pLdr	= (PPEB_LDR_DATA)(pPeb->Ldr);
  
	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY	pDte	= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	
	while (pDte) {
		
		// If not null
		if (pDte->FullDllName.Length != NULL) {
           	// Print the DLL name
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
				return (HMODULE)pDte->Reserved2[0];
            }

		}
		else {
			break;
		}
		
		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}
    // Return NULL if not found
    return NULL;
}

// Used for checking case-sensitive library names
BOOL IsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR   lStr1	[MAX_PATH],
			lStr2	[MAX_PATH];

	int		len1	= lstrlenW(Str1),
			len2	= lstrlenW(Str2);

	int		i		= 0,
			j		= 0;

	// Checking length. We dont want to overflow the buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

    // Converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++){
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating

	// Comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}
```
{% endcode %}



## API Hashing

Above we demonstrated creating our own custom WinAPI functions to hide the IAT table from security solutions. However, the strings we pass to our custom functions will easily be picked up as well. To bypass this, we can implement string hashing.

```c
GetProcAddressReplacement(GetModuleHandleReplacement("ntdll.dll"),"VirtualAllocEx")
```

_<mark style="color:red;">**NOTE:**</mark>_ "VirtualAllocEx" & "ntdll.dll" strings will be flagged by AV. With hashing our function will look like:

```c
GetProcAddressH(GetModuleHandleH(0x81E3778E),0xF10E27CA); 
```

#### Here's how it works:

_**GetProcAddressH:**_

```c
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR*	pFunctionName       = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress    = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Hashing every function name pFunctionName
		// If both hashes are equal then we found the function we want 
		if (dwApiNameHash == HASHA(pFunctionName)) {
			return pFunctionAddress;
		}
	}
```

We loop through each function name, hash it, and compare it with the hash passed to the function.\
