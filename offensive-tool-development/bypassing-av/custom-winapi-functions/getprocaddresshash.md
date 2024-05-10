# GetProcAddressHash

## Introduction

This function is similar to mattifestations [GetProcAddressWithHash](https://github.com/mattifestation/PIC\_Bindshell/blob/master/PIC\_Bindshell/GetProcAddressWithHash.h). Instead of having two functions ([GetModuleHandle ](https://www.rotta.rocks/offensive-tool-development/bypassing-av/hiding-and-obfuscating-iat#getmodulehandle-code)& [GetProcAddress](https://www.rotta.rocks/offensive-tool-development/bypassing-av/hiding-and-obfuscating-iat#getprocaddress-code)) we do all the work in one... searching through all loaded libraries loaded functions until we get the hash we're looking for.

### GetProcAddressHash

<mark style="color:red;">**NOTE**</mark>: When building PIC, we'll have to implement our own lstrlen or use another hash function as we won't be using CRT or the Windows SDK. Example PIC makefile flags:

```makefile
 -nostdlib -O2 --entry Entry -ffunction-sections
```

```c
#include <windows.h>
#include <winternl.h>

#define INITIAL_SEED	7


size_t strlen(const char *str) {
	size_t len = 0;
	while (str[len] != '\0')
		len++;
	return len;
}

UINT32 HASHA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = strlen(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


// Redefine PEB structures. The structure definitions in winternl.h are incomplete.
typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;


HMODULE GetProcAddressHash(DWORD dwHash)
{
	// Get PEB structure
	#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
	#endif // _WIN64

	// Get of current process (call pLdr->DllBase to get base address)
	PPEB_LDR_DATA		    pLdr	= (PPEB_LDR_DATA)(pPeb->Ldr);
	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY	pDte	= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// If not null
		if (pDte->FullDllName.Length) {
			// IMPORTANT - Must cast handle address to PBYTE or header parsing will fail
			PBYTE pBase = pDte->Reserved2[0];

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

				// TODO Compare hashes
				if (dwHash == HASHA(pFunctionName))
				{
					return (HMODULE) pFunctionAddress;
				}
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
```
