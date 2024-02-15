---
description: >-
  Understanding how PEs (portable executables) work is a crucial part of Windows
  exploitation. Whether we're developing evasive malware or reverse engineering,
  we need to understand how they work.
---

# Parsing PE Headers

## PE Structure

Every header shown is a struct that holds information about the PE file.

![](<../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png>)



## Structuring our code

One common way to structure code when parsing a Portable Executable is to create a struct that holds all data and headers for the PE.

```c
typedef struct _PE_HDRS
{
	PBYTE                    pFileBuffer; // Buffer from ReadFile
	DWORD                    dwFileSize;  // Size of file from GetFileSize

	PIMAGE_NT_HEADERS        pImgNtHdrs;
	PIMAGE_SECTION_HEADER    pImgSecHdr;

	PIMAGE_DATA_DIRECTORY    pEntryImportDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryBaseRelocDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryTLSDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryExceptionDataDir;
	PIMAGE_DATA_DIRECTORY    pEntryExportDataDir;

	BOOL                     bIsDLLFile;

} PE_HDRS, *PPE_HDRS;
```

Then when we parse each header we add it to the struct.

### Populating \_PE\_HDRS struct

Here's an example of a function we can use to parse the PE filebuffer we are working with into our struct above[**. For more information read below.**](#user-content-fn-1)[^1]

```c
BOOL InitializePeStruct(OUT PPE_HDRS pPeHdrs, IN PBYTE pFileBuffer, IN DWORD dwFileSize) {

	if (!pPeHdrs || !pFileBuffer || !dwFileSize)
              return FALSE;

	pPeHdrs->pFileBuffer              = pFileBuffer;
	pPeHdrs->dwFileSize               = dwFileSize;
	pPeHdrs->pImgNtHdrs               = (PIMAGE_NT_HEADERS)(pFileBuffer + ((PIMAGE_DOS_HEADER)pFileBuffer)->e_lfanew);

	if (pPeHdrs->pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
             return FALSE;

	pPeHdrs->bIsDLLFile               = (pPeHdrs->pImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
	pPeHdrs->pImgSecHdr               = IMAGE_FIRST_SECTION(pPeHdrs->pImgNtHdrs);
	pPeHdrs->pEntryImportDataDir      = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeHdrs->pEntryBaseRelocDataDir   = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeHdrs->pEntryTLSDataDir         = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	pPeHdrs->pEntryExceptionDataDir   = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeHdrs->pEntryExportDataDir      = &pPeHdrs->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	return TRUE;
}
```

### Relative Virtual Addresses (RVAs)

Relative Virtual Addresses are addresses used to reference locations within a PE file. For example, specifying the location of code, data, and resources.

_<mark style="color:red;">**IMPORTANT:**</mark>_ An RVA is a 32-bit value that specifies the **offset** of a data structure or section from the beginning of the PE file. Hence relative because it specifies the offset from the beginning of the file, rather than an absolute memory address.

The PE header contains several RVAs that specify the location of the code and data sections, the _**import**_ and _**export**_ tables, and other important data structures.

### DOS Header (IMAGE\_DOS\_HEADER)

The DOS header is located at the beginning of the PE file and contains information about the file, such as its size, and characteristics. _**But most importantly, it contains the RVA (offset) to the NT header.**_

_<mark style="color:yellow;">**Retrieve DOS Header (IMAGE\_DOS\_HEADER):**</mark>_

```c
// Pointer to the structure 
PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	
if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
	return -1;
}
```

_<mark style="color:red;">**NOTE:**</mark>_ Since the DOS header is at the very beginning of a PE file, retrieving the value is only a matter of getting a pointer. (pPE).

### NT Header (IMAGE\_NT\_HEADER)

The `e_lfanew` member of the DOS header is an RVA to the `IMAGE_NT_HEADERS` structure.&#x20;

_<mark style="color:yellow;">**Retrieve NT Header (IMAGE\_NT\_HEADER):**</mark>_

<pre class="language-c"><code class="lang-c">// Pointer to the structure
<strong>PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
</strong>
if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
	return -1;
}
</code></pre>

### File Header (IMAGE\_FILE\_HEADER)

Since the file header is a member of the `IMAGE_NT_HEADERS` structure, it can be accessed using the following line of code.

```c
IMAGE_FILE_HEADER		ImgFileHdr	= pImgNtHdrs->FileHeader;
```

### Optional Header (IMAGE\_OPTIONAL\_HEADER)

Since the optional header is a member of the `IMAGE_NT_HEADERS` structure, it is can be accessed using the following code.

_<mark style="color:yellow;">**Retrieve Optional Header (IMAGE\_OPTIONAL\_HEADER):**</mark>_

```c
IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
	return -1;
}
```

_<mark style="color:red;">**NOTE:**</mark>_ Depending on the compiler architecture, the `IMAGE_NT_OPTIONAL_HDR_MAGIC` constant will automatically expand to the correct value:

* `IMAGE_NT_OPTIONAL_HDR32_MAGIC` - 32-bit
* `IMAGE_NT_OPTIONAL_HDR64_MAGIC` - 64-bit

### DataDirectory (IMAGE\_DATA\_DIRECTORY)

The Data Directory can be accessed from the optional's header last member. This is an array of `IMAGE_DATA_DIRECTORY` meaning each element in the array is an `IMAGE_DATA_DIRECTORY` structure that references a special data directory. The `IMAGE_DATA_DIRECTORY` structure is shown below.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The fields of the structure contain information such as:

* `VirtualAddress` - Specifies the virtual address of the specified structure in the PE file, these are `RVAs`.
* `Size` - Specifies the size of the data directory.

### Export Table (IMAGE\_EXPORT\_DIRECTORY)

This structure is not officially documented by Microsoft. You will need to use unofficial documentation.\


**Export Table Structure**

The export table is a structure defined as `IMAGE_EXPORT_DIRECTORY` which is shown below.

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

**Retrieving The Export Table**

The `IMAGE_EXPORT_DIRECTORY` structure is used to store information about the functions and data that are exported from a PE file. This information is stored in the data directory array with the index `IMAGE_DIRECTORY_ENTRY_EXPORT`. To fetch it from the `IMAGE_OPTIONAL_HEADER` structure:

_<mark style="color:yellow;">**Retrieve Export Table:**</mark>_

```c
PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
```

### Import Table (IMAGE\_IMPORT\_DIRECTORY)

The import address table is an array of `IMAGE_IMPORT_DESCRIPTOR` structures with each one being for a DLL file that contains the functions that were used from these DLLs.

**Import Address Table Structure**

The `IMAGE_IMPORT_DESCRIPTOR` structure is also not officially documented by Microsoft although it is defined in the [Winnt.h Header File](https://learn.microsoft.com/en-us/windows/win32/api/winnt/) as follows:

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
```

_<mark style="color:yellow;">**Retrieving The Import Address Table**</mark>_

```c
IMAGE_IMPORT_DESCRIPTOR* pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
```

### Additional Undocumented Structures

Several undocumented structures can be accessed via the `IMAGE_DATA_DIRECTORY` array in the optional header but are not documented in the Winnt.h header file.&#x20;

`IMAGE_TLS_DIRECTORY` - This structure is used to store information about [Thread-Local Storage](https://learn.microsoft.com/en-us/cpp/c-language/thread-local-storage?view=msvc-170) (TLS) data in the PE file.

```c
PIMAGE_TLS_DIRECTORY pImgTlsDir  = (PIMAGE_TLS_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
```

`IMAGE_RUNTIME_FUNCTION_ENTRY` - This structure is used to store information about a runtime function in the PE file.

```c
PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRunFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
```

`IMAGE_BASE_RELOCATION` - This structure is used to store information about the base relocations in the PE file.

```c
PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
```



### PE Sections (IMPORTANT)

Structure of a PE Sections (`.text`, `.data`, `.reloc`, `.rsrc)`

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

_<mark style="color:red;">**IMPORTANT:**</mark>_** IMAGE\_SECTION\_HEADER Important Members**

Some of IMAGE\_SECTION\_HEADER's most important members;

* `Name` - A null-terminated ASCII string that specifies the name of the section.
* `VirtualAddress` - The virtual address of the section in memory, this is an `RVA`.
* `SizeOfRawData` - The size of the section in the PE file in bytes.
* `PointerToRelocations` - The file offset of the relocations for the section.
* `NumberOfRelocations` - The number of relocations for the section.
* `Characteristics` - Contains flags that specify the characteristics of the section.

_<mark style="color:yellow;">**Retrieving The IMAGE\_SECTION\_HEADER Structure**</mark>_

The `IMAGE_SECTION_HEADER` structure is stored in an array within the PE file's headers. To access the first element, skip past the `IMAGE_NT_HEADERS` since the sections are located immediately after the NT headers. The following snippet shows how to retrieve the `IMAGE_SECTION_HEADER` structure, where `pImgNtHdrs` is a pointer to `IMAGE_NT_HEADERS` structure.

```c
PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
```

**Looping Through The Array**

Looping through the array requires the array size which can be retrieved from the `IMAGE_FILE_HEADER.NumberOfSections` member. The subsequent elements in the array are located at an interval of `sizeof(IMAGE_SECTION_HEADER)` from the current element.

```c
PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
	// pImgSectionHdr is a pointer to section 1
	pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	// pImgSectionHdr is a pointer to section 2
}
```

[^1]: 
