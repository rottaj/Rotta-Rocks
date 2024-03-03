# NT Headers



## Introduction

In order to understand this page, we need to recap on Relative Virtual Addresses (RVA). An RVA is just an offset from where the image was loaded in memory (The Image base Virtual Address). **To Translate RVA into an absolute virtual address we **<mark style="color:yellow;">**add the value of the RVA to the value of the Image Base Address.**</mark>

**To summarize:**

1. Physical Memory Address is what CPU sees
2. Virtual Addreess (VA) is relative to Physical Address, per process (managed by OS)
3. RVA is relative to VA (file base or section base), per file (managed by linker and loader)



## NT Headers (IMAGE\_NT\_HEADERS)

The structure is defined in two different versions. One for 64 bit and one for 32 bit.

```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

### Signature

The first member of the NT Header structure is the Signature. It's a DWORD which means it occupies 4 bytes. It always has a fixed value of `0x50450000` which translates to `PE\0\0` in ASCII.

Here is the view in PE Bear:

<figure><img src="../../../.gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



### FileHeader (IMAGE\_FILE\_HEADER)

Also called the "COFF File Header", the FileHeader struct holds information about the PE file. Here is the struct:

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

* **Machine**: This is the CPU architecture. We’re only interested in two of them, `0x8864` for `AMD64` and `0x14c` for `i38`
* <mark style="color:yellow;">**NumberOfSections**</mark>: Holds the number of sections. (size of the section table).
* **TimeDateStamp**: When the file was created
* <mark style="color:yellow;">**SizeOfOptionalHeader**</mark>: The size of the optional header. (Used to iterate through each section)



## OptionalHeader (IMAGE\_OPTIONAL\_HEADER)

<mark style="color:yellow;">The Optional Header is the most important header of the NT Headers.</mark> The PE Loader looks for specific information in this header to be able to load the executable. **This header is essential for executable files.**

It doesn't have a fixed size which is why the `IMAGE_FILE_HEADER.SizeOfOptionalHeader` exists.

<mark style="color:yellow;">**IMPORTANT**</mark>**:** The first 8 members of the Optional Header structure are standard for every implementation of the `COFF` file format. the rest is an extension of `COFF` defined by Microsoft. **These additional members of the OptionalHeader structure are **<mark style="color:yellow;">**needed by the PE loader and linker**</mark>**.**



### Structure

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```



*   **Magic**: Integer that describes the state of the image. Three common values:

    * **`0x10B`:** Identifies the image as a `PE32` executable.
    * **`0x20B`:** Identifies the image as a `PE32+` executable.
    * **`0x107`:** Identifies the image as a ROM image.


* **SizeOfCode**: Holds the size of the code in the `.text` section. Or if there are multiple sections, the sum of all of them.
* **SizeOfInitializedData**: Holds the size of the initialized data in the `.data` section. Or if there are multiple sections, the sum of all of them.
* **SizeOfUninitializedData**: Holds the size of the unitialized data in the `.bss` section. Or if there are multiple sections, the sum of all of them.
* **AddressOfEntryPoint**: An RVA of the entry point when the file is loaded into memory. For program images, this relative address points to the starting address. For drivers it points to the initialization function. For DLL's an entrypoint is optional, and if absent, the AddressOfEntryPoint is set to `0`.
* **BaseOfCode**: An RVA of the start of the code section.
* **ImageBase**: Holds the preferred address of the image when loaded into memory. Due to ASLR, the address of specified in this field is almost never used. The PE Loader will choose an unused memory range to load the image into.
* **SectionAlignment**: Holds a value used for section alignment boundaries. Sections are aligned in boundaries that are multiples of this value. Defaults to the page size.
* **FileAlignment**: Similar to `SectionAligment` this field holds a value that gets used for section raw data alignment **on disk** (in bytes),
* <mark style="color:yellow;">**SizeOfImage**</mark>: The size of the image file (in bytes). Including all headers. Get's rounded to a multiple of `SectionAlignment`.
* <mark style="color:yellow;">**SizeOfHeaders**</mark>: The combined size of all headers rounded to a multiple of `FileAlignment`.
* **CheckSum**: Checksum of the image file, used to validate the image at load time.
* **Subsystem:** Subsystem if any. Can be useful for reversing. Console applications show: "Console"
* **SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve and SizeOfHeapCommit:** These fields specify the size of the stack to reserve, the size of the stack to commit, the size of the local heap space to reserve and the size of the local heap space to commit respectively.
* **NumberOfRvaAndSizes:** Size of the `DataDirectory` array.
* <mark style="color:yellow;">**DataDirectory**</mark>**:** An array of `IMAGE_DATA_DIRECTORY` structures. We will talk about this in the next post.z

**Here is the Optional Header in PE Bear**

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* **Magic Byte:** `0x20B` meaning that this is a `PE32+` executable.
* **SectionAlignment**: 1000
* **FileAlignment**: 200

