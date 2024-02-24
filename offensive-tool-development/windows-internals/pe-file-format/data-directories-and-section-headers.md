# Data Directories & Section Headers

## Introduction

What is a Data Directory? A Data Directory is as piece of data located within one of the sections within a PE file.&#x20;

<mark style="color:yellow;">**Data Directories contain useful information needed by the loader, an example is the Import Directory, which contains a list external functions imported from other libraries.]**</mark>

<mark style="color:red;">**IMPORTANT:**</mark> **Not all Data Directories have the same structure**, the `IMAGE_DATA_DIRECTORY.VirtualAddress`, however the type of that directory is what determines how the chunk of data is parsed.

## Data Directories

The last member of the IMAGE\_OPTIONAL\_HEADER structure is an array of IMAGE\_DATA\_DIRECTORY structures. Defined below:

```c
IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
```

`IMAGE_NUMBEROF_DIRECTORY_ENTRIES` is a constant defined with the value of `16`, meaning this array can hold up to **16** `IMAGE_DATA_DIRECTORY` directories.

```c
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
```

`IMAGE_DATA_DIRECTORY` is shown below

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The first variable is the RVA pointing to the start of the Data Directory, and the second is the size of the Data Directory.

### Directory Entries

Here’s a list of Data Directories defined in `winnt.h`. (Each one of these values represents an index in the DataDirectory array):

```c
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

Here is how it looks in PE Bear

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>



## Sections and Section Headers

### Sections

Sections are the containers of the actual data of an executable file. They occupy the rest of the PE file after the headers, precisely after the section headers.

* **.text**: Contains the executable code of the program.
* **.data**: Contains the initialized data.
* **.bss**: Contains the uninitialized data.
* **.rdata**: Contains read-only initialized data.
* **.edata**: Contains export tables.
* **.idata**: Contains import tables.
* **.reloc**: Contains image relocation information.
* **.rsrc**: Contains resources used by the program. (Images, icons, embedded binaries).
* **.tls**: (Thread Local Storage), provides storage for every executing thread of the program.



### Section Headers

After the Optional Headers comes the Section Headers. The headers contain information about the sections in the PE file.

A Section Header is a struct `IMAGE_SECTION_HEADER` defined in `winnt.h`.

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

* **Name**: The name of the section. `IMAGE_SIZEOF_SHORT_NAME` is a max of 8 characters.
* **PhysicalAddress or VirtualSize**: A `union`. (Only one member can have a value at a time). Contains the total size of the section when it's loaded into memory.
* **VirtualAddress**: For executable images this address holds the first byte of the section relative to the image base. For object files, it holds the first byte of the section before relocation is applied.
* **SizeOfRawData**: Contains the size of the section on Disk. Must be a multiple of `IMAGE_OPTIONAL_HEADER.FileAlignment`. `SizeOfRawData` and `VirtualSize` can be different.
* **PointerToRawData**: A pointer to the first page of the section within the file. For executable images, it must be a multiple of `IMAGE_OPTIONAL_HEADER.FileAlignment`.
* **PointerToRelocations**: A file pointer to the beginning of the relocation entries for the section. It sets to `0` for executable files.
* **NumberOfLineNumbers**: The number of COFF line number entries for the section. **It's set to `0` because COFF debugging is deprecated**.
* **Characteristics**: Flags that describe the characteristics of the section. Like if the section contains executable code, initialized/unitialized data, can be shared in memory.

<mark style="color:red;">**NOTE**</mark><mark style="color:red;">:</mark> `SizeOfRawData` and `VirtualSize` can be different, this is because:

`SizeOfRawData` must be a multiple of `IMAGE_OPTIONAL_HEADER.FIleAlignment` but `VirtualSize` is not.&#x20;



**Here is the SectionHeader in PE-Bear**

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>
