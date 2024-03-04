# Import Directory Table, ILT & IAT



## Introduction

A very important aspect of PE files are the PE imports. There are three main `Data Directories` present in the **Import Data** section `.idata`.&#x20;

* The Import Directory Table (**IDT**)
* Import Lookup Table (**ILT**)
* Import Address Table (**IAT**)

<mark style="color:red;">**IMPORTANT:**</mark> For every DLL an executable is loading, there will be an `IMPORT_IMAGE_DESCRIPTOR` (**IDT**), that contains the `Name` of the DLL, **and two fields that hold the RVA's to the `ILT` & `IAT`.**

<mark style="color:yellow;">**OriginalFirstThunk**</mark>: RVA of the Import Lookup Table (ILT).

<mark style="color:yellow;">**FirstThunk**</mark>: RVA of the Import Address Table (IAT).

##

## Import Directory Table

The Import Directory Table is located at the beginning of the `.idata` section.

It consists of an array of `IMAGE_IMPORT_DESCRIPTOR` structs. Each one of them is a `DLL`.

The array doesn't have a fixed size so the `IMAGE_IMPORT_DESCRIPTOR` is zeroed-out (NULL-Padded) to indicate the end of the array.

**The DLL struct looks like this:**

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
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```

* <mark style="color:yellow;">**OriginalFirstThunk**</mark>: RVA of the Import Lookup Table (ILT).
* TimeDateStamp: Set to 0 if not bound and set to -1 if bound.
* ForwarderChain: Used for DLL forwarding (DLL forwarding is when a DLL forwards some external functions to another DLL).
* Name: An RVA of an ASCII string that contains the name of the imported DLL.
* <mark style="color:yellow;">**FirstThunk**</mark>: RVA of the Import Address Table (IAT).

## Bound Imports

A bound import means that the import table contains fixed addresses for the imported functions. These addresses are calculated and written during compile time by the linker.

Using Bound imports is for speed optimization, it reduces time by the loader to resolve function addresses and fill the IAT.

### Bound Import Data Directory

The Bound Import Data Directory is the same as the Import DIrectory Table except it holds information about the bound imports.

It consits of `IMAGE_BOUND_IMPORT_DESCRIPTOR` structs.

```c
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
```

* **TimeDateStamp:** The time date stamp of the imported DLL.
* **OffsetModuleName:** An offset to a string with the name of the imported DLL.\
  It’s an offset from the first `IMAGE_BOUND_IMPORT_DESCRIPTOR`
* **NumberOfModuleForwarderRefs:** The number of the `IMAGE_BOUND_FORWARDER_REF` structures that immediately follow this structure.\
  `IMAGE_BOUND_FORWARDER_REF` is a structure that’s identical to `IMAGE_BOUND_IMPORT_DESCRIPTOR`, the only difference is that the last member is reserved.



## Import Lookup Table (ILT)

Also referred to as the Import Name Table (INT).

<mark style="color:yellow;">**Every DLL imported has a Import Lookup Table**</mark>.&#x20;

`IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk` holds the RVA of the ILT of the DLL.

The ILT is a table of names or references, it tells the loader what functions are needed for the imported DLL to run.

It consists of an array of 64-bit numbers for (PE32+), the last is zeroed-out to signify the end of the array.

Each entry of these entries encodes information as follows:

* **Bit 31/63 (most significant bit)**: This is called the Ordinal/Name flag, it specifies whether to import the function by name or by ordinal.
* **Bits 15-0:** If the Ordinal/Name flag is set to `1` these bits are used to hold the 16-bit ordinal number that will be used to import the function, bits 30-15/62-15 for PE32/PE32+ must be set to `0`.
* **Bits 30-0:** If the Ordinal/Name flag is set to `0` these bits are used to hold an RVA of a Hint/Name table.

### Hint/Name Table

The Name table is a `IMAGE_IMPORT_BY_NAME` struct

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

* **`Hint`:** A word that contains a number, this number is used to look-up the function, that number is first used as an index into the export name pointer table, if that initial check fails a binary search is performed on the DLL’s export name pointer table.
* **`Name`:** A null-terminated string that contains the name of the function to import.



## Import Address Table (IAT)

On disk, the IAT is identical to the ILT, however during bounding when the binary is being loaded into memory, the entries of the IAT get overwritten with the addresses of the functions that are being imported.



## Summary

* The ILT will contain references for all the functions that are being imported from the DLL.
* The IAT will be identical to the ILT until the executable is loaded in memory, then the loader will fill the IAT with the actual addresses of the imported functions.
* If the DLL import is a bound import, then the import information will be contained in `IMAGE_BOUND_IMPORT_DESCRIPTOR` structures in a separate Data Directory called the Bound Import Data Directory.

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Above we can see the RVA's to the ILT & IAT.**



## Fixing / Patching Import Address Table (IAT)

<mark style="color:yellow;">**NOTE:**</mark> Advancing to the next element in the IAT is done by adding the size of the structure to the current element's address. The final element within the IAT array is represented by a nullified `IMAGE_IMPORT_DESCRIPTOR` structure.

[<mark style="color:red;">**IMPORTANT:**</mark> A function can be resolved by both name and ordinal. In order to resolve the address, we need to determine how it's being imported first.](#user-content-fn-1)[^1]

### Access Import Nable Table (INT)

We can access the INT via the **`OriginalFirstThunk`** RVA from the **`IMPORT_IMAGE_DESCRIPTOR`**.

```c
typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // Used in the case of forwarded functions - not used.
        ULONGLONG Function;         // The address of the function to be populated
        ULONGLONG Ordinal;	    // Ordinal number of the function	
        ULONGLONG AddressOfData;    // RVA to PIMAGE_IMPORT_BY_NAME - used only if the function is imported by name rather by ordinal.
    } u1;
} IMAGE_THUNK_DATA64;
```



### Determine if a function is being imported by Ordinal.

To determine if a function is being imported by a name or ordinal, we can use **`IMAGE_SNAP_BY_ORDINAL`**. This verifies whether an import entry is being imported by an ordinal.

```c
pFunctionAddress = GetProcAddress(hModule, IMAGE_ORDINAL(PIMAGE_THUNK_DATA->u1.Ordinal));
```

If this function (`IMAGE_SNAP_ORDINAL`) returns **False**, it means that the import entry is being imported by name rather than ordinal.

### Importing a function by Name

If a function is being imported by name and not ordinal (see above), we can retrieve the functions name for use in `GetProcAddress` (relies on function name). We can retrieve the Name through the **`AddressOfData`** RVA found within **`IMAGE_THUNK_DATA`** that points to a **`IMAGE_IMPORT_BY_NAME`** struct:

```c
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;	// Look-up number of the function in the function export table - not used.
    CHAR   Name[1];	// Function name
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

When dealing with functions imported by name, their address can be resolved using the following code snippet:

```c
PIMAGE_IMPORT_BY_NAME pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + PIMAGE_THUNK_DATA->u1.AddressOfData);
pFunctionAddress = GetProcAddress(hModule, pImgImportByName->Name);
```

[^1]: IMPORTANT
