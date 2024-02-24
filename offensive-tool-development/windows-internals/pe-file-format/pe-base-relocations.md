# PE Base Relocations



## Relocations

When a program is compiled, the compiler assumes that the executable is going to be loaded at a certain base address, this address is saved in IMAGE\_OPTIONAL\_HEADER.ImageBase. Some addresses get hardcoded within the executable based on this ImageBase address.&#x20;

Due to `ASLR`, it is not probable that the base address is actually going to be used... so all hardcoded values that need relocating are stored in the `.reloc` section.

<mark style="color:red;">**NOTE:**</mark> Relocating is done by the loader, and it's what fixes the hard-coded values in the Relocation Table (located in `.reloc`).

### Example from 0xRicks Blog

Let’s take an example, the following code defines an `int` variable and a pointer to that variable:

```c
int test = 2;
int* testPtr = &test;
```

During compile-time, the compiler will assume a base address, let’s say it assumes a base address of `0x1000`, it decides that `test` will be located at an offset of `0x100` and based on that it gives `testPtr` a value of `0x1100`.\
Later on, a user runs the program and the image gets loaded into memory.\
It gets a base address of `0x2000`, this means that the hardcoded value of `testPtr` will be invalid, the loader fixes that value by adding the difference between the assumed base address and the actual base address, in this case it’s a difference of `0x1000` (`0x2000 - 0x1000`), so the new value of `testPtr` will be `0x2100` (`0x1100 + 0x1000`) which is the correct new address of `test`.



## Relocation Table

The Relocations Table is a Data Directory within the .reloc section. It contains all base relocations in the image.&#x20;

### Relocation Blocks

<mark style="color:yellow;">**The Base Relocation Table is divided into blocks, each block represents a base relocation for a 4K page and each block must start on a 32-bit boundary.**</mark>

Each block starts with an `IMAGE_BASE_RELOCATION` structure followed by any number of offset entries.

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;	// RVA to the base address of the section this block describes.
    DWORD   SizeOfBlock;	// The total size of the block, including the block header and all entries (discussed below).	
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
```

* **VirtualAddress**: RVA of the page
* **SizeOfBlock**: Size of the relocation block.

### Relocation Entry

<mark style="color:yellow;">**Reminder:**</mark> The relocation table is an array of relocation entries. Each element in the relocation table is as follows:

```c
typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset	: 12;  // Specifies where the base relocation is to be applied.
	WORD	Type	: 4;   // Indicates the type of base relocation to be applied.
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
```

## Relocation Types

It is worth noting that, there are multiple base relocation types as introduced by Microsoft [here](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types), where each type indicates a special way to apply relocations. However, the most notable types are:

* **IMAGE\_REL\_BASED\_ABSOLUTE** - The base relocation is skipped (no need to perform relocation).
* **IMAGE\_REL\_BASED\_DIR64** - The base relocation applies the difference to the 64-bit field at offset.
* **IMAGE\_REL\_BASED\_HIGHLOW** - The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
* **IMAGE\_REL\_BASED\_HIGH** - The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
* **IMAGE\_REL\_BASED\_LOW** - The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.

##

## How Relocation works

It's simple, each relocation entry get's processed by adding the RVA of the page image base address with the offset specified in the relocation entry (`IMAGE_BASE_RELOCATION.VirtualAddress`)

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

We know that each block starts with an 8-byte-long structure, meaning that the size of the entries is `0x20` bytes (32 bytes), each entry’s size is 2 bytes so the total number of entries should be 16.



## Fixing / Patching Relocation Table

Reminder: The relocation table is a&#x20;
