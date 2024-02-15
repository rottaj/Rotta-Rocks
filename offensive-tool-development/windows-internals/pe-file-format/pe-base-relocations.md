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

### Data Directory Blocks

The Data Directory is divided by blocks, each block represents a base relocation for a 4K page and each block must start on a 32-bit boundary.

Each block starts with an `IMAGE_BASE_RELOCATION` structure followed by any number of offset entries.

```c
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

* **VirtualAddress**: RVA of the page
* **SizeOfBlock**: Size of the relocation block.

## How Relocations works

It's simple, each relocation entry get's processed by adding the RVA of the page image base address with the offset specified in the relocation entry (`IMAGE_BASE_RELOCATION.VirtualAddress`)

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

We know that each block starts with an 8-byte-long structure, meaning that the size of the entries is `0x20` bytes (32 bytes), each entry’s size is 2 bytes so the total number of entries should be 16.
