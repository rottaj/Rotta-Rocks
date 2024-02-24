# PE File Structure



## Introduction

PE (Portable Executable) is a file format used in the Windows Operating system. It's is based of the [`COFF`](https://en.wikipedia.org/wiki/COFF) file format (Common Object File Format).

Executables `.exe`, Dynamic Link Libraries `.dll`, kernel modules `.srv`, Control Panel Applications `.cpl` and many others are all PE files.

## PE Structure

A typical PE structure is as follows:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="375"><figcaption><p>From 0xRicks blog post</p></figcaption></figure>

We can see the same thing in [hasherezade](https://github.com/hasherezade/pe-bear)'s PE-bear:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## DOS Header

Every PE file starts with a DOS Header, it's a 64 bytes long structure. It makes the PE file a MS-DOS executable. It contains the magic bytes `4D 5A` that signifies the file is in the DOS family. Named after [Mark Zbikowski](https://en.wikipedia.org/wiki/Mark\_Zbikowski).

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## DOS Stub

The DOS stub comes after the DOS header, it is a small MS-DOS 2.0 compatible executable that prints “This program cannot be run in DOS mode” when the program is run in DOS mode.

## NT Headers

The NT Headers contains three main parts:



*   ### PE Signature - 4 Byte signature that identifies the file as a PE


*   ### File Header - A standard `COFF` file header. (Hold some info on PE)


* ### Optional Header - <mark style="color:yellow;">The MOST important header of NT headers.</mark>

&#x20;      \->  <mark style="color:yellow;">**It's required for image files (like .**</mark><mark style="color:yellow;">**`exe`**</mark><mark style="color:yellow;">**). It provides important information on the OS loader.**</mark>



## Section Table

The section table immediately follows the the Optional Header. It is an array of Image Section Headers ([IMAGE\_SECTION\_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image\_section\_header)). Each header contains information about the section it refers to.



## Sections

Sections are where the actual contents of the files are stored. These include the actual code the program uses, dependencies, and data.
